// deevnet-broker-account writes one MQTT account into the broker's auth
// database and exits. It is invoked by sshd as a forced command, reads one
// request as JSON on stdin, and prints one response as JSON on stdout.
//
// It exists because the auth database must not be reachable from the network
// (CHG-0016). PostgreSQL is bound to loopback on the messaging VM, so only a
// program running on that host can reach it, and this is that program.
//
// Design: architecture/substrate/control-plane/broker-account-writer.
//
// Three things it must never do, and the reasons they are here rather than in
// a document nobody opens:
//
//   - It never looks at SSH_ORIGINAL_COMMAND. The key is pinned with
//     command=, so whatever the client asked for is irrelevant; reading it
//     would turn a fixed program into a dispatcher.
//   - It never interpolates a caller's string into SQL. Every statement below
//     is parameterised.
//   - It never returns database error text to the caller. The response names
//     the problem; the detail goes to stderr for the operator.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/brokeracct"
)

// configPath is fixed rather than taken from the environment. sshd passes the
// client no environment by default and `restrict` keeps it that way, so there
// is nothing to plumb - and a fixed path cannot be redirected by a caller.
const configPath = "/etc/deevnet/broker-account.json"

type config struct {
	// Declared so the file can carry Ansible's "managed" marker. Unknown
	// fields are refused - a typo in a config we own should be loud, not
	// silently defaulted - so the marker has to be a field the parser knows.
	Comment string `json:"_comment,omitempty"`

	Host string `json:"host"`
	Port int    `json:"port"`
	Name string `json:"database"`
	User string `json:"user"`
	// Password is read from this file rather than held here, so the secret
	// lives in one place with one set of permissions.
	PasswordFile string `json:"password_file"`

	// Every wait is bounded: a tenant's terraform apply is holding the other
	// end of this, and nothing here may hang.
	TimeoutSeconds          int `json:"timeout_seconds"`
	StatementTimeoutSeconds int `json:"statement_timeout_seconds"`
}

func main() {
	// One response, always, whatever happens. A caller that gets nothing on
	// stdout cannot tell a refusal from a crash, and the API's retry path
	// depends on telling them apart.
	resp, detail := run()
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "writing the response failed: %v\n", err)
		os.Exit(2)
	}
	if !resp.OK {
		if detail != nil {
			// Operator-facing. sshd carries this to the API, which logs it
			// and never puts it in front of a tenant - the same treatment
			// every other backend error gets.
			fmt.Fprintf(os.Stderr, "broker-account: %v\n", detail)
		}
		os.Exit(1)
	}
}

func fail(msg string, detail error) (brokeracct.Response, error) {
	return brokeracct.Response{Version: brokeracct.Version, OK: false, Message: msg}, detail
}

func run() (brokeracct.Response, error) {
	cfg, err := loadConfig()
	if err != nil {
		// Deliberately vague to the caller: a misconfigured host is not the
		// caller's business, and the path is not worth echoing.
		return fail("the writer is not configured", err)
	}

	// The whole invocation is bounded, not just the query. This is the
	// backstop for anything below that could block.
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()

	req, err := brokeracct.Decode(os.Stdin)
	if err != nil {
		return fail(err.Error(), nil)
	}
	if err := req.Validate(); err != nil {
		// Validation messages are written to be safe to return: they name the
		// field and the rule, never the caller's value.
		return fail(err.Error(), nil)
	}

	conn, err := connect(ctx, cfg)
	if err != nil {
		return fail("the database is unavailable", err)
	}
	defer conn.Close(context.Background())

	switch req.Op {
	case brokeracct.OpPut:
		existed, err := put(ctx, conn, req)
		if err != nil {
			return fail("writing the account failed", err)
		}
		return brokeracct.Response{
			Version: brokeracct.Version, OK: true,
			Username: req.Username(), Existed: existed,
		}, nil
	case brokeracct.OpDelete:
		if err := del(ctx, conn, req); err != nil {
			return fail("removing the account failed", err)
		}
		return brokeracct.Response{
			Version: brokeracct.Version, OK: true, Username: req.Username(),
		}, nil
	}
	// Unreachable: Validate refuses any other op. Kept so a future op added to
	// the contract without a branch here fails closed rather than silently
	// succeeding.
	return fail("unsupported operation", nil)
}

func loadConfig() (config, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return config{}, err
	}
	cfg := config{
		Host: "127.0.0.1", Port: 5432, Name: "vernemq", User: "deevnet_api",
		TimeoutSeconds: 10, StatementTimeoutSeconds: 5,
	}
	dec := json.NewDecoder(newLimitedReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return config{}, err
	}
	if cfg.PasswordFile == "" {
		return config{}, errors.New("password_file is not set")
	}
	if cfg.TimeoutSeconds <= 0 || cfg.StatementTimeoutSeconds <= 0 {
		return config{}, errors.New("timeouts must be positive")
	}
	return cfg, nil
}

func connect(ctx context.Context, cfg config) (*pgx.Conn, error) {
	pw, err := os.ReadFile(cfg.PasswordFile)
	if err != nil {
		return nil, fmt.Errorf("reading the database password: %w", err)
	}
	pc, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	pc.Host, pc.Port, pc.Database, pc.User = cfg.Host, uint16(cfg.Port), cfg.Name, cfg.User
	pc.Password = trimNewline(string(pw))
	// A second bound, inside the database: a lock must not become a hung
	// apply. The context above would cancel the client, but this stops the
	// server working on a statement nobody is waiting for any more.
	pc.RuntimeParams["statement_timeout"] =
		fmt.Sprintf("%d", cfg.StatementTimeoutSeconds*1000)
	return pgx.ConnectConfig(ctx, pc)
}

// put upserts the account. It is idempotent by construction: the API retries
// with the hash it already persisted, so a retry after an ambiguous failure
// converges instead of rotating a credential that devices are flashed with.
//
// xmax is how PostgreSQL reports which half of the upsert ran: zero on a fresh
// insert, non-zero when the row already existed and was updated. It makes a
// retry distinguishable in the audit trail without changing the outcome.
func put(ctx context.Context, conn *pgx.Conn, req brokeracct.Request) (bool, error) {
	pub, err := aclJSON(req.Publish)
	if err != nil {
		return false, err
	}
	sub, err := aclJSON(req.Subscribe)
	if err != nil {
		return false, err
	}
	var existed bool
	err = conn.QueryRow(ctx, `
		INSERT INTO vmq_auth_acl
		       (mountpoint, client_id, username, password, publish_acl, subscribe_acl)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (mountpoint, client_id, username) DO UPDATE
		   SET password      = EXCLUDED.password,
		       publish_acl   = EXCLUDED.publish_acl,
		       subscribe_acl = EXCLUDED.subscribe_acl
		RETURNING (xmax <> 0)`,
		req.Mountpoint(), req.ClientID(), req.Username(),
		req.PasswordHash, pub, sub).Scan(&existed)
	return existed, err
}

// del removes the account. A row that is not there is success, so a repeated
// delete converges rather than failing the second time.
func del(ctx context.Context, conn *pgx.Conn, req brokeracct.Request) error {
	_, err := conn.Exec(ctx, `
		DELETE FROM vmq_auth_acl
		 WHERE mountpoint = $1 AND client_id = $2 AND username = $3`,
		req.Mountpoint(), req.ClientID(), req.Username())
	return err
}

// aclJSON renders patterns in the shape vmq_diversity reads: a JSON array of
// objects each carrying one "pattern". Built here rather than by the caller,
// so the stored document cannot contain a key this program did not write -
// "modifiers" in particular, which ADR-0012 §10 refuses because a modifier can
// move a message out of the tenant's prefix.
func aclJSON(patterns []string) ([]byte, error) {
	out := make([]map[string]string, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, map[string]string{"pattern": p})
	}
	return json.Marshal(out)
}
