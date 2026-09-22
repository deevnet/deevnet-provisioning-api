// Package logwriter reaches the log store's user writer over SSH.
//
// It is brokerwriter's twin, and deliberately so: one SSH connection carrying
// one request to a program pinned to a key with command= and restrict, and one
// response read back. Keeping the two the same shape means an operator who has
// debugged one has debugged both.
//
// Two things differ, and both are about what crosses:
//
//   - The request carries the tenant's bearer tokens, not a hash of them.
//     vmauth compares the token it was configured with, so there is no
//     one-way form to send. The mitigation is the same key pinning and the
//     same forced command, plus a writer that runs as its own user.
//   - The far end is on Platform, the same segment as the API, so this path
//     crosses no zone rule (CHG-0020). The broker's writer crosses
//     platform -> iot_backend and needed one declared.
package logwriter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Config is what the API needs to reach the writer. Every field is required;
// there is no default that would be safe.
type Config struct {
	// Addr is host:port.
	Addr string
	User string
	// PrivateKey is the API's own key, in PEM, used for nothing else, so
	// revoking it revokes exactly this capability.
	PrivateKey []byte
	// HostKey is the store's public key, in authorized_keys form.
	//
	// Pinned, with no InsecureIgnoreHostKey path in this package. What would
	// be handed to an impostor here is a tenant's log tokens, which is worse
	// than what brokerwriter risks: those tokens are the credential itself.
	HostKey string

	// Bounds. A tenant's terraform apply is holding the other end, so nothing
	// here may hang.
	ConnectTimeout time.Duration
	SessionTimeout time.Duration
}

// Client is a tenant.LogWriter.
type Client struct {
	cfg     Config
	signer  ssh.Signer
	hostKey ssh.PublicKey
}

// New validates the configuration and parses both keys now, so a
// misconfiguration is a startup failure rather than a failed apply for
// whichever tenant goes first.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.Addr == "":
		return nil, fmt.Errorf("log writer address is required")
	case cfg.User == "":
		return nil, fmt.Errorf("log writer user is required")
	case len(cfg.PrivateKey) == 0:
		return nil, fmt.Errorf("log writer private key is required")
	case cfg.HostKey == "":
		return nil, fmt.Errorf("log writer host key is required; this client will not connect without one")
	case cfg.ConnectTimeout <= 0 || cfg.SessionTimeout <= 0:
		return nil, fmt.Errorf("log writer timeouts must be positive")
	}
	signer, err := ssh.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing the log writer private key: %w", err)
	}
	hk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
	if err != nil {
		return nil, fmt.Errorf("parsing the log writer host key: %w", err)
	}
	return &Client{cfg: cfg, signer: signer, hostKey: hk}, nil
}

// Put creates or updates a tenant's users in the store.
func (c *Client) Put(ctx context.Context, t tenant.LogTenant) error {
	return c.send(ctx, logauth.Request{
		Version: logauth.Version, Op: logauth.OpPut,
		Tenant: t.Name, Index: t.Index,
		IngestToken: t.IngestToken, ReadToken: t.ReadToken,
	})
}

// Remove deletes them. A tenant that has none is not an error, so a repeated
// delete converges.
func (c *Client) Remove(ctx context.Context, name string, index int) error {
	return c.send(ctx, logauth.Request{
		Version: logauth.Version, Op: logauth.OpDelete,
		Tenant: name, Index: index,
	})
}

func (c *Client) send(ctx context.Context, req logauth.Request) error {
	// Validated here as well as at the far end, so a request the writer would
	// refuse never becomes a 502 the tenant has to interpret.
	if err := req.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	client, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("opening the writer session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdin = bytes.NewReader(body)
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	// The command string is ignored: the key is pinned with command=, and the
	// writer never reads SSH_ORIGINAL_COMMAND. It is sent because the protocol
	// requires one, and named so sshd's log reads intelligibly.
	runErr := c.runBounded(ctx, sess, "deevnet-log-user")

	var resp logauth.Response
	decodeErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp)

	switch {
	case decodeErr == nil && resp.OK:
		return nil
	case decodeErr == nil && !resp.OK:
		return fmt.Errorf("the writer refused a request the API had already validated (%s); the two ends disagree about what is valid", resp.Message)
	case runErr != nil:
		// Ambiguous: the users may or may not have been written, and the
		// reload may or may not have happened. Safe to retry, because a put
		// carries the same tokens and the far end is idempotent.
		return fmt.Errorf("the writer did not answer: %w%s", runErr, trimmedStderr(&stderr))
	default:
		return fmt.Errorf("the writer answered with something that is not a response%s", trimmedStderr(&stderr))
	}
}

// runBounded runs the session under the context and makes sure a stalled
// exchange ends: ssh.Session has no context-aware Run, so the deadline is
// enforced by closing the session out from under it.
func (c *Client) runBounded(ctx context.Context, sess *ssh.Session, cmd string) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.SessionTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = sess.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return fmt.Errorf("the writer did not finish within %s: %w", c.cfg.SessionTimeout, ctx.Err())
	}
}

func (c *Client) dial(ctx context.Context) (*ssh.Client, error) {
	d := net.Dialer{Timeout: c.cfg.ConnectTimeout}
	conn, err := d.DialContext(ctx, "tcp", c.cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("reaching the writer at %s: %w", c.cfg.Addr, err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, c.cfg.Addr, &ssh.ClientConfig{
		User:            c.cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(c.signer)},
		HostKeyCallback: ssh.FixedHostKey(c.hostKey),
		// Pinning one key means accepting only that key's algorithm: the
		// client's preference decides which host key the server presents, and
		// without this a correct host can answer with a different key and fail
		// as "host key mismatch", which reads exactly like an attack.
		HostKeyAlgorithms: []string{c.hostKey.Type()},
		Timeout:           c.cfg.ConnectTimeout,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("authenticating to the writer: %w", err)
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

// trimmedStderr renders the writer's operator-facing output for the API's log,
// bounded because it is remote output on its way into a log line.
func trimmedStderr(b *bytes.Buffer) string {
	s := strings.TrimSpace(b.String())
	if s == "" {
		return ""
	}
	const max = 512
	if len(s) > max {
		s = s[:max] + "…"
	}
	return ": " + s
}
