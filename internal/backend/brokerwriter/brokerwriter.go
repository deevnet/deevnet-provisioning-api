// Package brokerwriter reaches the broker account writer on the messaging VM
// over SSH.
//
// The broker's auth database is not reachable from the network (CHG-0016), so
// this is not a database client. It is one SSH connection carrying one request
// to a program pinned to a key with command= and restrict, and reading one
// response back.
//
// Design: architecture/substrate/control-plane/broker-account-writer.
package brokerwriter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/deevnet/deevnet-provisioning-api/internal/brokeracct"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Config is what the API needs to reach the writer. Every field is required;
// there is no default that would be safe.
type Config struct {
	// Addr is host:port.
	Addr string
	User string
	// PrivateKey is the API's own key, in PEM. It is used for nothing else, so
	// revoking it revokes exactly this capability.
	PrivateKey []byte
	// HostKey is the messaging VM's public key, in authorized_keys form.
	//
	// Pinned, and there is no InsecureIgnoreHostKey path anywhere in this
	// package. Without it the first connection could be answered by anything
	// on the segment, and what it would be handed is a request to create an
	// MQTT account - the reply need only look plausible for the API to believe
	// an account exists that does not.
	HostKey string

	// Bounds. Nothing here may hang: a tenant's terraform apply is holding the
	// other end. ConnectTimeout covers reaching the host; SessionTimeout
	// covers the whole exchange once connected, so a writer that stalls after
	// accepting the request is still bounded.
	ConnectTimeout time.Duration
	SessionTimeout time.Duration
}

// Client is a tenant.BrokerWriter.
type Client struct {
	cfg     Config
	signer  ssh.Signer
	hostKey ssh.PublicKey
}

// New validates the configuration and parses both keys now rather than on the
// first tenant request, so a misconfiguration is a startup failure instead of
// a failed apply for whoever happens to go first.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.Addr == "":
		return nil, fmt.Errorf("broker writer address is required")
	case cfg.User == "":
		return nil, fmt.Errorf("broker writer user is required")
	case len(cfg.PrivateKey) == 0:
		return nil, fmt.Errorf("broker writer private key is required")
	case cfg.HostKey == "":
		return nil, fmt.Errorf("broker writer host key is required; this client will not connect without one")
	case cfg.ConnectTimeout <= 0 || cfg.SessionTimeout <= 0:
		return nil, fmt.Errorf("broker writer timeouts must be positive")
	}
	signer, err := ssh.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing the broker writer private key: %w", err)
	}
	hk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
	if err != nil {
		return nil, fmt.Errorf("parsing the broker writer host key: %w", err)
	}
	return &Client{cfg: cfg, signer: signer, hostKey: hk}, nil
}

// Put creates or updates an account.
func (c *Client) Put(ctx context.Context, a tenant.BrokerAccount) error {
	return c.send(ctx, brokeracct.Request{
		Version: brokeracct.Version, Op: brokeracct.OpPut,
		Tenant: a.Tenant, Account: a.Name,
		PasswordHash: a.PasswordHash,
		Publish:      a.Publish, Subscribe: a.Subscribe,
	})
}

// Remove deletes it. An account that is not there is not an error, so a
// repeated delete converges.
func (c *Client) Remove(ctx context.Context, tenantName, name string) error {
	return c.send(ctx, brokeracct.Request{
		Version: brokeracct.Version, Op: brokeracct.OpDelete,
		Tenant: tenantName, Account: name,
	})
}

func (c *Client) send(ctx context.Context, req brokeracct.Request) error {
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
	// writer never reads SSH_ORIGINAL_COMMAND. It is sent because the SSH
	// protocol requires one, and it is named so a human reading sshd's log
	// sees what was intended rather than an empty exec.
	runErr := c.runBounded(ctx, sess, "deevnet-broker-account")

	// The response is read whatever the exit status, because a refusal carries
	// its reason in the body and a non-zero exit alone does not say why.
	var resp brokeracct.Response
	decodeErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp)

	switch {
	case decodeErr == nil && resp.OK:
		return nil
	case decodeErr == nil && !resp.OK:
		// A definite refusal. The API validated and prefixed this request
		// before sending it, so the two ends disagreeing is a bug in one of
		// them rather than something a tenant did - say so, because the
		// alternative is an operator hunting a tenant's data for a fault that
		// is in the code.
		return fmt.Errorf("the writer refused a request the API had already validated (%s); the two ends disagree about what is valid", resp.Message)
	case runErr != nil:
		// No usable body: a timeout, a dropped connection, a writer that died
		// before answering. Ambiguous - the account may or may not have been
		// written - and safe to retry, because the caller sends the same hash.
		return fmt.Errorf("the writer did not answer: %w%s", runErr, trimmedStderr(&stderr))
	default:
		return fmt.Errorf("the writer answered with something that is not a response%s", trimmedStderr(&stderr))
	}
}

// runBounded runs the session under the context, and makes sure a stalled
// exchange ends. ssh.Session has no context-aware Run, so the deadline is
// enforced by closing the session out from under it - which is what unblocks
// a Run that is waiting on a peer that will never answer.
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
		// Drain, so the goroutine cannot outlive this call holding a buffer
		// the caller is about to read.
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
		// Pinning ONE key means accepting only that key's algorithm.
		//
		// A host usually has several host keys - ecdsa, ed25519 and rsa are
		// the stock set - and it is the CLIENT's preference that decides which
		// one the server presents. Without this, the server can answer with a
		// different key than the one pinned and the handshake fails as
		// "host key mismatch" on a host that is exactly who it says it is.
		// That failure looks identical to an attack, which is the worst way
		// for it to read.
		HostKeyAlgorithms: []string{c.hostKey.Type()},
		Timeout:           c.cfg.ConnectTimeout,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("authenticating to the writer: %w", err)
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

// trimmedStderr renders the writer's operator-facing output for the API's log.
// Bounded, because it is remote output and this string ends up in a log line.
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
