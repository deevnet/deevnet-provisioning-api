package brokerwriter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/deevnet/deevnet-provisioning-api/internal/brokeracct"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// A stand-in for the program on the messaging VM: a real SSH server, so the
// client's host-key pinning, authentication, stdin/stdout plumbing and
// timeouts are exercised rather than mocked.
type fakeWriter struct {
	addr     string
	hostKey  string // authorized_keys form, for pinning
	gotBody  chan []byte
	reply    brokeracct.Response
	replyRaw string // when set, sent instead of reply
	exitCode uint32
	stall    time.Duration // how long to wait before answering
	// alsoOffer are further host key types this server presents, so a client
	// that pins one key must also pin its algorithm to get that key back.
	alsoOffer []string
}

func (f *fakeWriter) extraHostKeys(t *testing.T) []ssh.Signer {
	t.Helper()
	var out []ssh.Signer
	for _, kind := range f.alsoOffer {
		out = append(out, hostSigner(t, kind))
	}
	return out
}

func hostSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	switch kind {
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	case "ed25519":
		_, sec, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = sec
	default:
		t.Fatalf("unknown host key kind %q", kind)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newFakeWriter(t *testing.T, clientPub ssh.PublicKey) *fakeWriter {
	return newFakeWriterOf(t, clientPub, "rsa")
}

// The extra kinds are taken HERE and not set on the returned value, because
// the server config is built in this function: a field set afterwards arrives
// too late and the extra keys are never offered. The first version of the
// multi-key test did exactly that and passed whether the client was correct
// or not.

// newFakeWriterOf pins a host key of the named kind. The kind matters: which
// key a server presents is chosen from the CLIENT's preference list, so a test
// only exercises that negotiation if the pinned key is NOT the client's first
// choice.
func newFakeWriterOf(t *testing.T, clientPub ssh.PublicKey, kind string, alsoOffer ...string) *fakeWriter {
	t.Helper()
	signer := hostSigner(t, kind)
	f := &fakeWriter{
		alsoOffer: alsoOffer,
		gotBody:   make(chan []byte, 4),
		hostKey:   string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		reply:     brokeracct.Response{Version: 1, OK: true, Username: "eds-lightd"},
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) != string(clientPub.Marshal()) {
				return nil, io.EOF
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)
	// A real sshd offers several host key types, and which one it presents is
	// decided by the CLIENT's preference. The fake does the same, or the test
	// would never exercise the negotiation that matters.
	for _, extra := range f.extraHostKeys(t) {
		cfg.AddHostKey(extra)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, cfg)
		}
	}()
	return f
}

func (f *fakeWriter) serve(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range chReqs {
				if r.Type == "exec" {
					_ = r.Reply(true, nil)
					body, _ := io.ReadAll(ch)
					f.gotBody <- body
					if f.stall > 0 {
						time.Sleep(f.stall)
					}
					out := f.replyRaw
					if out == "" {
						b, _ := json.Marshal(f.reply)
						out = string(b)
					}
					_, _ = ch.Write([]byte(out + "\n"))
					_, _ = ch.SendRequest("exit-status", false,
						ssh.Marshal(struct{ Status uint32 }{f.exitCode}))
					_ = ch.Close()
					return
				}
				_ = r.Reply(false, nil)
			}
		}()
	}
}

func clientKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemBytes, signer.PublicKey()
}

func dialFake(t *testing.T, f *fakeWriter, priv []byte, hostKey string) *Client {
	t.Helper()
	c, err := New(Config{
		Addr: f.addr, User: "deevnet-writer", PrivateKey: priv, HostKey: hostKey,
		ConnectTimeout: 5 * time.Second, SessionTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func account() tenant.BrokerAccount {
	return tenant.BrokerAccount{
		Tenant: "eds", Name: "lightd", PasswordHash: "$2a$12$" + strings.Repeat("x", 53),
		Publish: []string{"eds/a"}, Subscribe: []string{"eds/b"},
	}
}

func TestPutSendsTheContractAndSucceeds(t *testing.T) {
	priv, pub := clientKey(t)
	f := newFakeWriter(t, pub)
	c := dialFake(t, f, priv, f.hostKey)

	if err := c.Put(context.Background(), account()); err != nil {
		t.Fatal(err)
	}
	var got brokeracct.Request
	if err := json.Unmarshal(<-f.gotBody, &got); err != nil {
		t.Fatal(err)
	}
	if got.Op != brokeracct.OpPut || got.Tenant != "eds" || got.Account != "lightd" {
		t.Errorf("request = %+v", got)
	}
	// The wire carries the hash, never a plaintext password.
	if !strings.HasPrefix(got.PasswordHash, "$2a$") {
		t.Errorf("password_hash = %q", got.PasswordHash)
	}
	// And nothing the writer derives for itself.
	if strings.Contains(string(mustJSON(t, got)), `"username"`) {
		t.Error("the request carried a username; the writer derives it")
	}
}

func TestRemoveSendsADelete(t *testing.T) {
	priv, pub := clientKey(t)
	f := newFakeWriter(t, pub)
	c := dialFake(t, f, priv, f.hostKey)

	if err := c.Remove(context.Background(), "eds", "lightd"); err != nil {
		t.Fatal(err)
	}
	var got brokeracct.Request
	if err := json.Unmarshal(<-f.gotBody, &got); err != nil {
		t.Fatal(err)
	}
	if got.Op != brokeracct.OpDelete || got.PasswordHash != "" || len(got.Publish) != 0 {
		t.Errorf("a delete carried more than identity: %+v", got)
	}
}

// The host key is pinned. A different host answering must not be trusted,
// whatever it says - the reply need only look plausible for the API to
// believe an account exists that does not.
func TestAWrongHostKeyIsRefused(t *testing.T) {
	priv, pub := clientKey(t)
	f := newFakeWriter(t, pub)
	other := newFakeWriter(t, pub) // a different host key

	c := dialFake(t, f, priv, other.hostKey)
	err := c.Put(context.Background(), account())
	if err == nil {
		t.Fatal("the client accepted a host presenting a different key")
	}
	if !strings.Contains(err.Error(), "authenticating") {
		t.Errorf("err = %v", err)
	}
}

func TestAConfigWithoutAHostKeyIsRefused(t *testing.T) {
	priv, _ := clientKey(t)
	_, err := New(Config{
		Addr: "127.0.0.1:22", User: "x", PrivateKey: priv,
		ConnectTimeout: time.Second, SessionTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("a client was built with no host key to pin")
	}
}

// A refusal is reported as a disagreement between the two ends, because the
// API validated the request before sending it.
func TestARefusalNamesTheDisagreement(t *testing.T) {
	priv, pub := clientKey(t)
	f := newFakeWriter(t, pub)
	f.reply = brokeracct.Response{Version: 1, OK: false, Message: "publish pattern 1 is not under the tenant prefix"}
	f.exitCode = 1
	c := dialFake(t, f, priv, f.hostKey)

	err := c.Put(context.Background(), account())
	if err == nil {
		t.Fatal("a refusal was reported as success")
	}
	if !strings.Contains(err.Error(), "disagree") {
		t.Errorf("err = %v; a refusal after validation is a bug in one end, and should say so", err)
	}
}

// A stalled writer must not hold a tenant's apply open.
func TestASessionThatStallsIsBounded(t *testing.T) {
	priv, pub := clientKey(t)
	f := newFakeWriter(t, pub)
	f.stall = 3 * time.Second
	c, err := New(Config{
		Addr: f.addr, User: "w", PrivateKey: priv, HostKey: f.hostKey,
		ConnectTimeout: 5 * time.Second, SessionTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = c.Put(context.Background(), account())
	if err == nil {
		t.Fatal("a stalled writer was reported as success")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the call took %s; the session timeout did not bound it", elapsed)
	}
	if !strings.Contains(err.Error(), "did not") {
		t.Errorf("err = %v", err)
	}
}

// Garbage on stdout is not success, whatever the exit status.
func TestAnUnparseableAnswerIsNotSuccess(t *testing.T) {
	priv, pub := clientKey(t)
	f := newFakeWriter(t, pub)
	f.replyRaw = "this is not JSON"
	c := dialFake(t, f, priv, f.hostKey)
	if err := c.Put(context.Background(), account()); err == nil {
		t.Fatal("an unparseable answer was treated as success")
	}
}

func TestAnUnreachableHostIsAnError(t *testing.T) {
	priv, pub := clientKey(t)
	f := newFakeWriter(t, pub)
	c, err := New(Config{
		Addr: "127.0.0.1:1", User: "w", PrivateKey: priv, HostKey: f.hostKey,
		ConnectTimeout: 500 * time.Millisecond, SessionTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Put(context.Background(), account()); err == nil {
		t.Fatal("an unreachable writer was reported as success")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A host offers several host keys and the CLIENT's preference decides which
// one it presents. Pinning one key therefore means pinning its algorithm too -
// without that, a host that is exactly who it says it is answers with a
// different key and the handshake fails as "host key mismatch", which reads
// identically to an attack.
//
// This is a regression test: the first deployment of the writer failed this
// way against a stock sshd offering ecdsa, ed25519 and rsa.
func TestAHostOfferingSeveralKeysStillMatchesThePinnedOne(t *testing.T) {
	priv, pub := clientKey(t)
	// Pin the ed25519 key while the host ALSO offers rsa, which is the way
	// round that reproduces the failure: the client's default preference picks
	// rsa, so the pinned ed25519 key is never presented. The mirror of this
	// test - pinning rsa and offering ed25519 - passes with or without the
	// fix and proves nothing, which is how the first version of it was wrong.
	// Pin ed25519 while the host also offers rsa. That is the direction that
	// reproduces: x/crypto's default preference is ECDSA, then RSA, with
	// ed25519 LAST, so an unconstrained client asks for rsa and never sees
	// the pinned key. The mirror - pinning rsa, offering ed25519 - passes
	// with or without the fix and proves nothing.
	f := newFakeWriterOf(t, pub, "ed25519", "rsa")

	c := dialFake(t, f, priv, f.hostKey)
	if err := c.Put(context.Background(), account()); err != nil {
		t.Fatalf("a host offering more than one key type was refused: %v", err)
	}
	<-f.gotBody
}
