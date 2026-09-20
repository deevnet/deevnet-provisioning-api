package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/brokeracct"
)

// Real bcrypt hashes. Hand-made ones drift from the length bcrypt emits.
const otherHash = "$2a$12$tbijfVTpL/V.EMGr6PqVW.P8u3m3NHJVhUS4D4CdNvjDNnk.BEEJO"
const testHash = "$2a$12$vkf24cu3BovLL9fMP38C0.WOlTeHB9aEU1Vp3p4JP4OErWDg7AdmG"

// testConn gives a connection against the same throwaway PostgreSQL the store
// tests use, with the plugin's own table. The schema is VerneMQ's, quoted from
// its source; if it drifts from the role's schema.sql these tests stop meaning
// anything, which is why the shape is asserted below rather than assumed.
func testConn(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("DEEVNET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DEEVNET_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS vmq_auth_acl`,
		`CREATE TABLE vmq_auth_acl (
		   mountpoint varchar(10) NOT NULL, client_id varchar(128) NOT NULL,
		   username varchar(128) NOT NULL, password varchar(128),
		   publish_acl json, subscribe_acl json,
		   CONSTRAINT vmq_auth_acl_primary_key PRIMARY KEY (mountpoint, client_id, username))`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	return conn
}

func req() brokeracct.Request {
	return brokeracct.Request{
		Version: brokeracct.Version, Op: brokeracct.OpPut,
		Tenant: "eds", Account: "lightd", PasswordHash: testHash,
		Publish:   []string{"eds/lightstand/+/scene"},
		Subscribe: []string{"eds/lightstand/+/status"},
	}
}

func TestPutWritesWhatTheRowShouldContain(t *testing.T) {
	conn := testConn(t)
	ctx := context.Background()

	existed, err := put(ctx, conn, req())
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		t.Error("a fresh insert reported the row already existed")
	}

	var mp, cid, user, pw string
	var pub, sub string
	err = conn.QueryRow(ctx,
		`SELECT mountpoint, client_id, username, password,
		        publish_acl::text, subscribe_acl::text FROM vmq_auth_acl`).
		Scan(&mp, &cid, &user, &pw, &pub, &sub)
	if err != nil {
		t.Fatal(err)
	}
	if mp != "" || cid != "*" {
		t.Errorf("mountpoint/client_id = %q/%q, want \"\"/* (ADR-0012 §10)", mp, cid)
	}
	if user != "eds-lightd" {
		t.Errorf("username = %q, want the derived eds-lightd", user)
	}
	if pw != testHash {
		t.Error("the stored password is not the hash that was sent")
	}
	// The shape vmq_diversity reads. If this changes, the broker stops
	// enforcing ACLs and fails open on nothing visible.
	var got []map[string]string
	if err := json.Unmarshal([]byte(pub), &got); err != nil {
		t.Fatalf("publish_acl is not the expected JSON: %v", err)
	}
	if len(got) != 1 || got[0]["pattern"] != "eds/lightstand/+/scene" {
		t.Errorf("publish_acl = %s", pub)
	}
	if _, has := got[0]["modifiers"]; has {
		t.Error("the stored ACL carries modifiers, which can move a message out of the prefix")
	}
}

// The property the API's retry path depends on.
func TestPutIsIdempotentAndReportsExisted(t *testing.T) {
	conn := testConn(t)
	ctx := context.Background()

	if _, err := put(ctx, conn, req()); err != nil {
		t.Fatal(err)
	}
	existed, err := put(ctx, conn, req())
	if err != nil {
		t.Fatal(err)
	}
	if !existed {
		t.Error("the second put did not report the row already existed")
	}
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM vmq_auth_acl`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d rows after two identical puts, want 1", n)
	}
}

// Re-applying with changed ACLs must move them, or a tenant could never
// narrow a permission it had widened.
func TestPutUpdatesTheAclsAndPassword(t *testing.T) {
	conn := testConn(t)
	ctx := context.Background()
	if _, err := put(ctx, conn, req()); err != nil {
		t.Fatal(err)
	}

	r := req()
	r.Publish = []string{"eds/narrower"}
	r.PasswordHash = otherHash
	if _, err := put(ctx, conn, r); err != nil {
		t.Fatal(err)
	}
	var pub, pw string
	if err := conn.QueryRow(ctx, `SELECT publish_acl::text, password FROM vmq_auth_acl`).Scan(&pub, &pw); err != nil {
		t.Fatal(err)
	}
	if pub != `[{"pattern":"eds/narrower"}]` {
		t.Errorf("publish_acl = %s, want the narrowed pattern", pub)
	}
	if pw == testHash {
		t.Error("the password was not updated")
	}
}

func TestDeleteRemovesAndIsIdempotent(t *testing.T) {
	conn := testConn(t)
	ctx := context.Background()
	if _, err := put(ctx, conn, req()); err != nil {
		t.Fatal(err)
	}
	d := brokeracct.Request{Version: brokeracct.Version, Op: brokeracct.OpDelete, Tenant: "eds", Account: "lightd"}
	for i := 0; i < 2; i++ {
		if err := del(ctx, conn, d); err != nil {
			t.Fatalf("delete %d: %v", i+1, err)
		}
	}
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM vmq_auth_acl`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d rows after delete", n)
	}
}

// Two tenants may use the same account name without colliding, because the
// username is derived from both.
func TestTwoTenantsSameAccountNameDoNotCollide(t *testing.T) {
	conn := testConn(t)
	ctx := context.Background()
	a, b := req(), req()
	b.Tenant = "tdemo"
	b.Publish, b.Subscribe = []string{"tdemo/x"}, []string{"tdemo/x"}
	for _, r := range []brokeracct.Request{a, b} {
		if _, err := put(ctx, conn, r); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	rows, err := conn.Query(ctx, `SELECT username FROM vmq_auth_acl ORDER BY username`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if len(names) != 2 || names[0] != "eds-lightd" || names[1] != "tdemo-lightd" {
		t.Errorf("usernames = %v", names)
	}
}

// Parameterised SQL, proven rather than asserted: a pattern full of quotes and
// semicolons is stored as data. Validate would refuse this one for being
// outside the prefix, so it is driven straight at put to test the SQL layer.
func TestPatternsAreDataNotSQL(t *testing.T) {
	conn := testConn(t)
	ctx := context.Background()
	nasty := `eds/'); DROP TABLE vmq_auth_acl; --`
	r := req()
	r.Publish = []string{nasty}
	if _, err := put(ctx, conn, r); err != nil {
		t.Fatal(err)
	}
	var pub string
	if err := conn.QueryRow(ctx, `SELECT publish_acl::text FROM vmq_auth_acl`).Scan(&pub); err != nil {
		t.Fatalf("the table is gone or unreadable: %v", err)
	}
	var got []map[string]string
	if err := json.Unmarshal([]byte(pub), &got); err != nil || got[0]["pattern"] != nasty {
		t.Errorf("the pattern was not stored verbatim as data: %s", pub)
	}
}

func TestAclJSONShape(t *testing.T) {
	b, err := aclJSON([]string{"a/b", "c/#"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `[{"pattern":"a/b"},{"pattern":"c/#"}]` {
		t.Errorf("aclJSON = %s", b)
	}
	// An empty list must be [] and not null: the column is json, and null
	// would read as "no ACL document" rather than "no patterns".
	b, _ = aclJSON(nil)
	if string(b) != `[]` {
		t.Errorf("empty aclJSON = %s, want []", b)
	}
}
