package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/backend/grafana"
)

// selftest proves the card works end to end, the way an app and a device will
// use it: over TLS against the card's CA, with the tenant's own tokens and
// login. It is run by its own unit on every boot, and by hand with
// `sudo deevnet-kit selftest`.
//
// It leaves two log lines behind, one in the device partition and one in the
// app partition, each saying it came from the self-test. They age out with
// retention like any other line. The broker account it uses is created and
// removed again.

// The throwaway broker account. Its device name is also the last topic level,
// so the line it publishes lands under that device.
const selftestAccount = "kit-selftest"

// How long a line may take to travel device -> broker -> bridge -> store.
const selftestArrival = 45 * time.Second

func (k *kit) selftestFile() string { return k.p("/var/lib/deevnet-kit/selftest.json") }

type selftestResult struct {
	At     time.Time `json:"at"`
	Passed int       `json:"passed"`
	Failed []string  `json:"failed"`
}

type check struct {
	name string
	run  func() error
}

func (k *kit) cmdSelftest() error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(k.caFile())
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	hc := &http.Client{Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	marker := "selftest-" + mustHex(6)
	logBase := fmt.Sprintf("https://localhost:%d", logPort)

	var checks []check
	for _, u := range units {
		u := u
		checks = append(checks, check{"service " + u, func() error {
			out, _ := exec.Command("systemctl", "is-active", u).Output()
			if s := strings.TrimSpace(string(out)); s != "active" {
				return fmt.Errorf("%s", s)
			}
			return nil
		}})
	}
	for _, p := range []struct {
		what string
		port int
	}{{"broker", brokerPort}, {"log store", logPort}, {"grafana", dashboardPort}} {
		p := p
		checks = append(checks, check{fmt.Sprintf("TLS %s :%d", p.what, p.port), func() error {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp",
				fmt.Sprintf("127.0.0.1:%d", p.port), &tls.Config{RootCAs: pool, ServerName: "localhost"})
			if err != nil {
				return err
			}
			return c.Close()
		}})
	}
	checks = append(checks,
		check{"log bridge subscribed", func() error {
			resp, err := http.Get("http://127.0.0.1:9099/healthz")
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("healthz %d: the bridge has no working subscription", resp.StatusCode)
			}
			return nil
		}},
		check{"device log: MQTT -> bridge -> store", func() error {
			return k.selftestDeviceLog(st, hc, logBase, marker)
		}},
		check{"app log: ingest token -> store", func() error {
			body := fmt.Sprintf(`{"_msg":"deevnet-kit selftest %s-app","source":"deevnet-kit-selftest"}`, marker)
			req, _ := http.NewRequest(http.MethodPost, logBase+"/insert/jsonline", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+st.IngestToken)
			req.Header.Set("Content-Type", "application/stream+json")
			resp, err := hc.Do(req)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("ingest answered %d", resp.StatusCode)
			}
			return waitForLine(hc, logBase, st.ReadToken, fmt.Sprintf("%d-0", st.Index), marker+"-app")
		}},
		check{"grafana: tenant login, Editor in its own organisation", func() error {
			var orgs []struct {
				OrgID int    `json:"orgId"`
				Role  string `json:"role"`
			}
			if err := grafanaGet(hc, st, "/api/user/orgs", &orgs); err != nil {
				return err
			}
			if len(orgs) != 1 || orgs[0].OrgID != st.DashboardOrg || orgs[0].Role != grafana.TenantRole {
				return fmt.Errorf("organisations %+v, want only %d as %s", orgs, st.DashboardOrg, grafana.TenantRole)
			}
			return nil
		}},
		check{"grafana: data sources and the starter dashboard", func() error {
			for _, ds := range grafana.DataSources {
				if err := grafanaGet(hc, st, "/api/datasources/uid/"+ds.UID, nil); err != nil {
					return fmt.Errorf("%s: %w", ds.UID, err)
				}
			}
			return grafanaGet(hc, st, "/api/dashboards/uid/"+starterUID, nil)
		}},
		check{"grafana: device log readable through Grafana", func() error {
			q := map[string]any{"from": "now-1h", "to": "now", "queries": []map[string]any{{
				"refId": "A", "datasource": map[string]string{"uid": "deevnet-logs-devices"},
				"expr": fmt.Sprintf("%q", marker+"-device"), "queryType": "instant", "maxLines": 5,
			}}}
			var out struct {
				Results map[string]struct {
					Frames []struct {
						Data struct {
							Values []json.RawMessage `json:"values"`
						} `json:"data"`
					} `json:"frames"`
				} `json:"results"`
			}
			if err := grafanaPost(hc, st, "/api/ds/query", q, &out); err != nil {
				return err
			}
			for _, f := range out.Results["A"].Frames {
				if len(f.Data.Values) > 1 && strings.Contains(string(f.Data.Values[1]), marker) {
					return nil
				}
			}
			return errors.New("the self-test's device line did not come back through Grafana")
		}},
	)

	fmt.Printf("deevnet-kit selftest - tenant %s (index %d)\n\n", st.Tenant, st.Index)
	res := selftestResult{At: time.Now().UTC(), Failed: []string{}}
	for _, c := range checks {
		if err := c.run(); err != nil {
			fmt.Printf("  FAIL  %-52s %v\n", c.name, err)
			res.Failed = append(res.Failed, c.name)
			continue
		}
		fmt.Printf("  ok    %s\n", c.name)
		res.Passed++
	}
	if missing, err := k.uncoveredAddrs(); err == nil && len(missing) > 0 {
		fmt.Printf("\n  warn  the certificate does not name %v; devices dialling it will fail: sudo deevnet-kit regen-certs\n", missing)
	}
	if err := os.MkdirAll(filepath.Dir(k.selftestFile()), 0o755); err == nil {
		_ = writeJSON(k.selftestFile(), res, 0o644)
	}
	fmt.Println()
	if len(res.Failed) > 0 {
		return fmt.Errorf("%d of %d checks failed", len(res.Failed), len(checks))
	}
	fmt.Printf("all %d checks passed\n", len(checks))
	return nil
}

// selftestDeviceLog publishes one line as a device would - through a real
// broker account confined to its own log topic - and waits for the bridge to
// carry it into the device partition.
func (k *kit) selftestDeviceLog(st state, hc *http.Client, logBase, marker string) error {
	if _, err := os.Stat(k.accountFile(selftestAccount)); err == nil {
		if err := k.accountRemove(selftestAccount); err != nil { // left by a run that died
			return err
		}
	}
	pw := mustHex(16)
	if err := k.quiet(func() error {
		return k.accountAdd([]string{selftestAccount, "--device", selftestAccount,
			"--publish", "log/" + selftestAccount, "--password", pw})
	}); err != nil {
		return fmt.Errorf("creating the throwaway account: %w", err)
	}
	defer func() { _ = k.quiet(func() error { return k.accountRemove(selftestAccount) }) }()

	// _msg, not msg: LogsQL's phrase filter reads _msg, and the bridge fills
	// _msg only when the payload has none.
	msg := fmt.Sprintf(`{"_msg":"deevnet-kit selftest %s-device"}`, marker)
	topic := fmt.Sprintf("%s/log/%s", st.Tenant, selftestAccount)
	var last error
	// Mosquitto reloads its password file on the signal the account write
	// sends, which takes a moment: a publish straight after can be refused.
	for i := 0; i < 5; i++ {
		out, err := exec.Command("mosquitto_pub", "-h", "localhost", "-p", fmt.Sprint(brokerPort),
			"--cafile", k.caFile(), "-u", username(st, selftestAccount), "-P", pw,
			"-i", "deevnet-kit-selftest", "-q", "1", "-t", topic, "-m", msg).CombinedOutput()
		if err == nil {
			last = nil
			break
		}
		last = fmt.Errorf("mosquitto_pub: %v: %s", err, strings.TrimSpace(string(out)))
		time.Sleep(2 * time.Second)
	}
	if last != nil {
		return last
	}
	return waitForLine(hc, logBase, st.ReadToken, fmt.Sprintf("%d-2", st.Index), marker+"-device")
}

// waitForLine reads a partition with the tenant's read token until a line
// carrying the phrase arrives.
func waitForLine(hc *http.Client, base, token, partition, phrase string) error {
	deadline := time.Now().Add(selftestArrival)
	for {
		req, _ := http.NewRequest(http.MethodGet,
			base+"/select/logsql/query?query="+url.QueryEscape(fmt.Sprintf("%q", phrase)), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(grafana.PartitionHeader, partition)
		resp, err := hc.Do(req)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && bytes.Contains(b, []byte(phrase)) {
				return nil
			}
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("query answered %d", resp.StatusCode)
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return err
			}
			return fmt.Errorf("the line did not reach partition %s within %s", partition, selftestArrival)
		}
		time.Sleep(2 * time.Second)
	}
}

func grafanaGet(hc *http.Client, st state, path string, out any) error {
	return grafanaCall(hc, st, http.MethodGet, path, nil, out)
}

func grafanaPost(hc *http.Client, st state, path string, in, out any) error {
	return grafanaCall(hc, st, http.MethodPost, path, in, out)
}

// grafanaCall is a call as the TENANT's login, not the admin: the self-test
// proves what the tenant can do.
func grafanaCall(hc *http.Client, st state, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, dashboardURL("localhost")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(st.Tenant+":"+st.DashboardPassword)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s answered %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// quiet runs fn with stdout discarded: the account commands print for a
// person, and the self-test's output is its own report.
func (k *kit) quiet(fn func() error) error {
	saved := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fn()
	}
	os.Stdout = devnull
	defer func() { os.Stdout = saved; devnull.Close() }()
	return fn()
}

func mustHex(n int) string {
	h, err := randomHex(n)
	if err != nil {
		panic(err)
	}
	return h
}

// lastSelftest is the one-line summary status prints.
func (k *kit) lastSelftest() string {
	b, err := os.ReadFile(k.selftestFile())
	if err != nil {
		return "not run yet: sudo deevnet-kit selftest"
	}
	var r selftestResult
	if json.Unmarshal(b, &r) != nil {
		return "unreadable result: sudo deevnet-kit selftest"
	}
	when := r.At.Local().Format("2006-01-02 15:04")
	if len(r.Failed) == 0 {
		return fmt.Sprintf("passed (%d checks) at %s", r.Passed, when)
	}
	return fmt.Sprintf("FAILED %d at %s: %s - sudo deevnet-kit selftest", len(r.Failed), when, strings.Join(r.Failed, "; "))
}
