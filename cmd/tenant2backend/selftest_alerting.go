package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// How long a pushed sample may take to be found. The store hides its newest
// 30 seconds from queries (CHG-0070); a series lookup finds it sooner.
const selftestMetricsArrival = 90 * time.Second

// selftestMetrics pushes one sample with the ingest token, as an app does, and
// finds it again with the read token.
func selftestMetrics(hc *http.Client, base string, st state, marker string) error {
	sample := fmt.Sprintf("deevnet_kit_selftest{run=%q} 1\n", marker)
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/import/prometheus", strings.NewReader(sample))
	req.Header.Set("Authorization", "Bearer "+st.IngestToken)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("the push answered %d", resp.StatusCode)
	}
	q := url.Values{"match[]": {fmt.Sprintf("deevnet_kit_selftest{run=%q}", marker)}}
	deadline := time.Now().Add(selftestMetricsArrival)
	for {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/series?"+q.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+st.ReadToken)
		resp, err := hc.Do(req)
		if err == nil {
			var out struct {
				Data []map[string]string `json:"data"`
			}
			derr := json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if derr == nil && resp.StatusCode == http.StatusOK && len(out.Data) > 0 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the sample was not found within %s", selftestMetricsArrival)
		}
		time.Sleep(3 * time.Second)
	}
}

// selftestAlerting checks what alerting needs, without touching the tenant's
// rules: Alertmanager has a configuration, the phone's login reads its own
// topics and publishes nowhere, and each loaded group evaluates cleanly.
func (k *kit) selftestAlerting(st state, hc *http.Client, marker string) []check {
	ntfyBase := fmt.Sprintf("https://%s:%d", st.name("ntfy"), ntfyPort)
	topic := notifyTopic(st, "selftest")
	checks := []check{
		{"alertmanager: configuration loaded", func() error {
			resp, err := http.Get("http://127.0.0.1:9093/-/ready")
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("ready answered %d", resp.StatusCode)
			}
			return nil
		}},
		{"ntfy: the phone's login reads its own topics", func() error {
			if st.NotifyPassword == "" {
				return errors.New("no login yet: systemctl status backend-alerting")
			}
			code, err := ntfyDo(hc, http.MethodGet, ntfyBase+"/"+topic+"/json?poll=1", st.Tenant, st.NotifyPassword, "")
			if err != nil {
				return err
			}
			if code != http.StatusOK {
				return fmt.Errorf("reading %s answered %d", topic, code)
			}
			return nil
		}},
		{"ntfy: the phone's login publishes nowhere", func() error {
			if st.NotifyPassword == "" {
				return errors.New("no login yet: systemctl status backend-alerting")
			}
			code, err := ntfyDo(hc, http.MethodPost, ntfyBase+"/"+topic, st.Tenant, st.NotifyPassword, "tenant2backend selftest "+marker)
			if err != nil {
				return err
			}
			if code != http.StatusForbidden {
				return fmt.Errorf("a publish answered %d, want 403", code)
			}
			return nil
		}},
	}
	groups, err := k.loadAlerts()
	if err != nil || len(groups) == 0 {
		return checks
	}
	unit := "vmalert@" + st.Tenant
	return append(checks, check{"alerts: " + unit + " evaluates every group", func() error {
		active, _ := exec.Command("systemctl", "is-active", unit).Output()
		if s := strings.TrimSpace(string(active)); s != "active" {
			return fmt.Errorf("%s is %s", unit, s)
		}
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/rules", vmalertPortBase+st.Index))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var out struct {
			Data struct {
				Groups []struct {
					Name  string `json:"name"`
					Rules []struct {
						Name      string `json:"name"`
						LastError string `json:"lastError"`
					} `json:"rules"`
				} `json:"groups"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return err
		}
		if len(out.Data.Groups) != len(groups) {
			return fmt.Errorf("vmalert runs %d group(s), %d are loaded", len(out.Data.Groups), len(groups))
		}
		for _, g := range out.Data.Groups {
			for _, r := range g.Rules {
				if r.LastError != "" {
					return fmt.Errorf("%s/%s: %s", g.Name, r.Name, r.LastError)
				}
			}
		}
		return nil
	}})
}

// vmalertPortBase is the writer's vmalert_port_base in the image's
// log-user.json: a tenant's vmalert listens on this plus its index.
const vmalertPortBase = 20000

func ntfyDo(hc *http.Client, method, u, user, pass, body string) (int, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, u, rd)
	req.SetBasicAuth(user, pass)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
