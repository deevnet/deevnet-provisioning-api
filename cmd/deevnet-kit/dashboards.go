package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/backend/grafana"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Dashboards on the Pi (ADR-0024, CHG-0024).
//
// The same Grafana contract as Deevnet: one organisation named for the tenant,
// one Editor login, and the three log data sources with their fixed UIDs, so a
// dashboard written against Deevnet applies here unchanged. It is written by
// the same package the API uses, against this Pi's Grafana, so the rules are
// the API's rather than a copy.
//
// init cannot do this itself: it runs before any service starts, and this
// needs Grafana and vmauth up. So it is its own command, run by its own unit
// after both, on every boot - which also repairs anything changed by hand.

// The admin's login name. The tenant's login is the tenant's name, which
// grafana.Client refuses when it equals this.
const grafanaAdmin = "admin"

// grafanaReady is how long `dashboards` waits for Grafana to answer. A first
// start on a Pi 3 migrates an empty database and can take minutes.
const grafanaReady = 5 * time.Minute

// writeGrafanaEnv is grafana.service's EnvironmentFile: the two secrets. The
// rest of Grafana's settings are in the unit, where they can be read.
func (k *kit) writeGrafanaEnv(st state) error {
	env := fmt.Sprintf(`# deevnet-kit - generated; Grafana's secrets
GF_SECURITY_ADMIN_USER=%s
GF_SECURITY_ADMIN_PASSWORD=%s
GF_SECURITY_SECRET_KEY=%s
`, grafanaAdmin, st.GrafanaAdminPassword, st.GrafanaSecretKey)
	return writeFile(k.grafanaEnv(), []byte(env), 0o600)
}

func dashboardURL(h string) string { return fmt.Sprintf("https://%s:%d", h, dashboardPort) }

// dashboardEnv is kit.env's Grafana lines, under the names the Terraform
// grafana provider reads by itself. TF_VAR_grafana_org_id is there because
// that provider ignores its own org_id under basic auth, so every resource
// must carry it (CHG-0024). Empty until the organisation exists.
func dashboardEnv(st state, h string) string {
	if st.DashboardOrg == 0 {
		return "# Grafana is not set up yet: systemctl status deevnet-kit-dashboards\n"
	}
	return fmt.Sprintf(`GRAFANA_URL=%s
GRAFANA_AUTH=%s:%s
GRAFANA_ORG_ID=%d
TF_VAR_grafana_org_id=%d
GRAFANA_CA_CERT=site-ca.pem
`, dashboardURL(h), st.Tenant, st.DashboardPassword, st.DashboardOrg, st.DashboardOrg)
}

func (k *kit) cmdDashboards() error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	if st.GrafanaAdminPassword == "" || st.DashboardPassword == "" {
		return fmt.Errorf("this card was initialised without Grafana; its state has no Grafana secrets")
	}
	// localhost for both: the certificate names it, and a .local name is
	// not resolvable from every service.
	local := dashboardURL("localhost")
	if err := waitHealthy(local, k.caFile(), grafanaReady); err != nil {
		return err
	}
	c, err := grafana.New(grafana.Config{
		URL:           local,
		AdminUser:     grafanaAdmin,
		AdminPassword: st.GrafanaAdminPassword,
		CAFile:        k.caFile(),
		LogEndpoint:   fmt.Sprintf("https://localhost:%d", logPort),
	})
	if err != nil {
		return err
	}
	org, err := c.Ensure(context.Background(), tenant.DashTenant{
		Name: st.Tenant, Index: st.Index, Password: st.DashboardPassword, ReadToken: st.ReadToken,
	})
	if err != nil {
		return fmt.Errorf("grafana: %w", err)
	}
	if org != st.DashboardOrg {
		st.DashboardOrg = org
		if err := writeJSON(k.stateFile(), st, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("grafana: organisation %d for %s, with %d log data sources\n", org, st.Tenant, len(grafana.DataSources))
	return nil
}

func waitHealthy(base, caFile string, within time.Duration) error {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	deadline := time.Now().Add(within)
	for {
		resp, err := hc.Get(base + "/api/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("grafana did not answer at %s within %s", base, within)
		}
		time.Sleep(3 * time.Second)
	}
}
