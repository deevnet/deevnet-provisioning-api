package logauth

import (
	"strings"
	"testing"
)

func okGroup() AlertGroup {
	return AlertGroup{
		Name: "backend", Type: AlertTypeMetrics, Interval: "1m", Topic: "backend", Partition: PartitionWorkloads,
		Rules: []AlertRule{{Alert: "QueueBacklog", Expr: "backend_queue_depth > 100", For: "5m",
			Labels: map[string]string{"severity": "page"}, Annotations: map[string]string{"summary": "queue is {{ $value }}"}}},
	}
}

func okAlerts() Alerts {
	return Alerts{NotifyPassword: strings.Repeat("a1", 24), Groups: []AlertGroup{okGroup()}}
}

func TestAGoodGroupPasses(t *testing.T) {
	if err := okAlerts().Validate(); err != nil {
		t.Fatal(err)
	}
}

// The labels Alertmanager routes on are the platform's. vmalert lets a rule's
// labels beat -external.label (CHG-0071, Step 1, finding 1), so this refusal
// is what keeps one tenant's alert off another tenant's phone.
func TestARuleMayNotSetTheRoutingLabels(t *testing.T) {
	for _, k := range []string{"tenant", "deevnet_topic", "alertname", "__name__", "__tenant"} {
		g := okGroup()
		g.Rules[0].Labels = map[string]string{k: "eds"}
		if err := g.Validate(); err == nil {
			t.Errorf("label %q was accepted", k)
		}
	}
}

func TestAnAnnotationMayUseAnyPlainName(t *testing.T) {
	g := okGroup()
	g.Rules[0].Annotations = map[string]string{"tenant": "mentioning it is fine", "runbook_url": "https://x"}
	if err := g.Validate(); err != nil {
		t.Fatalf("annotations are not routed on, so these are allowed: %v", err)
	}
}

func TestGroupFieldsAreChecked(t *testing.T) {
	cases := map[string]func(*AlertGroup){
		"name":              func(g *AlertGroup) { g.Name = "Backend" },
		"type":              func(g *AlertGroup) { g.Type = "recording" },
		"interval too fast": func(g *AlertGroup) { g.Interval = "10s" },
		"interval garbage":  func(g *AlertGroup) { g.Interval = "often" },
		"topic":             func(g *AlertGroup) { g.Topic = "eds/other" },
		"topic empty":       func(g *AlertGroup) { g.Topic = "" },
		"partition":         func(g *AlertGroup) { g.Partition = "2-0" },
		"metrics devices":   func(g *AlertGroup) { g.Partition = PartitionDevices },
		"no rules":          func(g *AlertGroup) { g.Rules = nil },
		"rule name":         func(g *AlertGroup) { g.Rules[0].Alert = "9lives" },
		"empty expr":        func(g *AlertGroup) { g.Rules[0].Expr = "  " },
		"long expr":         func(g *AlertGroup) { g.Rules[0].Expr = strings.Repeat("x", MaxExprLen+1) },
		"control char":      func(g *AlertGroup) { g.Rules[0].Expr = "up\x00" },
		"for":               func(g *AlertGroup) { g.Rules[0].For = "forever" },
		"duplicate rules":   func(g *AlertGroup) { g.Rules = append(g.Rules, g.Rules[0]) },
	}
	for name, mut := range cases {
		g := okGroup()
		mut(&g)
		if err := g.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestALogsGroupMayReadTheDevicePartition(t *testing.T) {
	g := okGroup()
	g.Type, g.Partition = AlertTypeLogs, PartitionDevices
	g.Rules[0].Expr = `"door open" | stats count() as hits | filter hits:>0`
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTenantLimits(t *testing.T) {
	a := okAlerts()
	a.Groups = append(a.Groups, okGroup())
	if err := a.Validate(); err == nil {
		t.Error("two groups of the same name were accepted")
	}

	a = okAlerts()
	a.Groups = nil
	for i := 0; i <= MaxAlertGroups; i++ {
		g := okGroup()
		g.Name = "g" + strings.Repeat("x", i%10) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		a.Groups = append(a.Groups, g)
	}
	if err := a.Validate(); err == nil {
		t.Error("more than MaxAlertGroups groups were accepted")
	}

	a = okAlerts()
	a.NotifyPassword = "short"
	if err := a.Validate(); err == nil {
		t.Error("a short notify password was accepted")
	}
	a.NotifyPassword = strings.Repeat("a", 40) + ":x"
	if err := a.Validate(); err == nil {
		t.Error("a notify password with a colon was accepted")
	}
}

func TestAnAlertsRequestCarriesStateAndNoTokens(t *testing.T) {
	a := okAlerts()
	req := Request{Version: Version, Op: OpAlerts, Tenant: "eds", Index: 2, Alerts: &a}
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	req.ReadToken = strings.Repeat("r", 64)
	if err := req.Validate(); err == nil {
		t.Error("an alerts request with a token was accepted")
	}
	req = Request{Version: Version, Op: OpAlerts, Tenant: "eds", Index: 2}
	if err := req.Validate(); err == nil {
		t.Error("an alerts request without state was accepted")
	}
	put := Request{Version: Version, Op: OpPut, Tenant: "eds", Index: 2,
		IngestToken: strings.Repeat("i", 64), ReadToken: strings.Repeat("r", 64), Alerts: &a}
	if err := put.Validate(); err == nil {
		t.Error("a put carrying alerting state was accepted")
	}
}

func TestPartitionProjects(t *testing.T) {
	for p, want := range map[string]int{PartitionWorkloads: 0, PartitionPlatform: 1, PartitionDevices: 2} {
		if got := PartitionProject(p); got != want {
			t.Errorf("%s: %d, want %d", p, got, want)
		}
	}
}
