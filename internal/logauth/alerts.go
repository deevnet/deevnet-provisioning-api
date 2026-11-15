package logauth

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Tenant alerting (ADR-0023 §5, CHG-0071).
//
// The API sends one OpAlerts request carrying a tenant's whole alerting state:
// its ntfy login and every rule group it has. The writer keeps that state on
// the observability store and renders each tenant's vmalert rules, ntfy's
// users and Alertmanager's routes from it.
//
// The rules here are the boundary, because a tenant has no other way to put a
// rule on the store. Two of them matter more than the rest:
//
//   - No rule or group may set the labels Alertmanager routes on. In vmalert a
//     rule's own labels beat -external.label, and no flag stops it
//     (CHG-0071, Step 1, finding 1): a rule labelled tenant="other" would be
//     delivered to the other tenant's phone.
//   - A group reads a partition by name, never by number. The writer turns
//     the name into the partition header, which vmauth only honours among the
//     tenant's own partitions.

// Group types, as the API names them.
const (
	AlertTypeMetrics = "metrics"
	AlertTypeLogs    = "logs"
)

// Partitions a group may read, as the API names them.
const (
	PartitionWorkloads = "workloads"
	PartitionPlatform  = "platform"
	PartitionDevices   = "devices"
)

// Labels the substrate sets and routes on, which no tenant rule may set.
const (
	LabelTenant = "tenant"
	LabelTopic  = "deevnet_topic"
)

// Bounds on a tenant's alerting state.
const (
	MaxAlertGroups     = 20
	MaxRulesPerGroup   = 50
	MaxRulesPerTenant  = 200
	MaxExprLen         = 4096
	maxLabels          = 16
	maxLabelValueLen   = 512
	maxAnnotationLen   = 4096
	MinAlertInterval   = 30 * time.Second
	MaxAlertInterval   = time.Hour
	maxFor             = 24 * time.Hour
	DefaultAlertPeriod = "1m"

	// MinNotifyPasswordLen is the shortest ntfy password the writer will hash.
	// The API issues 48 hex characters.
	MinNotifyPasswordLen = 32
)

// Alerts is a tenant's whole alerting state.
type Alerts struct {
	// NotifyPassword is the tenant's ntfy login. The writer keeps only its
	// bcrypt hash.
	NotifyPassword string       `json:"notify_password"`
	Groups         []AlertGroup `json:"groups"`
}

// AlertGroup is one rule group, as the tenant declared it.
type AlertGroup struct {
	Name      string      `json:"name"`
	Type      string      `json:"type"`
	Interval  string      `json:"interval"`
	Topic     string      `json:"topic"`
	Partition string      `json:"partition"`
	Rules     []AlertRule `json:"rules"`
}

// AlertRule is one alerting rule. There is no recording rule: a tenant's
// vmalert holds a read token and runs with nowhere to write (ADR-0023 §5).
type AlertRule struct {
	Alert       string            `json:"alert"`
	Expr        string            `json:"expr"`
	For         string            `json:"for,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

var (
	groupNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	// A topic is the suffix of an ntfy topic, <tenant>-<topic>. Tenant names
	// have no dash, so a tenant's "<tenant>-*" never matches another's topics.
	topicRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	alertNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	labelNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	passwordRE  = regexp.MustCompile(`^[A-Za-z0-9]+$`)
)

// ValidTopic reports whether t may be a group's topic.
func ValidTopic(t string) bool { return topicRE.MatchString(t) }

// ValidGroupName reports whether n may name a rule group.
func ValidGroupName(n string) bool { return groupNameRE.MatchString(n) }

// Validate checks one group. The API calls it before storing a group, and the
// writer again before writing one.
func (g AlertGroup) Validate() error {
	if !groupNameRE.MatchString(g.Name) {
		return fmt.Errorf("group name %q must be 1-32 lowercase letters, digits or dashes, starting with a letter", g.Name)
	}
	switch g.Type {
	case AlertTypeMetrics, AlertTypeLogs:
	default:
		return fmt.Errorf("group %q: type must be %q or %q", g.Name, AlertTypeMetrics, AlertTypeLogs)
	}
	iv, err := time.ParseDuration(g.Interval)
	if err != nil || iv < MinAlertInterval || iv > MaxAlertInterval {
		return fmt.Errorf("group %q: interval %q must be a duration from %s to %s", g.Name, g.Interval, MinAlertInterval, MaxAlertInterval)
	}
	if !topicRE.MatchString(g.Topic) {
		return fmt.Errorf("group %q: topic %q must be 1-32 lowercase letters, digits or dashes", g.Name, g.Topic)
	}
	switch g.Partition {
	case PartitionWorkloads, PartitionPlatform:
	case PartitionDevices:
		if g.Type != AlertTypeLogs {
			return fmt.Errorf("group %q: only a logs group reads the devices partition; devices send logs, not metrics", g.Name)
		}
	default:
		return fmt.Errorf("group %q: partition must be %q, %q or %q", g.Name, PartitionWorkloads, PartitionPlatform, PartitionDevices)
	}
	if len(g.Rules) == 0 || len(g.Rules) > MaxRulesPerGroup {
		return fmt.Errorf("group %q: a group holds 1 to %d rules", g.Name, MaxRulesPerGroup)
	}
	seen := map[string]bool{}
	for _, r := range g.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("group %q: %w", g.Name, err)
		}
		// vmalert keys a rule's state by its name and labels, so two rules of
		// the same name in a group are allowed by it; here they are refused,
		// because the provider addresses rules by name in its plan.
		if seen[r.Alert] {
			return fmt.Errorf("group %q: two rules named %q", g.Name, r.Alert)
		}
		seen[r.Alert] = true
	}
	return nil
}

func (r AlertRule) validate() error {
	if !alertNameRE.MatchString(r.Alert) {
		return fmt.Errorf("rule name %q must be 1-64 letters, digits or underscores, not starting with a digit", r.Alert)
	}
	if strings.TrimSpace(r.Expr) == "" || len(r.Expr) > MaxExprLen {
		return fmt.Errorf("rule %q: expr must be 1 to %d characters", r.Alert, MaxExprLen)
	}
	if err := plainText("expr", r.Expr); err != nil {
		return fmt.Errorf("rule %q: %w", r.Alert, err)
	}
	if r.For != "" {
		d, err := time.ParseDuration(r.For)
		if err != nil || d < 0 || d > maxFor {
			return fmt.Errorf("rule %q: for %q must be a duration up to %s", r.Alert, r.For, maxFor)
		}
	}
	if err := validMap("label", r.Labels, maxLabelValueLen, true); err != nil {
		return fmt.Errorf("rule %q: %w", r.Alert, err)
	}
	if err := validMap("annotation", r.Annotations, maxAnnotationLen, false); err != nil {
		return fmt.Errorf("rule %q: %w", r.Alert, err)
	}
	return nil
}

func validMap(what string, m map[string]string, maxValue int, labels bool) error {
	if len(m) > maxLabels {
		return fmt.Errorf("at most %d %ss", maxLabels, what)
	}
	for k, v := range m {
		if !labelNameRE.MatchString(k) || strings.HasPrefix(k, "__") {
			return fmt.Errorf("%s name %q must be 1-64 letters, digits or underscores, not starting with a digit or __", what, k)
		}
		if labels {
			switch k {
			case LabelTenant, LabelTopic, "alertname":
				// The routing labels, and the alert's own name, are the
				// substrate's to set: see the package comment.
				return fmt.Errorf("label %q is set by the platform, not by a rule", k)
			}
		}
		if len(v) > maxValue {
			return fmt.Errorf("%s %q is longer than %d characters", what, k, maxValue)
		}
		if err := plainText(what+" "+k, v); err != nil {
			return err
		}
	}
	return nil
}

// plainText refuses what has no business in a rule: invalid UTF-8 and control
// characters other than tab and newline.
func plainText(what, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not valid UTF-8", what)
	}
	for _, c := range s {
		if c < 0x20 && c != '\t' && c != '\n' {
			return fmt.Errorf("%s contains a control character", what)
		}
	}
	return nil
}

// Validate checks a tenant's whole alerting state: each group, and the limits
// across them.
func (a Alerts) Validate() error {
	if len(a.NotifyPassword) < MinNotifyPasswordLen || len(a.NotifyPassword) > MaxTokenLen || !passwordRE.MatchString(a.NotifyPassword) {
		return fmt.Errorf("notify_password must be %d to %d letters or digits", MinNotifyPasswordLen, MaxTokenLen)
	}
	if len(a.Groups) > MaxAlertGroups {
		return fmt.Errorf("a tenant holds at most %d rule groups", MaxAlertGroups)
	}
	names := map[string]bool{}
	rules := 0
	for _, g := range a.Groups {
		if err := g.Validate(); err != nil {
			return err
		}
		if names[g.Name] {
			return fmt.Errorf("two rule groups named %q", g.Name)
		}
		names[g.Name] = true
		rules += len(g.Rules)
	}
	if rules > MaxRulesPerTenant {
		return fmt.Errorf("a tenant holds at most %d rules across its groups", MaxRulesPerTenant)
	}
	return nil
}

// PartitionProject is the ProjectID a named partition reads, (index, project)
// as ADR-0027 §2 numbers them.
func PartitionProject(p string) int {
	switch p {
	case PartitionPlatform:
		return 1
	case PartitionDevices:
		return 2
	default:
		return 0
	}
}
