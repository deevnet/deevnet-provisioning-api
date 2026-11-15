package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant alert rule groups (ADR-0023 §5, CHG-0071). See 0016_tenant_alerting.sql.

const alertGroupColumns = `tenant, name, type, interval, topic, partition, rules, created_at, updated_at`

func scanAlertGroup(row pgx.Row) (tenant.AlertRuleGroup, error) {
	var g tenant.AlertRuleGroup
	var rules []byte
	err := row.Scan(&g.Tenant, &g.Group.Name, &g.Group.Type, &g.Group.Interval, &g.Group.Topic,
		&g.Group.Partition, &rules, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return g, err
	}
	var rs []logauth.AlertRule
	if err := json.Unmarshal(rules, &rs); err != nil {
		return g, err
	}
	g.Group.Rules = rs
	return g, nil
}

// PutAlertRuleGroup inserts a group, or replaces one of the same name.
func (p *Postgres) PutAlertRuleGroup(ctx context.Context, g tenant.AlertRuleGroup) (tenant.AlertRuleGroup, error) {
	rules, err := json.Marshal(g.Group.Rules)
	if err != nil {
		return tenant.AlertRuleGroup{}, err
	}
	var out tenant.AlertRuleGroup
	err = pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenants WHERE name = $1)`, g.Tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return tenant.ErrNotFound
		}
		var err error
		out, err = scanAlertGroup(tx.QueryRow(ctx,
			`INSERT INTO tenant_alert_rule_groups (tenant, name, type, interval, topic, partition, rules)
			      VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (tenant, name) DO UPDATE
			         SET type = EXCLUDED.type, interval = EXCLUDED.interval, topic = EXCLUDED.topic,
			             partition = EXCLUDED.partition, rules = EXCLUDED.rules, updated_at = now()
			   RETURNING `+alertGroupColumns,
			g.Tenant, g.Group.Name, g.Group.Type, g.Group.Interval, g.Group.Topic, g.Group.Partition, rules))
		return err
	})
	if err != nil {
		return tenant.AlertRuleGroup{}, err
	}
	return out, nil
}

// GetAlertRuleGroup returns one group.
func (p *Postgres) GetAlertRuleGroup(ctx context.Context, tenantName, name string) (tenant.AlertRuleGroup, error) {
	g, err := scanAlertGroup(p.pool.QueryRow(ctx,
		`SELECT `+alertGroupColumns+` FROM tenant_alert_rule_groups WHERE tenant = $1 AND name = $2`, tenantName, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.AlertRuleGroup{}, tenant.ErrNotFound
	}
	return g, err
}

// ListAlertRuleGroups returns a tenant's groups, by name.
func (p *Postgres) ListAlertRuleGroups(ctx context.Context, tenantName string) ([]tenant.AlertRuleGroup, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+alertGroupColumns+` FROM tenant_alert_rule_groups WHERE tenant = $1 ORDER BY name`, tenantName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenant.AlertRuleGroup
	for rows.Next() {
		g, err := scanAlertGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeleteAlertRuleGroup removes a group. One that is not there is not an
// error, so a repeated delete converges.
func (p *Postgres) DeleteAlertRuleGroup(ctx context.Context, tenantName, name string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM tenant_alert_rule_groups WHERE tenant = $1 AND name = $2`, tenantName, name)
	return err
}
