package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Resealer moves a stored value to the current Transit key: *openbao.Client.
// The bool says the value changed.
type Resealer interface {
	Reseal(ctx context.Context, stored string) (string, bool, error)
}

// ResealReport counts what a reseal did, by column.
type ResealReport struct {
	Resealed map[string]int `json:"resealed"`
	Current  int            `json:"current"`
	// Failed are values neither key opens. They are left as they are: a
	// tenant's next apply supplies them again (ADR-0015 §4).
	Failed map[string]int `json:"failed"`
}

// The sealed columns, by table and key. A column added to seal() or sealOne()
// is added here, or a Transit key change would leave it behind.
var sealedColumns = []struct {
	table   string
	key     []string
	columns []string
}{
	{"tenants", []string{"name"}, []string{"tsig_secret", "state_secret", "log_ingest_token", "log_read_token", "dashboard_password"}},
	{"tenant_wifi_keys", []string{"tenant", "name"}, []string{"psk"}},
	{"admission_keys", []string{"tenant"}, []string{"psk"}},
}

// Reseal moves every stored secret to the current Transit key (CHG-0036), one
// value at a time. Each write is conditional on the value it read, so a value
// a request rewrote meanwhile is left alone: the request sealed it under the
// current key already. A sealed OpenBao stops it at once.
func (p *Postgres) Reseal(ctx context.Context, r Resealer) (ResealReport, error) {
	rep := ResealReport{Resealed: map[string]int{}, Failed: map[string]int{}}
	for _, t := range sealedColumns {
		for _, col := range t.columns {
			label := t.table + "." + col
			keys := ""
			for i, k := range t.key {
				if i > 0 {
					keys += ", "
				}
				keys += k
			}
			rows, err := p.pool.Query(ctx, fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s <> ''`, keys, col, t.table, col))
			if err != nil {
				return rep, fmt.Errorf("%s: %w", label, err)
			}
			type row struct {
				key    []any
				stored string
			}
			var all []row
			for rows.Next() {
				vals := make([]any, len(t.key)+1)
				ptrs := make([]any, len(vals))
				for i := range vals {
					ptrs[i] = &vals[i]
				}
				if err := rows.Scan(ptrs...); err != nil {
					rows.Close()
					return rep, fmt.Errorf("%s: %w", label, err)
				}
				s, _ := vals[len(t.key)].(string)
				all = append(all, row{key: vals[:len(t.key)], stored: s})
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return rep, fmt.Errorf("%s: %w", label, err)
			}

			for _, rw := range all {
				next, changed, err := r.Reseal(ctx, rw.stored)
				switch {
				case errors.Is(err, tenant.ErrSecretsUnavailable):
					return rep, err
				case err != nil:
					p.log().Error("stored secret opens under neither key; left as it is", "column", label, "key", rw.key, "err", err)
					rep.Failed[label]++
					continue
				case !changed:
					rep.Current++
					continue
				}
				where := ""
				args := []any{next, rw.stored}
				for i, k := range t.key {
					where += fmt.Sprintf(" AND %s = $%d", k, i+3)
					args = append(args, rw.key[i])
				}
				if _, err := p.pool.Exec(ctx, fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s = $2%s`, t.table, col, col, where), args...); err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return rep, fmt.Errorf("%s: %w", label, err)
				}
				rep.Resealed[label]++
			}
		}
	}
	return rep, nil
}
