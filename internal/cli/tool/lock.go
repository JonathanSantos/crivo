package tool

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"crivo/internal/cli"
	"crivo/internal/policy"
	"crivo/internal/schema"
)

// A trava (<política>.lock) guarda as colunas que cada tabela expõe para
// leitura. Uma regra sem lista de colunas expõe também as colunas criadas
// depois; o check compara com a trava e avisa, para a pessoa revisar.

type lockFile struct {
	Version int                 `json:"version"`
	Tables  map[string][]string `json:"tables"` // "schema.tabela" -> colunas legíveis
}

func lockPath(policyPath string) string { return policyPath + ".lock" }

// exposure calcula as colunas legíveis de cada tabela coberta por read.
func exposure(p *policy.Policy, sc *schema.Schema) map[string][]string {
	out := map[string][]string{}
	for _, r := range p.Rules {
		rd := r.Action(policy.Read)
		if r.Deny || rd == nil {
			continue
		}
		sch := p.SchemaOf(r)
		for _, tname := range p.MatchingTables(r, sch, sc.TableNames(sch)) {
			// a regra que vale para a tabela é a que o Resolve escolhe
			if p.Resolve(sch, tname) != r {
				continue
			}
			cols := append([]string(nil), rd.AllowedCols(sc.Table(sch, tname).ColumnNames())...)
			sort.Strings(cols)
			out[sch+"."+tname] = cols
		}
	}
	return out
}

func writeLock(policyPath string, tables map[string][]string) error {
	data, err := json.MarshalIndent(lockFile{Version: 1, Tables: tables}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(lockPath(policyPath), append(data, '\n'), 0o644); err != nil {
		return &cli.ConfigError{Msg: "gravando a trava: " + err.Error()}
	}
	return nil
}

// lockChecks avisa das colunas expostas que não estavam na trava.
func lockChecks(policyPath string, p *policy.Policy, sc *schema.Schema) policy.Diags {
	data, err := os.ReadFile(lockPath(policyPath))
	if err != nil {
		return nil // sem trava, nada a comparar
	}
	var lf lockFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return policy.Diags{{File: p.File, Severity: policy.SevWarning, Msg: lockPath(policyPath) + " ilegível; regrave com crivo check --lock"}}
	}
	var fresh []string
	for table, cols := range exposure(p, sc) {
		old := map[string]bool{}
		for _, c := range lf.Tables[table] {
			old[c] = true
		}
		for _, c := range cols {
			if !old[c] {
				fresh = append(fresh, table+"."+c)
			}
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	sort.Strings(fresh)
	return policy.Diags{{File: p.File, Severity: policy.SevWarning,
		Msg: fmt.Sprintf("coluna(s) exposta(s) desde a última trava: %s; revise e rode crivo check --lock", strings.Join(fresh, ", "))}}
}
