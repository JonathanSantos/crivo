package base

import (
	"fmt"
	"strings"
	"time"

	"crivo/internal/audit"
	"crivo/internal/cli"
	"crivo/internal/output"
)

// auditCmd lê o log de auditoria desta política (inclusive os arquivos
// rotacionados). Só lê o arquivo local: não passa pelo portão do banco.
type auditCmd struct {
	Since    time.Duration `default:"24h" help:"Janela de tempo (ex.: 30m, 24h, 168h)."`
	Decision string        `enum:",aceito,barrado,invalido,erro,pendente" default:"" help:"Só entradas com esta decisão."`
	Command  string        `help:"Só um comando (query, exec, run, approve...); inclui o mesmo comando vindo do MCP."`
	Limit    int           `default:"50" help:"Máximo de entradas, das mais novas."`
}

func (c *auditCmd) Run(e *env) error {
	if c.Since <= 0 || c.Limit <= 0 {
		return &cli.ConfigError{Msg: "--since e --limit precisam ser positivos"}
	}
	entries, err := audit.Read(e.p.Name, now().Add(-c.Since))
	if err != nil {
		return &cli.ConfigError{Msg: "lendo a auditoria: " + err.Error()}
	}
	var kept []audit.Entry
	for _, en := range entries {
		if c.Decision != "" && en.Decision != c.Decision {
			continue
		}
		if c.Command != "" && strings.TrimPrefix(en.Command, "mcp:") != c.Command {
			continue
		}
		kept = append(kept, en)
	}
	total := len(kept)
	if len(kept) > c.Limit {
		kept = kept[len(kept)-c.Limit:]
	}
	rows := &output.Rows{Columns: []string{"hora", "comando", "decisão", "linhas", "sql", "motivo"}}
	for _, en := range kept {
		t := en.Time.Local().Format("2006-01-02 15:04:05")
		cmd, dec, n := en.Command, en.Decision, fmt.Sprint(en.Rows)
		sql, reason := strings.Join(strings.Fields(en.SQL), " "), en.Reason
		rows.Values = append(rows.Values, []*string{&t, &cmd, &dec, &n, &sql, &reason})
	}
	rows.Footer = fmt.Sprintf("%d de %d entrada(s) nas últimas %s", len(kept), total, c.Since)
	return output.Write(e.stdout, e.format, rows)
}
