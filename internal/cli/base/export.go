package base

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"crivo/internal/audit"
	"crivo/internal/cli"
	"crivo/internal/output"
	"crivo/internal/run"
	"crivo/internal/sqlguard"
)

// exportCmd é o caminho legítimo para resultados grandes (diretiva export):
// a mesma leitura de query, com o teto da exportação em vez do limit, e a
// saída num arquivo CSV em vez do terminal. Passa pelo portão, pelos limites
// (as linhas contam na quota), pelo guard, pelas máscaras e pela auditoria.
type exportCmd struct {
	sqlArgs
	Output string `short:"o" required:"" help:"Arquivo CSV de saída: caminho relativo, dentro da pasta atual."`
	Force  bool   `help:"Sobrescreve o arquivo se ele existir."`
}

func (c *exportCmd) Run(e *env) (err error) {
	sql, err := cli.ReadSQL(c.SQL, c.File)
	if err != nil {
		return err
	}
	if !filepath.IsLocal(c.Output) {
		return &cli.ConfigError{Msg: fmt.Sprintf("-o precisa ser um caminho relativo dentro da pasta atual: %q", c.Output)}
	}
	if _, err := os.Stat(c.Output); err == nil && !c.Force {
		return &cli.ConfigError{Msg: c.Output + " já existe; use --force para sobrescrever"}
	}
	start := time.Now()
	var v *sqlguard.Verdict
	var n int64
	defer func() { e.audit("export", sql, v, start, n, false, err) }()
	if err = e.limits(); err != nil {
		return err
	}
	limit, quotaCut := e.p.ExportRows, false
	if e.p.QuotaRowsDay > 0 {
		if _, used, uerr := audit.Usage(e.p.Name, now()); uerr == nil && e.p.QuotaRowsDay-used < int64(limit) {
			limit, quotaCut = int(e.p.QuotaRowsDay-used), true
		}
	}
	g, err := e.guard()
	if err != nil {
		return err
	}
	if v, err = g.CheckExport(sql, limit); err != nil {
		return err
	}
	m, err := e.masker(v)
	if err != nil {
		return err
	}
	conn, err := e.sess.Conn()
	if err != nil {
		return err
	}
	res, err := run.Query(e.sess.Ctx(), conn, e.p, v.SQL, v.Cap)
	if err != nil {
		return e.onDBError(err)
	}
	n = int64(len(res.Rows))
	if err := writeFileAtomic(c.Output, &output.Rows{Columns: res.Columns, Values: masked(m, res, v)}); err != nil {
		return &cli.ConfigError{Msg: "gravando " + c.Output + ": " + err.Error()}
	}
	fmt.Fprintf(e.stdout, "✓ %d linha(s) em %s\n", n, c.Output)
	if e.p.QuotaRowsDay > 0 {
		if _, used, uerr := audit.Usage(e.p.Name, now()); uerr == nil {
			left := e.p.QuotaRowsDay - used - n // esta exportação ainda não está na auditoria
			if left < 0 {
				left = 0
			}
			fmt.Fprintf(e.stdout, "-- restam %d linhas da cota de hoje (quota %d rows/day)\n", left, e.p.QuotaRowsDay)
		}
	}
	switch {
	case res.Truncated && quotaCut:
		fmt.Fprintf(e.stdout, "-- parou em %d linhas: é o que resta da cota de hoje (quota %d rows/day); o resto fica para amanhã ou para um filtro menor\n", v.Cap, e.p.QuotaRowsDay)
	case res.Truncated && !v.CapByRequest:
		fmt.Fprintf(e.stdout, "-- parou no teto de exportação da política (%d linhas): há mais. Exporte só o recorte de que a pessoa precisa ou peça ao dono da política um teto maior; não junte várias exportações para passar do teto\n", v.Cap)
	case res.Truncated:
		fmt.Fprintf(e.stdout, "-- parou no LIMIT da query (%d linhas): há mais linhas\n", v.Cap)
	}
	return nil
}

func writeFileAtomic(path string, rows *output.Rows) error {
	tmp, err := os.CreateTemp(filepath.Dir(filepath.Clean(path)), ".crivo-export-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := output.WriteCSV(tmp, rows); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
