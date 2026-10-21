// Package base é a CLI do binário gerado (modo base): só comandos de
// consulta, respeitando a política embutida.
package base

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	"crivo/internal/audit"
	"crivo/internal/cli"
	"crivo/internal/mask"
	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/run"
	"crivo/internal/schema"
	"crivo/internal/skill"
	"crivo/internal/sqlguard"
)

// env é o estado compartilhado pelos comandos.
type env struct {
	p          *policy.Policy
	sess       *cli.Session
	stdout     io.Writer
	stderr     io.Writer
	format     output.Format
	jsonErrors bool
	via        string // prefixo do comando na auditoria ("" no CLI, "mcp:" no servidor MCP)
}

func (e *env) guard() (*sqlguard.Guard, error) {
	sc, err := e.sess.LoadSchema(cli.SchemaFresh)
	if err != nil {
		return nil, err
	}
	return sqlguard.New(e.p, sc)
}

type globals struct {
	Format     string `enum:"tsv,json,table" default:"tsv" help:"Formato da saída: tsv, json ou table."`
	JSONErrors bool   `name:"json-errors" help:"Erros em JSON no stderr."`
}

type rootCmd struct {
	globals
	Policy   policyCmd   `cmd:"" help:"Imprime a política embutida com números de linha."`
	Tables   tablesCmd   `cmd:"" help:"Lista as tabelas permitidas, ações e descrições."`
	Describe describeCmd `cmd:"" help:"Colunas permitidas de uma tabela, com tipo, nulabilidade, chaves e máscaras."`
	Skill    skillCmd    `cmd:"" help:"Gera e instala a skill do Copilot."`
	Refresh  refreshCmd  `cmd:"" help:"Recarrega o cache de schema."`
	Mcp      mcpCmd      `cmd:"" help:"Serve a política como servidor MCP (stdio) para clientes de IA. Opcional; o CLI com a skill continua sendo o modo principal."`
}

// Main roda o modo base com a política embutida.
func Main(src []byte, args []string) int {
	p, diags := policy.Parse("policy", string(src))
	if diags.HasErrors() {
		fmt.Fprintln(os.Stderr, "✗ política embutida inválida:\n"+diags.Error())
		return output.ExitConfig
	}
	root := &rootCmd{}
	opts := []kong.Option{
		kong.Name(p.Name),
		kong.Description(fmt.Sprintf("%s (%s). Toda query passa pelo Crivo.", p.About, p.EnvLabel())),
		kong.UsageOnError(),
		kong.Exit(func(int) {}),
	}
	if p.HasRead() {
		opts = append(opts,
			kong.DynamicCommand("query", "Executa um SELECT em transação READ ONLY.", "", &queryCmd{}),
			kong.DynamicCommand("explain", "Plano (EXPLAIN sem ANALYZE) de um SELECT validado.", "", &explainCmd{}))
	}
	if p.HasWrite() {
		opts = append(opts, kong.DynamicCommand("exec", "Executa INSERT/UPDATE/DELETE com teto de linhas.", "", &execCmd{}))
	}
	parser, err := kong.New(root, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return output.ExitBug
	}
	kctx, err := parser.Parse(args)
	if err != nil {
		if len(args) == 0 || isHelp(args) {
			return output.ExitOK
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", p.Name, err)
		return output.ExitConfig
	}
	if kctx.Command() == "" {
		return output.ExitOK
	}
	e := &env{p: p, stdout: os.Stdout, stderr: os.Stderr, format: output.Format(root.Format), jsonErrors: root.JSONErrors}
	e.sess = cli.NewSession(p, os.Stderr)
	defer e.sess.Close()
	err = kctx.Run(e)
	return cli.Report(os.Stderr, p, err, root.JSONErrors)
}

func isHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}

// ---------- policy, tables, describe ----------

type policyCmd struct{}

func (c *policyCmd) Run(e *env) error {
	fmt.Fprint(e.stdout, e.p.Numbered())
	g, err := sqlguard.New(e.p, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "-- funções liberadas: %s\n", strings.Join(g.AllowedFunctionList(), ", "))
	return nil
}

type tablesCmd struct{}

func actionsText(r *policy.Rule) string {
	var parts []string
	for _, a := range r.Actions {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

func (c *tablesCmd) Run(e *env) error {
	rows := &output.Rows{Columns: []string{"tabela", "ações", "descrição"}}
	var sc *schema.Schema
	for _, r := range e.p.Rules {
		if r.Deny || len(r.Actions) == 0 || policy.AlwaysBlocked(e.p.SchemaOf(r), r.Pattern) {
			continue
		}
		names := []string{r.Label()}
		if r.IsPattern() {
			if sc == nil {
				sc, _ = e.sess.LoadSchema(cli.SchemaFresh)
			}
			if sc != nil {
				sch := e.p.SchemaOf(r)
				names = nil
				for _, t := range e.p.MatchingTables(r, sch, sc.TableNames(sch)) {
					if sch != e.p.Schema {
						t = sch + "." + t
					}
					names = append(names, t)
				}
			}
		}
		desc := r.Doc
		if rd := r.Action(policy.Read); rd != nil && rd.Where != "" {
			desc = strings.TrimSpace(desc + " [filtro: só linhas com " + rd.Where + "]")
		}
		for _, n := range names {
			d, a := desc, actionsText(r)
			rows.Values = append(rows.Values, []*string{&n, &a, &d})
		}
	}
	rows.Footer = fmt.Sprintf("%d tabelas; qualquer outra não existe para você", len(rows.Values))
	return output.Write(e.stdout, e.format, rows)
}

type describeCmd struct {
	Table string `arg:"" help:"Tabela (ou schema.tabela)."`
}

func (c *describeCmd) Run(e *env) error {
	sch, name := e.p.Schema, strings.ToLower(c.Table)
	if i := strings.IndexByte(name, '.'); i >= 0 {
		sch, name = name[:i], name[i+1:]
	}
	r := e.p.Resolve(sch, name)
	if r == nil || r.Deny {
		d := &sqlguard.Denial{Rule: r, Reason: fmt.Sprintf("tabela %q não existe para a IA", c.Table), Accepted: "use o comando tables"}
		if r == nil {
			d.Rule = nil
		}
		return d
	}
	sc, err := e.sess.LoadSchema(cli.SchemaFresh)
	if err != nil {
		return err
	}
	t := sc.Table(sch, name)
	if t == nil {
		return &sqlguard.Denial{Rule: r, Reason: fmt.Sprintf("tabela %q está na política mas não existe no banco", c.Table), Accepted: "rode o comando refresh se ela acabou de ser criada"}
	}
	rows := &output.Rows{Columns: []string{"coluna", "tipo", "nulo", "chave", "máscara", "escrita"}}
	for _, ci := range skill.DescribeColumns(r, t) {
		ci := ci
		w := strings.Join(ci.Writable, ", ")
		rows.Values = append(rows.Values, []*string{&ci.Name, &ci.Type, &ci.Null, &ci.Key, &ci.Mask, &w})
	}
	var notes []string
	notes = append(notes, fmt.Sprintf("regra: %s (policy:%d)", actionsText(r), r.Pos.Line))
	if r.Doc != "" {
		notes = append(notes, r.Doc)
	}
	if rd := r.Action(policy.Read); rd != nil && rd.Where != "" {
		notes = append(notes, "filtro de leitura: só linhas com "+rd.Where)
	}
	rows.Footer = strings.Join(notes, " | ")
	return output.Write(e.stdout, e.format, rows)
}

type refreshCmd struct{}

func (c *refreshCmd) Run(e *env) error {
	sc, err := e.sess.LoadSchema(cli.SchemaRefresh)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "-- schema recarregado: %d tabelas em %s\n", len(sc.Tables), strings.Join(e.p.Schemas(), ", "))
	return nil
}

// ---------- query, explain, exec ----------

type sqlArgs struct {
	SQL  string `arg:"" optional:"" help:"SQL entre aspas."`
	File string `short:"f" type:"existingfile" help:"Lê o SQL de um arquivo (evita escapar aspas no shell)."`
}

func (e *env) audit(cmd string, sql string, v *sqlguard.Verdict, start time.Time, rows int64, dry bool, err error) {
	entry := audit.Entry{Command: e.via + cmd, SQL: sql, Rows: rows, DryRun: dry, Duration: time.Since(start).Milliseconds()}
	entry.Exit = cli.Report(io.Discard, e.p, err, false)
	if v != nil {
		entry.Rewritten = v.SQL
		for _, u := range v.Rules {
			entry.Rules = append(entry.Rules, fmt.Sprintf("%s %s (policy:%d)", u.Name, u.Verb, u.Rule.Pos.Line))
		}
	}
	var d *sqlguard.Denial
	var pe *sqlguard.ParseError
	var many *run.TooManyRows
	switch {
	case err == nil:
		entry.Decision = "aceito"
	case errors.As(err, &d):
		entry.Decision, entry.Reason = "barrado", d.Reason
		if d.Rule != nil {
			entry.Rules = []string{fmt.Sprintf("%s (policy:%d)", d.Rule.Label(), d.Rule.Pos.Line)}
		}
	case errors.As(err, &many):
		entry.Decision, entry.Reason = "barrado", many.Error()
	case errors.As(err, &pe):
		entry.Decision, entry.Reason = "invalido", pe.Message
	default:
		entry.Decision, entry.Reason = "erro", err.Error()
	}
	if aerr := audit.Write(e.p.Name, entry); aerr != nil {
		fmt.Fprintf(e.stderr, "aviso: log de auditoria falhou: %v\n", aerr)
	}
}

// onDBError renova o cache quando o banco diz que coluna/tabela não existe.
func (e *env) onDBError(err error) error {
	if run.SchemaChanged(err) {
		_ = schema.ClearCache(e.p.Name)
		_, _ = e.sess.LoadSchema(cli.SchemaRefresh)
	}
	return err
}

func (e *env) masked(res *run.Result, v *sqlguard.Verdict) [][]*string {
	if len(v.Masks) == 0 {
		return res.Rows
	}
	m := mask.New()
	for _, row := range res.Rows {
		for _, om := range v.Masks {
			if om.Index < len(row) && row[om.Index] != nil {
				s := m.Apply(om.Mode, *row[om.Index])
				row[om.Index] = &s
			}
		}
	}
	return res.Rows
}

type queryCmd struct{ sqlArgs }

func (c *queryCmd) Run(e *env) (err error) {
	start := time.Now()
	sql, err := cli.ReadSQL(c.SQL, c.File)
	if err != nil {
		return err
	}
	var v *sqlguard.Verdict
	var n int64
	defer func() { e.audit("query", sql, v, start, n, false, err) }()
	g, err := e.guard()
	if err != nil {
		return err
	}
	if v, err = g.Check(sqlguard.CmdQuery, sql); err != nil {
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
	return output.Write(e.stdout, e.format, &output.Rows{
		Columns: res.Columns, Types: res.Types, Values: e.masked(res, v),
		Footer: output.ReadFooter(len(res.Rows), res.Truncated, v.CapByRequest),
	})
}

type explainCmd struct{ sqlArgs }

func (c *explainCmd) Run(e *env) (err error) {
	start := time.Now()
	sql, err := cli.ReadSQL(c.SQL, c.File)
	if err != nil {
		return err
	}
	var v *sqlguard.Verdict
	defer func() { e.audit("explain", sql, v, start, 0, false, err) }()
	g, err := e.guard()
	if err != nil {
		return err
	}
	if v, err = g.Check(sqlguard.CmdQuery, sql); err != nil {
		return err
	}
	conn, err := e.sess.Conn()
	if err != nil {
		return err
	}
	res, err := run.Explain(e.sess.Ctx(), conn, e.p, v.SQL)
	if err != nil {
		return e.onDBError(err)
	}
	for _, row := range res.Rows {
		if len(row) > 0 && row[0] != nil {
			fmt.Fprintln(e.stdout, *row[0])
		}
	}
	fmt.Fprintln(e.stdout, "-- sql "+v.SQL)
	return nil
}

type execCmd struct {
	sqlArgs
	DryRun bool `name:"dry-run" help:"Executa, reporta as linhas afetadas e faz rollback."`
}

func (c *execCmd) Run(e *env) (err error) {
	start := time.Now()
	sql, err := cli.ReadSQL(c.SQL, c.File)
	if err != nil {
		return err
	}
	var v *sqlguard.Verdict
	var n int64
	defer func() { e.audit("exec", sql, v, start, n, c.DryRun, err) }()
	g, err := e.guard()
	if err != nil {
		return err
	}
	if v, err = g.Check(sqlguard.CmdExec, sql); err != nil {
		return err
	}
	conn, err := e.sess.Conn()
	if err != nil {
		return err
	}
	res, err := run.Exec(e.sess.Ctx(), conn, e.p, v.SQL, v.MaxRows, c.DryRun)
	if err != nil {
		var many *run.TooManyRows
		if errors.As(err, &many) {
			return &sqlguard.Denial{Rule: v.Target.Rule,
				Reason:   fmt.Sprintf("a escrita afetaria %d linhas; o máximo da regra é %d (rollback feito)", many.Affected, many.Max),
				Accepted: fmt.Sprintf("um WHERE mais restrito, que afete até %d linhas", many.Max)}
		}
		return e.onDBError(err)
	}
	n = res.Affected
	rows := &output.Rows{Footer: output.WriteFooter(res.Affected, c.DryRun)}
	if len(res.Columns) > 0 {
		rows.Columns, rows.Types, rows.Values = res.Columns, res.Types, e.masked(res, v)
	}
	if c.DryRun {
		fmt.Fprintln(e.stdout, "-- sql "+v.SQL)
	}
	return output.Write(e.stdout, e.format, rows)
}

// ---------- skill ----------

type skillOpts struct {
	WithSchema bool   `name:"with-schema" help:"Anexa as colunas permitidas de cada tabela."`
	Bin        string `help:"Como a skill chama o binário (nome ou caminho). Padrão: o nome, se a pasta do binário está no PATH; senão, o caminho absoluto."`
}

type skillCmd struct {
	Print   skillPrintCmd   `cmd:"" default:"withargs" hidden:"" help:"Imprime o SKILL.md."`
	Install skillInstallCmd `cmd:"" help:"Grava o SKILL.md no workspace (.github/skills)."`
	Vscode  skillVSCodeCmd  `cmd:"" name:"vscode" help:"Imprime o trecho de settings.json de auto-approve."`
	Mcp     skillMCPCmd     `cmd:"" name:"mcp" help:"Imprime a configuração do servidor MCP para VS Code, Claude Code e Claude Desktop."`
}

type skillMCPCmd struct {
	Bin       string `help:"Como a configuração chama o binário (nome ou caminho)."`
	AllowExec bool   `name:"allow-exec" help:"Inclui --allow-exec (escrita real pelo MCP)."`
}

func (c *skillMCPCmd) Run(e *env) error {
	fmt.Fprint(e.stdout, skill.MCPConfig(e.p, e.defaultBin(c.Bin), c.AllowExec))
	return nil
}

func (e *env) defaultBin(flag string) string {
	if flag != "" {
		return flag
	}
	exe, err := os.Executable()
	if err != nil {
		return e.p.Name
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	base := filepath.Base(exe)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if found, err := exec.LookPath(name); err == nil {
		if real, err := filepath.EvalSymlinks(found); err == nil && real == exe {
			return name
		}
	}
	return exe
}

func (e *env) skillContent(o skillOpts) (string, error) {
	opts := skill.Options{Bin: e.defaultBin(o.Bin), WithSchema: o.WithSchema}
	if o.WithSchema {
		sc, err := e.sess.LoadSchema(cli.SchemaFresh)
		if err != nil {
			return "", err
		}
		opts.Schema = sc
	}
	return skill.Generate(e.p, opts)
}

type skillPrintCmd struct{ skillOpts }

func (c *skillPrintCmd) Run(e *env) error {
	s, err := e.skillContent(c.skillOpts)
	if err != nil {
		return err
	}
	fmt.Fprint(e.stdout, s)
	return nil
}

type skillInstallCmd struct {
	skillOpts
	Personal bool   `help:"Grava em ~/.copilot/skills (todos os workspaces)."`
	Dir      string `help:"Grava em <pasta>/crivo-<name>/SKILL.md (ex.: .claude/skills)."`
	Force    bool   `help:"Sobrescreve uma skill existente."`
}

func (c *skillInstallCmd) Run(e *env) error {
	if c.Personal && c.Dir != "" {
		return &cli.ConfigError{Msg: "use --personal ou --dir, não os dois"}
	}
	s, err := e.skillContent(c.skillOpts)
	if err != nil {
		return err
	}
	var base string
	switch {
	case c.Personal:
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		base = filepath.Join(home, ".copilot", "skills")
	case c.Dir != "":
		base = c.Dir
	default:
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		base = filepath.Join(skill.WorkspaceRoot(wd), ".github", "skills")
	}
	path, err := skill.Install(e.p, base, s, c.Force)
	if err != nil {
		return &cli.ConfigError{Msg: err.Error()}
	}
	fmt.Fprintf(e.stdout, "✓ %s\n", path)
	return nil
}

type skillVSCodeCmd struct {
	Bin string `help:"Como a skill chama o binário (nome ou caminho)."`
}

func (c *skillVSCodeCmd) Run(e *env) error {
	fmt.Fprint(e.stdout, skill.VSCodeSettings(e.p, e.defaultBin(c.Bin)))
	return nil
}
