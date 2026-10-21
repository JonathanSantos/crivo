// Package tool é a CLI do crivo sem política embutida (modo ferramenta):
// cria, valida, testa e gera binários. Nenhum comando executa SQL da IA.
package tool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/alecthomas/kong"
	pg_query "github.com/pganalyze/pg_query_go/v6"
	"golang.org/x/term"

	"crivo/internal/cli"
	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/run"
	"crivo/internal/schema"
	"crivo/internal/secret"
	"crivo/internal/slot"
	"crivo/internal/sqlguard"
)

type env struct {
	stdout io.Writer
	stderr io.Writer
}

type rootCmd struct {
	Init    initCmd    `cmd:"" help:"Introspecta o banco e gera um arquivo .crivo com todas as tabelas negadas."`
	Check   checkCmd   `cmd:"" help:"Valida sintaxe e semântica e confere tabelas e colunas contra o schema real."`
	Test    testCmd    `cmd:"" help:"Roda a validação sem executar: decisão, regra e SQL reescrito."`
	Build   buildCmd   `cmd:"" help:"Gera o binário da base com a política embutida."`
	Grants  grantsCmd  `cmd:"" help:"Gera o SQL de um usuário de privilégio mínimo que espelha a política."`
	Secret  secretCmd  `cmd:"" help:"Grava ou remove a senha no keychain do sistema."`
	Version versionCmd `cmd:"" help:"Versão do Crivo e do parser."`
}

// Main roda o modo ferramenta.
func Main(args []string) int {
	root := &rootCmd{}
	parser, err := kong.New(root,
		kong.Name("crivo"),
		kong.Description("Transforma um arquivo de política (.crivo) num CLI local e seguro de acesso a um Postgres de pré-produção."),
		kong.UsageOnError(),
		kong.Exit(func(int) {}),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return output.ExitBug
	}
	kctx, err := parser.Parse(args)
	if err != nil {
		for _, a := range args {
			if a == "-h" || a == "--help" {
				return output.ExitOK
			}
		}
		if len(args) == 0 {
			return output.ExitOK
		}
		fmt.Fprintf(os.Stderr, "crivo: %v\n", err)
		return output.ExitConfig
	}
	if kctx.Command() == "" {
		return output.ExitOK
	}
	e := &env{stdout: os.Stdout, stderr: os.Stderr}
	err = kctx.Run(e)
	return cli.Report(os.Stderr, nil, err, false)
}

func loadPolicy(path string) (*policy.Policy, policy.Diags, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, &cli.ConfigError{Msg: err.Error()}
	}
	p, diags := policy.Parse(filepath.Base(path), string(src))
	if !diags.HasErrors() {
		diags = append(diags, sqlguard.CheckPolicy(p)...)
		diags.Sort()
	}
	return p, diags, nil
}

func printDiags(w io.Writer, ds policy.Diags) {
	for _, d := range ds {
		fmt.Fprintln(w, d.String())
	}
}

// ---------- check ----------

type schemaFlags struct {
	Offline bool `help:"Não conecta ao banco: usa só o cache de schema, se existir."`
	Refresh bool `help:"Ignora o cache e lê o catálogo do banco."`
}

type checkCmd struct {
	File string `arg:"" type:"existingfile" help:"Arquivo .crivo."`
	schemaFlags
}

// checkResult é o resultado de um check completo.
type checkResult struct {
	p      *policy.Policy
	diags  policy.Diags
	schema *schema.Schema
	note   string
}

func runCheck(path string, f schemaFlags, stderr io.Writer) (*checkResult, error) {
	p, diags, err := loadPolicy(path)
	if err != nil {
		return nil, err
	}
	res := &checkResult{p: p, diags: diags}
	if diags.HasErrors() {
		return res, nil
	}
	sess := cli.NewSession(p, stderr)
	defer sess.Close()
	mode := cli.SchemaAnyCache
	if f.Refresh {
		mode = cli.SchemaRefresh
	}
	var sc *schema.Schema
	if f.Offline {
		cached, _, cerr := schema.LoadCache(p.Name, schema.SourceKey(p.Connect, p.Schemas()))
		if cerr != nil {
			res.note = "schema não conferido (--offline e sem cache)"
			return res, nil
		}
		sc = cached
		res.note = "schema conferido pelo cache"
	} else {
		sc, err = sess.LoadSchema(mode)
		if err != nil {
			res.note = "schema não conferido: " + oneLine(err.Error())
			return res, nil
		}
		switch {
		case sess.SchemaFromDB:
			res.note = "schema conferido no banco"
		case sess.SchemaStale:
			res.note = "schema conferido pelo cache (vencido; use --refresh para reler)"
		default:
			res.note = "schema conferido pelo cache"
		}
	}
	res.schema = sc
	res.diags = append(res.diags, schemaChecks(p, sc)...)
	if sess.SchemaFromDB {
		res.diags = append(res.diags, privilegeChecks(sess, p, sc)...)
	}
	res.diags.Sort()
	return res, nil
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func (c *checkCmd) Run(e *env) error {
	res, err := runCheck(c.File, c.schemaFlags, e.stderr)
	if err != nil {
		return err
	}
	printDiags(e.stdout, res.diags)
	if res.diags.HasErrors() {
		fmt.Fprintf(e.stdout, "✗ %s: %d erro(s)\n", res.p.File, len(res.diags.Errors()))
		return &cli.ExitError{Code: output.ExitConfig}
	}
	fmt.Fprintf(e.stdout, "✓ %s: política %s, %d regras; %s\n", res.p.File, res.p.Name, len(res.p.Rules), res.note)
	return nil
}

func schemaChecks(p *policy.Policy, sc *schema.Schema) policy.Diags {
	var ds policy.Diags
	errf := func(pos policy.Pos, sev policy.Severity, format string, args ...any) {
		ds = append(ds, policy.Diag{File: p.File, Pos: pos, Severity: sev, Msg: fmt.Sprintf(format, args...)})
	}
	covered := map[string]bool{}
	for _, r := range p.Rules {
		sch := p.SchemaOf(r)
		tables := p.MatchingTables(r, sch, sc.TableNames(sch))
		if !r.IsPattern() && sc.Table(sch, r.Pattern) == nil {
			errf(r.Pos, policy.SevError, "tabela %q não existe no banco (schema %s)", r.Pattern, sch)
			continue
		}
		if r.IsPattern() && len(tables) == 0 {
			errf(r.Pos, policy.SevWarning, "o padrão %s não cobre nenhuma tabela do banco", r.Label())
		}
		sev := policy.SevError
		if r.IsPattern() {
			sev = policy.SevWarning
		}
		for _, tname := range tables {
			covered[sch+"."+tname] = true
			t := sc.Table(sch, tname)
			for _, a := range r.Actions {
				for _, c := range a.Cols {
					if t.Column(c) == nil {
						errf(a.Pos, sev, "coluna %q não existe em %s", c, tname)
					}
				}
				for _, m := range a.Masks {
					if t.Column(m.Column) == nil {
						errf(m.Pos, sev, "coluna mascarada %q não existe em %s", m.Column, tname)
					}
				}
				for _, c := range sqlguard.FilterColumns(a.Where) {
					if t.Column(c) == nil {
						errf(a.WherePos, sev, "o where cita a coluna %q, que não existe em %s", c, tname)
					}
				}
				if a.Verb == policy.Read && len(a.AllowedCols(t.ColumnNames())) == 0 {
					errf(a.Pos, sev, "read em %s não libera nenhuma coluna", tname)
				}
			}
		}
	}
	var hidden int
	for k := range sc.Tables {
		if !covered[k] {
			hidden++
		}
	}
	if hidden > 0 {
		errf(policy.Pos{}, policy.SevWarning, "%d tabela(s) do banco sem regra: invisíveis para a IA (deny por padrão)", hidden)
	}
	return ds
}

const privilegesQuery = `
SELECT n.nspname, c.relname,
       has_any_column_privilege(c.oid, 'INSERT'), has_any_column_privilege(c.oid, 'UPDATE'),
       has_table_privilege(c.oid, 'DELETE'), has_table_privilege(c.oid, 'TRUNCATE'),
       pg_has_role(c.relowner, 'USAGE')
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'p')
ORDER BY 1, 2`

// privilegeChecks compara os privilégios do usuário de conexão com a
// política e avisa quando o banco permite mais do que a política.
func privilegeChecks(sess *cli.Session, p *policy.Policy, sc *schema.Schema) policy.Diags {
	conn, err := sess.Conn()
	if err != nil {
		return nil
	}
	ctx := sess.Ctx()
	var ds policy.Diags
	warn := func(format string, args ...any) {
		ds = append(ds, policy.Diag{File: p.File, Severity: policy.SevWarning, Msg: fmt.Sprintf(format, args...)})
	}
	var user string
	var super, bypass bool
	if err := conn.QueryRow(ctx, `SELECT current_user, rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&user, &super, &bypass); err != nil {
		return nil
	}
	if super {
		warn("o usuário %s é superuser: se algo passar pelo Crivo, o banco não segura nada. Use um usuário de privilégio mínimo (crivo grants %s)", user, p.File)
		return ds
	}
	if bypass {
		warn("o usuário %s tem BYPASSRLS: as políticas de RLS sugeridas pelo crivo grants não valem para ele; os filtros where ficam só por conta do Crivo", user)
	}
	rows, err := conn.Query(ctx, privilegesQuery, p.Schemas())
	if err != nil {
		return nil
	}
	defer rows.Close()
	var excess []string
	owner := 0
	for rows.Next() {
		var sch, tbl string
		var ins, upd, del, trunc, own bool
		if err := rows.Scan(&sch, &tbl, &ins, &upd, &del, &trunc, &own); err != nil {
			return nil
		}
		r := p.Resolve(sch, tbl)
		allowed := func(v policy.Verb) bool { return r != nil && r.Action(v) != nil }
		var extra []string
		if ins && !allowed(policy.Insert) {
			extra = append(extra, "INSERT")
		}
		if upd && !allowed(policy.Update) {
			extra = append(extra, "UPDATE")
		}
		if del && !allowed(policy.Delete) {
			extra = append(extra, "DELETE")
		}
		if trunc {
			extra = append(extra, "TRUNCATE")
		}
		if own {
			owner++
		}
		if len(extra) > 0 {
			name := tbl
			if sch != p.Schema {
				name = sch + "." + tbl
			}
			excess = append(excess, name+" ("+strings.Join(extra, ", ")+")")
		}
	}
	if owner > 0 {
		warn("o usuário %s é dono de %d tabela(s): donos ignoram GRANT e podem alterar o schema. Prefira um usuário só de acesso (crivo grants %s)", user, owner, p.File)
	}
	if len(excess) > 0 {
		shown := excess
		if len(shown) > 5 {
			shown = append(shown[:5:5], fmt.Sprintf("e mais %d", len(excess)-5))
		}
		warn("o usuário %s pode escrever além da política em %d tabela(s): %s. O Crivo barra, mas com privilégio mínimo o banco vira a segunda camada (crivo grants %s)",
			user, len(excess), strings.Join(shown, "; "), p.File)
	}
	return ds
}

// ---------- test ----------

type testCmd struct {
	File    string `arg:"" type:"existingfile" help:"Arquivo .crivo."`
	SQL     string `arg:"" optional:"" help:"SQL a validar."`
	SQLFile string `short:"f" name:"sql-file" type:"existingfile" help:"Arquivo com vários casos separados por ';'. Um comentário '-- espera: aceito|barrado' antes do statement define o esperado."`
	As      string `enum:"auto,query,exec" default:"auto" help:"Simula o comando: query, exec ou auto (pelo tipo do statement)."`
	schemaFlags
}

var expectRe = regexp.MustCompile(`(?m)^\s*--\s*espera:\s*(aceito|barrado)\b`)

func (c *testCmd) Run(e *env) error {
	p, diags, err := loadPolicy(c.File)
	if err != nil {
		return err
	}
	if diags.HasErrors() {
		printDiags(e.stdout, diags)
		return &cli.ExitError{Code: output.ExitConfig}
	}
	var sc *schema.Schema
	if c.Offline {
		cached, _, cerr := schema.LoadCache(p.Name, schema.SourceKey(p.Connect, p.Schemas()))
		if cerr != nil {
			return &cli.ConfigError{Msg: "sem cache de schema para testar offline; rode crivo check " + c.File + " com acesso ao banco"}
		}
		sc = cached
	} else {
		sess := cli.NewSession(p, e.stderr)
		defer sess.Close()
		mode := cli.SchemaAnyCache
		if c.Refresh {
			mode = cli.SchemaRefresh
		}
		if sc, err = sess.LoadSchema(mode); err != nil {
			return err
		}
	}
	g, err := sqlguard.New(p, sc)
	if err != nil {
		return &cli.ConfigError{Msg: err.Error()}
	}
	cmd := map[string]sqlguard.Command{"auto": sqlguard.CmdAny, "query": sqlguard.CmdQuery, "exec": sqlguard.CmdExec}[c.As]

	if c.SQLFile == "" {
		sql, err := cli.ReadSQL(c.SQL, "")
		if err != nil {
			return err
		}
		return testOne(e.stdout, p, g, cmd, sql)
	}
	if c.SQL != "" {
		return &cli.ConfigError{Msg: "use o SQL no argumento ou -f, não os dois"}
	}
	data, err := os.ReadFile(c.SQLFile)
	if err != nil {
		return &cli.ConfigError{Msg: err.Error()}
	}
	stmts, err := pg_query.SplitWithScanner(string(data), true)
	if err != nil {
		return &sqlguard.ParseError{Message: err.Error()}
	}
	var total, mismatch, denied int
	for _, s := range stmts {
		expect := ""
		if m := expectRe.FindStringSubmatch(s); m != nil {
			expect = m[1]
		}
		body := strings.TrimSpace(stripComments(s))
		if body == "" {
			continue
		}
		total++
		fmt.Fprintf(e.stdout, "-- caso %d: %s\n", total, oneLine(body))
		err := testOne(e.stdout, p, g, cmd, body)
		got := "aceito"
		if err != nil {
			got = "barrado"
			denied++
		}
		if expect != "" && expect != got {
			mismatch++
			fmt.Fprintf(e.stdout, "  ✗ esperava %s\n", expect)
		}
		fmt.Fprintln(e.stdout)
	}
	fmt.Fprintf(e.stdout, "-- %d casos: %d aceitos, %d barrados", total, total-denied, denied)
	if expectRe.Match(data) {
		fmt.Fprintf(e.stdout, ", %d fora do esperado", mismatch)
		fmt.Fprintln(e.stdout)
		if mismatch > 0 {
			return &cli.ExitError{Code: output.ExitDenied}
		}
		return nil
	}
	fmt.Fprintln(e.stdout)
	if denied > 0 {
		return &cli.ExitError{Code: output.ExitDenied}
	}
	return nil
}

func stripComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "--") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func actionFor(r *policy.Rule, v policy.Verb) string {
	if a := r.Action(v); a != nil {
		return a.String()
	}
	return string(v)
}

func testOne(w io.Writer, p *policy.Policy, g *sqlguard.Guard, cmd sqlguard.Command, sql string) error {
	v, err := g.Check(cmd, sql)
	if err != nil {
		var d *sqlguard.Denial
		var pe *sqlguard.ParseError
		switch {
		case errors.As(err, &d):
			fmt.Fprintln(w, "✗ barrado")
			if d.Rule != nil {
				fmt.Fprintf(w, "  regra   %s   (%s)\n", cli.RuleText(d.Rule), p.RuleRef(d.Rule))
			}
			fmt.Fprintf(w, "  motivo  %s\n", d.Reason)
			if d.Accepted != "" {
				fmt.Fprintf(w, "  aceito  %s\n", d.Accepted)
			}
			return &cli.ExitError{Code: output.ExitDenied}
		case errors.As(err, &pe):
			fmt.Fprintln(w, "✗ SQL inválido")
			fmt.Fprintf(w, "  motivo  %s\n", pe.Message)
			return &cli.ExitError{Code: output.ExitParse}
		}
		return err
	}
	fmt.Fprintln(w, "✓ aceito")
	width := 0
	names := make([]string, len(v.Rules))
	for i, u := range v.Rules {
		names[i] = strings.TrimPrefix(u.Name, p.Schema+".")
		if len(names[i]) > width {
			width = len(names[i])
		}
	}
	for i, u := range v.Rules {
		label := "         "
		if i == 0 {
			label = "  regras "
		}
		fmt.Fprintf(w, "%s  %-*s  %s   (%s)\n", label, width, names[i], actionFor(u.Rule, u.Verb), p.RuleRef(u.Rule))
	}
	for i, m := range v.Masks {
		label := "         "
		if i == 0 {
			label = "  máscara"
		}
		fmt.Fprintf(w, "%s  %s → %s (%s)\n", label, m.Label, m.Mode, m.Column)
	}
	switch {
	case v.Kind == sqlguard.KindSelect && v.CapByRequest:
		fmt.Fprintf(w, "  teto     %d linhas (LIMIT da query)\n", v.Cap)
	case v.Kind == sqlguard.KindSelect:
		fmt.Fprintf(w, "  teto     %d linhas (política)\n", v.Cap)
	default:
		fmt.Fprintf(w, "  teto     %d linhas afetadas (%s)\n", v.MaxRows, v.Target.Name)
	}
	fmt.Fprintf(w, "  sql      %s\n", v.SQL)
	return nil
}

// ---------- build ----------

type buildCmd struct {
	File      string `arg:"" type:"existingfile" help:"Arquivo .crivo."`
	Output    string `short:"o" help:"Caminho do binário gerado (padrão: ./<name>)."`
	AllowProd bool   `name:"allow-prod" help:"Permite env prod (não recomendado)."`
	schemaFlags
}

func (c *buildCmd) Run(e *env) error {
	res, err := runCheck(c.File, c.schemaFlags, e.stderr)
	if err != nil {
		return err
	}
	printDiags(e.stdout, res.diags)
	if res.diags.HasErrors() {
		fmt.Fprintf(e.stdout, "✗ check falhou; binário não gerado\n")
		return &cli.ExitError{Code: output.ExitConfig}
	}
	p := res.p
	if p.Env == "prod" {
		if !c.AllowProd {
			return &cli.ConfigError{Msg: "env prod: o Crivo protege contra a IA, não contra quem tem acesso à máquina. Use --allow-prod se tiver certeza"}
		}
		fmt.Fprintln(e.stderr, "aviso: gerando binário para env prod. Nunca use credencial de produção com permissões amplas.")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	exe, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	src, err := os.ReadFile(c.File)
	if err != nil {
		return err
	}
	patched, err := slot.Patch(exe, src)
	if err != nil {
		return &cli.ConfigError{Msg: err.Error()}
	}
	out := c.Output
	if out == "" {
		out = "./" + p.Name
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(out), ".exe") {
		out += ".exe"
	}
	absOut, _ := filepath.Abs(out)
	if absOut == self {
		return &cli.ConfigError{Msg: "a saída não pode sobrescrever o próprio crivo"}
	}
	tmp, err := os.CreateTemp(filepath.Dir(absOut), ".crivo-build-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(patched); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("codesign", "--force", "--sign", "-", tmpName)
		if msg, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("codesign falhou: %v: %s", err, strings.TrimSpace(string(msg)))
		}
	}
	if err := os.Rename(tmpName, absOut); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "✓ %s (política %s, %d bytes; %s)\n", out, p.File, len(src), res.note)
	fmt.Fprintf(e.stdout, "  próximos passos:\n")
	if p.Secret == policy.SecretKeychain {
		fmt.Fprintf(e.stdout, "    crivo secret set %s     # se ainda não gravou a senha\n", p.Name)
	}
	fmt.Fprintf(e.stdout, "    %s skill install           # instala a skill no workspace\n", out)
	fmt.Fprintf(e.stdout, "    %s skill vscode            # trecho de auto-approve do settings.json\n", out)
	return nil
}

// ---------- secret ----------

type secretCmd struct {
	Set secretSetCmd `cmd:"" help:"Pede a senha (input oculto) e grava no keychain."`
	Rm  secretRmCmd  `cmd:"" help:"Remove a senha do keychain."`
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

type secretSetCmd struct {
	Name  string `arg:"" help:"Nome da política (diretiva name)."`
	Stdin bool   `help:"Lê a senha da primeira linha do stdin em vez de perguntar."`
}

func (c *secretSetCmd) Run(e *env) error {
	if !nameRe.MatchString(c.Name) {
		return &cli.ConfigError{Msg: fmt.Sprintf("nome inválido %q: use o valor da diretiva name", c.Name)}
	}
	var pw string
	if c.Stdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return &cli.ConfigError{Msg: "stdin vazio"}
		}
		pw = strings.TrimRight(line, "\r\n")
	} else {
		var err error
		if pw, err = secret.Prompt("senha de " + c.Name + ": "); err != nil {
			return err
		}
		again, err := secret.Prompt("confirme: ")
		if err != nil {
			return err
		}
		if again != pw {
			return &cli.ConfigError{Msg: "as senhas não conferem"}
		}
	}
	if pw == "" {
		return &cli.ConfigError{Msg: "senha vazia"}
	}
	if err := secret.Set(c.Name, pw); err != nil {
		return &cli.ConfigError{Msg: fmt.Sprintf("keychain: %v", err)}
	}
	fmt.Fprintf(e.stdout, "✓ senha de %s gravada no keychain (serviço %s, conta %s)\n", c.Name, secret.Service, c.Name)
	return nil
}

type secretRmCmd struct {
	Name string `arg:"" help:"Nome da política."`
}

func (c *secretRmCmd) Run(e *env) error {
	if err := secret.Remove(c.Name); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "✓ senha de %s removida do keychain\n", c.Name)
	return nil
}

// ---------- version ----------

type versionCmd struct{}

func (c *versionCmd) Run(e *env) error {
	fmt.Fprintf(e.stdout, "crivo %s (parser PostgreSQL %s via pg_query_go v6; %s/%s)\n", cli.Version, cli.ParserVersion(), runtime.GOOS, runtime.GOARCH)
	return nil
}

// ---------- init ----------

type initCmd struct {
	URL    string `arg:"" help:"URL do banco (postgres://usuario@host:5432/banco). A senha pode vir na URL, em PGPASSWORD ou no prompt; ela não vai para o arquivo."`
	Output string `short:"o" help:"Arquivo de saída (padrão: <banco>.crivo)."`
	Schema string `default:"public" help:"Schema a introspectar."`
	Force  bool   `help:"Sobrescreve o arquivo de saída."`
}

func (c *initCmd) Run(e *env) error {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return &cli.ConfigError{Msg: "URL inválida: use postgres://usuario@host:5432/banco"}
	}
	var pw string
	fromArg := false
	if u.User != nil {
		pw, _ = u.User.Password()
		u.User = url.User(u.User.Username())
	}
	q := u.Query()
	if q.Has("password") {
		pw = q.Get("password")
		q.Del("password")
		u.RawQuery = q.Encode()
	}
	if pw != "" {
		fromArg = true
	}
	mode := q.Get("sslmode")
	local := policy.IsLocalHost(u.Hostname())
	if mode == "" {
		// o arquivo gerado nasce com TLS validado; a URL do argumento só serve para esta conexão
		q.Set("sslmode", "verify-full")
		u.RawQuery = q.Encode()
	}
	clean := u.String()
	if fromArg {
		fmt.Fprintln(e.stderr, "aviso: a senha veio no argumento e ficou no histórico do shell; prefira PGPASSWORD ou o prompt")
	}
	if !local && !policy.TLSVerified(mode) {
		shown := mode
		if shown == "" {
			shown = "(ausente)"
		}
		fmt.Fprintf(e.stderr, "aviso: esta conexão do init usa sslmode=%s; o arquivo gerado usa verify-full (ajuste sslrootcert=... se a CA for interna)\n", shown)
	}
	if pw == "" {
		pw = os.Getenv("PGPASSWORD")
	}
	if pw == "" && term.IsTerminal(int(os.Stdin.Fd())) {
		pw, _ = secret.Prompt("senha (enter para nenhuma): ")
	}
	db := strings.Trim(u.Path, "/")
	name := sanitizeName(db)
	ctx, cancel := run.Context(&policy.Policy{Timeout: policy.DefaultTimeout})
	defer cancel()
	conn, err := run.Connect(ctx, clean, name, pw)
	if err != nil {
		return err
	}
	defer conn.Close(ctx) //nolint:errcheck
	sc, err := schema.Fetch(ctx, conn, []string{c.Schema})
	if err != nil {
		return &run.DBError{Err: err}
	}
	text := initText(name, clean, c.Schema, sc)
	out := c.Output
	if out == "" {
		out = name + ".crivo"
	}
	if _, err := os.Stat(out); err == nil && !c.Force {
		return &cli.ConfigError{Msg: out + " já existe; use --force para sobrescrever"}
	}
	if err := os.WriteFile(out, []byte(text), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "✓ %s: %d tabelas, todas negadas\n", out, len(sc.Tables))
	fmt.Fprintf(e.stdout, "  edite as regras e rode: crivo check %s\n", out)
	return nil
}

func sanitizeName(db string) string {
	s := strings.ToLower(db)
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		s = "base-" + s
	}
	if len(s) > 58 {
		s = strings.TrimRight(s[:58], "-")
	}
	return s
}

func initText(name, connect, sch string, sc *schema.Schema) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("# %s.crivo, gerado por crivo init\n", name)
	w("# Edite as regras e depois rode: crivo check %s.crivo && crivo test %s.crivo \"SELECT ...\"\n\n", name, name)
	w("name    %s\n", name)
	w("about   \"TODO: descreva a base em uma frase\"\n")
	w("env     preprod\n\n")
	w("connect %s\n", connect)
	w("secret  keychain\n")
	w("schema  %s\n\n", sch)
	w("limit   500 rows\n")
	w("timeout 5s\n\n")
	w("# Tudo começa negado (o que não tem regra não existe para a IA).\n")
	w("# Para liberar, tire o \"#\" e troque deny pelas ações, por exemplo:\n")
	w("#   read, update(status) max 20\n")
	w("#   read except(cpf) mask(email: partial)\n")
	w("#   read where status <> 'cancelado'\n")
	names := sc.TableNames(sch)
	sort.Strings(names)
	width := 0
	for _, n := range names {
		if len(n) > width {
			width = len(n)
		}
	}
	for _, n := range names {
		t := sc.Table(sch, n)
		w("\n#   colunas: %s\n", strings.Join(t.ColumnNames(), ", "))
		if t.Comment != "" {
			w("## %s\n", oneLine(t.Comment))
		}
		w("# %-*s  deny\n", width, n)
	}
	return b.String()
}

// ---------- grants ----------

type grantsCmd struct {
	File string `arg:"" type:"existingfile" help:"Arquivo .crivo."`
	Role string `help:"Nome do papel (padrão: crivo_<name>)."`
	schemaFlags
}

func ident(s string) string {
	if regexp.MustCompile(`^[a-z_][a-z0-9_]*$`).MatchString(s) {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func (c *grantsCmd) Run(e *env) error {
	res, err := runCheck(c.File, c.schemaFlags, e.stderr)
	if err != nil {
		return err
	}
	if res.diags.HasErrors() {
		printDiags(e.stderr, res.diags)
		return &cli.ExitError{Code: output.ExitConfig}
	}
	if res.schema == nil {
		return &cli.ConfigError{Msg: "grants precisa do schema: " + res.note}
	}
	p, sc := res.p, res.schema
	role := c.Role
	if role == "" {
		role = "crivo_" + strings.ReplaceAll(p.Name, "-", "_")
	}
	u, _ := url.Parse(p.Connect)
	db := strings.Trim(u.Path, "/")
	w := func(format string, args ...any) { fmt.Fprintf(e.stdout, format, args...) }
	w("-- Usuário de privilégio mínimo para a política %s (gerado por crivo grants; revise antes de rodar).\n", p.Name)
	w("-- Com ele, a política vira a segunda camada: o que escapar do Crivo o banco recusa.\n")
	w("-- Depois troque o usuário em connect e grave a senha: crivo secret set %s\n\n", p.Name)
	w("CREATE ROLE %s LOGIN PASSWORD 'troque-esta-senha';\n", ident(role))
	w("GRANT CONNECT ON DATABASE %s TO %s;\n", ident(db), ident(role))
	for _, s := range p.Schemas() {
		w("GRANT USAGE ON SCHEMA %s TO %s;\n", ident(s), ident(role))
	}
	writes := false
	var rls []string
	for _, r := range p.Rules {
		if r.Deny {
			continue
		}
		sch := p.SchemaOf(r)
		for _, tname := range p.MatchingTables(r, sch, sc.TableNames(sch)) {
			t := sc.Table(sch, tname)
			rel := ident(sch) + "." + ident(tname)
			w("\n-- %s (policy %s)\n", tname, p.RuleRef(r))
			for _, a := range r.Actions {
				priv := map[policy.Verb]string{policy.Read: "SELECT", policy.Insert: "INSERT", policy.Update: "UPDATE", policy.Delete: "DELETE"}[a.Verb]
				if a.Verb.IsWrite() {
					writes = true
				}
				cols := ""
				if a.Cols != nil && a.Verb != policy.Delete {
					allowed := a.AllowedCols(t.ColumnNames())
					if a.Verb == policy.Read {
						// o filtro where precisa ler as colunas que cita
						for _, fc := range sqlguard.FilterColumns(a.Where) {
							if !contains(allowed, fc) && t.Column(fc) != nil {
								allowed = append(allowed, fc)
							}
						}
					}
					q := make([]string, len(allowed))
					for i, col := range allowed {
						q[i] = ident(col)
					}
					cols = " (" + strings.Join(q, ", ") + ")"
				}
				w("GRANT %s%s ON %s TO %s;\n", priv, cols, rel, ident(role))
				if a.Where != "" && (a.Verb == policy.Read || a.Verb == policy.Update || a.Verb == policy.Delete) {
					rls = append(rls, fmt.Sprintf("-- CREATE POLICY %s ON %s FOR %s TO %s USING (%s);",
						ident(role+"_"+string(a.Verb)), rel, priv, ident(role), a.Where))
				}
			}
			if r.Action(policy.Read) == nil && (r.Action(policy.Update) != nil || r.Action(policy.Delete) != nil) {
				w("-- atenção: UPDATE/DELETE com WHERE precisam de SELECT nas colunas do WHERE; a política exige read para isso.\n")
			}
		}
	}
	if writes {
		w("\n-- INSERT em colunas com default de sequência (serial/identity) precisa de USAGE na sequência:\n")
		for _, s := range p.Schemas() {
			w("-- GRANT USAGE ON ALL SEQUENCES IN SCHEMA %s TO %s;\n", ident(s), ident(role))
		}
	} else {
		w("\n-- A política não tem escrita: o usuário fica só leitura também no banco.\n")
		w("ALTER ROLE %s SET default_transaction_read_only = on;\n", ident(role))
	}
	if len(rls) > 0 {
		w("\n-- Filtros de linha (where) também podem virar Row Level Security (opcional; afeta o papel %s):\n", role)
		for _, s := range sortedUnique(rls) {
			w("%s\n", s)
		}
		w("-- e ALTER TABLE ... ENABLE ROW LEVEL SECURITY nas tabelas acima.\n")
	}
	w("\nALTER ROLE %s SET statement_timeout = '%dms';\n", ident(role), p.Timeout.Milliseconds())
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
