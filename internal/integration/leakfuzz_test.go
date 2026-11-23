package integration

// Leak fuzzer diferencial: gera SELECTs (e alguns exec) aleatórios mas
// reproduzíveis sobre um schema próprio (crivo_fz) cujos valores protegidos
// carregam tokens sentinela. Todo SQL que o guard aceita é executado como a
// base executaria (v.SQL, run.Query/run.Exec dry-run, máscaras de
// base.masked) e cada célula da saída e cada mensagem de erro do banco é
// varrida: um token que aparece onde não devia é vazamento.
//
//	CRIVO_TEST_LOCALPG=1 go test -count=1 -run LeakFuzz -v ./internal/integration/
//
// Controles: CRIVO_LEAKFUZZ_N (iterações, padrão 300), CRIVO_LEAKFUZZ_SEED
// (padrão: hora), CRIVO_LEAKFUZZ_ONLY=i (só a iteração i da semente, para
// reproduzir) e CRIVO_LEAKFUZZ_VERBOSE=1 (loga cada statement e o desfecho).

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"crivo/internal/mask"
	"crivo/internal/policy"
	"crivo/internal/run"
	"crivo/internal/schema"
	"crivo/internal/sqlguard"
)

const fzSchema = "crivo_fz"

// ---------------------------------------------------------------------------
// fixture: schema, política e oráculo
// ---------------------------------------------------------------------------

type fzEnv struct {
	admin    string
	connect  string
	password string
	policy   *policy.Policy
	guard    *sqlguard.Guard
	conn     *pgx.Conn
	oracle   *fzOracle
}

func fzSetup(t *testing.T) *fzEnv {
	t.Helper()
	dsn := adminDSN(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("banco de teste indisponível: %v", err)
	}
	defer conn.Close(ctx)
	ddl, err := os.ReadFile("testdata/leakfuzz.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"DROP SCHEMA IF EXISTS " + fzSchema + " CASCADE",
		"CREATE SCHEMA " + fzSchema,
		"SET search_path = " + fzSchema,
		string(ddl),
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("preparando %s: %v", fzSchema, err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+fzSchema+" CASCADE")
			c.Close(context.Background())
		}
	})

	u, _ := url.Parse(dsn)
	pw, _ := u.User.Password()
	u.User = url.User(u.User.Username())
	src := fmt.Sprintf(`name    fz
about   "Base do leak fuzzer"
env     dev
connect %s
secret  env:CRIVO_FZ_PW
schema  %s
limit   25 rows
timeout 2s

pedidos     read, update(status, observacao) max 2
itens       read, insert, delete max 3
clientes    read except(cpf) mask(email: partial, telefone: redact, nome: hash)
pagamentos  read where status <> 'estornado', update(status) max 2
contatos    read except(documento) mask(apelido: hash, telefone: partial) where lower(status) <> 'inativo', update(status) max 2
audit_*     deny
`, u.String(), fzSchema)
	p, diags := policy.Parse("fz", src)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	e := &fzEnv{admin: dsn, connect: u.String(), password: pw, policy: p}
	e.reconnect(t)
	t.Cleanup(func() {
		if e.conn != nil {
			e.conn.Close(context.Background())
		}
	})
	sc, err := schema.Fetch(ctx, e.conn, p.Schemas())
	if err != nil {
		t.Fatal(err)
	}
	if e.guard, err = sqlguard.New(p, sc); err != nil {
		t.Fatal(err)
	}
	e.oracle = fzBuildOracle(t, dsn)
	return e
}

func (e *fzEnv) reconnect(t *testing.T) {
	t.Helper()
	if e.conn != nil {
		e.conn.Close(context.Background())
	}
	c, err := run.Connect(context.Background(), e.connect, e.policy.Name, e.password)
	if err != nil {
		t.Fatal(err)
	}
	e.conn = c
}

// fzToken é um token sentinela e o que ele protege.
type fzToken struct {
	token     string
	column    string          // tabela.coluna de origem
	forbidden bool            // nunca pode chegar à saída, nem mascarado
	mode      policy.MaskMode // máscara esperada (colunas mascaradas)
}

type fzOracle struct {
	windows map[string]*fzToken // trechos de 6 caracteres → token
	exact   map[string]bool     // valores originais das colunas mascaradas
	numeric []*regexp.Regexp    // ids e valores das linhas escondidas
	numText []string
}

var fzQuoted = regexp.MustCompile(`"[^"]*"|\d+`)

var fzTokenRE = regexp.MustCompile(`zq[a-z][0-9]{2}kw[a-z]`)

const fzWindow = 6

// fzBuildOracle lê do banco (como admin) os valores protegidos e confere que
// nenhum valor liberado contém um token.
func fzBuildOracle(t *testing.T, dsn string) *fzOracle {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	o := &fzOracle{windows: map[string]*fzToken{}, exact: map[string]bool{}}
	add := func(val, column string, forbidden bool, mode policy.MaskMode) {
		for _, tok := range fzTokenRE.FindAllString(strings.ToLower(val), -1) {
			tk := &fzToken{token: tok, column: column, forbidden: forbidden, mode: mode}
			for i := 0; i+fzWindow <= len(tok); i++ {
				o.windows[tok[i:i+fzWindow]] = tk
			}
			// "zq" + tipo + 1º dígito: pega trechos curtos (ex.: um erro
			// que cita só 4 caracteres do valor)
			if _, ok := o.windows[tok[:4]]; !ok {
				o.windows[tok[:4]] = &fzToken{token: tok[:4] + "…", column: column, forbidden: forbidden, mode: mode}
			}
		}
		if !forbidden {
			o.exact[val] = true
		}
	}
	type q struct {
		sql       string
		column    string
		forbidden bool
		mode      policy.MaskMode
	}
	hiddenPag := "status = 'estornado'"
	hiddenCon := "lower(status) = 'inativo'"
	for _, x := range []q{
		{"SELECT cpf FROM clientes", "clientes.cpf", true, ""},
		{"SELECT email FROM clientes", "clientes.email", false, policy.MaskPartial},
		{"SELECT telefone FROM clientes", "clientes.telefone", false, policy.MaskRedact},
		{"SELECT nome FROM clientes", "clientes.nome", false, policy.MaskHash},
		{"SELECT documento FROM contatos", "contatos.documento", true, ""},
		{"SELECT apelido FROM contatos WHERE NOT (" + hiddenCon + ")", "contatos.apelido", false, policy.MaskHash},
		{"SELECT telefone FROM contatos WHERE NOT (" + hiddenCon + ")", "contatos.telefone", false, policy.MaskPartial},
		{"SELECT concat_ws(' ', id, cliente_id, apelido, telefone, status, obs) FROM contatos WHERE " + hiddenCon, "contatos(linha escondida)", true, ""},
		{"SELECT concat_ws(' ', id, pedido_id, valor, status, ref) FROM pagamentos WHERE " + hiddenPag, "pagamentos(linha escondida)", true, ""},
		{"SELECT concat_ws(' ', id, actor, detalhe) FROM audit_log", "audit_log", true, ""},
		{"SELECT concat_ws(' ', id, texto) FROM notas", "notas", true, ""},
	} {
		vals := fzAdminStrings(t, conn, x.sql)
		for _, v := range vals {
			add(v, x.column, x.forbidden, x.mode)
		}
	}
	// números que só as linhas escondidas têm
	for _, sql := range []string{
		"SELECT id::text FROM pagamentos WHERE " + hiddenPag,
		"SELECT trunc(valor)::text FROM pagamentos WHERE " + hiddenPag,
		"SELECT id::text FROM contatos WHERE " + hiddenCon,
	} {
		for _, v := range fzAdminStrings(t, conn, sql) {
			o.numText = append(o.numText, v)
			// fronteira alfanumérica: "h:e97102" (hash) não é o id 97102
			o.numeric = append(o.numeric, regexp.MustCompile(`(^|[^0-9A-Za-z])`+regexp.QuoteMeta(v)+`([^0-9A-Za-z]|$)`))
		}
	}
	if len(o.windows) < 50 || len(o.numeric) < 6 {
		t.Fatalf("oráculo sem sentinelas suficientes: %d trechos, %d números", len(o.windows), len(o.numeric))
	}
	// nenhum valor liberado (colunas sem máscara, linhas visíveis) pode
	// conter um sentinela
	for _, sql := range []string{
		"SELECT concat_ws('|', id, cidade, criado_em) FROM clientes",
		"SELECT concat_ws('|', id, cliente_id, status, total, observacao) FROM pedidos",
		"SELECT concat_ws('|', id, pedido_id, produto, quantidade) FROM itens",
		"SELECT concat_ws('|', id, pedido_id, valor, status, ref) FROM pagamentos WHERE NOT (" + hiddenPag + ")",
		"SELECT concat_ws('|', id, cliente_id, status, obs) FROM contatos WHERE NOT (" + hiddenCon + ")",
	} {
		for _, v := range fzAdminStrings(t, conn, sql) {
			if hits := o.scanText(v); len(hits) > 0 {
				t.Fatalf("fixture inválida: valor liberado %q contém sentinela %s", v, hits[0])
			}
		}
	}
	return o
}

func fzAdminStrings(t *testing.T, conn *pgx.Conn, sql string) []string {
	t.Helper()
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "SET search_path = "+fzSchema); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.Query(ctx, sql)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s *string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		if s != nil {
			out = append(out, *s)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return out
}

// scanText devolve descrições dos sentinelas presentes no texto.
func (o *fzOracle) scanText(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, tk := range o.tokensIn(s) {
		if !seen[tk.token] {
			seen[tk.token] = true
			out = append(out, fmt.Sprintf("%s (%s)", tk.token, tk.column))
		}
	}
	for i, re := range o.numeric {
		if re.MatchString(s) {
			out = append(out, fmt.Sprintf("%s (número de linha escondida)", o.numText[i]))
		}
	}
	return out
}

// tokensIn devolve os tokens (por trecho) presentes no texto.
func (o *fzOracle) tokensIn(s string) []*fzToken {
	var out []*fzToken
	seen := map[*fzToken]bool{}
	low := strings.ToLower(s)
	for _, w := range []int{fzWindow, 4} {
		for i := 0; i+w <= len(low); i++ {
			if tk := o.windows[low[i:i+w]]; tk != nil && !seen[tk] {
				seen[tk] = true
				out = append(out, tk)
			}
		}
	}
	return out
}

var fzModeStrength = map[policy.MaskMode]int{policy.MaskPartial: 1, policy.MaskHash: 2, policy.MaskRedact: 3}

// fzFinding é um vazamento encontrado numa saída.
type fzFinding struct {
	class  string // assinatura curta para agrupar achados iguais
	detail string
}

// fzApplyMasks replica masked de internal/cli/base/base.go (sem pseudonym:
// a política do fuzzer usa só partial, redact e hash).
func fzApplyMasks(rows [][]*string, v *sqlguard.Verdict) {
	if len(v.Masks) == 0 {
		return
	}
	m := mask.New()
	for _, row := range rows {
		for _, om := range v.Masks {
			if om.Index < len(row) && row[om.Index] != nil {
				s := m.ApplyMask(om.Mask(), *row[om.Index])
				row[om.Index] = &s
			}
		}
	}
}

// check aplica as máscaras ao resultado (como a base) e varre as células.
func (o *fzOracle) check(res *run.Result, v *sqlguard.Verdict) []fzFinding {
	raw := make([][]*string, len(res.Rows))
	for i, row := range res.Rows {
		raw[i] = make([]*string, len(row))
		for j, c := range row {
			if c != nil {
				s := *c
				raw[i][j] = &s
			}
		}
	}
	fzApplyMasks(res.Rows, v)
	modes := map[int][]policy.MaskMode{}
	for _, om := range v.Masks {
		modes[om.Index] = append(modes[om.Index], om.Mode)
	}
	var out []fzFinding
	col := func(j int) string {
		if j < len(res.Columns) {
			return fmt.Sprintf("coluna %d %q", j, res.Columns[j])
		}
		return fmt.Sprintf("coluna %d", j)
	}
	for i, row := range res.Rows {
		for j, c := range row {
			if c != nil {
				if hits := o.scanText(*c); len(hits) > 0 {
					out = append(out, fzFinding{
						class:  "saida:" + fmt.Sprint(modes[j]) + ":" + strings.Join(fzKinds(hits), ","),
						detail: fmt.Sprintf("linha %d %s depois das máscaras %v = %q contém %s", i, col(j), modes[j], *c, strings.Join(hits, ", ")),
					})
					continue
				}
			}
			r := raw[i][j]
			if r == nil || len(modes[j]) == 0 {
				continue
			}
			// a célula saiu mascarada: o valor de origem precisa ser permitido
			for _, tk := range o.tokensIn(*r) {
				switch {
				case tk.forbidden:
					out = append(out, fzFinding{
						class:  "proibido-mascarado:" + tk.column,
						detail: fmt.Sprintf("linha %d %s: valor proibido %q (%s) chegou à saída, mascarado como %v → %q", i, col(j), *r, tk.column, modes[j], *c),
					})
				case !o.exact[*r]:
					out = append(out, fzFinding{
						class:  "transformado:" + tk.column,
						detail: fmt.Sprintf("linha %d %s: valor de %s transformado antes da máscara %v: %q → %q", i, col(j), tk.column, modes[j], *r, *c),
					})
				default:
					best := 0
					for _, m := range modes[j] {
						if fzModeStrength[m] > best {
							best = fzModeStrength[m]
						}
					}
					if best < fzModeStrength[tk.mode] {
						out = append(out, fzFinding{
							class:  "mascara-fraca:" + tk.column,
							detail: fmt.Sprintf("linha %d %s: %s (máscara %s) saiu com %v → %q", i, col(j), tk.column, tk.mode, modes[j], *c),
						})
					}
				}
			}
			for k, re := range o.numeric {
				if re.MatchString(*r) {
					out = append(out, fzFinding{
						class:  "proibido-mascarado:numero",
						detail: fmt.Sprintf("linha %d %s: número de linha escondida %s chegou à saída (mascarado %v)", i, col(j), o.numText[k], modes[j]),
					})
				}
			}
		}
	}
	return out
}

func fzKinds(hits []string) []string {
	var out []string
	for _, h := range hits {
		if i := strings.Index(h, "("); i >= 0 {
			out = append(out, strings.TrimSuffix(h[i+1:], ")"))
		}
	}
	sort.Strings(out)
	return out
}

// checkErr varre a mensagem de erro como a IA a recebe (run.SafeMessage, que
// cli.Report usa; Detail/Hint/Where não são mostrados).
func (o *fzOracle) checkErr(err error) []fzFinding {
	texts := []string{run.SafeMessage(err)}
	var out []fzFinding
	for _, s := range texts {
		if hits := o.scanText(s); len(hits) > 0 {
			out = append(out, fzFinding{
				class:  "erro-do-banco",
				detail: fmt.Sprintf("mensagem de erro do banco %q contém %s", s, strings.Join(hits, ", ")),
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// gerador
// ---------------------------------------------------------------------------

const (
	fzPlain   = iota // liberada sem máscara
	fzMasked         // partial/redact: só nua na saída
	fzHashed         // hash: nua na saída ou em GROUP BY/DISTINCT
	fzBlocked        // nunca
)

type fzCol struct {
	name string
	typ  string // int, num, text, date, bool, json
	cls  int
}

type fzRel struct {
	name string // alias usado para qualificar
	cols []fzCol
}

type fzCTE struct {
	name string
	cols []fzCol
}

var fzTableOrder = []string{"clientes", "pedidos", "itens", "pagamentos", "contatos", "audit_log", "notas"}

var fzTables = map[string][]fzCol{
	"clientes": {{"id", "int", fzPlain}, {"nome", "text", fzHashed}, {"cpf", "text", fzBlocked}, {"email", "text", fzMasked},
		{"telefone", "text", fzMasked}, {"cidade", "text", fzPlain}, {"criado_em", "date", fzPlain}},
	"pedidos":    {{"id", "int", fzPlain}, {"cliente_id", "int", fzPlain}, {"status", "text", fzPlain}, {"total", "num", fzPlain}, {"observacao", "text", fzPlain}},
	"itens":      {{"id", "int", fzPlain}, {"pedido_id", "int", fzPlain}, {"produto", "text", fzPlain}, {"quantidade", "int", fzPlain}},
	"pagamentos": {{"id", "int", fzPlain}, {"pedido_id", "int", fzPlain}, {"valor", "num", fzPlain}, {"status", "text", fzPlain}, {"ref", "text", fzPlain}},
	"contatos": {{"id", "int", fzPlain}, {"cliente_id", "int", fzPlain}, {"apelido", "text", fzHashed}, {"documento", "text", fzBlocked},
		{"telefone", "text", fzMasked}, {"status", "text", fzPlain}, {"obs", "text", fzPlain}},
	"audit_log": {{"id", "int", fzBlocked}, {"actor", "text", fzBlocked}, {"detalhe", "text", fzBlocked}},
	"notas":     {{"id", "int", fzBlocked}, {"texto", "text", fzBlocked}},
}

// fzWrappers imitam o filtro que o guard injeta (e variações).
var fzWrappers = map[string]string{
	"pagamentos": "SELECT id, pedido_id, valor, status, ref FROM %s WHERE status <> 'estornado' OFFSET 0",
	"contatos":   "SELECT id, cliente_id, apelido, telefone, status, obs FROM %s WHERE lower(status) <> 'inativo' OFFSET 0",
}

var fzNamePool = []string{"id", "email", "cidade", "nome", "status", "ref", "telefone", "apelido", "obs", "x", "y", "valor", "cpf", "total"}

type fzGen struct {
	r     *rand.Rand
	n     int
	ctes  []fzCTE
	depth int
	tags  map[string]bool
	bad   float64 // probabilidade de escolher algo fora da regra
}

func (g *fzGen) p(x float64) bool { return g.r.Float64() < x }
func (g *fzGen) intn(n int) int   { return g.r.Intn(n) }
func (g *fzGen) tag(s string)     { g.tags[s] = true }
func (g *fzGen) id(prefix string) string {
	g.n++
	return fmt.Sprintf("%s%d", prefix, g.n)
}
func fzPick[T any](g *fzGen, xs []T) T { return xs[g.r.Intn(len(xs))] }

// qcol é uma coluna qualificada escolhida no escopo.
type fzQCol struct {
	rel string
	col fzCol
}

func (q fzQCol) ref() string { return q.rel + "." + q.col.name }

const (
	ctxBare = iota
	ctxGeneral
	ctxGroup
)

func fzLegal(c fzCol, ctx int) bool {
	switch ctx {
	case ctxBare:
		return c.cls != fzBlocked
	case ctxGroup:
		return c.cls == fzPlain || c.cls == fzHashed
	}
	return c.cls == fzPlain
}

// col escolhe uma coluna do escopo; typ "" aceita qualquer tipo. Com
// probabilidade g.bad ignora a regra de contexto.
func (g *fzGen) col(rels []fzRel, ctx int, typ string) (fzQCol, bool) {
	var legal, all []fzQCol
	for _, r := range rels {
		for _, c := range r.cols {
			if c.name == "" || (typ != "" && c.typ != typ) {
				continue
			}
			q := fzQCol{r.name, c}
			all = append(all, q)
			if fzLegal(c, ctx) {
				legal = append(legal, q)
			}
		}
	}
	if len(all) == 0 {
		return fzQCol{}, false
	}
	if len(legal) == 0 || g.p(g.bad) {
		if len(legal) > 0 {
			g.tag("mischief-col")
		}
		return fzPick(g, all), true
	}
	// na saída, puxa para colunas mascaradas (o que interessa mover)
	if ctx == ctxBare && g.p(0.45) {
		var m []fzQCol
		for _, q := range legal {
			if q.col.cls != fzPlain {
				m = append(m, q)
			}
		}
		if len(m) > 0 {
			return fzPick(g, m), true
		}
	}
	return fzPick(g, legal), true
}

// colRef escreve a referência, às vezes sem qualificar (quando o nome é único).
func (g *fzGen) colRef(q fzQCol, rels []fzRel) string {
	if g.p(0.3) {
		n := 0
		for _, r := range rels {
			for _, c := range r.cols {
				if c.name == q.col.name {
					n++
				}
			}
		}
		if n == 1 || g.p(g.bad) {
			return q.col.name
		}
	}
	return q.ref()
}

func (g *fzGen) lit(typ string) string {
	switch typ {
	case "int":
		return strconv.Itoa(1 + g.intn(6))
	case "num":
		return fzPick(g, []string{"20.1", "10.5", "1"})
	case "date":
		return "'2024-03-01'"
	case "bool":
		return fzPick(g, []string{"true", "false"})
	}
	return fzPick(g, []string{"'pago'", "'aberto'", "'Recife'", "'x'", "'ativo'", "''"})
}

// expr gera uma expressão sobre uma coluna liberada; devolve o texto e o tipo.
func (g *fzGen) expr(rels []fzRel) (string, string) {
	q, ok := g.col(rels, ctxGeneral, "")
	if !ok {
		t := fzPick(g, []string{"int", "text"})
		return g.lit(t), t
	}
	x := g.colRef(q, rels)
	switch q.col.typ {
	case "int", "num":
		switch g.intn(9) {
		case 0:
			return x + " + 1", q.col.typ
		case 1:
			return x + " * 2", q.col.typ
		case 2:
			return "abs(" + x + ")", q.col.typ
		case 3:
			return "round(" + x + "::numeric, 1)", "num"
		case 4:
			return "mod(" + x + "::int, 3)", "int"
		case 5:
			return "greatest(" + x + ", 2)", q.col.typ
		case 6:
			return x + "::text", "text"
		case 7:
			return "coalesce(" + x + ", 0)", q.col.typ
		default:
			return "CASE WHEN " + x + " > 2 THEN 'alto' ELSE 'baixo' END", "text"
		}
	case "date":
		switch g.intn(4) {
		case 0:
			return "to_char(" + x + ", 'YYYY-MM')", "text"
		case 1:
			return "date_trunc('month', " + x + ")::date", "date"
		case 2:
			return "extract(year FROM " + x + ")", "num"
		default:
			return "date_part('day', " + x + ")", "num"
		}
	case "text":
		switch g.intn(15) {
		case 0:
			return "upper(" + x + ")", "text"
		case 1:
			return "lower(" + x + ")", "text"
		case 2:
			return "length(" + x + ")", "int"
		case 3:
			return "left(" + x + ", 3)", "text"
		case 4:
			return "substring(" + x + " FROM 2 FOR 4)", "text"
		case 5:
			return "replace(" + x + ", 'a', 'o')", "text"
		case 6:
			return "split_part(" + x + ", ' ', 1)", "text"
		case 7:
			return "lpad(" + x + ", 12, '.')", "text"
		case 8:
			return "concat(" + x + ", '-', " + g.lit("int") + ")", "text"
		case 9:
			return x + " || '!'", "text"
		case 10:
			return "coalesce(" + x + ", 'n/a')", "text"
		case 11:
			return "nullif(" + x + ", '')", "text"
		case 12:
			return "initcap(" + x + ")", "text"
		case 13:
			return "trim(" + x + ")", "text"
		default:
			return "CASE WHEN " + x + " IS NULL THEN '-' ELSE " + x + " END", "text"
		}
	}
	return x, q.col.typ
}

// pred gera um predicado; outer são escopos externos (correlação).
func (g *fzGen) pred(rels, outer []fzRel) string {
	all := append(append([]fzRel{}, rels...), outer...)
	switch g.intn(14) {
	case 0, 1, 2:
		if q, ok := g.col(rels, ctxGeneral, "int"); ok {
			x := g.colRef(q, rels)
			return fzPick(g, []string{x + " > " + g.lit("int"), x + " IN (1, 2, 3)", x + " BETWEEN 1 AND 4", x + " <> " + g.lit("int")})
		}
	case 3, 4:
		if q, ok := g.col(rels, ctxGeneral, "text"); ok {
			x := g.colRef(q, rels)
			return fzPick(g, []string{x + " LIKE 'p%'", x + " <> 'aberto'", x + " IS NOT NULL", "length(" + x + ") > 3", "upper(" + x + ") = 'PAGO'", x + " ILIKE '%a%'"})
		}
	case 5:
		g.tag("exists")
		sub, _ := g.selectStmt(all, fzSelOpts{anyTargets: true})
		return fzPick(g, []string{"EXISTS (", "NOT EXISTS ("}) + sub + ")"
	case 6:
		if q, ok := g.col(all, ctxGeneral, "int"); ok {
			g.tag("in-subquery")
			sub, _ := g.selectStmt(all, fzSelOpts{width: 1, types: []string{"int"}})
			return g.colRef(q, all) + fzPick(g, []string{" IN (", " NOT IN (", " = ANY ("}) + sub + ")"
		}
	case 7:
		if q, ok := g.col(rels, ctxGeneral, "int"); ok {
			g.tag("scalar-subquery")
			sub, _ := g.selectStmt(all, fzSelOpts{width: 1, types: []string{"int"}, scalar: true})
			return g.colRef(q, rels) + " <= (" + sub + ")"
		}
	case 8:
		a, okA := g.col(rels, ctxGeneral, "int")
		b, okB := g.col(rels, ctxGeneral, "text")
		if okA && okB {
			g.tag("row-compare")
			switch g.intn(3) {
			case 0:
				return "(" + a.ref() + ", " + b.ref() + ") = (1, 'pago')"
			case 1:
				return "ROW(" + a.ref() + ", " + b.ref() + ") IS NOT NULL"
			default:
				sub, _ := g.selectStmt(all, fzSelOpts{width: 2, types: []string{"int", "text"}})
				return "(" + a.ref() + ", " + b.ref() + ") IN (" + sub + ")"
			}
		}
	case 9:
		// sondas de erro: o cast falha numa linha que o filtro deveria esconder?
		if q, ok := g.col(rels, ctxGeneral, "text"); ok {
			g.tag("error-probe")
			x := g.colRef(q, rels)
			if g.p(0.4) {
				// seletiva: só as linhas de id alto (as escondidas) chegam ao cast
				if id, ok := g.col(rels, ctxGeneral, "int"); ok && id.rel == q.rel {
					g.tag("error-probe-selective")
					x = "CASE WHEN " + id.ref() + " > 6 THEN " + x + " ELSE '2024-01-01' END"
					if g.p(0.5) {
						return id.ref() + " > 6 AND " + fzPick(g, []string{q.ref() + "::int > 0", "to_date(" + q.ref() + ", 'Month') IS NULL", q.ref() + "::date IS NULL"})
					}
				}
			}
			return fzPick(g, []string{x + "::int > 0", x + "::int IS NULL", x + "::date IS NOT NULL", x + "::numeric = 1", "(" + x + ")::int4 <> 0",
				"to_date(" + x + ", 'Month') IS NULL", "to_date(" + x + ", 'YYYY-MM-DD') IS NOT NULL", "to_timestamp(" + x + ", 'Mon') < now()",
				"to_date(" + x + ", 'DD') = current_date", "make_date(2024, 1, " + x + "::int) IS NULL"})
		}
	case 10:
		e, t := g.expr(rels)
		return e + " = " + g.lit(t)
	case 11:
		if q, ok := g.col(rels, ctxGeneral, ""); ok {
			return g.colRef(q, rels) + fzPick(g, []string{" IS NULL", " IS NOT NULL"})
		}
	case 12:
		if len(outer) > 0 {
			if a, ok := g.col(rels, ctxGeneral, "int"); ok {
				if b, ok := g.col(outer, ctxGeneral, "int"); ok {
					g.tag("correlated")
					return a.ref() + " = " + b.ref()
				}
			}
		}
	}
	return fzPick(g, []string{"true", "1 = 1", "NOT false"})
}

type fzSelOpts struct {
	width      int      // número fixo de colunas (0: livre)
	types      []string // tipos pedidos por posição ("" ou ausente: qualquer)
	bare       bool     // colunas fixas podem sair nuas (lado de UNION)
	scalar     bool     // subquery escalar: uma linha
	anyTargets bool     // EXISTS: tanto faz a lista
	root       bool
	noSetOp    bool
}

// fzSel é um SELECT simples já com as partes em texto.
type fzSel struct {
	with, distinct, targets, from, where, group, having, window, order, limit string
	rels                                                                      []fzRel
	outer                                                                     []fzRel
	cols                                                                      []fzCol
}

func (s *fzSel) render() string {
	var b strings.Builder
	b.WriteString(s.with)
	b.WriteString("SELECT ")
	b.WriteString(s.distinct)
	b.WriteString(s.targets)
	if s.from != "" {
		b.WriteString(" FROM " + s.from)
	}
	if s.where != "" {
		b.WriteString(" WHERE " + s.where)
	}
	if s.group != "" {
		b.WriteString(" GROUP BY " + s.group)
	}
	if s.having != "" {
		b.WriteString(" HAVING " + s.having)
	}
	if s.window != "" {
		b.WriteString(" WINDOW " + s.window)
	}
	if s.order != "" {
		b.WriteString(" ORDER BY " + s.order)
	}
	if s.limit != "" {
		b.WriteString(" " + s.limit)
	}
	return b.String()
}

// selectStmt gera um SELECT (às vezes com operação de conjunto).
func (g *fzGen) selectStmt(outer []fzRel, o fzSelOpts) (string, []fzCol) {
	g.depth++
	defer func() { g.depth-- }()
	savedCTEs := len(g.ctes)
	defer func() { g.ctes = g.ctes[:savedCTEs] }()

	with := ""
	if (o.root && g.p(0.45)) || (!o.root && g.depth <= 3 && g.p(0.1)) {
		with = g.withClause(outer)
	}
	if !o.noSetOp && !o.scalar && g.depth <= 3 && g.p(0.18) {
		left := g.simple(outer, o)
		var rightSQL string
		var rightCols []fzCol
		if g.p(0.6) {
			// gêmeo: mesmas colunas, outro WHERE (o que UNION ALL aceita com máscara)
			tw := *left
			tw.where = g.pred(tw.rels, tw.outer)
			tw.with = ""
			rightSQL, rightCols = tw.render(), tw.cols
			if tw.order != "" || tw.limit != "" {
				rightSQL = "(" + rightSQL + ")"
			}
			g.tag("setop-twin")
		} else {
			o2 := o
			o2.width = len(left.cols)
			o2.types = nil
			for _, c := range left.cols {
				o2.types = append(o2.types, c.typ)
			}
			o2.noSetOp, o2.root, o2.bare = true, false, true
			rightSQL, rightCols = g.selectStmt(outer, o2)
			rightSQL = "(" + rightSQL + ")"
			g.tag("setop-other")
		}
		_ = rightCols
		op := fzPick(g, []string{"UNION ALL", "UNION ALL", "UNION ALL", "UNION", "INTERSECT", "EXCEPT", "EXCEPT ALL"})
		g.tag("setop:" + op)
		ls := left.render()
		if left.order != "" || left.limit != "" {
			ls = "(" + ls + ")"
		}
		sql := ls + " " + op + " " + rightSQL
		cols := left.cols
		if g.p(0.3) && len(cols) > 0 {
			i := g.intn(len(cols))
			if cols[i].name != "" && g.p(0.5) {
				sql += " ORDER BY " + cols[i].name
			} else {
				sql += " ORDER BY " + strconv.Itoa(i+1)
			}
		}
		return with + sql, cols
	}
	s := g.simple(outer, o)
	s.with = with
	return s.render(), s.cols
}

// simple gera um SELECT sem operação de conjunto.
func (g *fzGen) simple(outer []fzRel, o fzSelOpts) *fzSel {
	s := &fzSel{outer: outer}
	if g.p(0.06) && o.width <= 1 {
		// sem FROM
		typ := "int"
		if len(o.types) > 0 && o.types[0] != "" {
			typ = o.types[0]
		}
		n := g.id("k")
		s.targets = g.lit(typ) + " AS " + n
		s.cols = []fzCol{{name: n, typ: typ}}
		return s
	}
	s.rels, s.from = g.from(outer)
	if g.p(0.55) {
		s.where = g.pred(s.rels, outer)
		if g.p(0.3) {
			s.where += fzPick(g, []string{" AND ", " OR "}) + g.pred(s.rels, outer)
		}
	}
	mode := g.intn(10)
	if o.anyTargets {
		mode = 5
	}
	switch {
	case o.width > 0:
		g.fixedTargets(s, o)
	case mode < 2:
		g.groupTargets(s)
	case mode < 3:
		g.windowTargets(s)
	default:
		g.plainTargets(s)
	}
	if o.scalar && s.limit == "" {
		s.limit = "LIMIT 1"
	}
	return s
}

func fzOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (g *fzGen) alias(def string) (string, string) {
	if g.p(0.3) {
		n := fzPick(g, fzNamePool)
		g.tag("alias-pool")
		return " AS " + n, n
	}
	if g.p(0.2) {
		n := g.id("c")
		return " AS " + n, n
	}
	return "", def
}

// plainTargets: colunas nuas, expressões, *, t.*, DISTINCT, ORDER BY, LIMIT.
func (g *fzGen) plainTargets(s *fzSel) {
	if g.p(0.12) && len(s.rels) > 0 {
		g.tag("star")
		if g.p(0.5) {
			s.targets = "*"
			for _, r := range s.rels {
				s.cols = append(s.cols, fzVisible(r.cols)...)
			}
		} else {
			r := fzPick(g, s.rels)
			s.targets = r.name + ".*"
			s.cols = fzVisible(r.cols)
			if g.p(0.4) {
				q, ok := g.col(s.rels, ctxBare, "")
				if ok {
					s.targets += ", " + q.ref()
					s.cols = append(s.cols, q.col)
				}
			}
		}
	} else {
		k := 1 + g.intn(4)
		var parts []string
		for i := 0; i < k; i++ {
			t, c := g.target(s.rels, s.outer)
			parts = append(parts, t)
			s.cols = append(s.cols, c)
		}
		s.targets = strings.Join(parts, ", ")
	}
	if g.p(0.12) {
		g.tag("distinct")
		s.distinct = "DISTINCT "
	} else if g.p(0.08) {
		if q, ok := g.col(s.rels, ctxGroup, ""); ok {
			g.tag("distinct-on")
			s.distinct = "DISTINCT ON (" + q.ref() + ") "
			s.order = q.ref()
		}
	}
	if s.order == "" && g.p(0.35) && len(s.cols) > 0 {
		s.order = g.orderItem(s)
	}
	if g.p(0.2) {
		s.limit = fzPick(g, []string{"LIMIT 2", "LIMIT 3 OFFSET 1", "OFFSET 1", "FETCH FIRST 2 ROWS ONLY", "LIMIT ALL", "LIMIT 5"})
	}
}

func fzVisible(cols []fzCol) []fzCol {
	var out []fzCol
	for _, c := range cols {
		if c.cls != fzBlocked {
			out = append(out, c)
		}
	}
	return out
}

func (g *fzGen) orderItem(s *fzSel) string {
	switch g.intn(3) {
	case 0:
		g.tag("order-position")
		return strconv.Itoa(1+g.intn(len(s.cols))) + fzPick(g, []string{"", " DESC", " NULLS FIRST"})
	case 1:
		c := fzPick(g, s.cols)
		if c.name != "" {
			g.tag("order-name")
			return c.name
		}
	}
	if q, ok := g.col(s.rels, ctxGeneral, ""); ok {
		return q.ref() + fzPick(g, []string{"", " DESC"})
	}
	return "1"
}

// target gera um item da lista do SELECT.
func (g *fzGen) target(rels, outer []fzRel) (string, fzCol) {
	switch r := g.intn(40); {
	case r < 24:
		q, ok := g.col(rels, ctxBare, "")
		if !ok {
			break
		}
		a, name := g.alias(q.col.name)
		c := q.col
		c.name = name
		return g.colRef(q, rels) + a, c
	case r < 32:
		e, t := g.expr(rels)
		n := g.id("e")
		if g.p(0.15) {
			return e, fzCol{typ: t} // nome desconhecido
		}
		return e + " AS " + n, fzCol{name: n, typ: t}
	case r < 34:
		g.tag("scalar-subquery-target")
		sub, cols := g.selectStmt(append(append([]fzRel{}, rels...), outer...), fzSelOpts{width: 1, scalar: true})
		n := g.id("e")
		t := "text"
		if len(cols) > 0 {
			t = cols[0].typ
		}
		return "(" + sub + ") AS " + n, fzCol{name: n, typ: t}
	case r < 35:
		// referência à linha inteira e indireção
		if len(rels) > 0 {
			g.tag("whole-row")
			rel := fzPick(g, rels)
			n := g.id("w")
			cn := "id"
			if len(rel.cols) > 0 {
				cn = fzPick(g, rel.cols).name
			}
			return fzPick(g, []string{rel.name, "(" + rel.name + ")." + cn, "ROW(" + rel.name + ".*)", "json_build_object('r', " + rel.name + ")", "concat(" + rel.name + ")"}) + " AS " + n, fzCol{name: n, typ: "text"}
		}
	case r < 37:
		if q, ok := g.col(rels, ctxGeneral, "text"); ok {
			n := g.id("e")
			return "coalesce(" + q.ref() + ", " + g.lit("text") + ") AS " + n, fzCol{name: n, typ: "text"}
		}
	}
	n := g.id("k")
	t := fzPick(g, []string{"int", "text"})
	return g.lit(t) + " AS " + n, fzCol{name: n, typ: t}
}

// fixedTargets: n colunas com tipos pedidos (subqueries IN/escalares/set ops).
func (g *fzGen) fixedTargets(s *fzSel, o fzSelOpts) {
	var parts []string
	for i := 0; i < o.width; i++ {
		typ := ""
		if i < len(o.types) {
			typ = o.types[i]
		}
		ctx := ctxGeneral
		if o.bare && g.p(0.7) {
			ctx = ctxBare
		}
		q, ok := g.col(s.rels, ctx, typ)
		if ok && g.p(0.8) {
			ref := g.colRef(q, s.rels)
			if o.scalar && g.p(0.5) && (q.col.typ == "int" || q.col.typ == "num") {
				ref = "max(" + ref + ")"
			}
			parts = append(parts, ref)
			s.cols = append(s.cols, q.col)
			continue
		}
		t := typ
		if t == "" || t == "json" || t == "bool" {
			t = "int"
		}
		parts = append(parts, g.lit(t))
		s.cols = append(s.cols, fzCol{typ: t})
	}
	s.targets = strings.Join(parts, ", ")
}

// groupTargets: GROUP BY com chaves (liberadas ou hash) e agregações.
func (g *fzGen) groupTargets(s *fzSel) {
	var keys []fzQCol
	nk := g.intn(3)
	for i := 0; i < nk; i++ {
		if q, ok := g.col(s.rels, ctxGroup, ""); ok {
			keys = append(keys, q)
		}
	}
	var parts, grp []string
	for _, k := range keys {
		parts = append(parts, k.ref())
		c := k.col
		s.cols = append(s.cols, c)
		grp = append(grp, k.ref())
	}
	na := 1 + g.intn(2)
	for i := 0; i < na; i++ {
		a, t := g.agg(s.rels)
		n := g.id("a")
		parts = append(parts, a+" AS "+n)
		s.cols = append(s.cols, fzCol{name: n, typ: t})
	}
	s.targets = strings.Join(parts, ", ")
	if len(grp) > 0 {
		switch g.intn(6) {
		case 0:
			g.tag("rollup")
			s.group = "ROLLUP (" + strings.Join(grp, ", ") + ")"
		case 1:
			g.tag("grouping-sets")
			s.group = "GROUPING SETS ((" + strings.Join(grp, ", ") + "), ())"
		case 2:
			g.tag("group-position")
			var pos []string
			for i := range grp {
				pos = append(pos, strconv.Itoa(i+1))
			}
			s.group = strings.Join(pos, ", ")
		case 3:
			g.tag("cube")
			s.group = "CUBE (" + strings.Join(grp, ", ") + ")"
		default:
			s.group = strings.Join(grp, ", ")
		}
	}
	if g.p(0.2) {
		s.having = "count(*) " + fzPick(g, []string{"> 0", ">= 1", "< 100"})
	}
	if g.p(0.4) {
		s.order = strconv.Itoa(1 + g.intn(len(s.cols)))
	}
}

func (g *fzGen) agg(rels []fzRel) (string, string) {
	switch g.intn(12) {
	case 0, 1:
		return "count(*)", "int"
	case 2:
		if q, ok := g.col(rels, ctxGroup, ""); ok {
			g.tag("count-distinct")
			return "count(DISTINCT " + q.ref() + ")", "int"
		}
	case 3, 4:
		if q, ok := g.col(rels, ctxGeneral, "int"); ok {
			return fzPick(g, []string{"sum", "max", "min", "avg"}) + "(" + q.ref() + ")", "num"
		}
	case 5:
		if q, ok := g.col(rels, ctxGeneral, "text"); ok {
			o, _ := g.col(rels, ctxGeneral, "")
			ord := ""
			if o.rel != "" && g.p(0.5) {
				ord = " ORDER BY " + o.ref()
			}
			return "string_agg(" + q.ref() + ", ','" + ord + ")", "text"
		}
	case 6:
		if q, ok := g.col(rels, ctxGeneral, ""); ok {
			return fzPick(g, []string{"array_agg", "json_agg", "jsonb_agg"}) + "(" + q.ref() + ")", "json"
		}
	case 7:
		if q, ok := g.col(rels, ctxGeneral, "text"); ok {
			return fzPick(g, []string{"max", "min"}) + "(" + q.ref() + ")", "text"
		}
	case 8:
		if q, ok := g.col(rels, ctxGeneral, "int"); ok {
			return "bool_or(" + q.ref() + " > 2)", "bool"
		}
	case 9:
		if q, ok := g.col(rels, ctxGeneral, ""); ok {
			return "count(" + q.ref() + ") FILTER (WHERE " + q.ref() + " IS NOT NULL)", "int"
		}
	}
	return "count(*)", "int"
}

// windowTargets: funções de janela, às vezes com WINDOW nomeada.
func (g *fzGen) windowTargets(s *fzSel) {
	var parts []string
	if q, ok := g.col(s.rels, ctxBare, ""); ok {
		parts = append(parts, q.ref())
		s.cols = append(s.cols, q.col)
	}
	spec := ""
	if q, ok := g.col(s.rels, ctxGroup, ""); ok && g.p(0.6) {
		spec = "PARTITION BY " + q.ref()
	}
	if q, ok := g.col(s.rels, ctxGeneral, ""); ok {
		spec += " ORDER BY " + q.ref()
	}
	over := "(" + strings.TrimSpace(spec) + ")"
	if g.p(0.35) {
		g.tag("named-window")
		s.window = "w AS " + over
		over = "w"
	}
	g.tag("window")
	for i := 0; i < 1+g.intn(2); i++ {
		var f, t string
		switch g.intn(5) {
		case 0:
			f, t = "row_number()", "int"
		case 1:
			f, t = fzPick(g, []string{"rank()", "dense_rank()", "ntile(2)"}), "int"
		case 2:
			if q, ok := g.col(s.rels, ctxGeneral, ""); ok {
				f, t = fzPick(g, []string{"lag", "lead", "first_value", "last_value"})+"("+q.ref()+")", q.col.typ
			}
		case 3:
			if q, ok := g.col(s.rels, ctxGeneral, "int"); ok {
				f, t = "sum("+q.ref()+")", "num"
			}
		}
		if f == "" {
			f, t = "count(*)", "int"
		}
		n := g.id("j")
		parts = append(parts, f+" OVER "+over+" AS "+n)
		s.cols = append(s.cols, fzCol{name: n, typ: t})
	}
	s.targets = strings.Join(parts, ", ")
	if g.p(0.3) {
		s.order = strconv.Itoa(1 + g.intn(len(s.cols)))
	}
}

// from gera a lista do FROM, com joins.
func (g *fzGen) from(outer []fzRel) ([]fzRel, string) {
	n := 1
	if g.depth <= 3 {
		switch x := g.intn(20); {
		case x >= 18:
			n = 3
		case x >= 11:
			n = 2
		}
	}
	rels, sql := g.fromItem(outer, nil)
	for i := 1; i < n; i++ {
		switch g.intn(9) {
		case 0:
			r, s := g.fromItem(outer, rels)
			rels, sql = append(rels, r...), sql+", "+s
		case 1, 2:
			r, s := g.fromItem(outer, rels)
			all := append(append([]fzRel{}, rels...), r...)
			sql += fzPick(g, []string{" JOIN ", " LEFT JOIN ", " INNER JOIN ", " RIGHT JOIN ", " FULL JOIN "}) + s + " ON " + g.joinCond(rels, r, all)
			rels = all
		case 3:
			r, s := g.fromItem(outer, rels)
			if u := fzCommon(rels, r, g); u != "" {
				g.tag("using")
				sql += fzPick(g, []string{" JOIN ", " LEFT JOIN "}) + s + " USING (" + u + ")"
			} else {
				sql += " CROSS JOIN " + s
			}
			rels = append(rels, r...)
		case 4:
			g.tag("natural")
			r, s := g.fromItem(outer, rels)
			sql += fzPick(g, []string{" NATURAL JOIN ", " NATURAL LEFT JOIN "}) + s
			rels = append(rels, r...)
		case 5, 6:
			g.tag("lateral")
			r, s := g.lateral(outer, rels)
			kw := fzPick(g, []string{" CROSS JOIN LATERAL ", ", LATERAL ", " LEFT JOIN LATERAL "})
			sql += kw + s
			if kw == " LEFT JOIN LATERAL " {
				sql += " ON true"
			}
			rels = append(rels, r...)
		default:
			r, s := g.fromItem(outer, rels)
			sql += " CROSS JOIN " + s
			rels = append(rels, r...)
		}
	}
	return rels, sql
}

func fzCommon(a, b []fzRel, g *fzGen) string {
	in := map[string]bool{}
	for _, r := range a {
		for _, c := range r.cols {
			in[c.name] = true
		}
	}
	var out []string
	for _, r := range b {
		for _, c := range r.cols {
			if c.name != "" && in[c.name] && (c.cls == fzPlain || g.p(g.bad)) {
				out = append(out, c.name)
			}
		}
	}
	if len(out) == 0 {
		return ""
	}
	return fzPick(g, out)
}

func (g *fzGen) joinCond(left, right, all []fzRel) string {
	a, okA := g.col(left, ctxGeneral, "int")
	b, okB := g.col(right, ctxGeneral, "int")
	if okA && okB && g.p(0.8) {
		return a.ref() + " = " + b.ref()
	}
	return g.pred(all, nil)
}

// lateral gera (SELECT <colunas da esquerda> ...) AS l, que move valores
// de uma relação para colunas novas.
func (g *fzGen) lateral(outer, left []fzRel) ([]fzRel, string) {
	scope := append(append([]fzRel{}, left...), outer...)
	name := g.id("l")
	var parts []string
	var cols []fzCol
	if g.p(0.5) {
		// só referências à esquerda, sem FROM
		k := 1 + g.intn(3)
		for i := 0; i < k; i++ {
			q, ok := g.col(left, ctxBare, "")
			if !ok {
				break
			}
			a, nm := g.alias(q.col.name)
			parts = append(parts, q.ref()+a)
			c := q.col
			c.name = nm
			cols = append(cols, c)
		}
		if len(parts) == 0 {
			parts, cols = []string{"1 AS k"}, []fzCol{{"k", "int", fzPlain}}
		}
		sql := "(SELECT " + strings.Join(parts, ", ") + ") AS " + name
		if g.p(0.3) {
			sql = "(VALUES (" + strings.Join(fzStripAliases(parts), ", ") + ")) AS " + name
			for i := range cols {
				cols[i].name = fmt.Sprintf("column%d", i+1)
			}
			g.tag("lateral-values")
		}
		return []fzRel{{name, cols}}, sql
	}
	sub, scols := g.selectStmt(scope, fzSelOpts{})
	return []fzRel{{name, scols}}, "(" + sub + ") AS " + name
}

func fzStripAliases(parts []string) []string {
	out := make([]string, len(parts))
	for i, p := range parts {
		if j := strings.Index(p, " AS "); j >= 0 {
			p = p[:j]
		}
		out[i] = p
	}
	return out
}

func (g *fzGen) cte(name string) *fzCTE {
	for i := len(g.ctes) - 1; i >= 0; i-- {
		if g.ctes[i].name == name {
			return &g.ctes[i]
		}
	}
	return nil
}

func (g *fzGen) tableName() string {
	x := g.intn(100)
	switch {
	case x < 30:
		return "clientes"
	case x < 45:
		return "pedidos"
	case x < 52:
		return "itens"
	case x < 72:
		return "pagamentos"
	case x < 97:
		return "contatos"
	case x < 99:
		return "audit_log"
	}
	return "notas"
}

// fromItem gera um item do FROM.
func (g *fzGen) fromItem(outer, prev []fzRel) ([]fzRel, string) {
	x := g.intn(100)
	if g.depth > 3 {
		x = 0
	}
	switch {
	case x < 48:
		t := g.tableName()
		qualified := g.p(0.06)
		cols := fzTables[t]
		if c := g.cte(t); c != nil && !qualified {
			cols = c.cols
			g.tag("cte-shadows-table")
		}
		name := t
		if qualified {
			g.tag("schema-qualified")
			t = fzSchema + "." + t
		}
		sql := t
		if g.p(0.75) {
			name = g.id("t")
			if g.p(0.12) {
				name = fzPick(g, fzTableOrder[:5])
				g.tag("alias-table-name")
			}
			sql += " AS " + name
		}
		return []fzRel{{name, cols}}, sql
	case x < 62 && len(g.ctes) > 0:
		c := fzPick(g, g.ctes)
		name := c.name
		sql := c.name
		cols := c.cols
		if g.p(0.6) {
			name = g.id("t")
			sql += " AS " + name
			if g.p(0.3) {
				var names []string
				cols, names = g.renames(cols)
				sql += "(" + strings.Join(names, ", ") + ")"
			}
		}
		return []fzRel{{name, cols}}, sql
	case x < 82:
		g.tag("from-subquery")
		sub, cols := g.selectStmt(outer, fzSelOpts{})
		name := g.id("s")
		sql := "(" + sub + ") AS " + name
		if g.p(0.3) {
			var names []string
			cols, names = g.renames(cols)
			sql += "(" + strings.Join(names, ", ") + ")"
			g.tag("subquery-colnames")
		}
		return []fzRel{{name, cols}}, sql
	case x < 89:
		g.tag("wrapper-mimic")
		t := fzPick(g, []string{"pagamentos", "contatos"})
		body := fmt.Sprintf(fzWrappers[t], t)
		cols := fzTables[t]
		if c := g.cte(t); c != nil {
			cols = c.cols
			g.tag("wrapper-mimic-cte")
		} else {
			cols = fzVisible(cols)
		}
		switch {
		case g.p(0.3):
			// mutação: mesma forma, outro filtro
			body = strings.Replace(body, "<>", "=", 1)
			g.tag("wrapper-mutated")
		case g.p(0.3):
			// forma antiga do wrapper, sem a barreira OFFSET 0
			body = strings.TrimSuffix(body, " OFFSET 0")
			g.tag("wrapper-no-fence")
		}
		name := g.id("p")
		if g.p(0.2) {
			name = t
		}
		// as colunas vêm da lista do wrapper
		var wcols []fzCol
		list := strings.Split(strings.TrimPrefix(body[:strings.Index(body, " FROM ")], "SELECT "), ", ")
		for _, n := range list {
			c := fzCol{name: n, typ: "text", cls: fzPlain}
			for _, cc := range cols {
				if cc.name == n {
					c = cc
				}
			}
			wcols = append(wcols, c)
		}
		return []fzRel{{name, wcols}}, "(" + body + ") AS " + name
	case x < 94:
		g.tag("values")
		name := g.id("v")
		return []fzRel{{name, []fzCol{{"n", "int", fzPlain}, {"s", "text", fzPlain}}}},
			"(VALUES (1, 'um'), (2, 'dois'), (3, NULL)) AS " + name + "(n, s)"
	default:
		g.tag("generate_series")
		name := g.id("g")
		if g.p(0.3) {
			return []fzRel{{name, []fzCol{{"n", "int", fzPlain}, {"o", "int", fzPlain}}}},
				"generate_series(1, " + strconv.Itoa(1+g.intn(4)) + ") WITH ORDINALITY AS " + name + "(n, o)"
		}
		return []fzRel{{name, []fzCol{{"n", "int", fzPlain}}}}, "generate_series(1, " + strconv.Itoa(1+g.intn(4)) + ") AS " + name + "(n)"
	}
}

// renames devolve uma lista de alias de colunas: permutação dos nomes
// (troca de posições) ou nomes do pool, às vezes mais curta.
func (g *fzGen) renames(cols []fzCol) ([]fzCol, []string) {
	out := make([]fzCol, len(cols))
	copy(out, cols)
	n := len(cols)
	if n == 0 {
		return out, []string{"z0"}
	}
	if g.p(0.3) && n > 1 {
		n = 1 + g.intn(n-1)
	}
	names := make([]string, n)
	perm := g.r.Perm(len(cols))
	for i := 0; i < n; i++ {
		switch {
		case g.p(0.5) && cols[perm[i]].name != "":
			names[i] = cols[perm[i]].name // nome de outra posição
		case g.p(0.5):
			names[i] = fzPick(g, fzNamePool)
		default:
			names[i] = g.id("r")
		}
		out[i].name = names[i]
	}
	g.tag("renames")
	return out, names
}

// withClause gera WITH (às vezes RECURSIVE) e empilha as CTEs em g.ctes.
func (g *fzGen) withClause(outer []fzRel) string {
	recursive := g.p(0.25)
	k := 1 + g.intn(3)
	var parts []string
	pool := []string{"clientes", "pagamentos", "contatos", "pedidos", "w1", "w2", "a", "b"}
	var pending []string
	for _, i := range g.r.Perm(len(pool))[:k] {
		pending = append(pending, pool[i])
	}
	for i, name := range pending {
		if recursive && g.p(0.06) && i+1 < len(pending) {
			// referência adiante: o corpo cita uma CTE definida depois
			g.tag("recursive-forward")
			later := pending[i+1+g.intn(len(pending)-i-1)]
			parts = append(parts, name+" AS (SELECT * FROM "+later+")")
			g.ctes = append(g.ctes, fzCTE{name: name, cols: []fzCol{{"id", "int", fzPlain}}})
			continue
		}
		if recursive && g.p(0.5) {
			g.tag("recursive")
			rels, from := g.fromItem(outer, nil)
			q, ok := g.col(rels, ctxBare, "")
			v := "1"
			vcol := fzCol{"v", "int", fzPlain}
			if ok {
				v = q.ref()
				vcol = fzCol{"v", q.col.typ, q.col.cls}
			}
			step := "v"
			if g.p(g.bad + 0.05) {
				step = fzPick(g, []string{"'x'", "upper(v::text)", "n::text"})
				g.tag("recursive-mutate")
			}
			body := fmt.Sprintf("%s(n, v) AS (SELECT 1, %s FROM %s UNION ALL SELECT n + 1, %s FROM %s WHERE n < 3)", name, v, from, step, name)
			parts = append(parts, body)
			g.ctes = append(g.ctes, fzCTE{name: name, cols: []fzCol{{"n", "int", fzPlain}, vcol}})
			continue
		}
		sub, cols := g.selectStmt(outer, fzSelOpts{})
		head := name
		if g.p(0.25) && len(cols) > 0 {
			var names []string
			cols, names = g.renames(cols)
			head += "(" + strings.Join(names, ", ") + ")"
			g.tag("cte-colnames")
		}
		mat := fzPick(g, []string{"", "", "", "MATERIALIZED ", "NOT MATERIALIZED "})
		if mat != "" {
			g.tag("materialized")
		}
		parts = append(parts, head+" AS "+mat+"("+sub+")")
		g.ctes = append(g.ctes, fzCTE{name: name, cols: cols})
	}
	w := "WITH "
	if recursive {
		w = "WITH RECURSIVE "
	}
	g.tag("with")
	return w + strings.Join(parts, ", ") + " "
}

// ---------- exec ----------

func (g *fzGen) returning(rels []fzRel) string {
	if !g.p(0.8) {
		return ""
	}
	g.tag("returning")
	if g.p(0.3) {
		return " RETURNING *"
	}
	var parts []string
	for i := 0; i < 1+g.intn(3); i++ {
		t, _ := g.target(rels, nil)
		parts = append(parts, t)
	}
	return " RETURNING " + strings.Join(parts, ", ")
}

func (g *fzGen) execStmt() string {
	g.depth = 1
	with := ""
	if g.p(0.2) {
		with = g.withClause(nil)
	}
	idList := fzPick(g, []string{"1", "2", "97001", "97101", "1, 97001", "1, 2"})
	switch g.intn(8) {
	case 0, 1:
		g.tag("exec-update")
		tgt := []fzRel{{"pedidos", fzTables["pedidos"]}}
		val := fzPick(g, []string{"'nota'", "concat(status, '-x')", "upper(observacao)"})
		if g.p(0.5) {
			sub, _ := g.selectStmt(nil, fzSelOpts{width: 1, types: []string{"text"}, scalar: true})
			val = "(" + sub + ")"
		}
		return with + "UPDATE pedidos SET observacao = " + val + " WHERE id IN (" + idList + ")" + g.returning(tgt)
	case 2:
		g.tag("exec-update-from")
		rels, from := g.fromItem(nil, nil)
		all := append([]fzRel{{"u", fzTables["pedidos"]}}, rels...)
		cond := "true"
		if q, ok := g.col(rels, ctxGeneral, "int"); ok {
			cond = "u.cliente_id = " + q.ref()
		}
		return with + "UPDATE pedidos AS u SET status = 'pago' FROM " + from + " WHERE u.id = " + fzPick(g, []string{"1", "2"}) + " AND " + cond + g.returning(all)
	case 3:
		g.tag("exec-update-filtered")
		t := fzPick(g, []string{"pagamentos", "contatos"})
		return with + "UPDATE " + t + " SET status = " + fzPick(g, []string{"'pago'", "'ativo'", "status"}) + " WHERE id IN (" + idList + ")" + g.returning([]fzRel{{t, fzTables[t]}})
	case 4:
		g.tag("exec-delete")
		return with + "DELETE FROM itens WHERE id IN (" + fzPick(g, []string{"1", "2", "1, 2"}) + ")" + g.returning([]fzRel{{"itens", fzTables["itens"]}})
	case 5:
		g.tag("exec-delete-using")
		rels, from := g.fromItem(nil, nil)
		all := append([]fzRel{{"i", fzTables["itens"]}}, rels...)
		cond := "true"
		if q, ok := g.col(rels, ctxGeneral, "int"); ok {
			cond = "i.pedido_id = " + q.ref()
		}
		return with + "DELETE FROM itens AS i USING " + from + " WHERE i.id = 1 AND " + cond + g.returning(all)
	case 6:
		g.tag("exec-insert-select")
		rels, from := g.fromItem(nil, nil)
		prod := "'novo'"
		if q, ok := g.col(rels, ctxBare, "text"); ok && g.p(0.7) {
			prod = q.ref()
		}
		pid := "1"
		if q, ok := g.col(rels, ctxGeneral, "int"); ok {
			pid = q.ref()
		}
		return with + "INSERT INTO itens (pedido_id, produto, quantidade) SELECT " + pid + ", " + prod + ", 1 FROM " + from + " LIMIT 2" + g.returning([]fzRel{{"itens", fzTables["itens"]}})
	default:
		g.tag("exec-insert-values")
		return with + "INSERT INTO itens (pedido_id, produto, quantidade) VALUES (1, 'x', 1)" + g.returning([]fzRel{{"itens", fzTables["itens"]}})
	}
}

// fzSeeds são formas conhecidas (os dois vazamentos já corrigidos e
// vizinhos); o gerador as usa como ponto de partida de vez em quando.
var fzSeeds = []string{
	"WITH RECURSIVE a AS (SELECT status FROM pedidos), pedidos AS (SELECT email AS status FROM clientes) SELECT status FROM a",
	"WITH pagamentos AS (SELECT email AS id, 1 AS pedido_id, 1 AS valor, 'x' AS status, 'r' AS ref FROM clientes) SELECT p.id FROM (SELECT id, pedido_id, valor, status, ref FROM pagamentos WHERE status <> 'estornado') p",
	"WITH contatos AS (SELECT 1 AS id, 1 AS cliente_id, email AS apelido, telefone, 'a' AS status, cidade AS obs FROM clientes) SELECT * FROM (SELECT id, cliente_id, apelido, telefone, status, obs FROM contatos WHERE lower(status) <> 'inativo') c",
	"SELECT x.b FROM (SELECT email AS a, cidade AS b FROM clientes) AS x(b, a)",
	"WITH c(cidade, email) AS (SELECT email, cidade FROM clientes) SELECT cidade FROM c",
	"SELECT l.column1 FROM clientes c CROSS JOIN LATERAL (VALUES (c.email)) AS l",
	"SELECT id FROM pagamentos WHERE ref::int > 0",
	"SELECT id FROM contatos WHERE obs::int IS NULL",
	"SELECT p.id FROM pagamentos p JOIN pedidos d ON d.id = p.pedido_id WHERE p.ref::int = d.id",
	"SELECT * FROM pagamentos NATURAL JOIN contatos",
	"SELECT id FROM contatos WHERE to_date(obs, 'Month') IS NULL",
	"SELECT id FROM pagamentos WHERE to_date(ref, 'Month') IS NULL",
	"SELECT id FROM contatos WHERE id > 6 AND to_date(obs, 'Month') IS NULL",
	"SELECT id FROM pagamentos WHERE id > 6 AND ref::int > 0",
	"SELECT c.id FROM contatos c JOIN pedidos p ON p.id = c.id WHERE c.obs::int = p.id",
	// lacuna de nomes: o guard chama a coluna de "?column?", o Postgres de
	// "coalesce"; o NATURAL JOIN compara o email mascarado com o literal
	"SELECT s2.id FROM (SELECT coalesce('x@fz.example', 'x')) s1 NATURAL JOIN (SELECT email AS coalesce, id FROM clientes) s2",
}

// statement gera um statement e diz se é exec.
func (g *fzGen) statement() (string, bool) {
	g.bad = 0.01 + 0.05*g.r.Float64()
	if g.p(0.03) {
		g.tag("seed")
		return fzPick(g, fzSeeds), false
	}
	if g.p(0.15) {
		return g.execStmt(), true
	}
	if g.p(0.35) {
		return g.mover(), false
	}
	sql, _ := g.selectStmt(nil, fzSelOpts{root: true})
	return sql, false
}

// ---------- mover: camadas que só movem valores de posição ----------

// fzSrc é a relação corrente do mover: um item de FROM e suas colunas.
type fzSrc struct {
	from  string
	alias string
	cols  []fzCol
	bases map[string]bool // nomes de tabela citados (para não sombrear a si mesma)
}

// project escolhe colunas da fonte (subconjunto permutado, às vezes
// renomeadas com nomes de outras colunas) e devolve a lista e as colunas.
func (g *fzGen) project(src fzSrc) (string, []fzCol) {
	if g.p(0.12) {
		g.tag("mv-star")
		if g.p(0.5) {
			return "*", fzVisible(src.cols)
		}
		return src.alias + ".*", fzVisible(src.cols)
	}
	perm := g.r.Perm(len(src.cols))
	k := 1 + g.intn(len(src.cols))
	var parts []string
	var cols []fzCol
	used := map[string]bool{}
	for _, i := range perm[:k] {
		c := src.cols[i]
		if c.name == "" || (c.cls == fzBlocked && !g.p(g.bad)) {
			continue
		}
		ref := src.alias + "." + c.name
		name := c.name
		if c.cls == fzPlain && g.p(0.2) {
			e, t := g.expr([]fzRel{{src.alias, []fzCol{c}}})
			ref, c.typ = e, t
			name = g.id("e")
		}
		if g.p(0.4) {
			name = fzPick(g, fzNamePool)
		}
		if used[name] && !g.p(0.05) {
			name = g.id("m")
		}
		used[name] = true
		if name != c.name || strings.Contains(ref, "(") || strings.Contains(ref, " ") {
			ref += " AS " + name
		}
		c.name = name
		parts = append(parts, ref)
		cols = append(cols, c)
	}
	if len(parts) == 0 {
		n := g.id("k")
		return "1 AS " + n, []fzCol{{n, "int", fzPlain}}
	}
	return strings.Join(parts, ", "), cols
}

func (g *fzGen) moverBase() fzSrc {
	t := fzPick(g, []string{"clientes", "clientes", "contatos", "contatos", "pagamentos", "pedidos"})
	a := g.id("b")
	from := t + " AS " + a
	if g.p(0.15) {
		// a base vem pela imitação do filtro
		if w, ok := fzWrappers[t]; ok {
			from = "(" + fmt.Sprintf(w, t) + ") AS " + a
			g.tag("mv-wrapper-mimic")
		}
	}
	return fzSrc{from: from, alias: a, cols: fzTables[t], bases: map[string]bool{t: true}}
}

func fzMerge(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func (g *fzGen) mover() string {
	g.tag("mover")
	g.depth = 3 // expressões e subqueries pequenas
	var ctes []string
	recursive := false
	src := g.moverBase()
	layers := 1 + g.intn(4)
	for l := 0; l < layers; l++ {
		switch g.intn(11) {
		case 0, 1:
			g.tag("mv-subquery")
			list, cols := g.project(src)
			a := g.id("s")
			from := "(SELECT " + list + " FROM " + src.from + ") AS " + a
			if g.p(0.35) {
				var names []string
				cols, names = g.renames(cols)
				from += "(" + strings.Join(names, ", ") + ")"
			}
			src = fzSrc{from: from, alias: a, cols: cols, bases: src.bases}
		case 2, 3:
			g.tag("mv-cte")
			list, cols := g.project(src)
			name := g.id("c")
			if g.p(0.4) {
				// sombreia uma tabela que a própria CTE não cita
				for _, t := range g.r.Perm(5) {
					if !src.bases[fzTableOrder[t]] {
						name = fzTableOrder[t]
						g.tag("mv-cte-shadow")
						break
					}
				}
			}
			head := name
			if g.p(0.35) {
				var names []string
				cols, names = g.renames(cols)
				head += "(" + strings.Join(names, ", ") + ")"
			}
			ctes = append(ctes, head+" AS "+fzPick(g, []string{"", "", "MATERIALIZED ", "NOT MATERIALIZED "})+"(SELECT "+list+" FROM "+src.from+")")
			a := g.id("t")
			src = fzSrc{from: name + " AS " + a, alias: a, cols: cols, bases: src.bases}
			if g.p(0.3) {
				// a mesma CTE de novo, agora citada pelo nome da tabela que sombreia
				src.from = name
				src.alias = name
			}
		case 4:
			g.tag("mv-lateral")
			list, cols := g.project(src)
			a := g.id("l")
			sub := "(SELECT " + list + ") AS " + a
			if g.p(0.25) {
				sub = "(VALUES (" + strings.Join(fzStripAliases(strings.Split(list, ", ")), ", ") + ")) AS " + a
				for i := range cols {
					cols[i].name = fmt.Sprintf("column%d", i+1)
				}
			}
			if strings.Contains(list, "*") {
				continue
			}
			all := append(append([]fzCol{}, src.cols...), cols...)
			_ = all
			o := g.id("o")
			from := "(SELECT " + a + ".* FROM " + src.from + " CROSS JOIN LATERAL " + sub + ") AS " + o
			src = fzSrc{from: from, alias: o, cols: cols, bases: src.bases}
		case 5:
			g.tag("mv-union-all")
			list, cols := g.project(src)
			a := g.id("u")
			p1 := g.pred([]fzRel{{src.alias, src.cols}}, nil)
			p2 := g.pred([]fzRel{{src.alias, src.cols}}, nil)
			op := " UNION ALL "
			if g.p(0.15) {
				op = fzPick(g, []string{" UNION ", " INTERSECT ALL ", " EXCEPT "})
			}
			from := "(SELECT " + list + " FROM " + src.from + " WHERE " + p1 + op + "SELECT " + list + " FROM " + src.from + " WHERE " + p2 + ") AS " + a
			src = fzSrc{from: from, alias: a, cols: cols, bases: src.bases}
		case 6:
			var keys []fzCol
			for _, c := range src.cols {
				if c.name != "" && (c.cls == fzHashed || c.cls == fzPlain) && g.p(0.5) {
					keys = append(keys, c)
				}
			}
			if len(keys) == 0 {
				continue
			}
			g.tag("mv-group")
			var refs []string
			for _, c := range keys {
				refs = append(refs, src.alias+"."+c.name)
			}
			n := g.id("n")
			grp := strings.Join(refs, ", ")
			if g.p(0.3) {
				grp = fzPick(g, []string{"ROLLUP", "CUBE"}) + " (" + grp + ")"
			}
			a := g.id("g")
			from := "(SELECT " + strings.Join(refs, ", ") + ", count(*) AS " + n + " FROM " + src.from + " GROUP BY " + grp + ") AS " + a
			src = fzSrc{from: from, alias: a, cols: append(keys, fzCol{n, "int", fzPlain}), bases: src.bases}
		case 7:
			var keys []fzCol
			for _, c := range src.cols {
				if c.name != "" && (c.cls == fzHashed || c.cls == fzPlain) {
					keys = append(keys, c)
				}
			}
			if len(keys) == 0 {
				continue
			}
			g.tag("mv-distinct-on")
			k := fzPick(g, keys)
			list, cols := g.project(src)
			a := g.id("d")
			from := "(SELECT DISTINCT ON (" + src.alias + "." + k.name + ") " + list + " FROM " + src.from + " ORDER BY " + src.alias + "." + k.name + ") AS " + a
			src = fzSrc{from: from, alias: a, cols: cols, bases: src.bases}
		case 8:
			g.tag("mv-join")
			t := fzPick(g, []string{"pedidos", "clientes", "contatos", "pagamentos"})
			j := g.id("j")
			list, cols := g.project(src)
			var cond string
			switch g.intn(3) {
			case 0:
				cond = " NATURAL JOIN " + t + " AS " + j
			case 1:
				cond = " JOIN " + t + " AS " + j + " USING (id)"
			default:
				cond = " LEFT JOIN " + t + " AS " + j + " ON " + j + ".id = " + fzFirstInt(src)
			}
			a := g.id("s")
			from := "(SELECT " + list + " FROM " + src.from + cond + ") AS " + a
			src = fzSrc{from: from, alias: a, cols: cols, bases: fzMerge(src.bases, map[string]bool{t: true})}
		case 9:
			g.tag("mv-recursive")
			recursive = true
			list, cols := g.project(src)
			if strings.Contains(list, "*") {
				continue
			}
			name := g.id("r")
			var names []string
			for i := range cols {
				if cols[i].name == "" || strings.HasPrefix(cols[i].name, "n") {
					cols[i].name = g.id("x")
				}
				names = append(names, cols[i].name)
			}
			step := strings.Join(names, ", ")
			if g.p(0.1) && len(names) > 1 {
				// troca posições no termo recursivo
				step = strings.Join(append(names[1:], names[0]), ", ")
				g.tag("mv-recursive-swap")
			}
			ctes = append(ctes, name+"(n, "+strings.Join(names, ", ")+") AS (SELECT 1, "+strings.Join(fzStripAliases(strings.Split(list, ", ")), ", ")+" FROM "+src.from+" UNION ALL SELECT n + 1, "+step+" FROM "+name+" WHERE n < 2)")
			a := g.id("t")
			src = fzSrc{from: name + " AS " + a, alias: a, cols: append([]fzCol{{"n", "int", fzPlain}}, cols...), bases: src.bases}
		default:
			g.tag("mv-order-position")
			list, cols := g.project(src)
			a := g.id("s")
			from := "(SELECT " + list + " FROM " + src.from + " ORDER BY " + strconv.Itoa(1+g.intn(max(1, len(cols)))) + " LIMIT 4) AS " + a
			src = fzSrc{from: from, alias: a, cols: cols, bases: src.bases}
		}
	}
	list, cols := g.project(src)
	sql := "SELECT " + list + " FROM " + src.from
	if g.p(0.3) {
		sql += " WHERE " + g.pred([]fzRel{{src.alias, src.cols}}, nil)
	}
	if g.p(0.3) && len(cols) > 0 {
		sql += " ORDER BY " + strconv.Itoa(1+g.intn(len(cols)))
	}
	with := ""
	if len(ctes) > 0 {
		with = "WITH "
		if recursive {
			with = "WITH RECURSIVE "
		}
		with += strings.Join(ctes, ", ") + " "
	}
	return with + sql
}

func fzFirstInt(src fzSrc) string {
	for _, c := range src.cols {
		if c.typ == "int" && c.cls == fzPlain && c.name != "" {
			return src.alias + "." + c.name
		}
	}
	return "1"
}

// ---------------------------------------------------------------------------
// o teste
// ---------------------------------------------------------------------------

type fzStats struct {
	total, accepted, denied, parseErr, guardErr, dbErr, tooMany, clean, leaks int
	rawErrSentinel                                                            int // erro cru com sentinela, redigido pelo SafeMessage
	acceptedMasked, acceptedFiltered, acceptedExec                            int
	dbCodes                                                                   map[string]int
	denyReasons                                                               map[string]int
	tagAccepted, tagTotal                                                     map[string]int
	guardErrSamples, nameErrSamples                                           []string
}

func fzEnvInt(name string, def int64) int64 {
	if v := os.Getenv(name); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return n
		}
	}
	return def
}

func TestLeakFuzz(t *testing.T) {
	e := fzSetup(t)
	n := int(fzEnvInt("CRIVO_LEAKFUZZ_N", 300))
	seed := fzEnvInt("CRIVO_LEAKFUZZ_SEED", 1) // fixa: o CI que publica o release não pode falhar ao acaso; use sementes aleatórias à mão
	only := fzEnvInt("CRIVO_LEAKFUZZ_ONLY", -1)
	verbose := os.Getenv("CRIVO_LEAKFUZZ_VERBOSE") == "1"
	t.Logf("leak fuzzer: CRIVO_LEAKFUZZ_SEED=%d CRIVO_LEAKFUZZ_N=%d", seed, n)

	fzSelfTest(t, e)

	// CRIVO_LEAKFUZZ_SQL roda um statement só (prefixo "exec:" para exec),
	// para reduzir à mão um achado.
	if one := os.Getenv("CRIVO_LEAKFUZZ_SQL"); one != "" {
		st := &fzStats{dbCodes: map[string]int{}, denyReasons: map[string]int{}}
		exec := strings.HasPrefix(one, "exec:")
		one = strings.TrimPrefix(one, "exec:")
		f, v, outcome := e.runOne(t, st, one, exec)
		t.Logf("%s :: %s", outcome, one)
		if v != nil {
			t.Logf("reescrito: %s\nmáscaras: %+v", v.SQL, v.Masks)
			if !exec {
				if plan, err := run.Explain(context.Background(), e.conn, e.policy, v.SQL); err == nil {
					var b strings.Builder
					for _, r := range plan.Rows {
						if len(r) > 0 && r[0] != nil {
							b.WriteString("\n  " + *r[0])
						}
					}
					t.Logf("plano:%s", b.String())
				}
			}
		}
		for _, x := range f {
			t.Errorf("VAZAMENTO (%s): %s", x.class, x.detail)
		}
		return
	}

	st := &fzStats{dbCodes: map[string]int{}, denyReasons: map[string]int{}, tagAccepted: map[string]int{}, tagTotal: map[string]int{}}
	reported := map[string]bool{}
	deadline := time.Now().Add(9 * time.Minute)
	start := time.Now()
	first, last := 0, n
	if only >= 0 {
		first, last = int(only), int(only)+1
	}
	for i := first; i < last; i++ {
		if time.Now().After(deadline) {
			t.Logf("prazo interno esgotado na iteração %d", i)
			break
		}
		g := &fzGen{r: rand.New(rand.NewSource(seed*1_000_003 + int64(i))), tags: map[string]bool{}}
		sql, exec := func() (sql string, exec bool) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("gerador entrou em pânico na iteração %d: %v", i, r)
					sql = "SELECT 1"
				}
			}()
			return g.statement()
		}()
		findings, v, outcome := func() (f []fzFinding, v *sqlguard.Verdict, out string) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("pânico ao executar a iteração %d: %v\n  sql: %s", i, r, sql)
					out = "pânico"
				}
			}()
			return e.runOne(t, st, sql, exec)
		}()
		for tg := range g.tags {
			st.tagTotal[tg]++
			if v != nil {
				st.tagAccepted[tg]++
			}
		}
		if verbose {
			t.Logf("[%d] %s :: %s", i, outcome, sql)
		}
		if len(findings) == 0 {
			continue
		}
		st.leaks++
		for _, f := range findings {
			if reported[f.class] || len(reported) >= 5 {
				continue
			}
			reported[f.class] = true
			masks := ""
			if v != nil {
				masks = fmt.Sprintf("%+v", v.Masks)
			}
			rewritten := ""
			if v != nil {
				rewritten = v.SQL
			}
			t.Errorf("VAZAMENTO (%s)\n  reproduzir: CRIVO_LEAKFUZZ_SEED=%d CRIVO_LEAKFUZZ_ONLY=%d\n  sql:       %s\n  reescrito: %s\n  máscaras:  %s\n  achado:    %s",
				f.class, seed, i, sql, rewritten, masks, f.detail)
		}
	}
	el := time.Since(start)
	pct := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return 100 * float64(a) / float64(b)
	}
	t.Logf("leak fuzzer: seed=%d, %d statements em %v; aceitos %d (%.1f%%), barrados %d, parse %d, erro do guard %d, erro do banco %d, acima do max %d, limpos %d, com vazamento %d",
		seed, st.total, el.Round(time.Millisecond), st.accepted, pct(st.accepted, st.total), st.denied, st.parseErr, st.guardErr, st.dbErr, st.tooMany, st.clean, st.leaks)
	t.Logf("aceitos com máscara %d, com tabela filtrada %d, exec %d; erros do banco por SQLSTATE: %v; erros crus com sentinela (redigidos pelo SafeMessage): %d",
		st.acceptedMasked, st.acceptedFiltered, st.acceptedExec, st.dbCodes, st.rawErrSentinel)
	var tags []string
	for tg := range st.tagTotal {
		tags = append(tags, tg)
	}
	sort.Strings(tags)
	var b strings.Builder
	for _, tg := range tags {
		fmt.Fprintf(&b, " %s=%d/%d", tg, st.tagAccepted[tg], st.tagTotal[tg])
	}
	t.Logf("recursos (aceitos/gerados):%s", b.String())
	var reasons []string
	for r := range st.denyReasons {
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool { return st.denyReasons[reasons[i]] > st.denyReasons[reasons[j]] })
	if len(reasons) > 8 {
		reasons = reasons[:8]
	}
	for _, r := range reasons {
		t.Logf("barrado %4d× %s", st.denyReasons[r], r)
	}
	for _, s := range st.guardErrSamples {
		t.Logf("erro interno do guard (não é Denial): %s", s)
	}
	for _, s := range st.nameErrSamples {
		t.Logf("aceito pelo guard mas o banco não resolveu nomes: %s", s)
	}
	if only < 0 && st.total >= 100 && pct(st.accepted, st.total) < 25 {
		t.Errorf("só %.1f%% aceitos: o gerador precisa produzir mais SQL válido", pct(st.accepted, st.total))
	}
}

// runOne valida, executa e varre um statement.
func (e *fzEnv) runOne(t *testing.T, st *fzStats, sql string, exec bool) ([]fzFinding, *sqlguard.Verdict, string) {
	st.total++
	cmd := sqlguard.CmdQuery
	if exec {
		cmd = sqlguard.CmdExec
	}
	v, err := e.guard.Check(cmd, sql)
	if err != nil {
		var d *sqlguard.Denial
		var pe *sqlguard.ParseError
		switch {
		case errors.As(err, &d):
			st.denied++
			st.denyReasons[fzQuoted.ReplaceAllString(d.Reason, "_")]++
			return nil, nil, "barrado: " + d.Reason
		case errors.As(err, &pe):
			st.parseErr++
			return nil, nil, "parse: " + pe.Message
		}
		st.guardErr++
		if len(st.guardErrSamples) < 5 {
			st.guardErrSamples = append(st.guardErrSamples, fmt.Sprintf("%v :: %s", err, sql))
		}
		return nil, nil, "erro do guard: " + err.Error()
	}
	st.accepted++
	if len(v.Masks) > 0 {
		st.acceptedMasked++
	}
	for _, r := range v.Rules {
		if strings.HasSuffix(r.Name, ".pagamentos") || strings.HasSuffix(r.Name, ".contatos") {
			st.acceptedFiltered++
			break
		}
	}
	if e.conn == nil || e.conn.IsClosed() {
		e.reconnect(t)
	}
	ctx := context.Background()
	var res *run.Result
	if exec {
		st.acceptedExec++
		res, err = run.Exec(ctx, e.conn, e.policy, v.SQL, v.MaxRows, true)
	} else {
		res, err = run.Query(ctx, e.conn, e.policy, v.SQL, v.Cap)
	}
	if err != nil {
		var many *run.TooManyRows
		if errors.As(err, &many) {
			st.tooMany++
			return nil, v, "acima do max"
		}
		st.dbErr++
		code := "?"
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			code = pe.Code
			if (code == "42703" || code == "42P01" || code == "42702") && len(st.nameErrSamples) < 5 {
				st.nameErrSamples = append(st.nameErrSamples, fmt.Sprintf("%s %s :: %s", code, pe.Message, v.SQL))
			}
		}
		st.dbCodes[code]++
		if e.conn.IsClosed() {
			e.reconnect(t)
		}
		if len(e.oracle.scanText(err.Error())) > 0 {
			st.rawErrSentinel++
		}
		return e.oracle.checkErr(err), v, "erro do banco: " + run.SafeMessage(err)
	}
	f := e.oracle.check(res, v)
	if len(f) == 0 {
		st.clean++
	}
	return f, v, fmt.Sprintf("aceito (%d linhas)", len(res.Rows))
}

// fzSelfTest prova que o oráculo enxerga vazamentos antes de confiar num
// resultado limpo.
func fzSelfTest(t *testing.T, e *fzEnv) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, e.admin)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	rawQuery := func(sql string) *run.Result {
		res, err := run.Query(ctx, admin, e.policy, sql, 100)
		if err != nil {
			t.Fatalf("auto-teste %q: %v", sql, err)
		}
		return res
	}
	// 1. leitura crua de cada classe protegida precisa disparar
	for _, c := range []struct{ sql, want string }{
		{"SELECT cpf FROM clientes", "clientes.cpf"},
		{"SELECT email FROM clientes", "clientes.email"},
		{"SELECT telefone FROM clientes", "clientes.telefone"},
		{"SELECT nome FROM clientes", "clientes.nome"},
		{"SELECT documento FROM contatos", "contatos.documento"},
		{"SELECT apelido FROM contatos", "contatos.apelido"},
		{"SELECT telefone FROM contatos", "contatos.telefone"},
		{"SELECT obs FROM contatos", "contatos(linha escondida)"},
		{"SELECT ref FROM pagamentos", "pagamentos(linha escondida)"},
		{"SELECT id FROM pagamentos", "número de linha escondida"},
		{"SELECT concat('id=', id) FROM pagamentos", "número de linha escondida"},
		{"SELECT valor FROM pagamentos", "número de linha escondida"},
		{"SELECT id FROM contatos", "número de linha escondida"},
		{"SELECT actor FROM audit_log", "audit_log"},
		{"SELECT texto FROM notas", "notas"},
		{"SELECT left(email, 9) FROM clientes", "clientes.email"},
		{"SELECT upper(cpf) FROM clientes", "clientes.cpf"},
	} {
		f := e.oracle.check(rawQuery(c.sql), &sqlguard.Verdict{})
		found := false
		for _, x := range f {
			found = found || strings.Contains(x.detail, c.want)
		}
		if !found {
			t.Fatalf("auto-teste: %q sem máscara deveria vazar %s, achados: %+v", c.sql, c.want, f)
		}
	}
	// 2. o caminho guardado das tabelas liberadas sai limpo
	for _, sql := range []string{
		"SELECT * FROM clientes", "SELECT * FROM contatos", "SELECT * FROM pagamentos",
		"SELECT * FROM pedidos", "SELECT nome, count(*) FROM clientes GROUP BY nome",
		"SELECT c.email, k.apelido, k.telefone FROM clientes c JOIN contatos k ON k.cliente_id = c.id",
	} {
		v, err := e.guard.Check(sqlguard.CmdQuery, sql)
		if err != nil {
			t.Fatalf("auto-teste: %q barrado: %v", sql, err)
		}
		res, err := run.Query(ctx, e.conn, e.policy, v.SQL, v.Cap)
		if err != nil {
			t.Fatalf("auto-teste: %q: %v", sql, err)
		}
		if f := e.oracle.check(res, v); len(f) > 0 {
			t.Fatalf("auto-teste: %q guardado não deveria vazar: %+v", sql, f)
		}
	}
	// 3. máscara deslocada uma posição precisa disparar
	v, err := e.guard.Check(sqlguard.CmdQuery, "SELECT id, email, cidade FROM clientes")
	if err != nil || len(v.Masks) != 1 {
		t.Fatalf("auto-teste: verdict inesperado: %v %+v", err, v)
	}
	res, err := run.Query(ctx, e.conn, e.policy, v.SQL, v.Cap)
	if err != nil {
		t.Fatal(err)
	}
	v.Masks[0].Index++
	if f := e.oracle.check(res, v); len(f) == 0 {
		t.Fatal("auto-teste: máscara na posição errada não disparou")
	}
	// 4. máscara mais fraca (hash no lugar de redact) e valor transformado
	v, _ = e.guard.Check(sqlguard.CmdQuery, "SELECT telefone FROM clientes")
	res, _ = run.Query(ctx, e.conn, e.policy, v.SQL, v.Cap)
	v.Masks[0].Mode = policy.MaskPartial
	if f := e.oracle.check(res, v); len(f) == 0 || !strings.HasPrefix(f[0].class, "mascara-fraca") {
		t.Fatalf("auto-teste: máscara mais fraca não disparou: %+v", f)
	}
	res = rawQuery("SELECT substring(email FROM 3) FROM clientes")
	if f := e.oracle.check(res, &sqlguard.Verdict{Masks: []sqlguard.OutputMask{{Index: 0, Mode: policy.MaskPartial}}}); len(f) == 0 {
		t.Fatal("auto-teste: valor transformado antes da máscara não disparou")
	}
	// 5. erro do banco com valor escondido
	// (o texto cru precisa disparar; o que a IA vê passa por run.SafeMessage)
	if _, err := run.Query(ctx, admin, e.policy, "SELECT ref::int FROM pagamentos WHERE id = 97001", 1); err == nil || len(e.oracle.scanText(err.Error())) == 0 {
		t.Fatalf("auto-teste: erro com valor escondido não disparou: %v", err)
	}
}
