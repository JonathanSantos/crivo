package policy

import (
	"reflect"
	"strings"
	"testing"
)

const header = "name t\nabout \"x\"\nenv dev\nconnect postgres://u@h/db?sslmode=verify-full\n"

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, diags := Parse("p", src)
	if diags.HasErrors() {
		t.Fatalf("política deveria parsear:\n%s", diags.Error())
	}
	return p
}

func TestVerbIsWrite(t *testing.T) {
	for v, want := range map[Verb]bool{Read: false, Insert: true, Update: true, Delete: true, "deny": false, "": false} {
		if v.IsWrite() != want {
			t.Errorf("%q.IsWrite() = %v", v, !want)
		}
	}
}

func TestTLSEncrypted(t *testing.T) {
	for mode, want := range map[string]bool{
		"verify-full": true, "verify-ca": true, "require": true,
		"prefer": false, "allow": false, "disable": false, "": false, "VERIFY-FULL": false,
	} {
		if TLSEncrypted(mode) != want {
			t.Errorf("TLSEncrypted(%q) = %v", mode, !want)
		}
	}
}

func TestDiagsErrors(t *testing.T) {
	// sslmode=require gera aviso; a regra repetida gera erro
	_, diags := Parse("p", "name t\nabout \"x\"\nenv dev\nconnect postgres://u@h/db?sslmode=require\npedidos read\npedidos deny\n")
	if !diags.HasErrors() {
		t.Fatal("esperava erro")
	}
	errs := diags.Errors()
	if len(errs) != 1 || len(diags) != 2 {
		t.Fatalf("esperava 1 erro entre 2 diagnósticos, veio %v", diags)
	}
	for _, d := range errs {
		if d.Severity != SevError {
			t.Errorf("Errors() devolveu aviso: %v", d)
		}
	}
	if got := diags.Error(); got != "p:6:1: erro: regra repetida para pedidos (primeira na linha 5)" {
		t.Errorf("Error() = %q", got)
	}

	// só avisos: nada de erro
	_, diags = Parse("p", "name t\nabout \"x\"\nenv dev\nconnect postgres://u@h/db?sslmode=require\npedidos read\n")
	if diags.HasErrors() || diags.Errors() != nil || diags.Error() != "" || len(diags) != 1 {
		t.Errorf("esperava só um aviso: %v", diags)
	}

	// Error() junta um erro por linha, sem os avisos
	_, diags = Parse("p", "## doc\nname T\nenv x\n")
	lines := strings.Split(diags.Error(), "\n")
	if len(lines) != len(diags.Errors()) || len(lines) < 3 {
		t.Errorf("Error() com %d linhas para %d erros: %q", len(lines), len(diags.Errors()), diags.Error())
	}
	if strings.Contains(diags.Error(), "aviso") {
		t.Errorf("Error() não deveria conter avisos: %q", diags.Error())
	}
}

// ident valida diretivas, colunas e máscaras: minúsculas, formato e presença.
func TestIdentErrors(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"functions Lower", `nome de função "Lower": use minúsculas`},
		{"functions 1abc", `nome de função inválido: "1abc"`},
		{"functions", "esperava nome de função"},
		{"functions lower,", "esperava nome de função"},
		{"schema Vendas", `schema "Vendas": use minúsculas`},
		{"schema", "esperava schema"},
		{"schema 9x", `schema inválido: "9x"`},
		{"schema pg_catalog", "é de catálogo"},
		{"pedidos read(Status)", `nome de coluna "Status": use minúsculas`},
		{"pedidos read()", "esperava nome de coluna"},
		{"pedidos read(1x)", `nome de coluna inválido: "1x"`},
		{"pedidos read(id, )", "esperava nome de coluna"},
		{"pedidos read except(Cpf)", "use minúsculas"},
		{"clientes read mask(Email: partial)", "use minúsculas"},
		{"clientes read mask(: partial)", "esperava nome de coluna"},
		{"Pedidos read", `tabela "Pedidos": use minúsculas`},
	}
	for _, c := range cases {
		_, diags := Parse("p", header+c.line+"\n")
		if !diags.HasErrors() {
			t.Errorf("%q: esperava erro", c.line)
			continue
		}
		if !strings.Contains(diags.Error(), c.want) {
			t.Errorf("%q: erros %q não contêm %q", c.line, diags.Error(), c.want)
		}
	}
	// identificadores válidos passam
	p := mustParse(t, header+"functions minha_func, _f2\nschema app_1\npedidos read(id, cliente_id)\n")
	if !reflect.DeepEqual(p.Functions, []string{"minha_func", "_f2"}) || p.Schema != "app_1" {
		t.Errorf("functions=%v schema=%q", p.Functions, p.Schema)
	}
}

const accessorsSrc = `name loja
about "x"
env preprod
connect postgres://u@h/db?sslmode=verify-full
schema app

pedidos      read, update(status, observacao) max 20
clientes     read except(cpf) mask(email: partial, telefone: redact) limit 10
logs         read(id, msg), insert, delete
pagamentos   read where status <> 'estornado'
audit_*      deny
outro.coisas insert
`

func TestRuleAndActionAccessors(t *testing.T) {
	p := mustParse(t, accessorsSrc)
	byName := map[string]*Rule{}
	for _, r := range p.Rules {
		byName[r.Label()] = r
	}
	ped, cli, logs, pag, audit, outro := byName["pedidos"], byName["clientes"], byName["logs"], byName["pagamentos"], byName["audit_*"], byName["outro.coisas"]
	if ped == nil || cli == nil || logs == nil || pag == nil || audit == nil || outro == nil {
		t.Fatalf("regras: %v", byName)
	}

	// Verbs / HasWrite / Action
	verbs := []struct {
		r     *Rule
		verbs []string
		write bool
	}{
		{ped, []string{"read", "update"}, true},
		{cli, []string{"read"}, false},
		{logs, []string{"read", "insert", "delete"}, true},
		{audit, nil, false},
		{outro, []string{"insert"}, true},
	}
	for _, c := range verbs {
		if got := c.r.Verbs(); !reflect.DeepEqual(got, c.verbs) {
			t.Errorf("%s.Verbs() = %v, esperava %v", c.r.Label(), got, c.verbs)
		}
		if c.r.HasWrite() != c.write {
			t.Errorf("%s.HasWrite() = %v", c.r.Label(), !c.write)
		}
	}
	if ped.Action(Update) == nil || ped.Action(Delete) != nil || ped.Action(Read).Verb != Read {
		t.Error("Action em pedidos")
	}
	// deny e regra nil nunca devolvem ação (fail closed)
	if audit.Action(Read) != nil || (*Rule)(nil).Action(Read) != nil {
		t.Error("deny/nil não podem ter ação")
	}

	// AllowsCol / AllowedCols
	all := []string{"id", "nome", "cpf", "email", "telefone"}
	cr := cli.Action(Read)
	if got := cr.AllowedCols(all); !reflect.DeepEqual(got, []string{"id", "nome", "email", "telefone"}) {
		t.Errorf("except(cpf): %v", got)
	}
	lr := logs.Action(Read)
	if got := lr.AllowedCols([]string{"msg", "x", "id"}); !reflect.DeepEqual(got, []string{"msg", "id"}) {
		t.Errorf("read(id, msg) mantém a ordem da tabela: %v", got)
	}
	if got := ped.Action(Read).AllowedCols(all); !reflect.DeepEqual(got, all) {
		t.Errorf("read sem lista libera tudo: %v", got)
	}
	var nilAct *Action
	cols := []struct {
		a    *Action
		col  string
		want bool
	}{
		{nilAct, "id", false}, // sem ação, nada liberado
		{cr, "cpf", false}, {cr, "email", true}, {cr, "inexistente", true},
		{lr, "id", true}, {lr, "msg", true}, {lr, "outra", false},
		{ped.Action(Update), "status", true}, {ped.Action(Update), "total", false},
	}
	for _, c := range cols {
		if c.a.AllowsCol(c.col) != c.want {
			t.Errorf("AllowsCol(%q) em %v = %v", c.col, c.a, !c.want)
		}
	}
	if nilAct.AllowedCols(all) != nil {
		t.Error("ação nil não libera colunas")
	}

	// MaskOf
	for col, want := range map[string]MaskMode{"email": MaskPartial, "telefone": MaskRedact, "nome": "", "cpf": ""} {
		if got := cr.MaskOf(col); got != want {
			t.Errorf("MaskOf(%q) = %q", col, got)
		}
	}
	if nilAct.MaskOf("email") != "" {
		t.Error("MaskOf em ação nil")
	}

	// MaxRows: padrão 50 quando max não foi dado
	if ped.Action(Update).MaxRows() != 20 || logs.Action(Delete).MaxRows() != DefaultMaxRows || DefaultMaxRows != 50 {
		t.Error("MaxRows")
	}

	// ColsText / String reconstroem o texto da política
	texts := []struct {
		a         *Action
		cols, str string
	}{
		{ped.Action(Read), "", "read"},
		{ped.Action(Update), "(status, observacao)", "update(status, observacao) max 20"},
		{cr, " except(cpf)", "read except(cpf) mask(email: partial, telefone: redact) limit 10"},
		{lr, "(id, msg)", "read(id, msg)"},
		{pag.Action(Read), "", "read where status <> 'estornado'"},
		{&Action{Verb: Read, Masks: []Mask{{Column: "a", Mode: MaskHash}}, Limit: 3, Where: "a > 1"}, "", "read mask(a: hash) limit 3 where a > 1"},
	}
	for _, c := range texts {
		if got := c.a.ColsText(); got != c.cols {
			t.Errorf("ColsText() = %q, esperava %q", got, c.cols)
		}
		if got := c.a.String(); got != c.str {
			t.Errorf("String() = %q, esperava %q", got, c.str)
		}
	}
}

func TestPolicyAccessors(t *testing.T) {
	p := mustParse(t, accessorsSrc)
	if !p.HasRead() || !p.HasWrite() {
		t.Error("HasRead/HasWrite")
	}
	readOnly := mustParse(t, header+"pedidos read\naudit_* deny\n")
	if !readOnly.HasRead() || readOnly.HasWrite() {
		t.Error("política só de leitura")
	}
	writeOnly := mustParse(t, header+"pedidos insert\n")
	if writeOnly.HasRead() || !writeOnly.HasWrite() {
		t.Error("política só de escrita")
	}
	denyOnly := mustParse(t, header+"audit_* deny\n")
	if denyOnly.HasRead() || denyOnly.HasWrite() {
		t.Error("política só com deny")
	}

	// Schemas: padrão primeiro, depois os citados, sem repetir
	if got := p.Schemas(); !reflect.DeepEqual(got, []string{"app", "outro"}) {
		t.Errorf("Schemas() = %v", got)
	}
	multi := mustParse(t, header+"a.x read\nb.y read\na.z read\npublic.w read\n")
	if got := multi.Schemas(); !reflect.DeepEqual(got, []string{"public", "a", "b"}) {
		t.Errorf("Schemas() = %v", got)
	}

	// RuleRef usa a linha da regra
	for _, r := range p.Rules {
		if r.Pattern == "clientes" && p.RuleRef(r) != "p:8" {
			t.Errorf("RuleRef = %q", p.RuleRef(r))
		}
	}

	// EnvLabel
	for env, want := range map[string]string{"dev": "desenvolvimento", "preprod": "pré-produção", "prod": "produção", "outro": "outro", "": ""} {
		q := &Policy{Env: env}
		if q.EnvLabel() != want {
			t.Errorf("EnvLabel(%q) = %q", env, q.EnvLabel())
		}
	}

	// Numbered: largura pelo total de linhas, CR removido, sem linha vazia final
	src := strings.Repeat("x\n", 9) + "dez\r\n\n"
	n := (&Policy{Source: src}).Numbered()
	lines := strings.Split(strings.TrimSuffix(n, "\n"), "\n")
	if len(lines) != 10 || lines[0] != " 1  x" || lines[9] != "10  dez" {
		t.Errorf("Numbered() = %q", n)
	}
	if (&Policy{Source: "a"}).Numbered() != "1  a\n" {
		t.Errorf("Numbered() de uma linha = %q", (&Policy{Source: "a"}).Numbered())
	}
}

func TestMatchingTables(t *testing.T) {
	p := mustParse(t, header+"audit_* deny\naudit_log read\napp_* read\n*_tmp deny\nother.app_* read\n")
	rules := map[string]*Rule{}
	for _, r := range p.Rules {
		rules[r.Label()] = r
	}
	tables := []string{"audit_x", "audit_log", "app_b", "app_a", "app_tmp", "x_tmp", "pedidos", "pg_app"}
	cases := []struct {
		rule   string
		schema string
		want   []string
	}{
		{"audit_*", "public", []string{"audit_x"}},
		{"audit_log", "public", []string{"audit_log"}},
		// app_tmp casa com app_* e *_tmp: prefixo maior (app_) vence o deny
		{"app_*", "public", []string{"app_a", "app_b", "app_tmp"}},
		{"*_tmp", "public", []string{"x_tmp"}},
		{"other.app_*", "other", []string{"app_a", "app_b", "app_tmp"}},
		{"app_*", "other", nil},
	}
	for _, c := range cases {
		got := p.MatchingTables(rules[c.rule], c.schema, tables)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("MatchingTables(%s, %s) = %v, esperava %v", c.rule, c.schema, got, c.want)
		}
	}
}

// Precedência documentada: nome exato vence padrão; entre padrões, o maior
// prefixo literal vence; empate de prefixo → deny vence. A ordem das regras
// no arquivo não pode mudar o resultado.
func TestResolvePrecedenceOrders(t *testing.T) {
	cases := []struct {
		name  string
		rules []string
		table string
		want  string // padrão da regra vencedora; "" = nenhuma
		deny  bool
	}{
		{"exato antes do padrão", []string{"audit_log read", "audit_* deny"}, "audit_log", "audit_log", false},
		{"exato depois do padrão", []string{"audit_* deny", "audit_log read"}, "audit_log", "audit_log", false},
		{"exato deny vence padrão read", []string{"app_* read", "app_x deny"}, "app_x", "app_x", true},
		{"prefixo maior allow vence deny curto", []string{"*_x deny", "app_* read"}, "app_x", "app_*", false},
		{"prefixo maior allow vence deny curto (invertido)", []string{"app_* read", "*_x deny"}, "app_x", "app_*", false},
		{"prefixo maior deny vence allow curto", []string{"a* read", "app_* deny"}, "app_x", "app_*", true},
		{"empate: deny vence (deny primeiro)", []string{"x*_y deny", "x* read"}, "x_y", "x*_y", true},
		{"empate: deny vence (deny depois)", []string{"x* read", "x*_y deny"}, "x_y", "x*_y", true},
		{"curinga total como fallback", []string{"* deny", "pedidos read"}, "outra", "*", true},
		{"curinga total perde para exato", []string{"* deny", "pedidos read"}, "pedidos", "pedidos", false},
		{"padrão do meio", []string{"a*z read"}, "abcz", "a*z", false},
		{"padrão do meio não casa", []string{"a*z read"}, "abc", "", false},
		{"sem regra", []string{"pedidos read"}, "clientes", "", false},
		{"catálogo sempre bloqueado", []string{"pg_* read", "* read"}, "pg_class", "", false},
	}
	for _, c := range cases {
		p, diags := Parse("p", header+strings.Join(c.rules, "\n")+"\n")
		if diags.HasErrors() {
			t.Fatalf("%s: %v", c.name, diags.Error())
		}
		r := p.Resolve("", c.table)
		got, deny := "", false
		if r != nil {
			got, deny = r.Pattern, r.Deny
		}
		if got != c.want || deny != c.deny {
			t.Errorf("%s: Resolve(%q) = %q deny=%v, esperava %q deny=%v", c.name, c.table, got, deny, c.want, c.deny)
		}
	}
}

func TestResolveSchemas(t *testing.T) {
	p := mustParse(t, header+"schema app\npedidos read\nrel.pedidos deny\nrel.t* read\n")
	cases := []struct {
		schema, table string
		want          string // Label da regra; "" = nenhuma
	}{
		{"", "pedidos", "pedidos"}, // schema vazio = schema padrão da política
		{"app", "pedidos", "pedidos"},
		{"public", "pedidos", ""}, // regra sem schema vale só no padrão (app)
		{"rel", "pedidos", "rel.pedidos"},
		{"rel", "tx", "rel.t*"},
		{"", "tx", ""},
		{"pg_catalog", "pedidos", ""},
		{"information_schema", "tables", ""},
		{"pg_temp_1", "pedidos", ""},
	}
	for _, c := range cases {
		r := p.Resolve(c.schema, c.table)
		got := ""
		if r != nil {
			got = r.Label()
		}
		if got != c.want {
			t.Errorf("Resolve(%q, %q) = %q, esperava %q", c.schema, c.table, got, c.want)
		}
	}
}
