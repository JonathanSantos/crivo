package sqlguard

import (
	"errors"
	"strings"
	"testing"

	"crivo/internal/policy"
)

func namedQuery(t *testing.T, line string) (*policy.Policy, *policy.NamedQuery) {
	t.Helper()
	src := "name t\nabout \"x\"\nenv dev\nconnect postgres://u@h/db?sslmode=verify-full\n" +
		"pedidos read\nclientes read except(cpf) mask(email: partial)\n" + line + "\n"
	p, diags := policy.Parse("policy", src)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	return p, p.Queries[0]
}

// O valor entra na árvore como constante: texto malicioso continua texto.
func TestBindKeepsValuesAsConstants(t *testing.T) {
	p, q := namedQuery(t, `query por_status(s text, minimo numeric, desde date, ativo bool, id int) "SELECT id FROM pedidos WHERE status = $1 AND total > $2 AND criado_em >= $3 AND (id = $5 OR $4)"`)
	sql, err := Bind(q, map[string]string{"s": "x' OR '1'='1", "minimo": "10.50", "desde": "2026-01-31", "ativo": "false", "id": "9007199254740993"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"status = 'x'' OR ''1''=''1'", "total > 10.50", "criado_em >= '2026-01-31'::date", "id = 9007199254740993", "OR false"} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL ligado sem %q:\n%s", want, sql)
		}
	}
	g, err := New(p, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Check(CmdQuery, sql); err != nil {
		t.Fatalf("a consulta ligada deveria passar no guard: %v", err)
	}
}

func TestBindRejectsBadArguments(t *testing.T) {
	_, q := namedQuery(t, `query q(id int, d date, v numeric, b bool) "SELECT id FROM pedidos WHERE id = $1 AND criado_em > $2 AND total > $3 AND $4"`)
	ok := map[string]string{"id": "1", "d": "2026-01-01", "v": "1", "b": "true"}
	cases := []struct {
		name  string
		patch map[string]string
		drop  string
		want  string
	}{
		{"inteiro com texto", map[string]string{"id": "1 OR 1=1"}, "", "id precisa ser um inteiro"},
		{"inteiro decimal", map[string]string{"id": "1.5"}, "", "id precisa ser um inteiro"},
		{"data em outro formato", map[string]string{"d": "01/02/2026"}, "", "d precisa ser uma data AAAA-MM-DD"},
		{"número com expoente", map[string]string{"v": "1e9"}, "", "v precisa ser um número"},
		{"número com expressão", map[string]string{"v": "1)--"}, "", "v precisa ser um número"},
		{"booleano inválido", map[string]string{"b": "talvez"}, "", "b precisa ser true ou false"},
		{"parâmetro faltando", nil, "d", "falta o parâmetro d (date)"},
		{"parâmetro sobrando", map[string]string{"x": "1"}, "", "não tem o parâmetro x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vals := map[string]string{}
			for k, v := range ok {
				vals[k] = v
			}
			for k, v := range c.patch {
				vals[k] = v
			}
			delete(vals, c.drop)
			_, err := Bind(q, vals)
			var pe *ParamError
			if !errors.As(err, &pe) || !strings.Contains(pe.Msg, c.want) {
				t.Fatalf("esperava ParamError com %q, veio %v", c.want, err)
			}
		})
	}
}

// A consulta nomeada não ganha privilégio: se citar coluna bloqueada, o
// guard recusa na hora de rodar (e o check já avisa antes).
func TestNamedQueryStillGoesThroughGuard(t *testing.T) {
	p, q := namedQuery(t, `query vaza(id int) "SELECT cpf FROM clientes WHERE id = $1"`)
	sql, err := Bind(q, map[string]string{"id": "1"})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := New(p, testSchema())
	if _, err := g.Check(CmdQuery, sql); err == nil || !strings.Contains(err.Error(), `coluna "cpf" não está liberada`) {
		t.Fatalf("esperava recusa do cpf, veio %v", err)
	}
}

func TestCheckNamedQueries(t *testing.T) {
	cases := map[string]string{
		`query w(id int) "UPDATE pedidos SET status = 'x' WHERE id = $1"`: "precisa ser um único SELECT",
		`query d() "SELECT 1; SELECT 2"`:                                  "precisa ser um único SELECT",
		`query f(id int) "SELECT id FROM pedidos WHERE id = $2"`:          "usa $2, mas declara 1 parâmetro(s)",
		`query s() "SELEC id FROM pedidos"`:                               "SQL inválido",
		`query u(a int, b int) "SELECT id FROM pedidos WHERE id = $1"`:    "o parâmetro b ($2) não é usado",
	}
	for line, want := range cases {
		p, _ := namedQuery(t, line)
		var all []string // Error() só junta os erros; aqui avisos contam também
		for _, d := range CheckNamedQueries(p) {
			all = append(all, d.String())
		}
		if got := strings.Join(all, "\n"); !strings.Contains(got, want) {
			t.Errorf("%s: esperava %q, veio %q", line, want, got)
		}
	}
	p, _ := namedQuery(t, `query ok(id int) "SELECT id FROM pedidos WHERE id = $1"`)
	if ds := CheckNamedQueries(p); len(ds) != 0 {
		t.Errorf("consulta válida com diagnóstico: %s", ds.Error())
	}
}

func TestNamedQuerySyntax(t *testing.T) {
	base := "name t\nabout \"x\"\nenv dev\nconnect postgres://u@h/db?sslmode=verify-full\npedidos read\n"
	bad := map[string]string{
		`query sem_parenteses "SELECT 1"`:                "lista de parâmetros",
		`query t(id inteiro) "SELECT 1"`:                 "tipo de parâmetro desconhecido",
		`query t(id int, id int) "SELECT $1"`:            "parâmetro \"id\" repetido",
		`query t() SELECT 1`:                             "aspas",
		`query t() ""`:                                   "precisa de um SELECT",
		"query t() \"SELECT 1\"\nquery t() \"SELECT 2\"": "consulta \"t\" repetida",
	}
	for line, want := range bad {
		_, diags := policy.Parse("policy", base+line+"\n")
		if !diags.HasErrors() || !strings.Contains(diags.Error(), want) {
			t.Errorf("%s: esperava %q, veio %q", line, want, diags.Error())
		}
	}
	p, diags := policy.Parse("policy", base+"## Pedidos de um cliente\nquery do_cliente(cliente_id int) \"SELECT id FROM pedidos WHERE cliente_id = $1\"\n")
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	q := p.Query("do_cliente")
	if q == nil || q.Doc != "Pedidos de um cliente" || len(q.Params) != 1 || q.Params[0].Type != policy.ParamInt {
		t.Fatalf("consulta mal lida: %+v", q)
	}
}
