package sqlguard

import (
	"errors"
	"os"
	"strings"
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"crivo/internal/policy"
	"crivo/internal/schema"
)

// testSchema espelha o schema de exemplo usado nos testes de integração.
func testSchema() *schema.Schema {
	cols := func(names ...string) []schema.Column {
		out := make([]schema.Column, len(names))
		for i, n := range names {
			out[i] = schema.Column{Name: n, Type: "text"}
		}
		return out
	}
	s := &schema.Schema{Tables: map[string]*schema.Table{}}
	add := func(name string, c ...string) {
		s.Tables["public."+name] = &schema.Table{Schema: "public", Name: name, Kind: "table", Columns: cols(c...), PrimaryKey: []string{"id"}}
	}
	add("pedidos", "id", "cliente_id", "status", "total", "observacao", "criado_em")
	add("pedido_itens", "id", "pedido_id", "produto_id", "quantidade", "preco")
	add("produtos", "id", "nome", "preco", "ativo")
	add("clientes", "id", "nome", "cpf", "email", "telefone", "cidade")
	add("pagamentos", "id", "pedido_id", "valor", "status", "pago_em")
	add("audit_log", "id", "acao")
	add("usuarios", "id", "login")
	return s
}

func testGuard(t testing.TB) *Guard {
	t.Helper()
	src, err := os.ReadFile("../../examples/vendas.crivo")
	if err != nil {
		t.Fatal(err)
	}
	p, diags := policy.Parse("policy", string(src))
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	g, err := New(p, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGuardSpecCases(t *testing.T) {
	g := testGuard(t)
	cases := []struct {
		cmd  Command
		sql  string
		ok   bool
		want string // trecho do SQL reescrito (aceito) ou do motivo (barrado)
	}{
		{CmdQuery, "SELECT id, status FROM pedidos", true, "SELECT id, status FROM pedidos LIMIT 501"},
		{CmdQuery, "SELECT * FROM clientes", true, "SELECT clientes.id, clientes.nome, clientes.email, clientes.telefone, clientes.cidade FROM clientes LIMIT 501"},
		{CmdQuery, "SELECT cpf FROM clientes", false, `coluna "cpf" não está liberada`},
		{CmdQuery, "SELECT id FROM clientes WHERE cpf = '1'", false, `coluna "cpf" não está liberada`},
		{CmdQuery, "SELECT upper(email) FROM clientes", false, `mascarada (partial)`},
		{CmdQuery, "SELECT id FROM clientes ORDER BY email", false, `mascarada (partial)`},
		{CmdQuery, "SELECT * FROM pagamentos p", true, "FROM (SELECT id, pedido_id, valor, status, pago_em FROM pagamentos WHERE status <> 'estornado') p"},
		{CmdQuery, "SELECT * FROM audit_log", false, "negada pela política"},
		{CmdQuery, "SELECT * FROM usuarios", false, "não existe para a IA"},
		{CmdQuery, "SELECT * FROM pg_user", false, "catálogo"},
		{CmdQuery, "SELECT 1; DROP TABLE pedidos", false, "único statement"},
		{CmdQuery, "WITH x AS (DELETE FROM pedidos RETURNING *) SELECT * FROM x", false, "escrita dentro de CTE"},
		{CmdQuery, "SELECT nextval('pedidos_id_seq')", false, `"nextval" é sempre bloqueada`},
		{CmdQuery, "SELECT pg_sleep(10)", false, `"pg_sleep" é sempre bloqueada`},
		{CmdQuery, "SELECT * INTO copia FROM pedidos", false, "INTO"},
		{CmdQuery, "SELECT * FROM pedidos FOR UPDATE", false, "FOR UPDATE"},
		{CmdQuery, "SELECT id FROM pedidos p JOIN clientes c ON c.id = p.cliente_id", false, `coluna "id" é ambígua`},
		{CmdQuery, "SELECT * FROM pedidos LIMIT 10000", true, "LIMIT 501"},
		{CmdExec, "UPDATE pedidos SET status = 'pago' WHERE id = 1", true, "UPDATE pedidos SET status = 'pago' WHERE id = 1"},
		{CmdExec, "UPDATE pedidos SET total = 0 WHERE id = 1", false, `coluna "total" não pode ser alterada`},
		{CmdExec, "UPDATE pedidos SET status = 'pago'", false, "UPDATE sem WHERE"},
		{CmdExec, "DELETE FROM pedido_itens WHERE 1 = 1", false, "precisa usar ao menos uma coluna"},
		{CmdExec, "INSERT INTO pedido_itens VALUES (1, 2, 3)", false, "lista de colunas"},
		{CmdExec, "INSERT INTO produtos (nome) VALUES ('x')", false, `não permite insert`},
		{CmdQuery, "UPDATE pedidos SET status = 'x' WHERE id = 1", false, "query só aceita SELECT"},
		{CmdQuery, "select ID from PEDIDOS", true, "SELECT id FROM pedidos LIMIT 501"},

		// extras
		{CmdQuery, "SELECT email FROM clientes", true, "SELECT email FROM clientes LIMIT 501"},
		{CmdQuery, "SELECT p.id, c.email FROM pedidos p JOIN clientes c ON c.id = p.cliente_id", true, "LIMIT 501"},
		{CmdQuery, "SELECT c FROM clientes c", false, "linha inteira"},
		{CmdQuery, "SELECT row_to_json(c) FROM clientes c", false, `"row_to_json" fora da allowlist`},
		{CmdQuery, "SELECT id FROM clientes WHERE email LIKE 'a%'", false, "mascarada"},
		{CmdQuery, "SELECT email FROM clientes ORDER BY 1", false, "mascarada"},
		{CmdQuery, "SELECT email AS e FROM clientes ORDER BY e", false, "mascarada"},
		{CmdQuery, "SELECT e FROM (SELECT email AS e FROM clientes) s", true, "LIMIT 501"},
		{CmdQuery, "SELECT e FROM (SELECT email AS e FROM clientes) s WHERE e = 'x'", false, "mascarada"},
		{CmdQuery, "SELECT id FROM clientes WHERE 'a@b' IN (SELECT email FROM clientes)", false, "mascarada"},
		{CmdQuery, "SELECT (SELECT email FROM clientes LIMIT 1)", false, "mascarada"},
		{CmdQuery, "SELECT email FROM clientes UNION SELECT 'x'", false, "UNION"},
		{CmdQuery, "SELECT email FROM clientes UNION ALL SELECT nome FROM clientes", false, "mesma posição"},
		{CmdQuery, "SELECT email FROM clientes UNION ALL SELECT 'alvo@x.com'", false, "mesma posição"},
		{CmdQuery, "SELECT email FROM clientes UNION ALL VALUES ('a@x.com'), ('b@x.com')", false, "mesma posição"},
		{CmdQuery, "SELECT e FROM (SELECT email AS e FROM clientes UNION ALL SELECT 'x') s", false, "mesma posição"},
		{CmdQuery, "SELECT email, count(*) FROM clientes GROUP BY email UNION ALL SELECT 'x', 0", false, "mascarada"},
		{CmdQuery, "SELECT email FROM clientes WHERE cidade = 'SP' UNION ALL SELECT c.email FROM clientes c WHERE c.cidade = 'RJ'", true, "UNION ALL"},
		{CmdQuery, "SELECT nome FROM clientes UNION ALL SELECT 'x'", true, "UNION ALL"},
		{CmdQuery, "WITH x AS (SELECT * FROM clientes) SELECT * FROM x", true, "x.email"},
		{CmdQuery, "SELECT * FROM pedidos WHERE id = $1", false, "parâmetros"},
		{CmdQuery, "SELECT current_user", false, "função de sessão"},
		{CmdQuery, "SELECT 'pg_user'::regclass", false, `tipo "regclass"`},
		{CmdQuery, "SELECT status, count(*) FROM pedidos GROUP BY status ORDER BY 2 DESC LIMIT 10", true, "LIMIT 11"},
		{CmdQuery, "SELECT p.status, count(*) FROM pagamentos p GROUP BY 1", true, "'estornado') p GROUP BY 1"},
		{CmdQuery, "SELECT n FROM generate_series(1, 3) AS g(n)", true, "generate_series"},
		{CmdQuery, "SELECT date_trunc('day', criado_em::timestamp), count(*) FROM pedidos GROUP BY 1", true, "date_trunc"},
		{CmdQuery, "SELECT trim(nome), extract(year FROM now()) FROM produtos", true, "LIMIT 501"},
		{CmdQuery, "EXPLAIN SELECT 1", false, "EXPLAIN"},
		{CmdQuery, "COPY pedidos TO '/tmp/x'", false, "COPY"},
		{CmdQuery, "SET search_path = x", false, "SET"},
		{CmdQuery, "SELECT * FROM pedidos p JOIN pedido_itens i USING (id)", true, "USING (id)"},
		{CmdQuery, "SELECT id FROM pedidos JOIN pedido_itens USING (id)", true, "LIMIT 501"},
		{CmdQuery, "SELECT pi.quantidade FROM pedido_itens pi WHERE EXISTS (SELECT * FROM clientes c WHERE c.id = pi.pedido_id)", true, "EXISTS"},
		{CmdQuery, "SELECT * FROM public.pagamentos", true, "FROM (SELECT id, pedido_id, valor, status, pago_em FROM public.pagamentos WHERE status <> 'estornado') pagamentos"},
		{CmdQuery, "SELECT id FROM pedidos LIMIT 20", true, "LIMIT 21"},
		{CmdQuery, "SELECT id FROM pedidos LIMIT (SELECT 1)", false, "precisa"},
		{CmdQuery, "SELECT id FROM pedidos OFFSET 10", true, "OFFSET 10"},
		{CmdQuery, "SELECT lower(login) FROM usuarios", false, "não existe para a IA"},
		{CmdQuery, "SELECT * FROM pedidos p, LATERAL (SELECT * FROM pagamentos x WHERE x.pedido_id = p.id) y", true, "LATERAL"},
		{CmdExec, "SELECT 1", false, "exec só aceita"},
		{CmdExec, "UPDATE pedidos SET status = 'pago' WHERE true", false, "precisa usar ao menos uma coluna"},
		{CmdExec, "UPDATE pedidos p SET status = 'pago' FROM pagamentos g WHERE g.pedido_id = p.id", true, "FROM (SELECT"},
		{CmdExec, "INSERT INTO pedido_itens (pedido_id, produto_id, quantidade) VALUES (1, 2, 3) RETURNING *", true, "RETURNING pedido_itens.id"},
		{CmdExec, "INSERT INTO pedido_itens (pedido_id) SELECT id FROM pedidos WHERE status = 'aberto'", true, "INSERT INTO pedido_itens"},
		{CmdExec, "INSERT INTO pedido_itens (pedido_id) SELECT email FROM clientes", false, "mascarada"},
		{CmdExec, "INSERT INTO pedido_itens (pedido_id) VALUES (1) ON CONFLICT DO NOTHING", true, "ON CONFLICT DO NOTHING"},
		{CmdExec, "INSERT INTO pedido_itens (pedido_id) VALUES (1) ON CONFLICT (id) DO UPDATE SET quantidade = 1", false, "DO UPDATE exige update"},
		{CmdExec, "DELETE FROM pedido_itens WHERE pedido_id = 7 RETURNING id", true, "RETURNING id"},
		{CmdExec, "DELETE FROM pedidos WHERE id = 1", false, "não permite delete"},
		{CmdExec, "UPDATE pedidos SET status = (SELECT cpf FROM clientes LIMIT 1) WHERE id = 1", false, "cpf"},
		{CmdQuery, "SELECT email, count(*) FROM clientes GROUP BY email", false, "mascarada"},
		{CmdQuery, "SELECT count(DISTINCT email) FROM clientes", false, "mascarada"},
	}
	for _, tc := range cases {
		v, err := g.Check(tc.cmd, tc.sql)
		if tc.ok {
			if err != nil {
				t.Errorf("%q: esperava aceito, veio %v", tc.sql, err)
				continue
			}
			if !strings.Contains(v.SQL, tc.want) {
				t.Errorf("%q: SQL reescrito %q não contém %q", tc.sql, v.SQL, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q: esperava barrado, veio aceito: %s", tc.sql, v.SQL)
			continue
		}
		var d *Denial
		if !errors.As(err, &d) {
			t.Errorf("%q: esperava *Denial, veio %T %v", tc.sql, err, err)
			continue
		}
		if !strings.Contains(d.Reason, tc.want) {
			t.Errorf("%q: motivo %q não contém %q", tc.sql, d.Reason, tc.want)
		}
	}
}

func TestMasksAndRules(t *testing.T) {
	g := testGuard(t)
	v, err := g.Check(CmdQuery, "SELECT p.id, c.email, c.telefone FROM pedidos p JOIN clientes c ON c.id = p.cliente_id")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Masks) != 2 || v.Masks[0].Index != 1 || v.Masks[0].Mode != policy.MaskPartial || v.Masks[1].Mode != policy.MaskRedact {
		t.Fatalf("máscaras inesperadas: %+v", v.Masks)
	}
	if len(v.Rules) != 2 || v.Rules[0].Rule.Pattern != "pedidos" || v.Rules[1].Rule.Pattern != "clientes" {
		t.Fatalf("regras inesperadas: %+v", v.Rules)
	}
	if v.Cap != 500 || v.CapByRequest {
		t.Fatalf("teto inesperado: %d %v", v.Cap, v.CapByRequest)
	}
}

func TestWriteFilterInjected(t *testing.T) {
	src := `name t
about "x"
env dev
connect postgres://u@h/db?sslmode=verify-full
pagamentos read where status <> 'estornado', update(status) where valor > 0, delete
`
	p, diags := policy.Parse("policy", src)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	g, err := New(p, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	v, err := g.Check(CmdExec, "UPDATE pagamentos g SET status = 'x' WHERE id = 1 OR id = 2")
	if err != nil {
		t.Fatal(err)
	}
	want := "WHERE (id = 1 OR id = 2) AND g.valor > 0 AND g.status <> 'estornado'"
	if !strings.Contains(v.SQL, want) {
		t.Fatalf("SQL %q não contém %q", v.SQL, want)
	}
	v, err = g.Check(CmdExec, "DELETE FROM pagamentos WHERE id = 1 AND valor < 3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.SQL, "WHERE id = 1 AND valor < 3 AND pagamentos.status <> 'estornado'") {
		t.Fatalf("SQL inesperado: %s", v.SQL)
	}
	if v.MaxRows != policy.DefaultMaxRows {
		t.Fatalf("max inesperado: %d", v.MaxRows)
	}
}

func FuzzGuard(f *testing.F) {
	for _, s := range []string{
		"SELECT id, status FROM pedidos", "SELECT * FROM clientes", "SELECT * FROM pagamentos p",
		"WITH x AS (SELECT * FROM clientes) SELECT * FROM x", "SELECT 1; DROP TABLE pedidos",
		"UPDATE pedidos SET status = 'pago' WHERE id = 1", "SELECT email FROM clientes UNION ALL SELECT nome FROM clientes",
		"SELECT * FROM pedidos p JOIN pedido_itens i USING (id)", "SELECT n FROM generate_series(1, 3) AS g(n)",
	} {
		f.Add(s)
	}
	g := testGuard(f)
	f.Fuzz(func(t *testing.T, sql string) {
		v, err := g.Check(CmdQuery, sql)
		if err != nil {
			return
		}
		// todo SQL aceito por query faz deparse para um único SelectStmt
		tree, err := pg_query.Parse(v.SQL)
		if err != nil || len(tree.Stmts) != 1 || tree.Stmts[0].Stmt.GetSelectStmt() == nil {
			t.Fatalf("SQL aceito %q não é um único SELECT: %v", v.SQL, err)
		}
		if v.Kind != KindSelect {
			t.Fatalf("query aceitou %s", v.Kind)
		}
	})
}
