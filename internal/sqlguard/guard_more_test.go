package sqlguard

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"crivo/internal/policy"
)

// maskWant é a máscara esperada numa posição da saída.
type maskWant struct {
	index int
	mode  policy.MaskMode
}

// guardCase é um caso de Check. O zero de cmd é CmdQuery.
//
// Para casos aceitos, além do trecho do SQL reescrito, o helper confere
// sempre as máscaras de saída (nil = nenhuma) e quantas vezes o filtro de
// linha de pagamentos aparece no SQL (0 = nenhuma). Conferir só o SQL não
// basta: uma máscara pode sumir do Verdict sem mudar o texto reescrito.
type guardCase struct {
	cmd      Command
	sql      string
	ok       bool
	want     string // trecho do SQL reescrito (aceito) ou do motivo (barrado)
	masks    []maskWant
	filters  int  // ocorrências de "status <> 'estornado'" no SQL aceito
	parseErr bool // barrado pelo parser do Postgres (*ParseError), não por Denial
}

const pagamentosFilter = "status <> 'estornado'"

func runGuardCases(t *testing.T, g *Guard, cases []guardCase) {
	t.Helper()
	for _, c := range cases {
		v, err := g.Check(c.cmd, c.sql)
		if c.ok {
			if err != nil {
				t.Errorf("%q: esperava aceito, veio %T %v", c.sql, err, err)
				continue
			}
			if !strings.Contains(v.SQL, c.want) {
				t.Errorf("%q: SQL reescrito %q não contém %q", c.sql, v.SQL, c.want)
			}
			if n := strings.Count(v.SQL, pagamentosFilter); n != c.filters {
				t.Errorf("%q: filtro de linha aparece %d vezes, esperava %d: %s", c.sql, n, c.filters, v.SQL)
			}
			var got []maskWant
			for _, m := range v.Masks {
				got = append(got, maskWant{m.Index, m.Mode})
			}
			if !reflect.DeepEqual(got, c.masks) {
				t.Errorf("%q: máscaras %+v, esperava %+v", c.sql, got, c.masks)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q: esperava barrado, veio aceito: %s (máscaras %+v)", c.sql, v.SQL, v.Masks)
			continue
		}
		if c.parseErr {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Errorf("%q: esperava *ParseError, veio %T %v", c.sql, err, err)
			} else if !strings.Contains(pe.Message, c.want) {
				t.Errorf("%q: mensagem %q não contém %q", c.sql, pe.Message, c.want)
			}
			continue
		}
		var d *Denial
		if !errors.As(err, &d) {
			// erro interno ou "ainda pede reescritas" é bug, não recusa esperada
			t.Errorf("%q: esperava *Denial, veio %T %v", c.sql, err, err)
			continue
		}
		if !strings.Contains(d.Reason, c.want) {
			t.Errorf("%q: motivo %q não contém %q", c.sql, d.Reason, c.want)
		}
	}
}

// customGuard monta um Guard sobre testSchema com uma política em texto.
func customGuard(t *testing.T, rules string) *Guard {
	t.Helper()
	src := "name t\nabout \"x\"\nenv dev\nconnect postgres://u@h/db?sslmode=verify-full\n" + rules
	p, diags := policy.Parse("policy", src)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	g, err := New(p, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

const (
	notAllowed = "não está liberada"
	masked     = "é mascarada (partial)"
	redacted   = "é mascarada (redact)"
)

var (
	emailMask    = []maskWant{{0, policy.MaskPartial}}
	clientesStar = []maskWant{{2, policy.MaskPartial}, {3, policy.MaskRedact}}
)

func TestGroupingSets(t *testing.T) {
	runGuardCases(t, testGuard(t), []guardCase{
		// formas aceitas: o conteúdo de cada grouping set passa por groupItem
		{sql: "SELECT cidade, count(*) FROM clientes GROUP BY ROLLUP (cidade)", ok: true, want: "GROUP BY ROLLUP (cidade) LIMIT 501"},
		{sql: "SELECT status, cliente_id, count(*) FROM pedidos GROUP BY CUBE (status, cliente_id)", ok: true, want: "GROUP BY CUBE (status, cliente_id)"},
		{sql: "SELECT cidade, nome, count(*) FROM clientes GROUP BY GROUPING SETS ((cidade), (nome), ())", ok: true, want: "GROUPING SETS (cidade, nome, ())"},
		{sql: "SELECT cidade, count(*) FROM clientes GROUP BY ROLLUP (1)", ok: true, want: "ROLLUP (1)"},
		{sql: "SELECT p.status, count(*) FROM pagamentos p GROUP BY ROLLUP (p.status)", ok: true, want: "GROUP BY ROLLUP (p.status)", filters: 1},

		// cpf bloqueado não pode ser agrupado: o agrupamento revela os valores
		{sql: "SELECT count(*) FROM clientes GROUP BY ROLLUP (cpf)", want: notAllowed},
		{sql: "SELECT count(*) FROM clientes GROUP BY CUBE (cidade, cpf)", want: notAllowed},
		{sql: "SELECT count(*) FROM clientes GROUP BY GROUPING SETS ((cidade), (cpf))", want: notAllowed},
		{sql: "SELECT count(*) FROM clientes GROUP BY GROUPING SETS (ROLLUP (cidade, cpf))", want: notAllowed},
		{sql: "SELECT count(*) FROM clientes c GROUP BY ROLLUP (c.cpf)", want: notAllowed},
		{sql: "SELECT count(*) FROM clientes GROUP BY ROLLUP (length(cpf))", want: notAllowed},
		{sql: "SELECT DISTINCT ON (cpf) id FROM clientes", want: notAllowed},

		// email (partial) só sai nu na lista; agrupar vira oráculo de igualdade
		{sql: "SELECT email, count(*) FROM clientes GROUP BY ROLLUP (email)", want: masked},
		{sql: "SELECT email, count(*) FROM clientes GROUP BY CUBE (cidade, email)", want: masked},
		{sql: "SELECT count(*) FROM clientes GROUP BY GROUPING SETS ((cidade), (email))", want: masked},
		{sql: "SELECT count(*) FROM clientes GROUP BY GROUPING SETS (CUBE (cidade, email))", want: masked},
		{sql: "SELECT email, count(*) FROM clientes GROUP BY ROLLUP (1)", want: masked},      // por posição
		{sql: "SELECT email AS e, count(*) FROM clientes GROUP BY ROLLUP (e)", want: masked}, // por nome da saída
		{sql: "SELECT count(*) FROM clientes GROUP BY ROLLUP (lower(email))", want: masked},  // expressão
		{sql: "SELECT telefone, count(*) FROM clientes GROUP BY GROUPING SETS (telefone)", want: redacted},
		{sql: "SELECT DISTINCT ON (email) email FROM clientes", want: masked},
		{sql: "SELECT count(*) FROM clientes GROUP BY cidade HAVING max(email) > 'a'", want: masked},

		// GROUPING() não tem tratamento semântico: recusado como nó desconhecido
		{sql: "SELECT GROUPING(cidade), count(*) FROM clientes GROUP BY ROLLUP (cidade)", want: "não suportada pelo crivo: grouping_func"},
		{sql: "SELECT cidade, count(*) FROM clientes GROUP BY ROLLUP (3)", want: "posição 3 fora da lista"},
		{sql: "SELECT cidade, count(*) FROM clientes GROUP BY CUBE (0)", want: "posição 0 fora da lista"},
	})
}

// Com hash, agrupar é permitido (o valor não sai), mas filtrar/ordenar não.
// Também cobre o limit por tabela, que reduz o teto global.
func TestHashMaskAndTableLimit(t *testing.T) {
	g := customGuard(t, `clientes read except(cpf) mask(email: hash, telefone: redact)
produtos read limit 10
pedidos read
`)
	runGuardCases(t, g, []guardCase{
		{sql: "SELECT email, count(*) FROM clientes GROUP BY ROLLUP (email)", ok: true, want: "ROLLUP (email)", masks: []maskWant{{0, policy.MaskHash}}},
		{sql: "SELECT email, count(*) FROM clientes GROUP BY GROUPING SETS ((email), ())", ok: true, want: "GROUPING SETS", masks: []maskWant{{0, policy.MaskHash}}},
		{sql: "SELECT DISTINCT ON (email) email FROM clientes", ok: true, want: "DISTINCT ON (email)", masks: []maskWant{{0, policy.MaskHash}}},
		{sql: "SELECT count(DISTINCT email) FROM clientes", ok: true, want: "count(DISTINCT email)"},
		{sql: "SELECT id FROM clientes ORDER BY email", want: "mascarada (hash)"},
		{sql: "SELECT id FROM clientes WHERE email = 'a@b.com'", want: "mascarada (hash)"},
		{sql: "SELECT count(*) FROM clientes GROUP BY ROLLUP (lower(email))", want: "mascarada (hash)"},
		{sql: "SELECT row_number() OVER w FROM clientes WINDOW w AS (PARTITION BY email)", want: "mascarada (hash)"},
		{sql: "SELECT count(*) FROM clientes GROUP BY ROLLUP (telefone)", want: redacted},
		{sql: "SELECT count(*) FROM clientes GROUP BY ROLLUP (cpf)", want: notAllowed},

		// limit 10 na regra de produtos: SQL leva 11 (uma a mais para detectar truncamento)
		{sql: "SELECT nome FROM produtos", ok: true, want: "LIMIT 11"},
		{sql: "SELECT nome FROM produtos LIMIT 50", ok: true, want: "LIMIT 11"},
		{sql: "SELECT nome FROM produtos LIMIT 3", ok: true, want: "LIMIT 4"},
		{sql: "SELECT p.nome FROM pedidos x JOIN produtos p ON p.id = x.id", ok: true, want: "LIMIT 11"},
		{sql: "SELECT id FROM pedidos WHERE EXISTS (SELECT 1 FROM produtos)", ok: true, want: "LIMIT 11"},
	})
	v, err := g.Check(CmdQuery, "SELECT nome FROM produtos")
	if err != nil {
		t.Fatal(err)
	}
	if v.Cap != 10 || v.CapByRequest {
		t.Errorf("teto %d (por pedido=%v), esperava 10 da política", v.Cap, v.CapByRequest)
	}
}

func TestNamedWindow(t *testing.T) {
	runGuardCases(t, testGuard(t), []guardCase{
		{sql: "SELECT id, row_number() OVER w FROM pedidos WINDOW w AS (PARTITION BY status ORDER BY criado_em)", ok: true, want: "WINDOW w AS (PARTITION BY status ORDER BY criado_em)"},
		{sql: "SELECT id, sum(total) OVER (w ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM pedidos WINDOW w AS (ORDER BY id)", ok: true, want: "OVER (w ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)"},
		{sql: "SELECT count(*) OVER (ORDER BY criado_em::timestamp RANGE BETWEEN '1 day'::interval PRECEDING AND CURRENT ROW) FROM pedidos", ok: true, want: "RANGE BETWEEN '1 day'::interval PRECEDING"},
		{sql: "SELECT nome, rank() OVER w FROM clientes WINDOW w AS (PARTITION BY cidade), w2 AS (w ORDER BY nome)", ok: true, want: "w2 AS (w ORDER BY nome)"},
		{sql: "SELECT p.valor, sum(p.valor) OVER w FROM pagamentos p WINDOW w AS (PARTITION BY p.pedido_id)", ok: true, want: "WINDOW w AS (PARTITION BY p.pedido_id)", filters: 1},

		// a janela nomeada é processada à parte da chamada: precisa ser checada também
		{sql: "SELECT row_number() OVER w FROM clientes WINDOW w AS (PARTITION BY cpf)", want: notAllowed},
		{sql: "SELECT row_number() OVER w FROM clientes WINDOW w AS (ORDER BY cpf)", want: notAllowed},
		{sql: "SELECT row_number() OVER w FROM clientes WINDOW w AS (ORDER BY email)", want: masked},
		{sql: "SELECT row_number() OVER w FROM clientes WINDOW w AS (PARTITION BY lower(email))", want: masked},
		{sql: "SELECT rank() OVER w2 FROM clientes WINDOW w AS (PARTITION BY cidade), w2 AS (w ORDER BY email)", want: masked},
		{sql: "SELECT row_number() OVER (w ORDER BY email) FROM clientes WINDOW w AS (PARTITION BY cidade)", want: masked},
		{sql: "SELECT first_value(email) OVER w FROM clientes WINDOW w AS (ORDER BY id)", want: masked},
		{sql: "SELECT lag(cpf) OVER w FROM clientes WINDOW w AS (ORDER BY id)", want: notAllowed},
		// janela nomeada declarada mas não usada ainda é analisada
		{sql: "SELECT id FROM clientes WINDOW w AS (ORDER BY email)", want: masked},

		// offsets de moldura só como constante: subquery ou coluna seriam canal de dados
		{sql: "SELECT sum(id) OVER (ORDER BY id ROWS BETWEEN (SELECT 1) PRECEDING AND CURRENT ROW) FROM pedidos", want: "offset de janela precisa ser constante"},
		{sql: "SELECT sum(id) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND (SELECT length(cpf) FROM clientes LIMIT 1) FOLLOWING) FROM pedidos", want: "offset de janela precisa ser constante"},
		{sql: "SELECT sum(id) OVER w FROM pedidos WINDOW w AS (ORDER BY id ROWS BETWEEN id PRECEDING AND CURRENT ROW)", want: "offset de janela precisa ser constante"},
	})
}

func TestNaturalJoin(t *testing.T) {
	runGuardCases(t, testGuard(t), []guardCase{
		// colunas comuns: id, nome
		{sql: "SELECT * FROM clientes NATURAL JOIN produtos", ok: true, want: "clientes.cidade, produtos.id, produtos.nome, produtos.preco, produtos.ativo FROM clientes NATURAL JOIN produtos", masks: clientesStar},
		{sql: "SELECT id, nome FROM clientes NATURAL JOIN produtos", ok: true, want: "FROM clientes NATURAL JOIN produtos LIMIT 501"},
		{sql: "SELECT p.id, i.quantidade FROM pedidos p NATURAL JOIN pedido_itens i", ok: true, want: "NATURAL JOIN pedido_itens i"},
		{sql: "SELECT c.email FROM clientes c NATURAL LEFT JOIN produtos x", ok: true, want: "NATURAL LEFT JOIN produtos x", masks: emailMask},
		// pagamentos continua filtrado dentro do NATURAL JOIN
		{sql: "SELECT g.valor FROM pedido_itens i NATURAL JOIN pagamentos g", ok: true, want: "NATURAL JOIN (SELECT id, pedido_id, valor, status, pago_em FROM pagamentos WHERE status <> 'estornado') g", filters: 1},

		// NATURAL compara todas as colunas comuns, inclusive cpf (bloqueado) e
		// email (mascarado): seria oráculo de igualdade sem citar a coluna
		{sql: "SELECT c.id FROM clientes c NATURAL JOIN clientes d", want: `"c.cpf" não está liberada`},
		{sql: "SELECT c.id FROM clientes c NATURAL JOIN generate_series(1, 1) AS g(cpf)", want: `"c.cpf" não está liberada`},
		{sql: "SELECT c.id FROM clientes c NATURAL JOIN (SELECT '123' AS cpf) s", want: `"c.cpf" não está liberada`},
		{sql: "SELECT c.id FROM clientes c NATURAL JOIN (SELECT 'a@b.com' AS email) s", want: `"c.email" é mascarada`},
		{sql: "SELECT c.id FROM clientes c NATURAL LEFT JOIN generate_series(1, 1) AS g(email)", want: `"c.email" é mascarada`},
		{sql: "SELECT c.id FROM clientes c NATURAL FULL JOIN (SELECT '1199' AS telefone) s", want: `"c.telefone" é mascarada (redact)`},
		{sql: "SELECT 1 FROM (SELECT email AS e FROM clientes) x NATURAL JOIN (SELECT email AS e FROM clientes) y", want: `"x.e" é mascarada`},
		// coluna comum que aparece duas vezes num lado: o Postgres também recusa
		{sql: "SELECT 1 FROM (pedidos p JOIN pedido_itens i ON true) NATURAL JOIN produtos x", want: `coluna "id" do USING é ambígua`},
	})
}

func TestWithClause(t *testing.T) {
	runGuardCases(t, testGuard(t), []guardCase{
		// CTE com nome de tabela real a esconde: as colunas vêm da CTE
		{sql: "WITH clientes AS (SELECT id, nome FROM produtos) SELECT * FROM clientes", ok: true, want: "SELECT clientes.id, clientes.nome FROM clientes LIMIT 501"},
		// dentro da própria CTE (não recursiva) o nome ainda é a tabela real
		{sql: "WITH clientes AS (SELECT * FROM clientes) SELECT * FROM clientes", ok: true,
			want: "WITH clientes AS (SELECT clientes.id, clientes.nome, clientes.email, clientes.telefone, clientes.cidade FROM clientes)", masks: clientesStar},
		{sql: "WITH pagamentos AS (SELECT * FROM pagamentos) SELECT id FROM pagamentos", ok: true, want: "FROM (SELECT id, pedido_id, valor, status, pago_em FROM pagamentos WHERE status <> 'estornado') pagamentos)", filters: 1},
		// schema explícito ignora a CTE e precisa receber o filtro da tabela real
		{sql: "WITH pagamentos AS (SELECT 1 AS id) SELECT id FROM public.pagamentos", ok: true, want: "FROM (SELECT id, pedido_id, valor, status, pago_em FROM public.pagamentos WHERE status <> 'estornado') pagamentos", filters: 1},
		// sem RECURSIVE não há referência adiante: "a" lê a tabela real pedidos
		// (conferido no Postgres 16), então não há máscara a aplicar
		{sql: "WITH a AS (SELECT status FROM pedidos), pedidos AS (SELECT email AS status FROM clientes) SELECT status FROM a", ok: true, want: "SELECT status FROM a LIMIT 501"},
		{sql: "WITH x(a) AS (SELECT email FROM clientes) SELECT a FROM x", ok: true, want: "WITH x(a) AS (SELECT email FROM clientes) SELECT a FROM x", masks: emailMask},
		{sql: "WITH x AS MATERIALIZED (SELECT id FROM pedidos) SELECT id FROM x", ok: true, want: "WITH x AS MATERIALIZED (SELECT id FROM pedidos)"},
		{sql: "WITH x AS NOT MATERIALIZED (SELECT email FROM clientes) SELECT email FROM x", ok: true, want: "AS NOT MATERIALIZED", masks: emailMask},
		{sql: "WITH a AS (WITH b AS (SELECT id FROM pedidos) SELECT id FROM b) SELECT id FROM a", ok: true, want: "WITH a AS (WITH b AS (SELECT id FROM pedidos) SELECT id FROM b)"},
		{sql: "WITH a AS (SELECT id FROM pedidos), b AS (SELECT id FROM a) SELECT id FROM b", ok: true, want: "b AS (SELECT id FROM a)"},
		{sql: "SELECT e FROM (WITH x AS (SELECT email AS e FROM clientes) SELECT e FROM x) s", ok: true, want: "(WITH x AS (SELECT email AS e FROM clientes) SELECT e FROM x) s", masks: emailMask},

		// a origem da coluna atravessa CTEs, aliases e WITH aninhado
		{sql: "WITH clientes AS (SELECT cpf FROM clientes) SELECT * FROM clientes", want: notAllowed},
		{sql: "WITH clientes AS (SELECT id, email FROM clientes) SELECT id FROM clientes WHERE email LIKE 'a%'", want: masked},
		{sql: "WITH x(a) AS (SELECT email FROM clientes) SELECT a FROM x WHERE a = 'x'", want: `coluna "a" é mascarada`},
		{sql: "WITH x AS MATERIALIZED (SELECT cpf FROM clientes) SELECT 1 FROM x", want: notAllowed},
		{sql: "WITH x AS MATERIALIZED (SELECT email FROM clientes) SELECT upper(email) FROM x", want: masked},
		{sql: "WITH a AS (WITH b AS (SELECT email FROM clientes) SELECT email FROM b) SELECT 1 FROM a ORDER BY a.email", want: masked},
		{sql: "SELECT e FROM (WITH x AS (SELECT email AS e FROM clientes) SELECT e FROM x) s WHERE e = 'x'", want: masked},
		{sql: "SELECT id FROM clientes WHERE id IN (WITH x AS (SELECT id, email FROM clientes) SELECT id FROM x WHERE email = 'a')", want: masked},
		{sql: "SELECT (WITH x AS (SELECT cpf FROM clientes) SELECT 1 FROM x LIMIT 1)", want: notAllowed},
		// escopo: b só existe dentro de a; fora dele é uma tabela sem regra
		{sql: "WITH a AS (WITH b AS (SELECT id FROM pedidos) SELECT id FROM b) SELECT id FROM b", want: `tabela "b" não existe para a IA`},
		{sql: "WITH a AS (SELECT * FROM audit_log) SELECT 1 FROM a", want: "negada pela política"},
		{sql: "WITH x AS (INSERT INTO pedido_itens (pedido_id) VALUES (1) RETURNING id) SELECT * FROM x", want: "escrita dentro de CTE"},
		{sql: "WITH x AS (SELECT id FROM pedidos) SEARCH DEPTH FIRST BY id SET ord SELECT id FROM x", want: "SEARCH/CYCLE em CTE não é aceito"},
		{sql: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SEARCH BREADTH FIRST BY n SET ord SELECT n FROM r", want: "SEARCH/CYCLE em CTE não é aceito"},
		{sql: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) CYCLE n SET is_cycle USING path SELECT n FROM r", want: "SEARCH/CYCLE em CTE não é aceito"},

		// WITH em escrita (exec)
		{cmd: CmdExec, sql: "WITH x AS (SELECT id FROM pedidos WHERE status = 'aberto') UPDATE pedidos SET status = 'pago' WHERE id IN (SELECT id FROM x)", ok: true, want: "UPDATE pedidos SET status = 'pago' WHERE id IN (SELECT id FROM x)"},
		{cmd: CmdExec, sql: "WITH x AS (SELECT cpf FROM clientes) DELETE FROM pedido_itens WHERE pedido_id IN (SELECT 1 FROM x)", want: notAllowed},
		{cmd: CmdExec, sql: "WITH x AS (SELECT email FROM clientes) INSERT INTO pedido_itens (pedido_id) SELECT email FROM x", want: masked},
	})
}

func TestRecursiveCTE(t *testing.T) {
	runGuardCases(t, testGuard(t), []guardCase{
		{sql: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT n FROM r", ok: true, want: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT n FROM r LIMIT 501"},
		// a coluna mascarada pode circular nua, com a mesma origem nos dois termos
		{sql: "WITH RECURSIVE r(e) AS (SELECT email FROM clientes UNION ALL SELECT e FROM r) SELECT e FROM r", ok: true, want: "UNION ALL SELECT e FROM r", masks: emailMask},
		{sql: "WITH RECURSIVE r(id) AS (SELECT id FROM pagamentos UNION ALL SELECT id FROM r WHERE false) SELECT id FROM r", ok: true, want: "FROM (SELECT id, pedido_id, valor, status, pago_em FROM pagamentos WHERE status <> 'estornado') pagamentos", filters: 1},
		{sql: "WITH RECURSIVE r(id) AS (SELECT 1 UNION ALL SELECT g.id FROM r JOIN pagamentos g ON g.pedido_id = r.id) SELECT id FROM r", ok: true, want: "JOIN (SELECT id, pedido_id, valor, status, pago_em FROM pagamentos WHERE status <> 'estornado') g", filters: 1},

		{sql: "WITH RECURSIVE r(c) AS (SELECT cpf FROM clientes UNION ALL SELECT c FROM r) SELECT c FROM r", want: notAllowed},
		{sql: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r, clientes c WHERE c.cpf = '1') SELECT n FROM r", want: notAllowed},
		{sql: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE EXISTS (SELECT 1 FROM clientes WHERE cpf = '1')) SELECT n FROM r", want: notAllowed},
		// a auto-referência herda as origens do termo não recursivo
		{sql: "WITH RECURSIVE r(e) AS (SELECT email FROM clientes UNION ALL SELECT e FROM r WHERE e LIKE 'a%') SELECT e FROM r", want: `coluna "e" é mascarada`},
		{sql: "WITH RECURSIVE r(e) AS (SELECT email FROM clientes UNION SELECT e FROM r) SELECT e FROM r", want: "não pode passar por UNION"},
		{sql: "WITH RECURSIVE r(a, b) AS (SELECT nome, email FROM clientes UNION ALL SELECT b, a FROM r) SELECT a, b FROM r", want: "na mesma posição"},
		{sql: "WITH RECURSIVE r(e) AS (SELECT 'palpite@x.com' UNION ALL SELECT email FROM clientes, r) SELECT e FROM r", want: "na mesma posição"},
		{sql: "WITH RECURSIVE r(e) AS (SELECT email FROM clientes UNION ALL SELECT e FROM r) SELECT e FROM r ORDER BY e", want: masked},
		{sql: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3 ORDER BY 1) SELECT n FROM r", want: "ORDER BY em CTE recursiva"},
		{sql: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r LIMIT (SELECT 3)) SELECT n FROM r", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "WITH RECURSIVE r(a, b) AS (SELECT 1 UNION ALL SELECT a + 1, 2 FROM r) SELECT a FROM r", want: "números de colunas diferentes"},
		// WITH aninhado no corpo de uma CTE recursiva não é analisado; a
		// cobertura recusa (fail closed) em vez de deixar passar
		{sql: "WITH RECURSIVE r AS (WITH pedidos AS (SELECT email AS status FROM clientes) SELECT status FROM pedidos UNION ALL SELECT status FROM r WHERE false) SELECT status FROM r", want: "parte da query não foi analisada"},
	})
}

// Bypass de coluna bloqueada (cpf) e mascarada (email/telefone) por dentro de
// construções de expressão: cada uma precisa repassar a coluna para checagem.
func TestExpressionBypass(t *testing.T) {
	constructs := []struct {
		name string
		tmpl string // %s é a coluna
	}{
		{"case when", "SELECT CASE WHEN %s = '1' THEN 1 ELSE 0 END FROM clientes"},
		{"case arg", "SELECT CASE %s WHEN '1' THEN 1 END FROM clientes"},
		{"case result", "SELECT CASE WHEN id = 1 THEN %s END FROM clientes"},
		{"case else", "SELECT CASE WHEN id = 1 THEN 'x' ELSE %s END FROM clientes"},
		{"coalesce", "SELECT coalesce(%s, '') FROM clientes"},
		{"nullif", "SELECT nullif(%s, '') FROM clientes"},
		{"greatest", "SELECT greatest(%s, 'a') FROM clientes"},
		{"row comparison", "SELECT id FROM clientes WHERE (id, %s) = (1, '1')"},
		{"row constructor", "SELECT ROW(id, %s) FROM clientes"},
		{"array", "SELECT ARRAY[%s] FROM clientes"},
		{"array subscript", "SELECT (ARRAY[%s])[1] FROM clientes"},
		{"in list (left)", "SELECT id FROM clientes WHERE %s IN ('1', '2')"},
		{"in list (right)", "SELECT id FROM clientes WHERE '1' IN (nome, %s)"},
		{"not in", "SELECT id FROM clientes WHERE %s NOT IN ('1')"},
		{"between", "SELECT id FROM clientes WHERE %s BETWEEN '0' AND '5'"},
		{"between bound", "SELECT id FROM clientes WHERE nome BETWEEN %s AND 'z'"},
		{"between symmetric", "SELECT id FROM clientes WHERE nome BETWEEN SYMMETRIC 'a' AND %s"},
		{"is distinct from", "SELECT id FROM clientes WHERE %s IS DISTINCT FROM '1'"},
		{"is not distinct from", "SELECT id FROM clientes WHERE %s IS NOT DISTINCT FROM '1'"},
		{"is null", "SELECT id FROM clientes WHERE %s IS NULL"},
		{"boolean test", "SELECT id FROM clientes WHERE (%s = '1') IS TRUE"},
		{"not", "SELECT id FROM clientes WHERE NOT (%s = '1')"},
		{"any", "SELECT id FROM clientes WHERE %s = ANY (ARRAY['1', '2'])"},
		{"like", "SELECT id FROM clientes WHERE %s LIKE '1%%'"},
		{"cast", "SELECT %s::text FROM clientes"},
		{"collate", "SELECT %s COLLATE \"C\" FROM clientes"},
		{"concat operator", "SELECT %s || '' FROM clientes"},
		{"function arg", "SELECT length(%s) FROM clientes"},
		{"named arg", "SELECT jsonb_build_object('k', %s) FROM clientes"},
		{"aggregate", "SELECT string_agg(%s, ',') FROM clientes"},
		{"aggregate order", "SELECT string_agg(nome, ',' ORDER BY %s) FROM clientes"},
		{"aggregate filter", "SELECT count(*) FILTER (WHERE %s = '1') FROM clientes"},
		{"having", "SELECT cidade FROM clientes GROUP BY cidade HAVING max(%s) = '1'"},
		{"order by", "SELECT id FROM clientes ORDER BY %s"},
		{"join on", "SELECT p.id FROM pedidos p JOIN clientes c ON c.%s = p.status"},
		{"lateral function", "SELECT g FROM clientes c, generate_series(1, length(c.%s)) g"},
		{"scalar subquery", "SELECT (SELECT %s FROM clientes LIMIT 1)"},
		{"array subquery", "SELECT ARRAY(SELECT %s FROM clientes)"},
		{"in subquery", "SELECT id FROM pedidos WHERE status IN (SELECT %s FROM clientes)"},
		{"exists filter", "SELECT id FROM pedidos WHERE EXISTS (SELECT 1 FROM clientes WHERE %s = '1')"},
		{"distinct aggregate expr", "SELECT count(DISTINCT lower(%s)) FROM clientes"},
		{"values", "SELECT * FROM (VALUES ((SELECT %s FROM clientes LIMIT 1))) v(x)"},
	}
	var cases []guardCase
	for _, c := range constructs {
		for _, col := range []struct{ name, want string }{
			{"cpf", notAllowed},
			{"email", masked},
			{"telefone", redacted},
		} {
			cases = append(cases, guardCase{sql: strings.ReplaceAll(c.tmpl, "%s", col.name), want: col.want})
		}
	}
	// "%%" do LIKE vira "%" depois da troca
	for i := range cases {
		cases[i].sql = strings.ReplaceAll(cases[i].sql, "%%", "%")
	}
	runGuardCases(t, testGuard(t), cases)
}

// Contrapartida aceita das mesmas construções com colunas liberadas.
func TestExpressionAccepted(t *testing.T) {
	runGuardCases(t, testGuard(t), []guardCase{
		{sql: "SELECT CASE WHEN cidade = 'SP' THEN nome ELSE 'x' END FROM clientes", ok: true, want: "CASE WHEN cidade = 'SP' THEN nome ELSE 'x' END"},
		{sql: "SELECT CASE cidade WHEN 'SP' THEN 1 END FROM clientes", ok: true, want: "CASE cidade WHEN 'SP' THEN 1 END"},
		{sql: "SELECT coalesce(nome, ''), nullif(cidade, '') FROM clientes", ok: true, want: "COALESCE(nome, ''), NULLIF(cidade, '')"},
		{sql: "SELECT greatest(id, 1), least(id, 2) FROM clientes", ok: true, want: "GREATEST(id, 1), LEAST(id, 2)"},
		{sql: "SELECT id FROM clientes WHERE (id, cidade) = (1, 'SP')", ok: true, want: "WHERE (id, cidade) = (1, 'SP')"},
		{sql: "SELECT ARRAY[nome, cidade] FROM clientes", ok: true, want: "ARRAY[nome, cidade]"},
		{sql: "SELECT id FROM clientes WHERE id IN (1, 2) AND id BETWEEN 1 AND 10", ok: true, want: "id IN (1, 2) AND id BETWEEN 1 AND 10"},
		{sql: "SELECT id FROM clientes WHERE cidade IS DISTINCT FROM 'SP'", ok: true, want: "cidade IS DISTINCT FROM 'SP'"},
		{sql: "SELECT count(*) FILTER (WHERE cidade = 'SP') FROM clientes", ok: true, want: "FILTER (WHERE cidade = 'SP')"},
		{sql: "SELECT string_agg(nome, ',' ORDER BY cidade) FROM clientes", ok: true, want: "string_agg(nome, ',' ORDER BY cidade)"},
		{sql: "SELECT (ARRAY[nome])[1] FROM clientes", ok: true, want: "(ARRAY[nome])[1]"},
		// ORDER BY pelo nome da saída usa a coluna da saída (regra do Postgres)
		{sql: "SELECT nome AS email FROM clientes ORDER BY email", ok: true, want: "ORDER BY email"},
		{sql: "SELECT email AS nome FROM clientes ORDER BY nome", want: masked},
		// email nu, qualificado ou via subquery: sai com máscara na posição certa
		{sql: "SELECT id, c.email, nome, telefone FROM clientes c", ok: true, want: "SELECT id, c.email, nome, telefone FROM clientes c", masks: []maskWant{{1, policy.MaskPartial}, {3, policy.MaskRedact}}},
		{sql: "SELECT e FROM (SELECT email FROM clientes) s(e)", ok: true, want: "s(e)", masks: emailMask},
		{sql: "SELECT id FROM pedidos WHERE EXISTS (SELECT email FROM clientes)", ok: true, want: "EXISTS (SELECT email FROM clientes)"},
	})
}

func TestLimitOffsetForms(t *testing.T) {
	g := testGuard(t)
	runGuardCases(t, g, []guardCase{
		{sql: "SELECT id FROM pedidos LIMIT -1", want: "LIMIT precisa ser um número inteiro"},
		{sql: "SELECT id FROM pedidos LIMIT 1 + 1", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos LIMIT 10.0", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos LIMIT 10.5", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos LIMIT '10'", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos LIMIT 10::int", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos LIMIT (SELECT count(cpf) FROM clientes)", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos OFFSET (SELECT 1)", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos OFFSET id", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos UNION ALL SELECT id FROM produtos LIMIT 1 + 1", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT * FROM (SELECT id FROM pedidos LIMIT 2 * 2) s", want: "LIMIT/OFFSET precisam ser números inteiros"},
		{sql: "SELECT id FROM pedidos ORDER BY id FETCH FIRST 5 ROWS WITH TIES", want: "WITH TIES"},
		{sql: "SELECT id FROM pedidos OFFSET ALL", parseErr: true, want: "syntax error"},

		// NULL e ALL significam "sem limite": vira o teto da política
		{sql: "SELECT id FROM pedidos LIMIT NULL", ok: true, want: "SELECT id FROM pedidos LIMIT 501"},
		{sql: "SELECT id FROM pedidos LIMIT ALL", ok: true, want: "SELECT id FROM pedidos LIMIT 501"},
		{sql: "SELECT id FROM pedidos LIMIT 9999999999", ok: true, want: "LIMIT 501"},
		{sql: "SELECT id FROM pedidos LIMIT 0", ok: true, want: "LIMIT 1"},
		{sql: "SELECT id FROM pedidos LIMIT 10 OFFSET 5", ok: true, want: "LIMIT 11 OFFSET 5"},
		{sql: "SELECT id FROM pedidos OFFSET NULL", ok: true, want: "LIMIT 501"},
		{sql: "SELECT id FROM pedidos FETCH FIRST 5 ROWS ONLY", ok: true, want: "LIMIT 6"},
		{sql: "SELECT id FROM pedidos UNION ALL SELECT id FROM produtos LIMIT 3", ok: true, want: "LIMIT 4"},
		{sql: "SELECT * FROM (SELECT id FROM pedidos LIMIT 7 OFFSET 1) s", ok: true, want: "(SELECT id FROM pedidos LIMIT 7 OFFSET 1) s"},
	})
	for _, c := range []struct {
		sql   string
		cap   int
		byReq bool
	}{
		{"SELECT id FROM pedidos LIMIT ALL", 500, false},
		{"SELECT id FROM pedidos LIMIT NULL", 500, false},
		{"SELECT id FROM pedidos LIMIT 0", 0, true},
		{"SELECT id FROM pedidos LIMIT 500", 500, false},
		{"SELECT id FROM pedidos LIMIT 499", 499, true},
	} {
		v, err := g.Check(CmdQuery, c.sql)
		if err != nil {
			t.Errorf("%q: %v", c.sql, err)
			continue
		}
		if v.Cap != c.cap || v.CapByRequest != c.byReq {
			t.Errorf("%q: teto %d (por pedido=%v), esperava %d (%v)", c.sql, v.Cap, v.CapByRequest, c.cap, c.byReq)
		}
	}
}

func TestShapeDenials(t *testing.T) {
	runGuardCases(t, testGuard(t), []guardCase{
		{sql: "SELECT * FROM pedidos WHERE id = $1", want: "parâmetros ($1)"},
		{sql: "SELECT * FROM pagamentos TABLESAMPLE SYSTEM (50)", want: "não suportada pelo crivo: range_table_sample"},
		{sql: "SELECT xmlelement(name a)", want: "não suportada pelo crivo: xml_expr"},
		{sql: "SELECT 1 OPERATOR(public.=) 1", want: "operador qualificado"},
		{sql: "SELECT 1 OPERATOR(pg_catalog.=) 1", ok: true, want: "OPERATOR(pg_catalog.=)"},
		{sql: "SELECT public.lower(nome) FROM produtos", want: `função qualificada "public.lower"`},
		{sql: "SELECT (c).cpf FROM clientes c", want: "linha inteira"},
		{sql: "SELECT count(c) FROM clientes c", want: "linha inteira"},
		{sql: "SELECT id FROM clientes c WHERE c IS NULL", want: "linha inteira"},
		{sql: "SELECT (c.*)::text FROM clientes c", want: "* não é aceito nesta posição"},
		{sql: "SELECT ROW(c.*) FROM clientes c", want: "* não é aceito nesta posição"},
		{sql: "SELECT public.clientes.cpf FROM clientes", want: "com schema não é aceita"},
		{sql: "SELECT 1 FROM outro_banco.public.pedidos", want: "outro banco"},
		{sql: "SELEC 1", parseErr: true, want: "syntax error"},
		{sql: "   ", want: "SQL vazio"},
	})
}

func TestErrorTypes(t *testing.T) {
	d := &Denial{Reason: "motivo x", Accepted: "y"}
	if d.Error() != "motivo x" {
		t.Errorf("Denial.Error() = %q", d.Error())
	}
	pe := &ParseError{Message: "syntax error", Position: 3}
	if pe.Error() != "syntax error" {
		t.Errorf("ParseError.Error() = %q", pe.Error())
	}
	_, err := testGuard(t).Check(CmdQuery, "SELECT FROM WHERE")
	var perr *ParseError
	if !errors.As(err, &perr) {
		t.Fatalf("esperava *ParseError, veio %T %v", err, err)
	}
	if perr.Position <= 0 || !strings.Contains(perr.Error(), "syntax error") {
		t.Errorf("ParseError sem posição ou mensagem: %+v", perr)
	}
}

func TestAllowedFunctionList(t *testing.T) {
	g := customGuard(t, "functions minha_func\npedidos read\n")
	// uma função sempre bloqueada inserida à mão na política não entra na allowlist
	g2, err := New(&policy.Policy{File: "p", Schema: "public", Limit: 10, Functions: []string{"pg_sleep", "nextval", "extra_ok"}}, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		g       *Guard
		in, out []string
	}{
		{g, []string{"count", "btrim", "generate_series", "minha_func"}, []string{"pg_sleep", "nextval", "extra_ok"}},
		{g2, []string{"count", "extra_ok"}, []string{"pg_sleep", "nextval", "minha_func"}},
	} {
		list := c.g.AllowedFunctionList()
		if !sort.StringsAreSorted(list) {
			t.Errorf("lista fora de ordem: %v", list)
		}
		set := map[string]bool{}
		for _, f := range list {
			set[f] = true
		}
		for _, f := range c.in {
			if !set[f] {
				t.Errorf("%q deveria estar na allowlist", f)
			}
		}
		for _, f := range c.out {
			if set[f] {
				t.Errorf("%q não deveria estar na allowlist", f)
			}
		}
	}
	if _, err := g2.Check(CmdQuery, "SELECT pg_sleep(1)"); err == nil || !strings.Contains(err.Error(), "sempre bloqueada") {
		t.Errorf("pg_sleep passou: %v", err)
	}
	if _, err := g.Check(CmdQuery, "SELECT minha_func(id) FROM pedidos"); err != nil {
		t.Errorf("função liberada em functions foi recusada: %v", err)
	}
}

func TestCheckPolicy(t *testing.T) {
	cases := []struct {
		where string
		want  string // "" = sem diagnóstico
	}{
		{"status <> 'estornado'", ""},
		{"valor > 0 AND status IN ('a', 'b')", ""},
		{"lower(status) = 'x'", ""},
		{"minha_func(status)", ""}, // liberada pela diretiva functions
		{"id IN (SELECT pedido_id FROM pedidos)", ""},
		// o where vai até a próxima vírgula: texto extra precisa ser recusado aqui
		{"status <> 'x' limit 10", "sem cláusulas extras"},
		{"status <> 'x' ORDER BY 1", "sem cláusulas extras"},
		{"status <> 'x' UNION SELECT 1", "sem cláusulas extras"},
		{"status <> 'x' FOR UPDATE", "sem cláusulas extras"},
		{"status <> 'x' GROUP BY 1", "sem cláusulas extras"},
		{"1=1; DROP TABLE x", "uma única condição"},
		{"pg_sleep(1) IS NULL", `"pg_sleep" é sempre bloqueada`},
		{"foo(status)", `"foo" fora da allowlist`},
		{"id = $1", "parâmetros"},
		{"current_user = 'x'", "função de sessão"},
		{"status::regclass IS NULL", `tipo "regclass"`},
		{"status <> 'x' AND", "syntax error"},
	}
	for _, c := range cases {
		src := "name t\nabout \"x\"\nenv dev\nconnect postgres://u@h/db?sslmode=verify-full\nfunctions minha_func\npagamentos read where " + c.where + "\n"
		p, pd := policy.Parse("policy", src)
		if pd.HasErrors() {
			t.Fatalf("%q: a política deveria parsear: %v", c.where, pd.Error())
		}
		diags := CheckPolicy(p)
		if c.want == "" {
			if len(diags) != 0 {
				t.Errorf("%q: diagnóstico inesperado: %v", c.where, diags)
			}
			if _, err := New(p, testSchema()); err != nil {
				t.Errorf("%q: New recusou: %v", c.where, err)
			}
			continue
		}
		if len(diags) != 1 {
			t.Errorf("%q: esperava 1 diagnóstico, veio %v", c.where, diags)
			continue
		}
		d := diags[0]
		act := p.Rules[0].Actions[0]
		if d.Severity != policy.SevError || d.Pos != act.WherePos || d.File != "policy" {
			t.Errorf("%q: diagnóstico com severidade/posição erradas: %+v (where em %+v)", c.where, d, act.WherePos)
		}
		if !strings.Contains(d.Msg, "where inválido") || !strings.Contains(d.Msg, c.want) {
			t.Errorf("%q: mensagem %q não contém %q", c.where, d.Msg, c.want)
		}
		// New recusa a mesma política, com a posição do where
		if _, err := New(p, testSchema()); err == nil || !strings.Contains(err.Error(), "policy:6:23: where inválido") {
			t.Errorf("%q: New deveria recusar com posição, veio %v", c.where, err)
		}
	}

	// vários where: um diagnóstico por ação inválida, cada um na sua posição
	src := "name t\nabout \"x\"\nenv dev\nconnect postgres://u@h/db?sslmode=verify-full\n" +
		"pagamentos read where foo(1), update(status) where valor > 0, delete where bar(2)\npedidos read where id > 0\n"
	p, pd := policy.Parse("policy", src)
	if pd.HasErrors() {
		t.Fatal(pd.Error())
	}
	diags := CheckPolicy(p)
	if len(diags) != 2 || diags[0].Pos.Col != 23 || diags[1].Pos.Line != 5 || diags[1].Pos.Col <= diags[0].Pos.Col {
		t.Errorf("diagnósticos inesperados: %v", diags)
	}
	if CheckPolicy(&policy.Policy{File: "vazia"}) != nil {
		t.Error("política sem regras não tem diagnósticos")
	}
}

func TestFilterColumns(t *testing.T) {
	cases := []struct {
		expr string
		want []string
	}{
		{"status <> 'estornado'", []string{"status"}},
		{"valor > 0 AND status = 'x' AND valor < 10", []string{"valor", "status"}},
		{"g.valor > 0", []string{"valor"}},
		{"lower(nome) = 'x' OR coalesce(cidade, '') = ''", []string{"nome", "cidade"}},
		{"CASE WHEN ativo THEN preco ELSE 0 END > 1", []string{"ativo", "preco"}},
		// subquery fica de fora: suas colunas são de outra tabela
		{"EXISTS (SELECT 1 FROM pedidos WHERE cliente_id = 1)", nil},
		{"t.* IS NOT NULL", nil},
		{"true", nil},
		// expressões inválidas não derrubam: devolvem nil
		{"", nil},
		{"(", nil},
		{"status = ", nil},
		{"1 = 1; SELECT 2", nil},
		{"status = 'x' UNION SELECT 1", nil},
	}
	for _, c := range cases {
		got := FilterColumns(c.expr)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("FilterColumns(%q) = %v, esperava %v", c.expr, got, c.want)
		}
	}
}

func TestFilterNode(t *testing.T) {
	g := customGuard(t, "pagamentos read where status <> 'estornado', update(status) where valor > 0 AND status = 'pago'\npedidos read\n")
	pag, ped := g.Policy.Rules[0], g.Policy.Rules[1]
	read, upd := pag.Action(policy.Read), pag.Action(policy.Update)
	if n := g.FilterNode(read); n == nil || n.GetAExpr() == nil {
		t.Errorf("filtro de read deveria ser A_Expr, veio %v", n)
	}
	if n := g.FilterNode(upd); n == nil || n.GetBoolExpr() == nil || len(n.GetBoolExpr().Args) != 2 {
		t.Errorf("filtro de update deveria ser AND de 2 termos, veio %v", n)
	}
	if g.FilterNode(ped.Action(policy.Read)) != nil {
		t.Error("ação sem where não tem filtro")
	}
	if g.FilterNode(nil) != nil || g.FilterNode(&policy.Action{Where: "x = 1"}) != nil {
		t.Error("ação fora da política não tem filtro")
	}
	// o filtro compilado deparseia para a mesma expressão
	tree, err := pg_query.Parse("SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	tree.Stmts[0].Stmt.GetSelectStmt().WhereClause = g.FilterNode(read)
	sql, err := pg_query.Deparse(tree)
	if err != nil || !strings.Contains(sql, "WHERE status <> 'estornado'") {
		t.Errorf("deparse do filtro: %q %v", sql, err)
	}
}

// TestKnownLeaks documenta vazamentos encontrados e ainda não corrigidos.
// Ficam pulados até a correção; o corpo descreve o comportamento correto.
// Vazamentos achados nesta suíte e confirmados contra o Postgres real
// (ver também internal/integration/leaks_test.go). Cada caso fixa a correção.
func TestFixedLeaks(t *testing.T) {
	// Em WITH RECURSIVE uma CTE enxerga as definidas depois; o guard resolvia
	// "pedidos" em "a" como a tabela real e o email saía sem máscara.
	runGuardCases(t, testGuard(t), []guardCase{
		{sql: "WITH RECURSIVE a AS (SELECT status FROM pedidos), pedidos AS (SELECT email AS status FROM clientes) SELECT status FROM a WHERE status LIKE 'a%'", want: "citada antes de ser definida"},
		{sql: "WITH RECURSIVE a AS (SELECT status FROM pedidos), pedidos AS (SELECT email AS status FROM clientes) SELECT status FROM a", want: "citada antes de ser definida"},
		{sql: "WITH RECURSIVE a AS (SELECT 1 AS n FROM a) SELECT n FROM a", want: "citada antes de ser definida"},
		{cmd: CmdExec, sql: "WITH RECURSIVE a AS (SELECT status FROM pedidos), pedidos AS (SELECT email AS status FROM clientes) UPDATE pedidos SET observacao = (SELECT status FROM a LIMIT 1) WHERE id = 1", want: "citada antes de ser definida"},
		// sem RECURSIVE o Postgres lê a tabela real: o guard também
		{sql: "WITH a AS (SELECT status FROM pedidos), pedidos AS (SELECT email AS status FROM clientes) SELECT status FROM a", ok: true, want: "SELECT status FROM a"},
		// a recursão normal continua aceita
		{sql: "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n FROM r", ok: true, want: "WITH RECURSIVE r"},
		{sql: "WITH RECURSIVE b AS (SELECT 1 AS n), r(n) AS (SELECT n FROM b UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n FROM r", ok: true, want: "FROM b"},
	})

	// Uma subquery idêntica ao filtro de pagamentos, mas sobre uma CTE de
	// mesmo nome, passava na re-checagem como a tabela real e perdia a máscara.
	runGuardCases(t, testGuard(t), []guardCase{
		{sql: "WITH pagamentos AS (SELECT email AS id, 1 AS pedido_id, 1 AS valor, 'x' AS status, 1 AS pago_em FROM clientes) SELECT p.id FROM (SELECT id, pedido_id, valor, status, pago_em FROM pagamentos WHERE status <> 'estornado') p",
			ok: true, want: "SELECT p.id", masks: emailMask, filters: 1},
	})

	// O upsert altera a linha existente sem o WHERE do update nem o filtro do
	// read; em tabela com filtro de linha ele é recusado.
	g := customGuard(t, "pagamentos read where status <> 'estornado', insert, update(status) where valor > 0\n")
	runGuardCases(t, g, []guardCase{
		{cmd: CmdExec, sql: "INSERT INTO pagamentos (id, status) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET status = 'y' RETURNING *", want: "ON CONFLICT DO UPDATE não é aceito em pagamentos, que tem filtro where"},
		{cmd: CmdExec, sql: "INSERT INTO pagamentos (id, status) VALUES (1, 'x') ON CONFLICT DO NOTHING", ok: true, want: "ON CONFLICT DO NOTHING"},
	})
	onlyUpdateFilter := customGuard(t, "pedidos read, insert, update(status) where status <> 'cancelado'\n")
	runGuardCases(t, onlyUpdateFilter, []guardCase{
		{cmd: CmdExec, sql: "INSERT INTO pedidos (id, status) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET status = 'y'", want: "que tem filtro where"},
	})
	noFilter := customGuard(t, "pedidos read, insert, update(status)\n")
	runGuardCases(t, noFilter, []guardCase{
		{cmd: CmdExec, sql: "INSERT INTO pedidos (id, status) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET status = 'y'", ok: true, want: "DO UPDATE SET status = 'y'"},
	})
}
