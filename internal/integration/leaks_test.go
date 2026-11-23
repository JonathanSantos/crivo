package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Consultas que enganavam o guard e devolviam o email em claro. Rodam no
// banco de verdade pelo binário gerado: o resultado precisa vir barrado ou
// mascarado, nunca com o valor original.
func TestKnownBypassesDoNotLeakAgainstPostgres(t *testing.T) {
	f := setup(t)
	bin, env, dir := generated(t, f)
	clear := []string{"contato@atlaslog.com.br", "financeiro@nortetex.com.br"}
	cases := map[string]string{
		// WITH RECURSIVE deixa uma CTE citar outra definida depois; o guard
		// resolvia "pedidos" em "a" como a tabela real
		"referência adiante em WITH RECURSIVE": "WITH RECURSIVE a AS (SELECT status FROM pedidos), pedidos AS (SELECT email AS status FROM clientes) SELECT status FROM a",
		// subquery idêntica ao filtro de pagamentos, mas sobre uma CTE com o
		// mesmo nome; a re-checagem a tomava pela tabela real
		"imitação do filtro sobre CTE": "WITH pagamentos AS (SELECT email AS id, 1 AS pedido_id, 1 AS valor, 'x' AS status, 1 AS pago_em FROM clientes) SELECT p.id FROM (SELECT id, pedido_id, valor, status, pago_em FROM pagamentos WHERE status <> 'estornado') p",
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			out, code := runIn(t, env, dir, bin, "query", sql)
			for _, c := range clear {
				if strings.Contains(out, c) {
					t.Fatalf("vazou %s (código %d):\n%s", c, code, out)
				}
			}
			if code != 0 && code != 2 {
				t.Errorf("código %d, esperava 0 (mascarado) ou 2 (barrado)\n%s", code, out)
			}
		})
	}
}

// O filtro de linha é barreira: condições da query nunca são avaliadas em
// linhas escondidas. O Postgres ordena as condições por custo; com um filtro
// mais caro que a condição da query (lower(status) vs to_date), sem a
// barreira o to_date rodava na linha estornada e o erro trazia o conteúdo
// dela ("esto..."). Achado pelo fuzz de vazamentos.
func TestRowFilterIsAnOptimizationFence(t *testing.T) {
	f := setup(t)
	bin, env, dir := variant(t, f, "pagamentos      read where status <> 'estornado'",
		"pagamentos      read where lower(lower(lower(lower(lower(lower(status)))))) <> 'estornado'")
	// só "estornado" tem 9 letras: a divisão por zero só acontece na linha
	// escondida, e o erro (ou a falta dele) diria que ela existe
	for _, sql := range []string{
		"SELECT id FROM pagamentos WHERE length(status) / (length(status) - 9) > 0",
		"SELECT p.id FROM pagamentos p JOIN pedidos d ON d.id = p.pedido_id WHERE length(p.status) / (length(p.status) - 9) > 0",
	} {
		out, code := runIn(t, env, dir, bin, "query", sql)
		if code != 0 || strings.Contains(out, "division by zero") {
			t.Errorf("a condição foi avaliada em linha escondida (código %d):\n%s\n%s", code, sql, out)
		}
	}
}

// Na escrita o filtro também vem antes: o WHERE da IA vai dentro de um CASE
// e nunca roda em linha escondida (nem no --dry-run, liberado sem clique).
func TestWriteFilterRunsFirst(t *testing.T) {
	f := setup(t)
	bin, env, dir := variant(t, f, "pagamentos      read where status <> 'estornado'",
		"pagamentos      read where lower(lower(lower(lower(lower(lower(status)))))) <> 'estornado', update(status) max 10")
	out, code := runIn(t, env, dir, bin, "exec", "UPDATE pagamentos SET status = status WHERE length(status) / (length(status) - 9) > 0", "--dry-run")
	if code != 0 || strings.Contains(out, "division by zero") {
		t.Fatalf("o WHERE da escrita foi avaliado em linha escondida (código %d):\n%s", code, out)
	}
}

// variant gera um binário com a política do fixture trocando um trecho.
func variant(t *testing.T, f *fixture, from, to string) (bin string, env []string, dir string) {
	t.Helper()
	_, env, dir = generated(t, f)
	crivo := filepath.Join(dir, "crivo"+exeSuffix())
	src := strings.Replace(f.policy.Source, from, to, 1)
	if src == f.policy.Source {
		t.Fatalf("fixture mudou: %q não encontrado", from)
	}
	pol := filepath.Join(dir, "variante.crivo")
	if err := os.WriteFile(pol, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "vendas-variante")
	if out, code := runIn(t, env, dir, crivo, "build", pol, "-o", bin); code != 0 {
		t.Fatalf("build: código %d\n%s", code, out)
	}
	return bin + exeSuffix(), env, dir
}

// NATURAL JOIN com uma coluna que o guard não sabia nomear como o Postgres
// (coalesce, cast de constante) virava comparação com o email mascarado:
// 1 linha para o email certo, 0 para o errado. Achado pelo fuzz.
func TestNaturalJoinCannotCompareMaskedColumn(t *testing.T) {
	f := setup(t)
	bin, env, dir := generated(t, f)
	for _, sql := range []string{
		"SELECT s2.id FROM (SELECT coalesce('contato@atlaslog.com.br', 'x')) s1 NATURAL JOIN (SELECT email AS coalesce, id FROM clientes) s2",
		"SELECT s2.id FROM (SELECT 'contato@atlaslog.com.br'::text) s1 NATURAL JOIN (SELECT email AS text, id FROM clientes) s2",
		"SELECT s2.id FROM (SELECT CASE WHEN true THEN 'contato@atlaslog.com.br' END) s1 NATURAL JOIN (SELECT email AS \"case\", id FROM clientes) s2",
		"SELECT s2.id FROM (SELECT CASE WHEN true THEN 'contato@atlaslog.com.br' ELSE cidade END FROM clientes) s1 NATURAL JOIN (SELECT email AS cidade, id FROM clientes) s2",
	} {
		out, code := runIn(t, env, dir, bin, "query", sql)
		if code != 2 {
			t.Errorf("deveria ser barrado (código %d):\n%s\n%s", code, sql, out)
		}
	}
}

// Os nomes que o guard dá às colunas (TestColumnNamesFollowPostgres, no
// sqlguard) conferidos contra o Postgres de verdade.
func TestPostgresColumnNames(t *testing.T) {
	f := setup(t)
	c := adminConn(t, f)
	cases := map[string]string{
		"SELECT coalesce(nome, 'x') FROM " + testSchemaName + ".clientes":                   "coalesce",
		"SELECT CASE WHEN true THEN 1 END":                                                  "case",
		"SELECT CASE WHEN true THEN 1 END::text":                                            "text",
		"SELECT CASE WHEN true THEN 'x' ELSE nome END FROM " + testSchemaName + ".clientes": "nome",
		"SELECT CASE WHEN true THEN 'x' ELSE 'y' END":                                       "case",
		"SELECT nome::text FROM " + testSchemaName + ".clientes":                            "nome",
		"SELECT 'x'::varchar":                                                               "varchar",
		"SELECT nullif(nome, '') FROM " + testSchemaName + ".clientes":                      "nullif",
		"SELECT greatest(1, 2)":                                                             "greatest",
		"SELECT least(1, 2)":                                                                "least",
		"SELECT EXISTS (SELECT 1)":                                                          "exists",
		"SELECT ARRAY[1, 2]":                                                                "array",
		"SELECT (SELECT nome FROM " + testSchemaName + ".clientes LIMIT 1)":                 "nome",
		"SELECT lower(nome) FROM " + testSchemaName + ".clientes":                           "lower",
		"SELECT current_date":                                                               "current_date",
		"SELECT 1 + 1":                                                                      "?column?",
	}
	for sql, want := range cases {
		rows, err := c.Query(context.Background(), sql)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		got := string(rows.FieldDescriptions()[0].Name)
		rows.Close()
		if got != want {
			t.Errorf("%s: o Postgres chama de %q, o teste do guard espera %q", sql, got, want)
		}
	}
}

// As derivações aceitas (split_part do email, date_trunc do mês) devolvem
// exatamente o que a máscara já mostra, linha a linha, no banco de verdade.
func TestVisiblePartsMatchMasks(t *testing.T) {
	f := setup(t)
	bin, env, dir := variant(t, f, "clientes        read except(cpf) mask(email: partial, telefone: redact, nome: hash)",
		"clientes        read except(cpf) mask(email: email, telefone: redact, nome: hash)")
	out, code := runIn(t, env, dir, bin, "query", "SELECT email, split_part(email, '@', 2) AS dominio FROM clientes", "--format", "json")
	if code != 0 {
		t.Fatalf("código %d\n%s", code, out)
	}
	var res struct {
		Rows []map[string]string `json:"rows"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.Rows) == 0 {
		t.Fatalf("saída: %v\n%s", err, out)
	}
	for _, r := range res.Rows {
		if r["email"] == "" { // NULL nas duas
			continue
		}
		if "***@"+r["dominio"] != r["email"] {
			t.Errorf("o domínio derivado %q não é o que a máscara mostra %q", r["dominio"], r["email"])
		}
	}
	if out, code = runIn(t, env, dir, bin, "query", "SELECT id FROM clientes WHERE split_part(email, '@', 2) = 'atlaslog.com.br'"); code != 0 || !strings.Contains(out, "1 linha") {
		t.Errorf("filtro pelo domínio: código %d\n%s", code, out)
	}

	bin, env, dir = variant(t, f, "pagamentos      read where status <> 'estornado'", "pagamentos      read mask(pago_em: month) where status <> 'estornado'")
	out, code = runIn(t, env, dir, bin, "query", "SELECT pago_em, to_char(date_trunc('month', pago_em), 'YYYY-MM') AS mes FROM pagamentos", "--format", "json")
	if code != 0 {
		t.Fatalf("código %d\n%s", code, out)
	}
	res.Rows = nil
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.Rows) == 0 {
		t.Fatalf("saída: %v\n%s", err, out)
	}
	for _, r := range res.Rows {
		if r["mes"] != r["pago_em"] {
			t.Errorf("o mês derivado %q não é o que a máscara mostra %q", r["mes"], r["pago_em"])
		}
	}
}
