package integration

import (
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
