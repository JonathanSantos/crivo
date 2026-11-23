package base

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"crivo/internal/audit"
	"crivo/internal/output"
	"crivo/internal/testenv"
)

func TestAuditCommandFilters(t *testing.T) {
	testenv.Isolate(t)
	now := time.Now()
	for _, e := range []audit.Entry{
		{Time: now.Add(-48 * time.Hour), Command: "query", Decision: "aceito", SQL: "SELECT antigo"},
		{Time: now.Add(-time.Hour), Command: "query", Decision: "barrado", SQL: "SELECT cpf\n  FROM clientes", Reason: "coluna bloqueada"},
		{Time: now.Add(-30 * time.Minute), Command: "mcp:exec", Decision: "pendente", SQL: "DELETE FROM pedido_itens WHERE id = 1"},
		{Time: now.Add(-time.Minute), Command: "query", Decision: "aceito", SQL: "SELECT id FROM pedidos", Rows: 3},
	} {
		if err := audit.Write("vendas", e); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		args    []string
		want    []string
		absent  []string
		summary string
	}{
		{[]string{"audit"}, []string{"SELECT cpf FROM clientes\tcoluna bloqueada", "mcp:exec\tpendente", "SELECT id FROM pedidos"}, []string{"antigo"}, "3 de 3 entrada(s) nas últimas 24h0m0s"},
		{[]string{"audit", "--decision", "barrado"}, []string{"SELECT cpf"}, []string{"pedidos"}, "1 de 1"},
		{[]string{"audit", "--command", "exec"}, []string{"mcp:exec"}, []string{"SELECT"}, "1 de 1"},
		{[]string{"audit", "--since", "72h", "--limit", "1"}, []string{"SELECT id FROM pedidos"}, []string{"antigo", "cpf"}, "1 de 4"},
	}
	for _, c := range cases {
		code, out, errOut := runBase(t, c.args...)
		if code != output.ExitOK || !strings.Contains(out, c.summary) {
			t.Fatalf("%v: código %d\n%s%s", c.args, code, out, errOut)
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: faltou %q\n%s", c.args, w, out)
			}
		}
		for _, w := range c.absent {
			if strings.Contains(out, w) {
				t.Errorf("%v: não devia ter %q\n%s", c.args, w, out)
			}
		}
	}
	if code, _, _ := runBase(t, "audit", "--decision", "talvez"); code != output.ExitConfig {
		t.Errorf("decisão inválida: código %d", code)
	}
}

func TestMarkdownFormat(t *testing.T) {
	testenv.Isolate(t)
	code, out, _ := runBase(t, "tables", "--format", "markdown")
	if code != output.ExitOK || !strings.HasPrefix(out, "| tabela | ações | descrição |\n| --- | --- | --- |\n") ||
		!strings.Contains(out, "| pagamentos | read where status <> 'estornado' |") || !strings.Contains(out, "_5 tabelas; qualquer outra não existe para você_") {
		t.Fatalf("código %d\n%s", code, out)
	}
}

func TestMCPResources(t *testing.T) {
	testenv.Isolate(t)
	src := policyWith(t, "")
	p := seed(t, src)
	cs := connect(t, &mcpServer{p: p, format: output.TSV})
	ctx := context.Background()
	list, err := cs.ListResources(ctx, nil)
	if err != nil || len(list.Resources) != 2 {
		t.Fatalf("recursos: %v %+v", err, list)
	}
	pol, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "crivo://vendas/policy"})
	if err != nil || !strings.Contains(pol.Contents[0].Text, "23  clientes        read except(cpf)") {
		t.Fatalf("recurso policy: %v", err)
	}
	guide, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "crivo://vendas/guide"})
	if err != nil || !strings.Contains(guide.Contents[0].Text, "| email |") || strings.Contains(guide.Contents[0].Text, "| cpf |") {
		t.Fatalf("recurso guide: %v", err)
	}
	// sem cache, o guia precisaria do banco: erro, nunca o schema inventado
	testenv.Isolate(t)
	cs2 := connect(t, &mcpServer{p: p, format: output.TSV})
	if _, err := cs2.ReadResource(ctx, &mcp.ReadResourceParams{URI: "crivo://vendas/guide"}); err == nil {
		t.Error("guia sem schema deveria falhar")
	}
}

// describe --sample passa pelo caminho de leitura: sem banco para na senha,
// e entra na auditoria e nos limites como describe-sample.
func TestDescribeSample(t *testing.T) {
	home := withCache(t, vendasPolicy)
	code, out, errOut := runBase(t, "describe", "clientes", "--sample", "3")
	if code != output.ExitConfig || !strings.Contains(out, "email\ttext") || !strings.Contains(errOut, "segredo ausente") {
		t.Fatalf("código %d\n%s%s", code, out, errOut)
	}
	e := auditEntries(t, home, "vendas")
	if len(e) != 1 || e[0].Command != "describe-sample" || !strings.HasPrefix(e[0].SQL, `SELECT "id", "nome", "email", "telefone", "cidade" FROM "public"."clientes" LIMIT 3`) {
		t.Fatalf("auditoria: %+v", e)
	}
	if code, _, errOut = runBase(t, "describe", "clientes", "--sample", "21"); code != output.ExitConfig || !strings.Contains(errOut, "até 20") {
		t.Errorf("--sample grande: código %d\n%s", code, errOut)
	}
}
