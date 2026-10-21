package base

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"crivo/internal/output"
	"crivo/internal/policy"
)

// connectMCP sobe o servidor MCP em memória e devolve uma sessão de cliente.
func connectMCP(t *testing.T, allowExec bool) *mcp.ClientSession {
	t.Helper()
	src, err := os.ReadFile("../../../examples/vendas.crivo")
	if err != nil {
		t.Fatal(err)
	}
	p, diags := policy.Parse("policy", string(src))
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	s := &mcpServer{p: p, format: output.TSV, allowExec: allowExec}
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	go func() { _ = s.server().Run(ctx, st) }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "teste", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestMCPToolsAndPolicy(t *testing.T) {
	cs := connectMCP(t, false)
	ctx := context.Background()
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*mcp.Tool{}
	for _, tool := range lt.Tools {
		got[tool.Name] = tool
	}
	for _, name := range []string{"tables", "describe", "policy", "query", "explain", "exec"} {
		if got[name] == nil {
			t.Errorf("ferramenta %q ausente; tenho %v", name, keys(got))
		}
	}
	if !got["query"].Annotations.ReadOnlyHint || got["exec"].Annotations.ReadOnlyHint {
		t.Error("anotações de leitura/escrita erradas")
	}
	if !strings.Contains(got["exec"].Description, "desligada") {
		t.Errorf("sem --allow-exec a descrição de exec deve dizer que a escrita real está desligada: %q", got["exec"].Description)
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || !strings.Contains(text(res), "funções liberadas") || !strings.Contains(text(res), "pedidos") {
		t.Errorf("policy inesperada (erro=%v): %s", res.IsError, text(res))
	}

	// tables não precisa de banco quando a política não tem padrão liberado
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "tables"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || !strings.Contains(text(res), "clientes") {
		t.Errorf("tables inesperado (erro=%v): %s", res.IsError, text(res))
	}
}

func TestMCPExecNeedsAllowFlag(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	cs := connectMCP(t, false)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "exec", Arguments: map[string]any{
		"sql": "UPDATE pedidos SET status = 'pago' WHERE id = 1", "dry_run": false}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "--allow-exec") || !strings.Contains(text(res), "barrado pelo crivo") {
		t.Errorf("exec real sem --allow-exec deveria ser barrado com a dica da flag: erro=%v %s", res.IsError, text(res))
	}
	logs, err := os.ReadFile(dir + "/.crivo/logs/vendas.jsonl")
	if err != nil || !strings.Contains(string(logs), `"command":"mcp:exec"`) || !strings.Contains(string(logs), `"decision":"barrado"`) {
		t.Errorf("auditoria do MCP inesperada: %v\n%s", err, logs)
	}

	// format inválido é erro de configuração, sem tocar no banco
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "query", Arguments: map[string]any{"sql": "SELECT 1", "format": "xml"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "tsv, json ou table") {
		t.Errorf("format inválido: erro=%v %s", res.IsError, text(res))
	}
}

func keys(m map[string]*mcp.Tool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
