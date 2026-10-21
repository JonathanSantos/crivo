package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestGeneratedBinaryMCP sobe o binário gerado como servidor MCP (stdio) e
// chama as ferramentas como um cliente de IA faria.
func TestGeneratedBinaryMCP(t *testing.T) {
	f := setup(t)
	bin, env, dir := generated(t, f)
	ctx := context.Background()

	start := func(args ...string) *mcp.ClientSession {
		t.Helper()
		c := exec.Command(bin, args...)
		c.Env, c.Dir = env, dir
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "it", Version: "0"}, nil).Connect(ctx, &mcp.CommandTransport{Command: c}, nil)
		if err != nil {
			t.Fatalf("conectando ao MCP %v: %v", args, err)
		}
		t.Cleanup(func() { cs.Close() })
		return cs
	}
	call := func(cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s %v: %v", name, args, err)
		}
		var b strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				b.WriteString(tc.Text)
			}
		}
		return b.String(), res.IsError
	}

	cs := start("mcp")
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range lt.Tools {
		names = append(names, tool.Name)
	}
	if got := strings.Join(names, ","); !strings.Contains(got, "query") || !strings.Contains(got, "exec") {
		t.Fatalf("ferramentas: %s", got)
	}

	cases := []struct {
		tool  string
		args  map[string]any
		isErr bool
		want  string
	}{
		{"query", map[string]any{"sql": "SELECT id, email FROM clientes ORDER BY id LIMIT 1"}, false, "co***@atlaslog.com.br"},
		{"query", map[string]any{"sql": "SELECT cpf FROM clientes"}, true, `coluna "cpf" não está liberada`},
		{"query", map[string]any{"sql": "SELEC 1"}, true, "SQL inválido"},
		{"describe", map[string]any{"table": "clientes"}, false, "partial"},
		{"exec", map[string]any{"sql": "UPDATE pedidos SET status = 'enviado' WHERE id = 1"}, false, "1 linha seria afetada"},
		{"exec", map[string]any{"sql": "UPDATE pedidos SET status = 'enviado' WHERE id = 1", "dry_run": false}, true, "--allow-exec"},
		{"exec", map[string]any{"sql": "DELETE FROM pedido_itens WHERE quantidade > 0"}, true, "o máximo da regra é 2"},
	}
	for _, tc := range cases {
		out, isErr := call(cs, tc.tool, tc.args)
		if isErr != tc.isErr || !strings.Contains(out, tc.want) {
			t.Errorf("%s %v: erro=%v (quero %v), saída:\n%s", tc.tool, tc.args, isErr, tc.isErr, out)
		}
	}
	if f.count(t, "pedidos") != "4" {
		t.Fatal("dados foram alterados sem --allow-exec")
	}

	// com --allow-exec a escrita real acontece
	cs2 := start("mcp", "--allow-exec")
	out, isErr := call(cs2, "exec", map[string]any{"sql": "UPDATE pedidos SET observacao = 'via mcp' WHERE id = 1", "dry_run": false})
	if isErr || !strings.Contains(out, "1 linha afetada") {
		t.Errorf("exec real com --allow-exec: erro=%v %s", isErr, out)
	}
	out, _ = call(cs2, "query", map[string]any{"sql": "SELECT observacao FROM pedidos WHERE id = 1"})
	if !strings.Contains(out, "via mcp") {
		t.Errorf("escrita não persistiu: %s", out)
	}

	logs, err := os.ReadFile(filepath.Join(dir, ".crivo", "logs", "vendas-it.jsonl"))
	if err != nil || !strings.Contains(string(logs), `"command":"mcp:query"`) || !strings.Contains(string(logs), `"command":"mcp:exec"`) || strings.Contains(string(logs), "atlaslog") {
		t.Errorf("auditoria do MCP inesperada: %v\n%s", err, logs)
	}
}
