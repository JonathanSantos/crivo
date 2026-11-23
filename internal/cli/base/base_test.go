package base

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/alecthomas/kong"

	"crivo/internal/output"
)

func runBase(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	src, err := os.ReadFile("../../../examples/vendas.crivo")
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code = mainWith(src, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestBaseNoArgsPrintsUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}} {
		code, out, _ := runBase(t, args...)
		if code != output.ExitOK {
			t.Errorf("%v: código %d, esperava %d", args, code, output.ExitOK)
		}
		if !strings.Contains(out, "Usage: vendas <command>") || !strings.Contains(out, "query") {
			t.Errorf("%v: ajuda ausente na saída:\n%s", args, out)
		}
	}
}

// Antes, `exec "<escrita>" --help` imprimia a ajuda e seguia para executar a
// escrita (só parava por falta de senha). A ajuda não pode chegar ao banco.
func TestBaseHelpNeverRunsCommand(t *testing.T) {
	cases := [][]string{
		{"exec", "DELETE FROM pedido_itens WHERE pedido_id = 1", "--help"},
		{"query", "SELECT id FROM pedidos", "-h"},
		{"query", "--help"},
	}
	for _, args := range cases {
		code, out, errOut := runBase(t, args...)
		if code != output.ExitOK {
			t.Errorf("%v: código %d, esperava %d; stderr: %s", args, code, output.ExitOK, errOut)
		}
		if errOut != "" {
			t.Errorf("%v: o comando rodou depois da ajuda; stderr: %s", args, errOut)
		}
		if !strings.Contains(out, "Usage: vendas "+args[0]) {
			t.Errorf("%v: ajuda do subcomando ausente:\n%s", args, out)
		}
	}
}

// --dry-run=false virava escrita real com uma linha de comando que ainda
// contém "--dry-run" (o texto que o auto-approve do VS Code procura).
func TestDryRunRejectsValue(t *testing.T) {
	for _, v := range []string{"false", "0", "no", "true"} {
		code, _, errOut := runBase(t, "exec", "DELETE FROM pedido_itens WHERE pedido_id = 1", "--dry-run="+v)
		if code != output.ExitConfig {
			t.Errorf("--dry-run=%s: código %d, esperava %d", v, code, output.ExitConfig)
		}
		if !strings.Contains(errOut, "não aceita valor") {
			t.Errorf("--dry-run=%s: erro inesperado %q", v, errOut)
		}
		if strings.Contains(errOut, "segredo") || strings.Contains(errOut, "senha") {
			t.Errorf("--dry-run=%s: chegou a buscar a senha", v)
		}
	}
}

// Sem o banco: confere só o que o kong entrega ao exec. Se a flag deixasse de
// ligar, toda simulação viraria escrita real.
func TestDryRunFlagParsing(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"exec", "DELETE FROM t WHERE id = 1", "--dry-run"}, true},
		{[]string{"exec", "--dry-run", "DELETE FROM t WHERE id = 1"}, true},
		{[]string{"exec", "DELETE FROM t WHERE id = 1"}, false},
	}
	for _, c := range cases {
		var root struct {
			Exec execCmd `cmd:""`
		}
		parser, err := kong.New(&root, kong.Exit(func(int) { t.Fatalf("%v: o kong pediu para sair", c.args) }))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(c.args); err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if got := bool(root.Exec.DryRun); got != c.want {
			t.Errorf("%v: DryRun = %v, esperava %v", c.args, got, c.want)
		}
	}
}
