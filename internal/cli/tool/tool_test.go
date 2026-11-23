package tool

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crivo/internal/output"
)

func runTool(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = mainWith(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// Sem argumentos o crivo saía mudo com código 0: no Windows parecia que o
// programa "só fechava".
func TestNoArgsPrintsUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}} {
		code, out, _ := runTool(t, args...)
		if code != output.ExitOK {
			t.Errorf("%v: código %d, esperava %d", args, code, output.ExitOK)
		}
		if !strings.Contains(out, "Usage: crivo <command>") || !strings.Contains(out, "build") {
			t.Errorf("%v: ajuda ausente na saída:\n%s", args, out)
		}
	}
}

// --help num subcomando imprimia a ajuda e seguia rodando o comando.
func TestSubcommandHelpDoesNotRun(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "vendas")
	code, out, errOut := runTool(t, "build", "--offline", "../../../examples/vendas.crivo", "-o", dst, "--help")
	if code != output.ExitOK {
		t.Errorf("código %d, esperava %d; stderr: %s", code, output.ExitOK, errOut)
	}
	if !strings.Contains(out, "Usage: crivo build") {
		t.Errorf("ajuda do build ausente:\n%s", out)
	}
	for _, p := range []string{dst, dst + ".exe"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("--help gerou o binário %s", p)
		}
	}
}

func TestUnknownCommandPointsToHelp(t *testing.T) {
	code, _, errOut := runTool(t, "bogus")
	if code != output.ExitConfig {
		t.Errorf("código %d, esperava %d", code, output.ExitConfig)
	}
	if !strings.Contains(errOut, "crivo --help") {
		t.Errorf("erro sem indicar a ajuda: %q", errOut)
	}
}

// Fluxo principal sem banco: check e test com o schema vindo de um DDL.
func TestSchemaSQLWithoutDatabase(t *testing.T) {
	const pol, ddl = "../../../examples/vendas.crivo", "../../../testdata/schema.sql"
	code, out, errOut := runTool(t, "check", pol, "--schema-sql", ddl)
	if code != output.ExitOK || !strings.Contains(out, "schema conferido pelo DDL") {
		t.Fatalf("check: código %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	code, out, errOut = runTool(t, "test", pol, "--schema-sql", ddl, "-f", "../../../examples/queries.sql")
	if code != output.ExitOK || !strings.Contains(out, "0 fora do esperado") {
		t.Fatalf("test -f: código %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	code, out, _ = runTool(t, "test", pol, "--schema-sql", ddl, "SELECT cpf FROM clientes")
	if code != output.ExitDenied || !strings.Contains(out, "barrado") {
		t.Fatalf("cpf deveria ser barrado: código %d\n%s", code, out)
	}
	code, out, _ = runTool(t, "grants", pol, "--schema-sql", ddl)
	if code != output.ExitOK || !strings.Contains(out, "GRANT SELECT (id, nome, email, telefone, cidade) ON public.clientes") {
		t.Fatalf("grants: código %d\n%s", code, out)
	}
}
