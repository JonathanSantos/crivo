package main

// Ponta a ponta sem banco: compila o crivo de verdade e percorre o fluxo do
// README com o schema vindo do DDL. É o único teste que exercita o build
// gerando um executável (o binário de teste do go não tem o slot) e o
// binário gerado lendo a política do próprio arquivo.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"crivo/internal/output"
	"crivo/internal/slot"
	"crivo/internal/testenv"
)

func exe(path string) string {
	if runtime.GOOS == "windows" {
		return path + ".exe"
	}
	return path
}

// run roda o binário e devolve código, stdout e stderr. O ambiente é o do
// teste (HOME e cache isolados pelo testenv).
func run(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errOut.String()
	case err != nil:
		t.Fatalf("%s %v: %v", bin, args, err)
	}
	return 0, out.String(), errOut.String()
}

func TestEndToEndWithoutDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("compila o binário; pulado com -short")
	}
	dir := t.TempDir()
	// compila antes de isolar a HOME: o go usa o cache de módulos de verdade
	crivo := exe(filepath.Join(dir, "crivo"))
	if out, err := exec.Command("go", "build", "-o", crivo, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	home := testenv.Isolate(t)
	t.Setenv("CRIVO_E2E_PW", "") // senha ausente: nada tenta conectar
	src, err := os.ReadFile("../../examples/vendas.crivo")
	if err != nil {
		t.Fatal(err)
	}
	policyText := strings.Replace(string(src), "secret  keychain", "secret  env:CRIVO_E2E_PW", 1)
	pol := filepath.Join(dir, "vendas.crivo")
	if err := os.WriteFile(pol, []byte(policyText), 0o644); err != nil {
		t.Fatal(err)
	}
	ddl := "../../testdata/schema.sql"

	// sem argumentos: ajuda, código 0, e não fica esperando Enter (saída capturada)
	if code, out, _ := run(t, crivo); code != 0 || !strings.Contains(out, "Usage: crivo <command>") {
		t.Fatalf("crivo sem argumentos: código %d\n%s", code, out)
	}
	if code, out, errOut := run(t, crivo, "check", pol, "--schema-sql", ddl); code != 0 || !strings.Contains(out, "schema conferido pelo DDL") {
		t.Fatalf("check: código %d\n%s%s", code, out, errOut)
	}

	gen := filepath.Join(dir, "vendas")
	code, out, errOut := run(t, crivo, "build", pol, "--schema-sql", ddl, "-o", gen)
	if code != 0 || !strings.Contains(out, "próximos passos") {
		t.Fatalf("build: código %d\n%s%s", code, out, errOut)
	}
	gen = exe(gen)
	data, err := os.ReadFile(gen)
	if err != nil {
		t.Fatal(err)
	}
	if embedded, ok, err := slot.ReadFrom(data); err != nil || !ok || string(embedded) != policyText {
		t.Fatalf("o binário gerado não carrega a política no slot: ok=%v err=%v", ok, err)
	}

	// o binário gerado é o modo base: sem build, com a política embutida
	if code, out, _ := run(t, gen); code != 0 || !strings.Contains(out, "Usage: vendas <command>") || strings.Contains(out, "build") {
		t.Fatalf("binário gerado sem argumentos: código %d\n%s", code, out)
	}
	if code, out, _ := run(t, gen, "policy"); code != 0 || !strings.Contains(out, "secret  env:CRIVO_E2E_PW") {
		t.Fatalf("policy: código %d\n%s", code, out)
	}
	if code, _, errOut := run(t, gen, "build", pol); code != output.ExitConfig || !strings.Contains(errOut, "unexpected argument build") {
		t.Fatalf("a IA não pode alcançar o build pelo binário gerado: código %d\n%s", code, errOut)
	}
	// sem cache o binário precisaria do banco; com o cache (mesma pasta isolada) não
	if code, _, errOut := run(t, gen, "describe", "clientes"); code != output.ExitConfig || !strings.Contains(errOut, "CRIVO_E2E_PW") {
		t.Fatalf("describe sem cache nem senha: código %d\n%s", code, errOut)
	}
	p := testenv.LoadPolicy(t, pol)
	testenv.SeedCache(t, p, testenv.SchemaFromDDL(t, p, ddl), 0)
	if code, out, errOut := run(t, gen, "describe", "clientes"); code != 0 || !strings.Contains(out, "email\ttext\tsim\t\tpartial") {
		t.Fatalf("describe com cache: código %d\n%s%s", code, out, errOut)
	}
	if code, _, errOut := run(t, gen, "query", "SELECT cpf FROM clientes"); code != output.ExitDenied || !strings.Contains(errOut, `coluna "cpf" não está liberada`) {
		t.Fatalf("query barrada: código %d\n%s", code, errOut)
	}
	if code, _, errOut := run(t, gen, "query", "SELECT id FROM pedidos"); code != output.ExitConfig || !strings.Contains(errOut, "CRIVO_E2E_PW") {
		t.Fatalf("query aceita sem senha: código %d\n%s", code, errOut)
	}
	log, err := os.ReadFile(filepath.Join(home, ".crivo", "logs", "vendas.jsonl"))
	if err != nil || strings.Count(string(log), "\n") != 2 || !strings.Contains(string(log), `"decision":"barrado"`) {
		t.Fatalf("auditoria na HOME isolada: %v\n%s", err, log)
	}

	// build de novo no mesmo caminho substitui o binário; sobre o próprio crivo, recusa
	if code, _, errOut := run(t, crivo, "build", pol, "--schema-sql", ddl, "-o", gen); code != 0 {
		t.Fatalf("rebuild: código %d\n%s", code, errOut)
	}
	if code, _, errOut := run(t, crivo, "build", pol, "--schema-sql", ddl, "-o", crivo); code != output.ExitConfig || !strings.Contains(errOut, "não pode sobrescrever o próprio crivo") {
		t.Fatalf("build sobre o crivo: código %d\n%s", code, errOut)
	}
	if code, _, _ := run(t, crivo, "version"); code != 0 {
		t.Fatal("o crivo foi danificado pelo build recusado")
	}

	// um binário gerado não serve de base para outro build (o slot já está cheio)
	if code, _, errOut := run(t, gen, "--help"); code != 0 || errOut != "" {
		t.Fatalf("--help do gerado: código %d\n%s", code, errOut)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".crivo-build-*"))
	if len(leftovers) > 0 {
		t.Errorf("o build deixou temporários: %v", leftovers)
	}
}
