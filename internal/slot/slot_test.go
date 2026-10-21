package slot

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPatchInMemory(t *testing.T) {
	exe := append(append([]byte("cabeçalho"), slot[:]...), []byte("rodapé")...)
	out, err := Patch(exe, []byte("name x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(exe) {
		t.Fatal("o patch não pode mudar o tamanho do executável")
	}
	p, ok, err := ReadFrom(out)
	if err != nil || !ok || string(p) != "name x\n" {
		t.Fatalf("leitura do slot: %q %v %v", p, ok, err)
	}
	if _, err := Patch(out, []byte("y")); err == nil {
		t.Fatal("patch em slot preenchido precisa falhar")
	}
	if _, err := Patch(append(exe, slot[:]...), []byte("y")); err == nil {
		t.Fatal("dois slots precisam falhar")
	}
	if _, err := Patch(exe, bytes.Repeat([]byte("a"), MaxPolicy+1)); err == nil {
		t.Fatal("política grande demais precisa falhar")
	}
	if _, ok := Embedded(); ok {
		t.Fatal("o binário de teste não tem política")
	}
}

func TestPatchRealBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("compila um binário")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "probe")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "./testdata/slotprobe")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	run := func(path string) string {
		out, err := exec.Command(path).CombinedOutput()
		if err != nil {
			t.Fatalf("executando %s: %v\n%s", path, err, out)
		}
		return string(out)
	}
	if got := run(bin); got != "ferramenta" {
		t.Fatalf("modo sem política: %q", got)
	}
	exe, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	policy := "name vendas\n# comentário preservado\n"
	patched, err := Patch(exe, []byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "vendas")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	if err := os.WriteFile(out, patched, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		if msg, err := exec.Command("codesign", "--force", "--sign", "-", out).CombinedOutput(); err != nil {
			t.Fatalf("codesign: %v %s", err, msg)
		}
	}
	got := run(out)
	if !strings.HasPrefix(got, "base:") || strings.TrimPrefix(got, "base:") != policy {
		t.Fatalf("modo com política: %q", got)
	}
}
