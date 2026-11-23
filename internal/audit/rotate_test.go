package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A rotação não pode zerar os limites: Usage e Read leem os arquivos
// rotacionados também.
func TestRotationKeepsUsage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	old := MaxSize
	MaxSize = 300 // umas duas linhas por arquivo
	t.Cleanup(func() { MaxSize = old })

	now := time.Now()
	for i := 0; i < 7; i++ {
		e := Entry{Time: now.Add(-time.Duration(i) * time.Second), Command: "query", Decision: "aceito", Rows: 10, SQL: "SELECT id FROM pedidos WHERE id = 1"}
		if err := Write("vendas", e); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(home, ".crivo", "logs")
	if _, err := os.Stat(filepath.Join(dir, "vendas.jsonl.1")); err != nil {
		t.Fatalf("deveria ter rotacionado: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vendas.jsonl.4")); err == nil {
		t.Error("guardou mais arquivos antigos do que Keep")
	}
	entries, err := Read("vendas", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	minute, rows, err := Usage("vendas", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if minute != len(entries) || rows != int64(10*len(entries)) || len(entries) < 4 {
		t.Errorf("Usage = %d execuções, %d linhas; Read viu %d entradas", minute, rows, len(entries))
	}
}

func TestUsageCountsOnlyAcceptedExecutions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	now := time.Now()
	for _, e := range []Entry{
		{Time: now, Command: "query", Decision: "aceito", Rows: 5},
		{Time: now, Command: "mcp:exec", Decision: "aceito", Rows: 2},
		{Time: now, Command: "query", Decision: "barrado"},
		{Time: now, Command: "describe", Decision: "aceito", Rows: 100},
		{Time: now.Add(-2 * time.Minute), Command: "query", Decision: "aceito", Rows: 1},
	} {
		if err := Write("x", e); err != nil {
			t.Fatal(err)
		}
	}
	minute, rows, err := Usage("x", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	wantRows := int64(7)
	if now.Add(-2*time.Minute).Day() == now.Day() {
		wantRows = 8 // a de dois minutos atrás ainda é de hoje
	}
	if minute != 2 || rows != wantRows {
		t.Errorf("Usage = %d, %d; esperava 2 execuções e %d linhas", minute, rows, wantRows)
	}
}
