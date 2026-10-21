package output

import (
	"bytes"
	"strings"
	"testing"
)

func s(v string) *string { return &v }

func TestTSV(t *testing.T) {
	var b bytes.Buffer
	_ = Write(&b, TSV, &Rows{
		Columns: []string{"id", "obs"},
		Values:  [][]*string{{s("1"), s("a\tb\nc\\d")}, {s("2"), nil}},
		Footer:  ReadFooter(2, false, false),
	})
	want := "id\tobs\n1\ta\\tb\\nc\\\\d\n2\tNULL\n-- 2 linhas\n"
	if b.String() != want {
		t.Fatalf("obtido %q\nquero  %q", b.String(), want)
	}
}

func TestLimits(t *testing.T) {
	big := strings.Repeat("x", MaxValue+10)
	if got := clip(big); !strings.HasSuffix(got, "…(+10 bytes)") {
		t.Fatalf("valor longo: %q", got[len(got)-20:])
	}
	var rows [][]*string
	for i := 0; i < 300; i++ {
		rows = append(rows, []*string{s(strings.Repeat("y", 1500))})
	}
	var b bytes.Buffer
	_ = Write(&b, TSV, &Rows{Columns: []string{"v"}, Values: rows, Footer: ReadFooter(300, true, false)})
	if b.Len() > MaxTotal+500 || !strings.Contains(b.String(), "saída cortada em 256 KB") {
		t.Fatalf("teto total não aplicado: %d bytes", b.Len())
	}
	if !strings.HasSuffix(b.String(), "-- 300 linhas (truncado: refine o filtro ou agregue)\n") {
		t.Fatal("rodapé de truncado")
	}
}

func TestFooters(t *testing.T) {
	cases := map[string]string{
		ReadFooter(1, false, false): "1 linha",
		ReadFooter(20, true, true):  "20 linhas (LIMIT da query; pode haver mais)",
		WriteFooter(3, false):       "3 linhas afetadas",
		WriteFooter(3, true):        "3 linhas seriam afetadas (dry-run, rollback)",
		WriteFooter(1, true):        "1 linha seria afetada (dry-run, rollback)",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("%q != %q", got, want)
		}
	}
}

func TestMessage(t *testing.T) {
	var b bytes.Buffer
	WriteMessage(&b, Message{Title: "barrado pelo crivo", Rule: "pedidos  read, update(status, observacao) max 20", RuleRef: "policy:16",
		Reason: `coluna "total" não pode ser alterada`, Accepted: "status, observacao"}, false)
	want := "✗ barrado pelo crivo\n  regra   pedidos  read, update(status, observacao) max 20   (policy:16)\n  motivo  coluna \"total\" não pode ser alterada\n  aceito  status, observacao\n"
	if b.String() != want {
		t.Fatalf("obtido:\n%s", b.String())
	}
}
