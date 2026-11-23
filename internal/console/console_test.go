package console

import (
	"bytes"
	"strings"
	"testing"
)

func TestShouldPause(t *testing.T) {
	cases := []struct {
		args        []string
		procs       int
		interactive bool
		want        bool
	}{
		{nil, 1, true, true},                  // duplo clique, sem argumentos
		{nil, 2, true, false},                 // rodado de um terminal
		{nil, 0, true, false},                 // sem console (macOS, Linux, serviço)
		{nil, 1, false, false},                // saída capturada: nunca espera Enter
		{[]string{"version"}, 1, true, false}, // com argumentos nunca pausa
	}
	for _, c := range cases {
		if got := ShouldPause(c.args, c.procs, c.interactive); got != c.want {
			t.Errorf("ShouldPause(%v, %d, %v) = %v, esperava %v", c.args, c.procs, c.interactive, got, c.want)
		}
	}
}

func TestPauseExplainsAndWaitsForEnter(t *testing.T) {
	var out bytes.Buffer
	Pause(&out, strings.NewReader("\n"), "crivo.exe")
	if !strings.Contains(out.String(), `.\crivo.exe --help`) || !strings.Contains(out.String(), "Enter") {
		t.Errorf("mensagem inesperada:\n%s", out.String())
	}
}
