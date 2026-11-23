package output

import (
	"bytes"
	"strings"
	"testing"
)

// Sem motivo, a linha "motivo" não aparece vazia (antes saía "  motivo  ").
func TestWriteMessageOmitsEmptyReason(t *testing.T) {
	var buf bytes.Buffer
	WriteMessage(&buf, Message{Title: "configuração", Hint: "rode refresh"}, false)
	if got := buf.String(); strings.Contains(got, "motivo") || got != "✗ configuração\n  dica    rode refresh\n" {
		t.Errorf("saída inesperada: %q", got)
	}
}
