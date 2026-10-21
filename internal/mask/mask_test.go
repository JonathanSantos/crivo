package mask

import (
	"strings"
	"testing"

	"crivo/internal/policy"
)

func TestPartial(t *testing.T) {
	cases := map[string]string{
		"joana@exemplo.com.br": "jo***@exemplo.com.br",
		"a@x.com":              "a***@x.com",
		"(11) 98765-4321":      "(11) 9****-**21",
		"123.456.789-01":       "123.***.***-01",
		"Atlas Logística":      "At***a",
		"abc":                  "***",
	}
	for in, want := range cases {
		if got := Partial(in); got != want {
			t.Errorf("Partial(%q) = %q, quero %q", in, got, want)
		}
	}
}

func TestHashStableWithinRun(t *testing.T) {
	m := New()
	a, b := m.Apply(policy.MaskHash, "x@y.com"), m.Apply(policy.MaskHash, "x@y.com")
	if a != b || !strings.HasPrefix(a, "h:") || len(a) != 8 {
		t.Fatalf("hash inesperado: %q %q", a, b)
	}
	if New().Apply(policy.MaskHash, "x@y.com") == a {
		t.Fatal("hash não deveria se repetir entre execuções")
	}
	if m.Apply(policy.MaskRedact, "segredo") != "***" {
		t.Fatal("redact")
	}
}
