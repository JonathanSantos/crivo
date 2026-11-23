package policy

import (
	"strings"
	"testing"
)

// Parâmetros que trocam o destino da conexão não passam no check: com eles a
// URL mostra um host e o driver conecta em outro, fora da regra de TLS.
func TestConnectRejectsTargetOverrides(t *testing.T) {
	base := "name x\nabout \"x\"\nenv dev\nsecret keychain\npedidos read\nconnect "
	cases := map[string]string{
		"postgres://app@localhost:5432/app?host=db.example.com&sslmode=disable": "parâmetro host",
		"postgres://app@localhost:5432/app?hostaddr=203.0.113.5":                "parâmetro hostaddr",
		"postgres://app@pg:5432/app?sslmode=verify-full&service=prod":           "parâmetro service",
		"postgres://app@pg:5432/app?sslmode=verify-full&servicefile=/tmp/x":     "parâmetro servicefile",
	}
	for url, want := range cases {
		_, diags := Parse("x.crivo", base+url+"\n")
		if !diags.HasErrors() || !strings.Contains(diags.Error(), want) {
			t.Errorf("%s: esperava erro com %q, veio:\n%s", url, want, diags.Error())
		}
	}
	if _, diags := Parse("x.crivo", base+"postgres://app@pg:5432/app?sslmode=verify-full&application_name=x\n"); diags.HasErrors() {
		t.Errorf("parâmetro inofensivo não pode ser recusado:\n%s", diags.Error())
	}
}
