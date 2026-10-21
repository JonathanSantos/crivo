package policy

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regrava os golden files")

// dump descreve a política parseada de forma estável para o golden file.
func dump(p *Policy, diags Diags) string {
	var b strings.Builder
	for _, d := range diags {
		fmt.Fprintln(&b, d.String())
	}
	if diags.HasErrors() {
		return b.String()
	}
	fmt.Fprintf(&b, "name=%s about=%q env=%s connect=%s secret=%s/%s schema=%s limit=%d timeout=%s functions=%v\n",
		p.Name, p.About, p.Env, p.Connect, p.Secret, p.SecretVar, p.Schema, p.Limit, p.Timeout, p.Functions)
	for _, r := range p.Rules {
		fmt.Fprintf(&b, "rule %d:%d %s deny=%v doc=%q body=%q\n", r.Pos.Line, r.Pos.Col, r.Label(), r.Deny, r.Doc, r.Body)
		for _, a := range r.Actions {
			fmt.Fprintf(&b, "  action %d:%d %s cols=%v except=%v where=%q max=%d limit=%d masks=%v\n",
				a.Pos.Line, a.Pos.Col, a.Verb, a.Cols, a.Except, a.Where, a.Max, a.Limit, a.Masks)
		}
	}
	return b.String()
}

func TestGolden(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.crivo")
	if len(files) == 0 {
		t.Fatal("sem casos")
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		p, diags := Parse(filepath.Base(f), string(src))
		got := dump(p, diags)
		golden := strings.TrimSuffix(f, ".crivo") + ".golden"
		if *update {
			if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%s: %v (rode go test -update)", golden, err)
		}
		if got != string(want) {
			t.Errorf("%s difere do golden:\n--- obtido\n%s\n--- esperado\n%s", f, got, want)
		}
		if strings.HasPrefix(filepath.Base(f), "ok_") && diags.HasErrors() {
			t.Errorf("%s: esperava sem erros", f)
		}
		if strings.HasPrefix(filepath.Base(f), "err_") && !diags.HasErrors() {
			t.Errorf("%s: esperava erros", f)
		}
	}
}

func TestResolvePrecedence(t *testing.T) {
	p, diags := Parse("p", `name t
about "x"
env dev
connect postgres://u@h/db?sslmode=verify-full
audit_*      deny
audit_log_*  read
audit_log_x  read, delete
a*           read
a*           deny
`)
	// a* repetido é erro; testamos a precedência sem ele
	if !diags.HasErrors() {
		t.Fatal("esperava erro de regra repetida")
	}
	p, diags = Parse("p", `name t
about "x"
env dev
connect postgres://u@h/db?sslmode=verify-full
audit_*      deny
audit_log_*  read
audit_log_x  read, delete
x*           read
x*_y         deny
`)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	cases := map[string]string{
		"audit_log_x":  "audit_log_x",
		"audit_log_y":  "audit_log_*",
		"audit_outra":  "audit_*",
		"x_y":          "x*_y", // empate de prefixo: deny vence
		"xa":           "x*",
		"pg_class":     "",
		"desconhecida": "",
	}
	for table, want := range cases {
		r := p.Resolve("", table)
		got := ""
		if r != nil {
			got = r.Pattern
		}
		if got != want {
			t.Errorf("Resolve(%q) = %q, quero %q", table, got, want)
		}
	}
	if p.Resolve("information_schema", "tables") != nil || p.Resolve("pg_catalog", "pg_user") != nil {
		t.Error("catálogo precisa ser sempre bloqueado")
	}
}

func TestConnectTLS(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
		want    string // trecho do diagnóstico, se houver
	}{
		{"postgres://u@pg.interno/db?sslmode=verify-full", false, ""},
		{"postgres://u@pg.interno/db?sslmode=verify-ca", false, ""},
		{"postgres://u@pg.interno/db?sslmode=require", false, "não valida o certificado"},
		{"postgres://u@pg.interno/db", true, "precisa de sslmode=verify-full"},
		{"postgres://u@pg.interno/db?sslmode=disable", true, "permite conexão sem TLS"},
		{"postgres://u@pg.interno/db?sslmode=prefer", true, "permite conexão sem TLS"},
		{"postgres://u@pg.interno/db?sslmode=xpto", true, "desconhecido"},
		{"postgres://u@localhost:5432/db", false, "host localhost é local"},
		{"postgres://u@127.0.0.1/db?sslmode=disable", false, "é local"},
	}
	for _, c := range cases {
		_, diags := Parse("p", "name t\nabout \"x\"\nenv dev\nconnect "+c.url+"\npedidos read\n")
		if diags.HasErrors() != c.wantErr {
			t.Errorf("%s: erro=%v, esperava %v: %v", c.url, diags.HasErrors(), c.wantErr, diags)
		}
		var all []string
		for _, d := range diags {
			all = append(all, d.String())
		}
		text := strings.Join(all, "\n")
		if c.want != "" && !strings.Contains(text, c.want) {
			t.Errorf("%s: diagnóstico %q não contém %q", c.url, text, c.want)
		}
	}
}
