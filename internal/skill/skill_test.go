package skill

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"crivo/internal/policy"
	"crivo/internal/schema"
)

var update = flag.Bool("update", false, "regrava os golden files")

func vendas(t *testing.T) *policy.Policy {
	t.Helper()
	src, err := os.ReadFile("../../examples/vendas.crivo")
	if err != nil {
		t.Fatal(err)
	}
	p, diags := policy.Parse("policy", string(src))
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	return p
}

func testSchema() *schema.Schema {
	col := func(n, typ string, nn bool) schema.Column { return schema.Column{Name: n, Type: typ, NotNull: nn} }
	s := &schema.Schema{Tables: map[string]*schema.Table{}}
	s.Tables["public.pedidos"] = &schema.Table{Schema: "public", Name: "pedidos", PrimaryKey: []string{"id"},
		Columns:     []schema.Column{col("id", "integer", true), col("cliente_id", "integer", true), col("status", "text", true), col("total", "numeric(12,2)", true), col("observacao", "text", false)},
		ForeignKeys: []schema.ForeignKey{{Columns: []string{"cliente_id"}, RefSchema: "public", RefTable: "clientes", RefColumns: []string{"id"}}}}
	s.Tables["public.clientes"] = &schema.Table{Schema: "public", Name: "clientes", PrimaryKey: []string{"id"},
		Columns: []schema.Column{col("id", "integer", true), col("nome", "text", true), col("cpf", "text", true), col("email", "text", false), col("telefone", "text", false)}}
	s.Tables["public.pedido_itens"] = &schema.Table{Schema: "public", Name: "pedido_itens", Columns: []schema.Column{col("id", "integer", true), col("quantidade", "integer", true)}}
	s.Tables["public.produtos"] = &schema.Table{Schema: "public", Name: "produtos", Columns: []schema.Column{col("id", "integer", true), col("nome", "text", true)}}
	s.Tables["public.pagamentos"] = &schema.Table{Schema: "public", Name: "pagamentos", Columns: []schema.Column{col("id", "integer", true), col("status", "text", true)}}
	s.Tables["public.audit_log"] = &schema.Table{Schema: "public", Name: "audit_log", Columns: []schema.Column{col("id", "integer", true)}}
	return s
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (rode go test -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s difere do golden:\n%s", name, got)
	}
}

var frontRe = regexp.MustCompile(`(?s)^---\nname: ([^\n]+)\ndescription: ("[^\n]*")\n---\n`)

func TestSkillGolden(t *testing.T) {
	p := vendas(t)
	plain, err := Generate(p, Options{Bin: "vendas"})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "vendas.SKILL.md", plain)
	withSchema, err := Generate(p, Options{Bin: "vendas", WithSchema: true, Schema: testSchema()})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "vendas-with-schema.SKILL.md", withSchema)
	again, _ := Generate(p, Options{Bin: "vendas"})
	if again != plain {
		t.Fatal("geração não é determinística")
	}
	for _, s := range []string{"pg-hml", "svc_app", "postgres://"} {
		if strings.Contains(plain, s) {
			t.Errorf("a skill não pode conter dados de conexão (%s)", s)
		}
	}
}

func TestFrontmatter(t *testing.T) {
	p := vendas(t)
	s, _ := Generate(p, Options{Bin: "vendas"})
	m := frontRe.FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("frontmatter inválido:\n%s", s[:200])
	}
	if m[1] != "crivo-vendas" || !regexp.MustCompile(`^[a-z0-9-]{1,64}$`).MatchString(m[1]) {
		t.Fatalf("name inválido: %q", m[1])
	}
	dir := t.TempDir()
	path, err := Install(p, dir, s, false)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(path)) != m[1] {
		t.Fatalf("name %q diferente da pasta %q", m[1], filepath.Dir(path))
	}
	if _, err := Install(p, dir, s, false); err == nil {
		t.Fatal("install sem --force precisa falhar se o arquivo existe")
	}
	if _, err := Install(p, dir, s, true); err != nil {
		t.Fatal(err)
	}
	// description até 1024 caracteres mesmo com muitas tabelas
	long := *p
	long.Rules = nil
	for i := 0; i < 300; i++ {
		long.Rules = append(long.Rules, &policy.Rule{Pattern: strings.Repeat("t", 20) + string(rune('a'+i%26)) + strings.Repeat("x", i%7), Actions: []*policy.Action{{Verb: policy.Read}}})
	}
	if d := Description(&long, "vendas"); len([]rune(d)) > MaxDescription {
		t.Fatalf("description com %d caracteres", len([]rune(d)))
	}
}

func TestVSCodeSettings(t *testing.T) {
	got := VSCodeSettings(vendas(t), "vendas")
	want := `"chat.tools.terminal.autoApprove": {
  "/^vendas (tables|describe|policy|query|explain|refresh)\\b/": true,
  "/^vendas exec\\b.*--dry-run/": true,
  "/^vendas exec\\b/": false
}
`
	if got != want {
		t.Fatalf("obtido:\n%s\nesperado:\n%s", got, want)
	}
}
