// Package testenv isola os testes do mundo real: HOME, perfil do Windows,
// cache e keychain apontam para lugares descartáveis. Só testes importam.
package testenv

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"crivo/internal/policy"
	"crivo/internal/schema"
)

// Isolate aponta HOME, USERPROFILE (o os.UserHomeDir do Windows) e
// XDG_CACHE_HOME para uma pasta temporária e troca o keychain do sistema
// por um mock em memória. Devolve a pasta usada como HOME.
func Isolate(t testing.TB) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	keyring.MockInit()
	return home
}

// LoadPolicy lê e valida uma política de arquivo (caminho relativo ao teste).
func LoadPolicy(t testing.TB, path string) *policy.Policy {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, diags := policy.Parse(filepath.Base(path), string(src))
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	return p
}

// SchemaFromDDL monta o schema de um arquivo DDL para os schemas da política.
func SchemaFromDDL(t testing.TB, p *policy.Policy, ddlPath string) *schema.Schema {
	t.Helper()
	src, err := os.ReadFile(ddlPath)
	if err != nil {
		t.Fatal(err)
	}
	sc, _, err := schema.FromDDL(string(src), p.Schemas())
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// SeedCache grava o schema no cache da política (depois de Isolate), com a
// mesma chave de origem que o binário calcula. age define a idade do cache:
// 0 é fresco; acima de schema.TTL, vencido.
func SeedCache(t testing.TB, p *policy.Policy, sc *schema.Schema, age time.Duration) {
	t.Helper()
	c := *sc // Version já vem certo do FromDDL
	c.Source = schema.SourceKey(p.Connect, p.Schemas())
	c.FetchedAt = time.Now().UTC().Add(-age)
	if err := schema.SaveCache(p.Name, &c); err != nil {
		t.Fatal(err)
	}
}
