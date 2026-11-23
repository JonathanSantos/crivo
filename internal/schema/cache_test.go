package schema

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// isolate aponta HOME, USERPROFILE e XDG_CACHE_HOME para pastas temporárias:
// nenhum teste lê ou apaga o cache de verdade. Devolve a pasta de cache.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	cache := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CACHE_HOME", cache)
	return cache
}

func sampleSchema(source string, fetched time.Time) *Schema {
	return &Schema{
		Version:   cacheVersion,
		FetchedAt: fetched,
		Source:    source,
		Tables: map[string]*Table{
			"public.pedidos": {
				Schema:  "public",
				Name:    "pedidos",
				Kind:    "table",
				Comment: "pedidos de venda",
				Columns: []Column{
					{Name: "id", Type: "bigint", NotNull: true},
					{Name: "cliente_id", Type: "bigint", NotNull: true},
					{Name: "status", Type: "text", Comment: "aberto | pago"},
				},
				PrimaryKey: []string{"id"},
				ForeignKeys: []ForeignKey{
					{Columns: []string{"cliente_id"}, RefSchema: "public", RefTable: "clientes", RefColumns: []string{"id"}},
				},
			},
		},
	}
}

func writeCacheFile(t *testing.T, cache, name, content string) {
	t.Helper()
	dir := filepath.Join(cache, "crivo", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCacheDirHonorsXDGCacheHome(t *testing.T) {
	cache := isolate(t)
	got, err := CacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(cache, "crivo"); got != want {
		t.Fatalf("CacheDir() = %q, quero %q", got, want)
	}
	p, err := cachePath("dev")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(cache, "crivo", "dev", "schema.json"); p != want {
		t.Fatalf("cachePath() = %q, quero %q", p, want)
	}
}

func TestCacheDirFallsBackToHomeDotCache(t *testing.T) {
	isolate(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// Vazio explícito: sem isso, um XDG_CACHE_HOME da máquina vazaria no teste.
	t.Setenv("XDG_CACHE_HOME", "")
	got, err := CacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".cache", "crivo"); got != want {
		t.Fatalf("CacheDir() = %q, quero %q", got, want)
	}
}

func TestCacheFailsWithoutAnyHome(t *testing.T) {
	// Sem XDG nem HOME não há pasta de cache; nenhuma operação pode
	// cair no diretório corrente.
	isolate(t)
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if _, err := CacheDir(); err == nil {
		t.Fatal("CacheDir() deveria falhar; parando antes de gravar em pasta real")
	}
	if _, _, err := LoadCache("dev", "x"); err == nil || errors.Is(err, ErrNoCache) {
		t.Errorf("LoadCache() = %v, quero erro de HOME (não ErrNoCache)", err)
	}
	if err := SaveCache("dev", sampleSchema("x", time.Now())); err == nil {
		t.Error("SaveCache() deveria falhar")
	}
	if err := ClearCache("dev"); err == nil {
		t.Error("ClearCache() deveria falhar")
	}
}

func TestSaveThenLoadRoundTripsFresh(t *testing.T) {
	isolate(t)
	src := SourceKey("postgres://app@db.example.com/app?sslmode=verify-full", []string{"public"})
	// Truncado e em UTC para sobreviver ao JSON sem diferença de relógio monotônico.
	want := sampleSchema(src, time.Now().UTC().Truncate(time.Second))
	if err := SaveCache("dev", want); err != nil {
		t.Fatal(err)
	}
	got, fresh, err := LoadCache("dev", src)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Error("cache recém-gravado deveria estar dentro do TTL")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip divergiu:\nobtido %+v\nquero  %+v", got, want)
	}
}

func TestLoadCacheStaleStillReturned(t *testing.T) {
	// Cache vencido ainda serve (fresh=false): quem chama decide se renova.
	cases := []struct {
		name  string
		age   time.Duration
		fresh bool
	}{
		{"within TTL", TTL - time.Minute, true},
		{"older than TTL", TTL + time.Minute, false},
		{"very old", 30 * 24 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolate(t)
			want := sampleSchema("src", time.Now().Add(-tc.age).UTC().Truncate(time.Second))
			if err := SaveCache("dev", want); err != nil {
				t.Fatal(err)
			}
			got, fresh, err := LoadCache("dev", "src")
			if err != nil {
				t.Fatal(err)
			}
			if fresh != tc.fresh {
				t.Errorf("fresh = %v, quero %v", fresh, tc.fresh)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("schema devolvido diverge do gravado")
			}
		})
	}
}

func TestLoadCacheRejectsUnusableFiles(t *testing.T) {
	cur, next := fmt.Sprint(cacheVersion), fmt.Sprint(cacheVersion+1)
	cases := []struct {
		name    string
		content string // "" = sem arquivo
		source  string
	}{
		{name: "missing file", source: "abc"},
		{name: "corrupt json", content: `{"version": ` + cur + `, "source": "abc", "tables": {`, source: "abc"},
		{name: "not an object", content: `[]`, source: "abc"},
		// Formato antigo/novo: melhor buscar de novo que interpretar errado.
		{name: "version mismatch", content: `{"version": ` + next + `, "fetched_at": "2099-01-01T00:00:00Z", "source": "abc", "tables": {}}`, source: "abc"},
		{name: "version missing", content: `{"fetched_at": "2099-01-01T00:00:00Z", "source": "abc", "tables": {}}`, source: "abc"},
		// Outro banco ou outra lista de schemas: usar esse cache resolveria
		// colunas contra o catálogo errado.
		{name: "source mismatch", content: `{"version": ` + cur + `, "fetched_at": "2099-01-01T00:00:00Z", "source": "outro", "tables": {}}`, source: "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := isolate(t)
			if tc.content != "" {
				writeCacheFile(t, cache, "dev", tc.content)
			}
			s, fresh, err := LoadCache("dev", tc.source)
			if !errors.Is(err, ErrNoCache) {
				t.Fatalf("erro %v, quero ErrNoCache", err)
			}
			if s != nil || fresh {
				t.Fatalf("devolveu schema=%v fresh=%v junto com ErrNoCache", s, fresh)
			}
		})
	}
}

func TestLoadCacheIsPerName(t *testing.T) {
	// O cache de uma política não responde pelo nome de outra.
	isolate(t)
	if err := SaveCache("dev", sampleSchema("src", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCache("staging", "src"); !errors.Is(err, ErrNoCache) {
		t.Fatalf("erro %v, quero ErrNoCache", err)
	}
}

func TestSaveCacheOverwritesAndLeavesNoTemp(t *testing.T) {
	cache := isolate(t)
	first := sampleSchema("a", time.Now().UTC().Truncate(time.Second))
	second := sampleSchema("b", time.Now().UTC().Truncate(time.Second))
	delete(second.Tables, "public.pedidos")
	for _, s := range []*Schema{first, second} {
		if err := SaveCache("dev", s); err != nil {
			t.Fatal(err)
		}
	}
	got, _, err := LoadCache("dev", "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tables) != 0 {
		t.Errorf("segunda gravação não substituiu a primeira: %v", got.Tables)
	}
	entries, err := os.ReadDir(filepath.Join(cache, "crivo", "dev"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "schema.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("pasta do cache contém %v, quero só schema.json", names)
	}
}

func TestSaveCacheIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissões Unix não se aplicam no Windows")
	}
	// O cache tem nomes de colunas e comentários: só o dono lê.
	cache := isolate(t)
	if err := SaveCache("dev", sampleSchema("src", time.Now())); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cache, "crivo", "dev")
	for path, want := range map[string]os.FileMode{
		filepath.Join(cache, "crivo"):     0o700,
		dir:                               0o700,
		filepath.Join(dir, "schema.json"): 0o600,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: permissão %o, quero %o", path, got, want)
		}
	}
}

func TestClearCacheIsIdempotentAndRemovesOnlyThatName(t *testing.T) {
	cache := isolate(t)
	// Apagar o que não existe não é erro: "crivo schema --clear" é idempotente.
	if err := ClearCache("dev"); err != nil {
		t.Fatalf("ClearCache sem arquivo: %v", err)
	}
	if err := SaveCache("dev", sampleSchema("src", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := SaveCache("staging", sampleSchema("src", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := ClearCache("dev"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCache("dev", "src"); !errors.Is(err, ErrNoCache) {
		t.Errorf("depois de ClearCache: %v, quero ErrNoCache", err)
	}
	if _, err := os.Stat(filepath.Join(cache, "crivo", "dev", "schema.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("arquivo ainda existe: %v", err)
	}
	// Só o cache pedido some.
	if _, _, err := LoadCache("staging", "src"); err != nil {
		t.Errorf("cache de outro nome foi afetado: %v", err)
	}
	if err := ClearCache("dev"); err != nil {
		t.Fatalf("segundo ClearCache: %v", err)
	}
}

func TestSourceKeyIsStableAndChangesWithDatabaseOrSchemas(t *testing.T) {
	isolate(t)
	const url = "postgres://app@db.example.com:5432/app?sslmode=verify-full"
	base := SourceKey(url, []string{"public", "vendas"})
	if again := SourceKey(url, []string{"public", "vendas"}); again != base {
		t.Fatalf("mesma entrada deu chaves diferentes: %q e %q", base, again)
	}
	// Qualquer mudança de banco ou de schemas precisa invalidar o cache.
	others := map[string]string{
		"other host":     SourceKey("postgres://app@db2.example.com:5432/app?sslmode=verify-full", []string{"public", "vendas"}),
		"other database": SourceKey("postgres://app@db.example.com:5432/app2?sslmode=verify-full", []string{"public", "vendas"}),
		"fewer schemas":  SourceKey(url, []string{"public"}),
		"other order":    SourceKey(url, []string{"vendas", "public"}),
		"no schemas":     SourceKey(url, nil),
	}
	seen := map[string]string{base: "base"}
	for name, k := range others {
		if prev, dup := seen[k]; dup {
			t.Errorf("%s colide com %s: %q", name, prev, k)
		}
		seen[k] = name
	}
}
