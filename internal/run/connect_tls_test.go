package run

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestMain tira do ambiente as variáveis que o pgx usa como padrão: com um
// PGSSLMODE=require exportado, os casos sem sslmode mudariam de resultado.
func TestMain(m *testing.M) {
	for _, k := range []string{"PGHOST", "PGHOSTADDR", "PGPORT", "PGSSLMODE", "PGSERVICE", "PGSERVICEFILE", "PGSSLROOTCERT"} {
		os.Unsetenv(k)
	}
	os.Exit(m.Run())
}

// A checagem de TLS olha o destino que o pgx vai usar, não a releitura da
// URL. Antes, ?host= trocava o destino por um host remoto sem TLS e passava,
// porque url.Hostname() via só o localhost da URL.
func TestCheckTLSUsesTheDriverTarget(t *testing.T) {
	cases := []struct {
		connect string
		ok      bool
		host    string // host recusado
	}{
		{"postgres://app@localhost:5432/app?host=db.example.invalid&sslmode=disable", false, "db.example.invalid"},
		{"postgres://app@[::1]:5432/app?host=db.example.invalid", false, "db.example.invalid"}, // prefer: alternativo sem TLS
		{"host=db.example.invalid sslmode=disable password=%zz", false, "db.example.invalid"},  // url.Parse falha, pgx não
		{"host=db.example.invalid dbname=app", false, "db.example.invalid"},
		{"postgres://app@db.example.invalid/app?sslmode=allow", false, "db.example.invalid"},
		{"postgres://app@db.example.invalid/app?sslmode=prefer", false, "db.example.invalid"},
		{"postgres://app@db.example.invalid/app?sslmode=verify-full", true, ""},
		{"postgres://app@db.example.invalid/app?sslmode=require", true, ""},
		{"postgres://app@db.example.invalid/app?sslmode=verify-full&host=localhost", true, ""},
		{"postgres://app@localhost/app", true, ""},
		{"postgres://app@127.0.0.1/app?sslmode=disable", true, ""},
		{"host=/tmp dbname=app sslmode=disable", true, ""}, // socket unix é local
	}
	for _, c := range cases {
		cfg, err := pgx.ParseConfig(c.connect)
		if err != nil {
			t.Fatalf("%s: %v", c.connect, err)
		}
		err = checkTLS(cfg, c.connect)
		var insec *InsecureError
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: deveria aceitar, veio %v", c.connect, err)
		case !c.ok && (!errors.As(err, &insec) || insec.Host != c.host):
			t.Errorf("%s: deveria recusar %s, veio %v", c.connect, c.host, err)
		}
	}
}

// O Connect recusa antes de discar (contexto já cancelado: se a checagem
// falhasse, o erro seria de conexão, não InsecureError).
func TestConnectRefusesHostOverrideBeforeDialing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, s := range []string{
		"postgres://app@localhost:5432/app?host=db.example.invalid&sslmode=disable",
		"host=db.example.invalid sslmode=disable password=%zz",
	} {
		var insec *InsecureError
		if _, err := Connect(ctx, s, "x", ""); !errors.As(err, &insec) {
			t.Errorf("%s: esperava InsecureError, veio %v", s, err)
		}
	}
}
