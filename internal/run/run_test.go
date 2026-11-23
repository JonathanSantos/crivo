package run

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"crivo/internal/policy"
)

func TestTooManyRowsMessageStatesAffectedAndMax(t *testing.T) {
	err := error(&TooManyRows{Affected: 37, Max: 20})
	want := "a escrita afetaria 37 linhas; o máximo da regra é 20"
	if err.Error() != want {
		t.Fatalf("obtido %q\nquero  %q", err.Error(), want)
	}
}

func TestDBErrorKeepsMessageAndUnwraps(t *testing.T) {
	inner := errors.New("conexão: recusada")
	err := error(&DBError{Err: inner})
	if err.Error() != "conexão: recusada" {
		t.Errorf("Error() = %q, quero a mensagem do erro interno", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("errors.Is não alcança o erro interno")
	}
	// Embrulhado de novo, ainda é reconhecido como erro do banco (saída 4).
	var db *DBError
	if !errors.As(fmt.Errorf("query: %w", err), &db) {
		t.Error("errors.As não acha *DBError embrulhado")
	}
}

func TestInsecureErrorMessageNamesHostModeAndFix(t *testing.T) {
	cases := []struct {
		host, mode, want string
	}{
		{"db.example.com", "disable", "conexão a db.example.com recusada: sslmode=disable permite tráfego sem TLS; use sslmode=verify-full"},
		{"db.example.com", "prefer", "conexão a db.example.com recusada: sslmode=prefer permite tráfego sem TLS; use sslmode=verify-full"},
		// Sem sslmode o driver usa prefer; a mensagem diz que faltou.
		{"db.example.com", "", "conexão a db.example.com recusada: sslmode=(ausente) permite tráfego sem TLS; use sslmode=verify-full"},
	}
	for _, tc := range cases {
		got := (&InsecureError{Host: tc.host, Mode: tc.mode}).Error()
		if got != tc.want {
			t.Errorf("obtido %q\nquero  %q", got, tc.want)
		}
	}
}

func TestSchemaChangedOnlyForUndefinedColumnOrTable(t *testing.T) {
	col := &pgconn.PgError{Code: "42703", Message: `column "x" does not exist`}
	tbl := &pgconn.PgError{Code: "42P01", Message: `relation "x" does not exist`}
	other := &pgconn.PgError{Code: "42601", Message: "syntax error"}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Coluna ou tabela inexistente: o cache de schema pode estar velho.
		{"undefined column", col, true},
		{"undefined table", tbl, true},
		{"undefined column in DBError", &DBError{Err: col}, true},
		{"undefined table in DBError wrapped", fmt.Errorf("query: %w", &DBError{Err: tbl}), true},
		{"undefined column wrapped", fmt.Errorf("query: %w", col), true},
		// Outros erros não podem disparar renovação de cache.
		{"syntax error", other, false},
		{"syntax error in DBError", &DBError{Err: other}, false},
		{"plain error", errors.New(`column "x" does not exist`), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SchemaChanged(tc.err); got != tc.want {
				t.Fatalf("SchemaChanged() = %v, quero %v", got, tc.want)
			}
		})
	}
}

func TestConnectRefusesRemoteWithoutTLSBeforeDialing(t *testing.T) {
	// Contexto já cancelado e host .invalid: se o Connect tentasse discar,
	// falharia sem rede em vez de devolver InsecureError.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name, url, host, mode string
	}{
		{"sslmode missing", "postgres://app@db.example.invalid:5432/app", "db.example.invalid", ""},
		{"sslmode disable", "postgres://app@db.example.invalid:5432/app?sslmode=disable", "db.example.invalid", "disable"},
		{"sslmode prefer", "postgres://app@db.example.invalid:5432/app?sslmode=prefer", "db.example.invalid", "prefer"},
		{"sslmode allow", "postgres://app@db.example.invalid:5432/app?sslmode=allow", "db.example.invalid", "allow"},
		{"postgresql scheme", "postgresql://app@db.example.invalid/app?sslmode=disable", "db.example.invalid", "disable"},
		// IP remoto não é exceção: só a própria máquina é.
		{"remote ip", "postgres://app@192.0.2.10:5432/app?sslmode=disable", "192.0.2.10", "disable"},
		// Parecer local no nome não basta.
		{"localhost lookalike", "postgres://app@localhost.example.invalid/app?sslmode=disable", "localhost.example.invalid", "disable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := Connect(ctx, tc.url, "dev", "s3gr3do")
			if conn != nil {
				conn.Close(context.Background())
				t.Fatal("Connect devolveu conexão")
			}
			var ie *InsecureError
			if !errors.As(err, &ie) {
				t.Fatalf("erro %v (%T), quero *InsecureError", err, err)
			}
			if ie.Host != tc.host || ie.Mode != tc.mode {
				t.Errorf("InsecureError{Host: %q, Mode: %q}, quero {%q, %q}", ie.Host, ie.Mode, tc.host, tc.mode)
			}
			// A mensagem nunca carrega a senha.
			if strings.Contains(err.Error(), "s3gr3do") {
				t.Errorf("mensagem expõe a senha: %q", err.Error())
			}
		})
	}
}

func TestConnectRejectsUnparseableURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := Connect(ctx, "postgres://%zz", "dev", "")
	if conn != nil {
		conn.Close(context.Background())
		t.Fatal("Connect devolveu conexão")
	}
	if err == nil || !strings.HasPrefix(err.Error(), "URL de conexão inválida: ") {
		t.Fatalf("erro %v, quero prefixo %q", err, "URL de conexão inválida: ")
	}
	// URL inválida é erro de configuração, não do banco nem de TLS.
	var ie *InsecureError
	var db *DBError
	if errors.As(err, &ie) || errors.As(err, &db) {
		t.Fatalf("erro classificado como %T", err)
	}
}

func TestContextDeadlineIsTimeoutPlusSlack(t *testing.T) {
	// A folga de 30s deixa o statement_timeout do banco disparar primeiro,
	// com mensagem clara, antes do cancelamento do lado do cliente.
	for _, timeout := range []time.Duration{policy.DefaultTimeout, 2 * time.Minute} {
		p := &policy.Policy{Timeout: timeout}
		before := time.Now()
		ctx, cancel := Context(p)
		after := time.Now()
		dl, ok := ctx.Deadline()
		cancel()
		if !ok {
			t.Fatal("contexto sem deadline")
		}
		lo, hi := before.Add(timeout+30*time.Second), after.Add(timeout+30*time.Second)
		if dl.Before(lo) || dl.After(hi) {
			t.Errorf("timeout %v: deadline %v fora de [%v, %v]", timeout, dl, lo, hi)
		}
		if ctx.Err() == nil {
			t.Error("cancel() não encerrou o contexto")
		}
	}
}
