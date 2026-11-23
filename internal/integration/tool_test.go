package integration

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// runIn roda um binário com o ambiente isolado do teste e devolve a saída
// combinada e o código.
func runIn(t *testing.T, env []string, dir, bin string, args ...string) (string, int) {
	t.Helper()
	c := exec.Command(bin, args...)
	c.Env, c.Dir = env, dir
	out, err := c.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("%s %v: %v", bin, args, err)
	}
	return string(out), 0
}

// adminConn conecta como admin no banco do fixture. Nunca chame adminDSN de
// novo: sem CRIVO_TEST_DSN cada chamada sobe outro contêiner, sem o schema.
func adminConn(t *testing.T, f *fixture) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), f.admin)
	if err != nil {
		t.Skipf("banco de teste indisponível: %v", err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// tempRole cria um papel com nome único (papéis valem para o cluster todo) e
// apaga no fim. Pula se o usuário de teste não pode criar papéis.
func tempRole(t *testing.T, admin *pgx.Conn) string {
	t.Helper()
	role := fmt.Sprintf("crivo_it_%d", rand.IntN(1_000_000))
	if _, err := admin.Exec(context.Background(), "CREATE ROLE "+role+" LOGIN PASSWORD 'it'"); err != nil {
		t.Skipf("sem permissão para criar papel: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = admin.Exec(ctx, "DROP OWNED BY "+role)
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+role)
	})
	return role
}

// withUser troca o usuário da URL de conexão.
func withUser(connect, user string) string {
	u, _ := url.Parse(connect)
	u.User = url.User(user)
	return u.String()
}

// init de verdade: introspecta o banco, gera tudo negado com os comentários
// das tabelas e nunca grava a senha que veio na URL.
func TestInitAgainstDatabase(t *testing.T) {
	f := setup(t)
	_, env, dir := generated(t, f)
	crivo := filepath.Join(dir, "crivo"+exeSuffix())
	out := filepath.Join(dir, "gerada.crivo")
	adminURL := f.admin

	text, code := runIn(t, env, dir, crivo, "init", adminURL, "--schema", testSchemaName, "-o", out)
	if code != 0 || !strings.Contains(text, "7 tabelas, todas negadas") {
		t.Fatalf("init: código %d\n%s", code, text)
	}
	if u, _ := url.Parse(adminURL); u.User != nil {
		if pw, ok := u.User.Password(); ok && !strings.Contains(text, "a senha veio no argumento") {
			t.Errorf("init deveria avisar da senha no argumento (%d caracteres)", len(pw))
		}
	}
	gen, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"schema  " + testSchemaName, "## Clientes PJ", "# clientes", "deny", "#   colunas: id, nome, cpf, email, telefone, cidade"} {
		if !strings.Contains(string(gen), want) {
			t.Errorf("arquivo gerado sem %q:\n%s", want, gen)
		}
	}
	if u, _ := url.Parse(adminURL); u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" && strings.Contains(string(gen), ":"+pw+"@") {
			t.Fatal("o init gravou a senha da URL no arquivo")
		}
	}
	if _, code := runIn(t, env, dir, crivo, "init", adminURL, "--schema", testSchemaName, "-o", out); code != 5 {
		t.Errorf("init sobre arquivo existente sem --force: código %d, esperava 5", code)
	}
}

// O check conectado audita o usuário: superuser e escrita além da política
// viram avisos, sem derrubar o check.
func TestCheckWarnsAboutPrivileges(t *testing.T) {
	f := setup(t)
	_, env, dir := generated(t, f)
	crivo := filepath.Join(dir, "crivo"+exeSuffix())
	admin := adminConn(t, f)
	ctx := context.Background()

	var super bool
	if err := admin.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "admin.crivo")
	if err := os.WriteFile(pol, []byte(f.policy.Source), 0o644); err != nil {
		t.Fatal(err)
	}
	text, code := runIn(t, env, dir, crivo, "check", pol, "--refresh")
	if code != 0 || !strings.Contains(text, "schema conferido no banco") {
		t.Fatalf("check como admin: código %d\n%s", code, text)
	}
	if super && !strings.Contains(text, "é superuser") {
		t.Errorf("check com superuser deveria avisar:\n%s", text)
	}

	// papel que pode INSERT e TRUNCATE em pedidos, além do que a política dá
	role := tempRole(t, admin)
	for _, s := range []string{
		"GRANT USAGE ON SCHEMA " + testSchemaName + " TO " + role,
		"GRANT SELECT, INSERT, TRUNCATE ON " + testSchemaName + ".pedidos TO " + role,
		"GRANT SELECT ON ALL TABLES IN SCHEMA " + testSchemaName + " TO " + role,
	} {
		if _, err := admin.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	limited := strings.Replace(f.policy.Source, f.connect, withUser(f.connect, role), 1)
	if err := os.WriteFile(pol, []byte(limited), 0o644); err != nil {
		t.Fatal(err)
	}
	envRole := append(append([]string{}, env...), "CRIVO_IT_PW=it")
	text, code = runIn(t, envRole, dir, crivo, "check", pol, "--refresh")
	if code != 0 {
		t.Fatalf("check como papel limitado: código %d\n%s", code, text)
	}
	if !strings.Contains(text, "pode escrever além da política em 1 tabela(s): pedidos (INSERT, TRUNCATE)") || strings.Contains(text, "superuser") {
		t.Errorf("aviso de excesso inesperado:\n%s", text)
	}
}

// O SQL do crivo grants, aplicado de verdade, cria um papel que o próprio
// banco limita: o cpf e as colunas não graváveis são recusados pelo Postgres,
// mesmo sem o Crivo no meio.
func TestGrantsSQLMakesTheDatabaseEnforcePolicy(t *testing.T) {
	f := setup(t)
	_, env, dir := generated(t, f)
	crivo := filepath.Join(dir, "crivo"+exeSuffix())
	admin := adminConn(t, f)
	ctx := context.Background()

	role := fmt.Sprintf("crivo_it_g%d", rand.IntN(1_000_000))
	pol := filepath.Join(dir, "vendas-it.crivo")
	sql, code := runIn(t, env, dir, crivo, "grants", pol, "--role", role, "--offline")
	if code != 0 {
		// sem cache o grants precisa do banco
		sql, code = runIn(t, env, dir, crivo, "grants", pol, "--role", role)
	}
	if code != 0 {
		t.Fatalf("grants: código %d\n%s", code, sql)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP OWNED BY "+role)
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+role)
	})
	if _, err := admin.Exec(ctx, sql); err != nil {
		var pg *pgconn.PgError
		if asPg(err, &pg) && pg.Code == "42501" {
			t.Skipf("usuário de teste não pode criar papéis: %v", err)
		}
		t.Fatalf("o SQL do grants não roda no banco: %v\n%s", err, sql)
	}
	u, _ := url.Parse(f.admin)
	u.User = url.UserPassword(role, "troque-esta-senha")
	c, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Skipf("não foi possível entrar como %s (autenticação do cluster): %v", role, err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, "SET search_path = "+testSchemaName); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		sql string
		ok  bool
	}{
		{"SELECT id, nome, email FROM clientes", true},
		{"SELECT cpf FROM clientes", false},
		{"SELECT * FROM audit_log", false},
		{"SELECT * FROM usuarios", false},
		{"BEGIN; UPDATE pedidos SET status = 'pago' WHERE id = 1; ROLLBACK", true},
		{"BEGIN; UPDATE pedidos SET total = 0 WHERE id = 1; ROLLBACK", false},
		{"BEGIN; DELETE FROM pedidos WHERE id = 1; ROLLBACK", false},
		{"TRUNCATE pedidos", false},
	}
	for _, tc := range cases {
		_, err := c.Exec(ctx, tc.sql)
		if tc.ok && err != nil {
			t.Errorf("%s: o papel deveria poder, veio %v", tc.sql, err)
		}
		if !tc.ok {
			var pg *pgconn.PgError
			if !asPg(err, &pg) || pg.Code != "42501" {
				t.Errorf("%s: o banco deveria recusar por permissão (42501), veio %v", tc.sql, err)
			}
		}
		_, _ = c.Exec(ctx, "ROLLBACK")
	}
}

// Quando o schema muda por baixo do cache, o binário gerado se recupera:
// o erro do banco (42703) renova o cache e a próxima tentativa já é barrada
// pelo Crivo; refresh traz colunas novas.
func TestSchemaChangeRefreshesCache(t *testing.T) {
	f := setup(t)
	bin, env, dir := generated(t, f)
	admin := adminConn(t, f)
	ctx := context.Background()

	if out, code := runIn(t, env, dir, bin, "describe", "clientes"); code != 0 || !strings.Contains(out, "cidade") {
		t.Fatalf("describe inicial: código %d\n%s", code, out)
	}
	if _, err := admin.Exec(ctx, "ALTER TABLE "+testSchemaName+".clientes DROP COLUMN cidade, ADD COLUMN apelido text"); err != nil {
		t.Fatal(err)
	}
	out, code := runIn(t, env, dir, bin, "query", "SELECT cidade FROM clientes")
	if code != 4 || !strings.Contains(out, "o cache de schema foi renovado") {
		t.Fatalf("coluna que sumiu: código %d (esperava 4)\n%s", code, out)
	}
	out, code = runIn(t, env, dir, bin, "query", "SELECT cidade FROM clientes")
	if code != 2 {
		t.Fatalf("depois da renovação o Crivo deveria barrar: código %d\n%s", code, out)
	}
	if out, code = runIn(t, env, dir, bin, "describe", "clientes"); code != 0 || !strings.Contains(out, "apelido") || strings.Contains(out, "cidade") {
		t.Fatalf("describe depois da mudança: código %d\n%s", code, out)
	}
	if out, code = runIn(t, env, dir, bin, "refresh"); code != 0 || !strings.Contains(out, "-- schema recarregado: 7 tabelas em "+testSchemaName) {
		t.Fatalf("refresh: código %d\n%s", code, out)
	}
	if out, code = runIn(t, env, dir, bin, "explain", "SELECT id FROM pedidos WHERE status = 'pago'"); code != 0 || !strings.Contains(out, "-- sql SELECT id FROM pedidos WHERE status = 'pago' LIMIT 4") {
		t.Fatalf("explain: código %d\n%s", code, out)
	}
}

func exeSuffix() string {
	if os.PathSeparator == '\\' {
		return ".exe"
	}
	return ""
}

func asPg(err error, target **pgconn.PgError) bool {
	for err != nil {
		if pg, ok := err.(*pgconn.PgError); ok {
			*target = pg
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
