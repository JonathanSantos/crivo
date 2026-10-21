// Testes de integração contra um Postgres real.
//
// Fonte do banco, nesta ordem:
//   - CRIVO_TEST_DSN: URL de um usuário que pode criar schema (o teste cria e
//     apaga o schema crivo_it);
//   - testcontainers-go, quando há Docker;
//   - sem nenhum dos dois, os testes são pulados.
package integration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"crivo/internal/mask"
	"crivo/internal/policy"
	"crivo/internal/run"
	"crivo/internal/schema"
	"crivo/internal/sqlguard"
)

const testSchemaName = "crivo_it"

type fixture struct {
	connect  string // URL sem senha
	password string
	policy   *policy.Policy
	guard    *sqlguard.Guard
}

func adminDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("CRIVO_TEST_DSN"); dsn != "" {
		return dsn
	}
	if testing.Short() {
		t.Skip("sem CRIVO_TEST_DSN e -short")
	}
	var dsn string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Skipf("sem Docker para testcontainers (%v) e sem CRIVO_TEST_DSN", r)
			}
		}()
		testcontainers.SkipIfProviderIsNotHealthy(t)
		ctx := context.Background()
		c, err := tcpostgres.Run(ctx, "postgres:17-alpine",
			tcpostgres.WithDatabase("vendas"), tcpostgres.WithUsername("postgres"), tcpostgres.WithPassword("postgres"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)))
		if err != nil {
			t.Skipf("testcontainers: %v", err)
		}
		t.Cleanup(func() { _ = c.Terminate(context.Background()) })
		dsn, err = c.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
	}()
	return dsn
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dsn := adminDSN(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("banco de teste indisponível: %v", err)
	}
	defer conn.Close(ctx)
	ddl, err := os.ReadFile("../../testdata/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		"DROP SCHEMA IF EXISTS " + testSchemaName + " CASCADE",
		"CREATE SCHEMA " + testSchemaName,
		"SET search_path = " + testSchemaName,
		string(ddl),
	}
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("preparando schema: %v", err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+testSchemaName+" CASCADE")
			c.Close(context.Background())
		}
	})

	u, _ := url.Parse(dsn)
	pw, _ := u.User.Password()
	u.User = url.User(u.User.Username())
	src := fmt.Sprintf(`name    vendas-it
about   "Base de teste"
env     dev
connect %s
secret  env:CRIVO_IT_PW
schema  %s
limit   3 rows
timeout 1s

pedidos         read, update(status, observacao) max 2
pedido_itens    read, insert, delete max 2
produtos        read
clientes        read except(cpf) mask(email: partial, telefone: redact, nome: hash)
pagamentos      read where status <> 'estornado'
audit_*         deny
`, u.String(), testSchemaName)
	p, diags := policy.Parse("policy", src)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	f := &fixture{connect: u.String(), password: pw, policy: p}
	c := f.conn(t)
	sc, err := schema.Fetch(ctx, c, p.Schemas())
	if err != nil {
		t.Fatal(err)
	}
	if f.guard, err = sqlguard.New(p, sc); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) conn(t *testing.T) *pgx.Conn {
	t.Helper()
	c, err := run.Connect(context.Background(), f.connect, f.policy.Name, f.password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func (f *fixture) query(t *testing.T, sql string) (*run.Result, *sqlguard.Verdict) {
	t.Helper()
	v, err := f.guard.Check(sqlguard.CmdQuery, sql)
	if err != nil {
		t.Fatalf("%q barrado: %v", sql, err)
	}
	res, err := run.Query(context.Background(), f.conn(t), f.policy, v.SQL, v.Cap)
	if err != nil {
		t.Fatalf("%q: %v", sql, err)
	}
	m := mask.New()
	for _, row := range res.Rows {
		for _, om := range v.Masks {
			if row[om.Index] != nil {
				s := m.Apply(om.Mode, *row[om.Index])
				row[om.Index] = &s
			}
		}
	}
	return res, v
}

func (f *fixture) exec(t *testing.T, sql string, dry bool) (*run.Result, error) {
	t.Helper()
	v, err := f.guard.Check(sqlguard.CmdExec, sql)
	if err != nil {
		t.Fatalf("%q barrado: %v", sql, err)
	}
	return run.Exec(context.Background(), f.conn(t), f.policy, v.SQL, v.MaxRows, dry)
}

func (f *fixture) count(t *testing.T, table string) string {
	t.Helper()
	res, _ := f.query(t, "SELECT count(*) FROM "+table)
	return *res.Rows[0][0]
}

func TestQueryMasksAndLimit(t *testing.T) {
	f := setup(t)
	res, v := f.query(t, "SELECT * FROM clientes ORDER BY id")
	if strings.Join(res.Columns, ",") != "id,nome,email,telefone,cidade" {
		t.Fatalf("colunas: %v", res.Columns)
	}
	if got := *res.Rows[0][2]; got != "co***@atlaslog.com.br" {
		t.Errorf("email mascarado: %q", got)
	}
	if got := *res.Rows[0][3]; got != "***" {
		t.Errorf("telefone: %q", got)
	}
	if got := *res.Rows[0][1]; !strings.HasPrefix(got, "h:") {
		t.Errorf("nome com hash: %q", got)
	}
	if res.Rows[2][2] != nil {
		t.Errorf("NULL precisa continuar NULL")
	}
	if len(res.Rows) != 3 || res.Truncated || v.Cap != 3 {
		t.Errorf("3 clientes cabem no teto: %d %v", len(res.Rows), res.Truncated)
	}

	res, _ = f.query(t, "SELECT id FROM pedido_itens")
	if len(res.Rows) != 3 || !res.Truncated {
		t.Errorf("teto da política: %d linhas, truncado=%v", len(res.Rows), res.Truncated)
	}

	res, _ = f.query(t, "SELECT status, count(*) FROM pagamentos GROUP BY status ORDER BY status")
	for _, r := range res.Rows {
		if *r[0] == "estornado" {
			t.Error("filtro where não aplicado: estorno apareceu")
		}
	}
}

func TestExecMaxDryRunAndRollback(t *testing.T) {
	f := setup(t)
	res, err := f.exec(t, "UPDATE pedidos SET status = 'pago' WHERE id = 2", true)
	if err != nil || res.Affected != 1 {
		t.Fatalf("dry-run: %v %+v", err, res)
	}
	got, _ := f.query(t, "SELECT status FROM pedidos WHERE id = 2")
	if *got.Rows[0][0] != "aberto" {
		t.Fatal("dry-run não pode gravar")
	}
	if _, err := f.exec(t, "UPDATE pedidos SET status = 'pago' WHERE id = 2", false); err != nil {
		t.Fatal(err)
	}
	got, _ = f.query(t, "SELECT status FROM pedidos WHERE id = 2")
	if *got.Rows[0][0] != "pago" {
		t.Fatal("exec real não gravou")
	}

	before := f.count(t, "pedido_itens")
	_, err = f.exec(t, "DELETE FROM pedido_itens WHERE quantidade > 0", false)
	var many *run.TooManyRows
	if !errors.As(err, &many) || many.Affected != 4 || many.Max != 2 {
		t.Fatalf("esperava TooManyRows(4 > 2), veio %v", err)
	}
	if after := f.count(t, "pedido_itens"); after != before {
		t.Fatalf("rollback falhou: %s → %s", before, after)
	}
}

func TestStatementTimeout(t *testing.T) {
	f := setup(t)
	// generate_series grande o bastante para estourar 1s de statement_timeout
	v, err := f.guard.Check(sqlguard.CmdQuery, "SELECT count(*) FROM generate_series(1, 200000000) AS g(n)")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = run.Query(context.Background(), f.conn(t), f.policy, v.SQL, v.Cap)
	var dbe *run.DBError
	if !errors.As(err, &dbe) || !strings.Contains(err.Error(), "57014") {
		t.Fatalf("esperava cancelamento por statement_timeout (57014), veio %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("timeout demorou demais")
	}
}

// TestReadOnlyAlone executa escrita sem passar pelo sqlguard dentro da
// transação do query: o READ ONLY sozinho também precisa segurar.
func TestReadOnlyAlone(t *testing.T) {
	f := setup(t)
	for _, sql := range []string{
		"UPDATE pedidos SET status = 'x'",
		"DELETE FROM pedidos",
		"CREATE TABLE copia AS SELECT * FROM pedidos",
		"WITH x AS (DELETE FROM pedido_itens RETURNING *) SELECT * FROM x",
	} {
		_, err := run.Query(context.Background(), f.conn(t), f.policy, sql, 10)
		if err == nil || !strings.Contains(err.Error(), "25006") {
			t.Errorf("%q: esperava erro read-only (25006), veio %v", sql, err)
		}
	}
	if f.count(t, "pedidos") != "4" {
		t.Fatal("dados foram alterados")
	}
}

// generated compila o crivo e gera o binário da base numa pasta temporária.
// Devolve o binário, o ambiente (senha, HOME e cache isolados) e a pasta.
func generated(t *testing.T, f *fixture) (bin string, env []string, dir string) {
	t.Helper()
	dir = t.TempDir()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	crivo := filepath.Join(dir, "crivo"+exe)
	if out, err := exec.Command("go", "build", "-o", crivo, "../../cmd/crivo").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	policyFile := filepath.Join(dir, "vendas-it.crivo")
	if err := os.WriteFile(policyFile, []byte(f.policy.Source), 0o644); err != nil {
		t.Fatal(err)
	}
	env = append(os.Environ(), "CRIVO_IT_PW="+f.password, "XDG_CACHE_HOME="+filepath.Join(dir, "cache"), "HOME="+dir, "USERPROFILE="+dir)
	bin = filepath.Join(dir, "vendas-it"+exe)
	c := exec.Command(crivo, "build", policyFile, "-o", bin)
	c.Env, c.Dir = env, dir
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("crivo build: %v\n%s", err, out)
	}
	return bin, env, dir
}

// TestGeneratedBinary compila o crivo, gera o binário da base e roda os
// comandos como a IA rodaria no terminal.
func TestGeneratedBinary(t *testing.T) {
	f := setup(t)
	bin, env, dir := generated(t, f)
	cmd := func(name string, args ...string) (string, int) {
		c := exec.Command(name, args...)
		c.Env, c.Dir = env, dir
		out, err := c.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), code
	}
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"query", "SELECT id, email FROM clientes ORDER BY id LIMIT 1"}, 0, "co***@atlaslog.com.br"},
		{[]string{"query", "SELECT cpf FROM clientes"}, 2, `coluna "cpf" não está liberada`},
		{[]string{"query", "SELEC 1"}, 3, "SQL inválido"},
		{[]string{"query", "SELECT * FROM audit_log"}, 2, "negada"},
		{[]string{"exec", "UPDATE pedidos SET status = 'enviado' WHERE id = 1", "--dry-run"}, 0, "1 linha seria afetada"},
		{[]string{"exec", "DELETE FROM pedido_itens WHERE quantidade > 0"}, 2, "o máximo da regra é 2"},
		{[]string{"build", "x"}, 5, "unexpected argument"},
		{[]string{"policy"}, 0, "funções liberadas"},
		{[]string{"describe", "clientes"}, 0, "partial"},
		{[]string{"skill"}, 0, "name: crivo-vendas-it"},
	}
	for _, tc := range cases {
		out, code := cmd(bin, tc.args...)
		if code != tc.code || !strings.Contains(out, tc.want) {
			t.Errorf("vendas-it %v: código %d (quero %d), saída:\n%s", tc.args, code, tc.code, out)
		}
	}
	logs, err := os.ReadFile(filepath.Join(dir, ".crivo", "logs", "vendas-it.jsonl"))
	if err != nil || !strings.Contains(string(logs), `"decision":"barrado"`) || strings.Contains(string(logs), "atlaslog") {
		t.Errorf("auditoria inesperada (precisa registrar decisões e nunca valores): %v\n%s", err, logs)
	}
}
