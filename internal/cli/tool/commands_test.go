package tool

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/schema"
	"crivo/internal/secret"
	"crivo/internal/testenv"
)

var update = flag.Bool("update", false, "regrava os arquivos golden de testdata/")

const (
	vendasPolicy = "../../../examples/vendas.crivo"
	vendasDDL    = "../../../testdata/schema.sql"
	vendasCases  = "../../../examples/queries.sql"
)

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (rode com -update para criar)", err)
	}
	if got != string(want) {
		t.Errorf("%s difere do golden:\n--- obtido\n%s\n--- esperado\n%s", name, got, want)
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------- check ----------

// Cada regra de testdata/checks.crivo quebra uma checagem diferente contra o
// schema real; o check precisa apontar linha, coluna e motivo de cada uma e
// sair com 5 (configuração).
func TestCheckReportsSchemaProblems(t *testing.T) {
	testenv.Isolate(t)
	code, out, _ := runTool(t, "check", "testdata/checks.crivo", "--schema-sql", vendasDDL)
	if code != output.ExitConfig {
		t.Fatalf("código %d, esperava %d\n%s", code, output.ExitConfig, out)
	}
	for _, want := range []string{
		`checks.crivo:8:1: erro: tabela "fantasma" não existe no banco (schema public)`,
		`checks.crivo:9:23: erro: coluna "nao_existe" não existe em pedidos`,
		`checks.crivo:10:27: erro: coluna mascarada "sumida" não existe em clientes`,
		`checks.crivo:11:28: erro: o where cita a coluna "coluna_x", que não existe em pagamentos`,
		`checks.crivo:12:17: erro: read em produtos não libera nenhuma coluna`,
		`checks.crivo:13:1: aviso: o padrão tmp_* não cobre nenhuma tabela do banco`,
		`aviso: 3 tabela(s) do banco sem regra: invisíveis para a IA (deny por padrão)`,
		`✗ checks.crivo: 5 erro(s)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("faltou %q em:\n%s", want, out)
		}
	}
}

func TestCheckSyntaxErrorStopsBeforeSchema(t *testing.T) {
	testenv.Isolate(t)
	code, out, _ := runTool(t, "check", "../../policy/testdata/err_syntax.crivo", "--schema-sql", vendasDDL)
	if code != output.ExitConfig || !strings.Contains(out, "erro") || strings.Contains(out, "schema conferido") {
		t.Fatalf("código %d\n%s", code, out)
	}
}

// De onde o check tirou o schema aparece na última linha; sem banco nem
// cache ele não falha, mas diz que não conferiu. Nenhum caso aqui conecta:
// sem cache, a sessão para na senha ausente do keychain (mock).
func TestCheckSchemaSources(t *testing.T) {
	cases := []struct {
		name string
		seed time.Duration // -1: sem cache
		args []string
		note string
	}{
		{"offline sem cache", -1, []string{"--offline"}, "schema não conferido (--offline e sem cache)"},
		{"offline com cache", 0, []string{"--offline"}, "schema conferido pelo cache"},
		{"cache fresco", 0, nil, "schema conferido pelo cache"},
		{"cache vencido", schema.TTL + time.Hour, nil, "schema conferido pelo cache (vencido; use --refresh para reler)"},
		{"sem cache nem senha", -1, nil, "schema não conferido: senha não encontrada no keychain; rode: crivo secret set vendas"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testenv.Isolate(t)
			if c.seed >= 0 {
				p := testenv.LoadPolicy(t, vendasPolicy)
				testenv.SeedCache(t, p, testenv.SchemaFromDDL(t, p, vendasDDL), c.seed)
			}
			code, out, errOut := runTool(t, append([]string{"check", vendasPolicy}, c.args...)...)
			if code != output.ExitOK || !strings.Contains(out, c.note) {
				t.Fatalf("código %d, esperava nota %q\nstdout: %s\nstderr: %s", code, c.note, out, errOut)
			}
		})
	}
}

// ---------- test ----------

func TestTestCommandSingleStatement(t *testing.T) {
	testenv.Isolate(t)
	cases := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{"aceito com máscara e teto", []string{"SELECT * FROM clientes"}, output.ExitOK,
			[]string{"✓ aceito", "máscara  clientes.email → partial", "teto     500 linhas (política)", "sql      SELECT clientes.id, clientes.nome"}},
		{"LIMIT da query vira o teto", []string{"SELECT id FROM pedidos LIMIT 5"}, output.ExitOK,
			[]string{"teto     5 linhas (LIMIT da query)", "LIMIT 6"}},
		{"escrita mostra o teto de linhas afetadas", []string{"UPDATE pedidos SET status = 'pago' WHERE id = 1"}, output.ExitOK,
			[]string{"teto     20 linhas afetadas (public.pedidos)"}},
		{"barrado com regra", []string{"SELECT cpf FROM clientes"}, output.ExitDenied,
			[]string{"✗ barrado", "(vendas.crivo:23)", `motivo  coluna "cpf" não está liberada`, "aceito  id, nome, email, telefone, cidade"}},
		{"SQL inválido", []string{"SELEC id FROM pedidos"}, output.ExitParse, []string{"✗ SQL inválido", "motivo  syntax error"}},
		{"--as exec recusa SELECT", []string{"SELECT id FROM pedidos", "--as", "exec"}, output.ExitDenied, []string{"exec só aceita"}},
		{"--as query recusa escrita", []string{"DELETE FROM pedido_itens WHERE id = 1", "--as", "query"}, output.ExitDenied, []string{"query só aceita SELECT"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"test", vendasPolicy, "--schema-sql", vendasDDL}, c.args...)
			code, out, errOut := runTool(t, args...)
			if code != c.code {
				t.Fatalf("código %d, esperava %d\nstdout: %s\nstderr: %s", code, c.code, out, errOut)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("faltou %q em:\n%s", w, out)
				}
			}
		})
	}
}

// Num arquivo de casos, "-- espera:" transforma o test numa suíte: a saída
// marca cada divergência e o código é 2 se alguma existir. Sem expectativas,
// qualquer recusa já dá 2 (o CI do usuário pode usar isso).
func TestTestCommandCaseFile(t *testing.T) {
	testenv.Isolate(t)
	dir := t.TempDir()
	cases := []struct {
		name, content string
		code          int
		want          []string
	}{
		{"expectativas cumpridas", "-- espera: aceito\nSELECT id FROM pedidos;\n-- espera: barrado\nSELECT cpf FROM clientes;\n", output.ExitOK,
			[]string{"-- caso 1: SELECT id FROM pedidos", "-- caso 2: SELECT cpf FROM clientes", "-- 2 casos: 1 aceitos, 1 barrados, 0 fora do esperado"}},
		{"expectativa errada", "-- espera: aceito\nSELECT cpf FROM clientes;\n", output.ExitDenied,
			[]string{"✗ esperava aceito", "1 fora do esperado"}},
		{"sem expectativas e com recusa", "SELECT id FROM pedidos;\nDROP TABLE pedidos;\n", output.ExitDenied,
			[]string{"-- 2 casos: 1 aceitos, 1 barrados\n"}},
		{"sem expectativas e tudo aceito", "SELECT id FROM pedidos;\n-- só comentário\n;\n", output.ExitOK,
			[]string{"-- 1 casos: 1 aceitos, 0 barrados\n"}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := writeFile(t, dir, "casos"+string(rune('a'+i))+".sql", c.content)
			code, out, _ := runTool(t, "test", vendasPolicy, "--schema-sql", vendasDDL, "-f", f)
			if code != c.code {
				t.Fatalf("código %d, esperava %d\n%s", code, c.code, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("faltou %q em:\n%s", w, out)
				}
			}
		})
	}
}

// O arquivo de exemplo do repositório é a referência do README: todos os
// casos dele precisam bater com o esperado.
func TestExampleQueriesMatchExpectations(t *testing.T) {
	testenv.Isolate(t)
	code, out, _ := runTool(t, "test", vendasPolicy, "--schema-sql", vendasDDL, "-f", vendasCases)
	if code != output.ExitOK || !strings.Contains(out, ", 0 fora do esperado") {
		t.Fatalf("código %d\n%s", code, out)
	}
}

func TestTestCommandConfigErrors(t *testing.T) {
	testenv.Isolate(t)
	dir := t.TempDir()
	f := writeFile(t, dir, "q.sql", "SELECT 1;")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"SQL e -f juntos", []string{"test", vendasPolicy, "SELECT 1", "-f", f, "--schema-sql", vendasDDL}, "use o SQL no argumento ou -f"},
		{"sem SQL", []string{"test", vendasPolicy, "--schema-sql", vendasDDL}, "informe o SQL"},
		{"offline sem cache", []string{"test", vendasPolicy, "SELECT 1", "--offline"}, "ou passe --schema-sql com o DDL"},
		{"DDL inválido", []string{"test", vendasPolicy, "SELECT 1", "--schema-sql", writeFile(t, dir, "ruim.sql", "CREATE TABLE (")}, "DDL inválido"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := runTool(t, c.args...)
			if code != output.ExitConfig || !strings.Contains(errOut, c.want) {
				t.Fatalf("código %d, esperava %d com %q\nstderr: %s", code, output.ExitConfig, c.want, errOut)
			}
		})
	}
}

// ---------- grants ----------

// O SQL do usuário mínimo é para rodar no banco: qualquer mudança nele
// precisa ser revisada no golden.
func TestGrantsGolden(t *testing.T) {
	testenv.Isolate(t)
	for _, c := range []struct{ policy, golden string }{
		{vendasPolicy, "grants_vendas.golden"},
		{"testdata/readonly.crivo", "grants_readonly.golden"},
	} {
		t.Run(c.golden, func(t *testing.T) {
			args := []string{"grants", c.policy, "--schema-sql", vendasDDL}
			if strings.Contains(c.policy, "readonly") {
				args = append(args, "--role", "Leitor IA")
			}
			code, out, errOut := runTool(t, args...)
			if code != output.ExitOK {
				t.Fatalf("código %d\n%s", code, errOut)
			}
			golden(t, c.golden, out)
		})
	}
}

// Propriedades que o golden não deixa óbvias.
func TestGrantsSemantics(t *testing.T) {
	testenv.Isolate(t)
	_, out, _ := runTool(t, "grants", vendasPolicy, "--schema-sql", vendasDDL)
	for _, want := range []string{
		// except(cpf) vira GRANT por coluna: o banco passa a recusar o cpf sozinho
		"GRANT SELECT (id, nome, email, telefone, cidade) ON public.clientes TO crivo_vendas;",
		"GRANT UPDATE (status, observacao) ON public.pedidos TO crivo_vendas;",
		"GRANT DELETE ON public.pedido_itens TO crivo_vendas;",
		// política com escrita não pode deixar o papel só leitura
		"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public",
		"ALTER ROLE crivo_vendas SET statement_timeout = '5000ms';",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("faltou %q", want)
		}
	}
	for _, never := range []string{"audit_log", "usuarios", "default_transaction_read_only", "cpf"} {
		if strings.Contains(out, never) {
			t.Errorf("o grants não pode citar %q", never)
		}
	}
	_, ro, _ := runTool(t, "grants", "testdata/readonly.crivo", "--schema-sql", vendasDDL)
	if !strings.Contains(ro, "SET default_transaction_read_only = on") || strings.Contains(ro, "SEQUENCES") {
		t.Errorf("política só de leitura deveria gerar papel read-only:\n%s", ro)
	}
}

func TestGrantsNeedsSchema(t *testing.T) {
	testenv.Isolate(t)
	code, _, errOut := runTool(t, "grants", vendasPolicy, "--offline")
	if code != output.ExitConfig || !strings.Contains(errOut, "grants precisa do schema") {
		t.Fatalf("código %d\n%s", code, errOut)
	}
}

func TestIdentQuoting(t *testing.T) {
	for in, want := range map[string]string{
		"crivo_vendas": "crivo_vendas",
		"Leitor":       `"Leitor"`,
		"vendas-hml":   `"vendas-hml"`,
		`a"b`:          `"a""b"`,
		"1abc":         `"1abc"`,
	} {
		if got := ident(in); got != want {
			t.Errorf("ident(%q) = %s, esperava %s", in, got, want)
		}
	}
}

// ---------- secret ----------

// O keychain aqui é o mock em memória do go-keyring (testenv.Isolate).
func TestSecretSetAndRemove(t *testing.T) {
	testenv.Isolate(t)
	code, out, errOut := runToolIn(t, "s3nha\r\nlixo\n", "secret", "set", "vendas", "--stdin")
	if code != output.ExitOK || !strings.Contains(out, "✓ senha de vendas gravada no keychain (serviço crivo, conta vendas)") {
		t.Fatalf("set: código %d\n%s%s", code, out, errOut)
	}
	if pw, err := keyring.Get(secret.Service, "vendas"); err != nil || pw != "s3nha" {
		t.Fatalf("keychain tem %q, %v; esperava só a primeira linha sem \\r\\n", pw, err)
	}
	if code, out, _ = runTool(t, "secret", "rm", "vendas"); code != output.ExitOK || !strings.Contains(out, "removida") {
		t.Fatalf("rm: código %d\n%s", code, out)
	}
	if _, err := keyring.Get(secret.Service, "vendas"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("a senha deveria ter saído do keychain: %v", err)
	}
	code, _, errOut = runTool(t, "secret", "rm", "vendas")
	if code != output.ExitConfig || !strings.Contains(errOut, "não havia senha de vendas") {
		t.Fatalf("rm de novo: código %d\n%s", code, errOut)
	}
}

func TestSecretSetRejectsBadInput(t *testing.T) {
	testenv.Isolate(t)
	cases := []struct {
		name, stdin, polName, want string
	}{
		{"nome fora do padrão", "x\n", "Vendas Prod", "nome inválido"},
		{"stdin vazio", "", "vendas", "stdin vazio"},
		{"senha vazia", "\n", "vendas", "senha vazia"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := runToolIn(t, c.stdin, "secret", "set", c.polName, "--stdin")
			if code != output.ExitConfig || !strings.Contains(errOut, c.want) {
				t.Fatalf("código %d, esperava %d com %q\n%s", code, output.ExitConfig, c.want, errOut)
			}
		})
	}
	if _, err := keyring.Get(secret.Service, "vendas"); !errors.Is(err, keyring.ErrNotFound) {
		t.Error("entrada recusada não pode gravar nada no keychain")
	}
}

// ---------- build ----------

// O caminho feliz do build precisa de um executável com slot e é coberto
// pelo teste de ponta a ponta em cmd/crivo. Aqui ficam as recusas, que vêm
// antes de tocar no executável.
func TestBuildRefusals(t *testing.T) {
	testenv.Isolate(t)
	dir := t.TempDir()
	prod := writeFile(t, dir, "prod.crivo", strings.Replace(mustRead(t, vendasPolicy), "env     preprod", "env     prod", 1))
	out := filepath.Join(dir, "saida")
	cases := []struct {
		name   string
		args   []string
		stdout string
		stderr string
	}{
		{"env prod sem --allow-prod", []string{"build", prod, "--schema-sql", vendasDDL, "-o", out}, "", "env prod"},
		{"check com erro", []string{"build", "testdata/checks.crivo", "--schema-sql", vendasDDL, "-o", out}, "✗ check falhou; binário não gerado", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runTool(t, c.args...)
			if code != output.ExitConfig || !strings.Contains(stdout, c.stdout) || !strings.Contains(stderr, c.stderr) {
				t.Fatalf("código %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("recusa não pode deixar binário para trás")
			}
		})
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---------- init e version ----------

// O init só aceita URL postgres com o nome do banco; o resto falha antes de
// conectar. Sem o banco, o arquivo gerado teria um name que o check recusa.
func TestInitRejectsBadURL(t *testing.T) {
	testenv.Isolate(t)
	cases := map[string]string{
		"mysql://u@h/db":                      "URL inválida",
		"://":                                 "URL inválida",
		"pg-hml:5432/vendas":                  "URL inválida",
		"postgres://u@localhost:5432/":        "URL sem o nome do banco",
		"postgresql://u:senha@localhost:5432": "URL sem o nome do banco",
	}
	for u, want := range cases {
		out := filepath.Join(t.TempDir(), "x.crivo")
		code, _, errOut := runTool(t, "init", u, "-o", out)
		if code != output.ExitConfig || !strings.Contains(errOut, want) {
			t.Errorf("%q: código %d, esperava %q\n%s", u, code, want, errOut)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%q: URL recusada não pode gerar arquivo", u)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"vendas":                  "vendas",
		"Vendas_HML":              "vendas-hml",
		"  erp..core  ":           "erp-core",
		"2024_dados":              "base-2024-dados",
		"":                        "base", // nunca termina em hífen (o check recusaria o name)
		"___":                     "base",
		strings.Repeat("a", 70):   strings.Repeat("a", 58),
		strings.Repeat("ab-", 30): strings.TrimRight(strings.Repeat("ab-", 30)[:58], "-"),
	} {
		got := sanitizeName(in)
		if got != want {
			t.Errorf("sanitizeName(%q) = %q, esperava %q", in, got, want)
		}
	}
}

// O arquivo gerado pelo init precisa ser uma política válida (tudo negado)
// e listar as colunas de cada tabela para quem for editar.
func TestInitTextIsAValidDenyAllPolicy(t *testing.T) {
	p, _ := policy.Parse("x.crivo", "name x\nabout \"x\"\nenv dev\nconnect postgres://u@localhost/x\nsecret keychain\npedidos read\n")
	sc := testenv.SchemaFromDDL(t, p, vendasDDL)
	text := initText("vendas", "postgres://svc@pg-hml:5432/vendas?sslmode=verify-full", "public", sc)
	golden(t, "init_vendas.golden", text)

	got, diags := policy.Parse("vendas.crivo", text)
	if diags.HasErrors() {
		t.Fatalf("o init gerou política inválida:\n%s", diags.Error())
	}
	if len(got.Rules) != 0 {
		t.Errorf("o init deveria nascer sem regras ativas, tem %d", len(got.Rules))
	}
	if !strings.Contains(text, "#   colunas: id, nome, cpf, email, telefone, cidade\n#   sugestão: read except(cpf) mask(nome: pseudonym, email: email, telefone: last4)\n## Clientes PJ\n# clientes      deny") {
		t.Errorf("bloco de clientes inesperado:\n%s", text)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := runTool(t, "version")
	if code != output.ExitOK || !regexp.MustCompile(`^crivo \S+ \(parser PostgreSQL \d+\.\d+ via pg_query_go v6; \w+/\w+\)\n$`).MatchString(out) {
		t.Fatalf("código %d, saída %q", code, out)
	}
}

// O build não pode sobrescrever o próprio crivo. A checagem antiga comparava
// o texto dos caminhos e deixava passar /var vs /private/var (macOS) e links.
func TestSameFile(t *testing.T) {
	dir := t.TempDir()
	real := writeFile(t, dir, "crivo", "x")
	other := writeFile(t, dir, "outro", "x")
	cases := []struct {
		name string
		a    string
		want bool
	}{
		{"mesmo texto", real, true},
		{"caminho com ..", filepath.Join(dir, "sub", "..", "crivo"), true},
		{"outro arquivo igual", other, false},
		{"inexistente", filepath.Join(dir, "novo"), false},
	}
	if runtime.GOOS != "windows" { // link simbólico pede privilégio no Windows
		link := filepath.Join(dir, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			name string
			a    string
			want bool
		}{"link simbólico", link, true})
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if got := sameFile(c.a, real); got != c.want {
			t.Errorf("%s: sameFile(%q) = %v, esperava %v", c.name, c.a, got, c.want)
		}
	}
}

// ---------- dado pessoal exposto e trava de colunas ----------

func TestCheckWarnsAboutExposedPersonalData(t *testing.T) {
	testenv.Isolate(t)
	_, out, _ := runTool(t, "check", vendasPolicy, "--schema-sql", vendasDDL)
	// o exemplo mascara email e telefone e tira o cpf, mas deixa o nome nu
	if !strings.Contains(out, "clientes.nome parece nome de pessoa e sai sem máscara; sugestão: mask(nome: pseudonym)") {
		t.Errorf("faltou o aviso do nome:\n%s", out)
	}
	for _, never := range []string{"clientes.cpf parece", "clientes.email parece", "produtos.nome parece"} {
		if strings.Contains(out, never) {
			t.Errorf("aviso indevido %q:\n%s", never, out)
		}
	}
	_, out, _ = runTool(t, "check", "testdata/checks.crivo", "--schema-sql", vendasDDL)
	if !strings.Contains(out, "clientes.cpf parece documento e sai sem máscara; sugestão: except(cpf)") {
		t.Errorf("faltou o aviso do cpf exposto:\n%s", out)
	}
}

// A trava guarda as colunas expostas; uma coluna nova numa regra sem lista
// de colunas aparece como aviso até a pessoa revisar e regravar.
func TestLockDetectsNewlyExposedColumns(t *testing.T) {
	testenv.Isolate(t)
	dir := t.TempDir()
	pol := writeFile(t, dir, "vendas.crivo", mustRead(t, vendasPolicy))
	code, out, errOut := runTool(t, "check", pol, "--schema-sql", vendasDDL, "--lock")
	if code != output.ExitOK || !strings.Contains(out, "✓ trava gravada em "+pol+".lock") {
		t.Fatalf("--lock: código %d\n%s%s", code, out, errOut)
	}
	lock := mustRead(t, pol+".lock")
	if !strings.Contains(lock, `"public.clientes": [`) || strings.Contains(lock, `"cpf"`) || strings.Contains(lock, "audit_log") {
		t.Fatalf("trava inesperada:\n%s", lock)
	}
	if _, out, _ = runTool(t, "check", pol, "--schema-sql", vendasDDL); strings.Contains(out, "desde a última trava") {
		t.Fatalf("sem mudança não pode avisar:\n%s", out)
	}
	ddl := strings.Replace(mustRead(t, vendasDDL), "  cidade text\n);", "  cidade text,\n  rg text\n);", 1)
	changed := writeFile(t, dir, "schema2.sql", ddl)
	_, out, _ = runTool(t, "check", pol, "--schema-sql", changed)
	if !strings.Contains(out, "coluna(s) exposta(s) desde a última trava: public.clientes.rg") || !strings.Contains(out, "clientes.rg parece documento") {
		t.Fatalf("coluna nova sem aviso:\n%s", out)
	}
	// o build roda o mesmo check e mostra o aviso também
	_, out, _ = runTool(t, "build", pol, "--schema-sql", changed, "-o", filepath.Join(dir, "saida"))
	if !strings.Contains(out, "desde a última trava") {
		t.Errorf("build sem o aviso da trava:\n%s", out)
	}
	// --lock sem schema não grava nada
	if code, _, errOut := runTool(t, "check", pol, "--offline", "--lock"); code != output.ExitConfig || !strings.Contains(errOut, "--lock precisa do schema") {
		t.Errorf("--lock offline sem cache: código %d\n%s", code, errOut)
	}
}

// check --json é o contrato da extensão do VS Code.
func TestCheckJSONContract(t *testing.T) {
	testenv.Isolate(t)
	code, out, _ := runTool(t, "check", "testdata/checks.crivo", "--schema-sql", vendasDDL, "--json")
	var got struct {
		File        string `json:"file"`
		OK          bool   `json:"ok"`
		Note        string `json:"note"`
		Diagnostics []struct {
			Line, Col         int
			Severity, Message string
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != output.ExitConfig {
		t.Fatalf("código %d, JSON inválido (%v):\n%s", code, err, out)
	}
	if got.OK || !strings.HasSuffix(got.File, "checks.crivo") || !strings.Contains(got.Note, "DDL") {
		t.Errorf("cabeçalho inesperado: %+v", got)
	}
	found := false
	for _, d := range got.Diagnostics {
		if d.Line == 8 && d.Col == 1 && d.Severity == "error" && strings.Contains(d.Message, `"fantasma" não existe`) {
			found = true
		}
		if d.Severity != "error" && d.Severity != "warning" {
			t.Errorf("severidade fora do contrato: %+v", d)
		}
	}
	if !found {
		t.Errorf("diagnóstico da linha 8 ausente: %+v", got.Diagnostics)
	}
	code, out, _ = runTool(t, "check", vendasPolicy, "--schema-sql", vendasDDL, "--json")
	if code != output.ExitOK || !strings.Contains(out, `"ok":true`) {
		t.Errorf("política válida: código %d\n%s", code, out)
	}
}

// Consulta nomeada que o guard recusaria não passa no check.
func TestCheckValidatesNamedQueries(t *testing.T) {
	testenv.Isolate(t)
	dir := t.TempDir()
	src := strings.Replace(mustRead(t, vendasPolicy), "timeout 5s\n",
		"timeout 5s\nquery boa(id int) \"SELECT id, status FROM pedidos WHERE id = $1\"\nquery vaza(id int) \"SELECT cpf FROM clientes WHERE id = $1\"\n", 1)
	pol := writeFile(t, dir, "q.crivo", src)
	code, out, _ := runTool(t, "check", pol, "--schema-sql", vendasDDL)
	if code != output.ExitConfig || !strings.Contains(out, `query vaza seria barrada pelo crivo: coluna "cpf" não está liberada`) || strings.Contains(out, "query boa") {
		t.Fatalf("código %d\n%s", code, out)
	}
}

// examples/recursos.crivo documenta todos os recursos opcionais: ele precisa
// continuar válido e com as consultas prontas aceitas pelo guard.
func TestFeatureShowcasePolicyIsValid(t *testing.T) {
	testenv.Isolate(t)
	code, out, errOut := runTool(t, "check", "../../../examples/recursos.crivo", "--schema-sql", vendasDDL)
	if code != output.ExitOK || strings.Contains(out, "erro") {
		t.Fatalf("código %d\n%s%s", code, out, errOut)
	}
	p := testenv.LoadPolicy(t, "../../../examples/recursos.crivo")
	if p.Expires.IsZero() || p.MaxCost == 0 || p.RatePerMinute == 0 || p.QuotaRowsDay == 0 || !p.ApprovalWrites || len(p.Queries) != 2 {
		t.Errorf("o exemplo deixou de mostrar algum recurso: %+v", p)
	}
}
