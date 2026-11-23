package base

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crivo/internal/audit"
	"crivo/internal/output"
	"crivo/internal/skill"
	"crivo/internal/testenv"
)

const (
	vendasPolicy = "../../../examples/vendas.crivo"
	padraoPolicy = "testdata/padrao.crivo"
	vendasDDL    = "../../../testdata/schema.sql"
)

// runPolicy roda o binário gerado com a política do arquivo.
func runPolicy(t *testing.T, policyPath string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	src, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code = mainWith(src, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// withCache isola o teste e semeia um cache fresco de schema para a política.
func withCache(t *testing.T, policyPath string) (home string) {
	t.Helper()
	home = testenv.Isolate(t)
	p := testenv.LoadPolicy(t, policyPath)
	testenv.SeedCache(t, p, testenv.SchemaFromDDL(t, p, vendasDDL), 0)
	return home
}

// auditEntries lê o log de auditoria da política na HOME isolada.
func auditEntries(t *testing.T, home, name string) []audit.Entry {
	t.Helper()
	f, err := os.Open(filepath.Join(home, ".crivo", "logs", name+".jsonl"))
	if err != nil {
		t.Fatalf("log de auditoria ausente: %v", err)
	}
	defer f.Close()
	var out []audit.Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("linha de auditoria inválida %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

// ---------- policy, tables, describe ----------

func TestPolicyCommandPrintsNumberedPolicyAndFunctions(t *testing.T) {
	testenv.Isolate(t)
	code, out, _ := runBase(t, "policy")
	if code != output.ExitOK {
		t.Fatalf("código %d", code)
	}
	for _, want := range []string{" 1  # vendas.crivo\n", "23  clientes        read except(cpf)", "-- funções liberadas: ", "count"} {
		if !strings.Contains(out, want) {
			t.Errorf("faltou %q em:\n%s", want, out)
		}
	}
}

// tables não precisa do banco para regras com nome exato, e mostra o filtro
// de linha para a IA saber que não vê tudo. audit_* (deny) não aparece.
func TestTablesListsOnlyVisibleRules(t *testing.T) {
	testenv.Isolate(t)
	code, out, _ := runBase(t, "tables")
	if code != output.ExitOK {
		t.Fatalf("código %d", code)
	}
	for _, want := range []string{
		"tabela\tações\tdescrição\n",
		"pedidos\tread, update(status, observacao) max 20\tPedidos de venda.",
		"pagamentos\tread where status <> 'estornado'\tPagamentos confirmados (estornos ficam de fora) [filtro: só linhas com status <> 'estornado']",
		"-- 5 tabelas; qualquer outra não existe para você",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("faltou %q em:\n%s", want, out)
		}
	}
	if strings.Contains(out, "audit") {
		t.Error("tabela negada apareceu no tables")
	}
}

// Padrão de nome vira a lista de tabelas reais que ele cobre (via cache).
func TestTablesExpandsPatternsFromSchema(t *testing.T) {
	withCache(t, padraoPolicy)
	code, out, errOut := runPolicy(t, padraoPolicy, "tables", "--format", "json")
	if code != output.ExitOK {
		t.Fatalf("código %d\n%s", code, errOut)
	}
	var got struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--format json inválido: %v\n%s", err, out)
	}
	var names []string
	for _, r := range got.Rows {
		names = append(names, r["tabela"].(string))
	}
	if strings.Join(names, ",") != "pedido_itens,pedidos,fantasma" {
		t.Errorf("tabelas %v, esperava pedido_itens, pedidos e fantasma", names)
	}
}

func TestDescribe(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		table  string
		code   int
		out    []string // stdout
		errOut []string // stderr
		absent []string // linhas que não podem existir (coluna bloqueada)
	}{
		{"colunas liberadas e máscaras", vendasPolicy, "clientes", output.ExitOK,
			[]string{"coluna\ttipo\tnulo\tchave\tmáscara\tescrita\n", "email\ttext\tsim\t\tpartial\t\n", "telefone\ttext\tsim\t\tredact\t\n",
				"-- regra: read except(cpf) mask(email: partial, telefone: redact) (policy:23) | Clientes PJ."}, nil, []string{"\ncpf\t"}},
		{"colunas graváveis e chave estrangeira", vendasPolicy, "public.pedidos", output.ExitOK,
			[]string{"status\ttext\tnão\t\t\tupdate\n", "cliente_id\tinteger\tnão\tFK → clientes.id"}, nil, nil},
		{"filtro de linha no rodapé", vendasPolicy, "pagamentos", output.ExitOK,
			[]string{"filtro de leitura: só linhas com status <> 'estornado'"}, nil, nil},
		{"tabela negada", vendasPolicy, "audit_log", output.ExitDenied, nil,
			[]string{`tabela "audit_log" não existe para a IA`, "use o comando tables"}, nil},
		{"tabela sem regra", vendasPolicy, "usuarios", output.ExitDenied, nil, []string{`tabela "usuarios" não existe para a IA`}, nil},
		{"catálogo sempre bloqueado", vendasPolicy, "pg_catalog.pg_class", output.ExitDenied, nil, []string{"não existe para a IA"}, nil},
		{"na política mas não no banco", padraoPolicy, "fantasma", output.ExitDenied, nil,
			[]string{"está na política mas não existe no banco", "rode o comando refresh"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withCache(t, c.policy)
			code, out, errOut := runPolicy(t, c.policy, "describe", c.table)
			if code != c.code {
				t.Fatalf("código %d, esperava %d\nstdout: %s\nstderr: %s", code, c.code, out, errOut)
			}
			for _, w := range c.out {
				if !strings.Contains(out, w) {
					t.Errorf("stdout sem %q:\n%s", w, out)
				}
			}
			for _, w := range c.errOut {
				if !strings.Contains(errOut, w) {
					t.Errorf("stderr sem %q:\n%s", w, errOut)
				}
			}
			for _, w := range c.absent {
				if strings.Contains(out, w) {
					t.Errorf("stdout não pode citar %q:\n%s", w, out)
				}
			}
		})
	}
}

// Sem cache, describe e refresh precisam do banco; o keychain (mock) não tem
// senha, então param ali, com o código 5 e a dica do comando certo.
func TestCommandsNeedingDatabaseStopAtMissingSecret(t *testing.T) {
	for _, args := range [][]string{{"describe", "pedidos"}, {"refresh"}} {
		testenv.Isolate(t)
		code, _, errOut := runBase(t, args...)
		if code != output.ExitConfig || !strings.Contains(errOut, "rode: crivo secret set vendas") {
			t.Errorf("%v: código %d\n%s", args, code, errOut)
		}
	}
}

// ---------- query, explain, exec: recusa, auditoria e códigos ----------

// Cada desfecho vira uma linha de auditoria com a decisão, o motivo e o
// código de saída, sem dados do resultado. Nenhum caso aqui conecta: a
// recusa vem antes da conexão, e o aceito para na senha ausente.
func TestQueryOutcomesAndAudit(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		code     int
		stderr   string
		command  string
		decision string
		reason   string
		dry      bool
	}{
		{"coluna bloqueada", []string{"query", "SELECT cpf FROM clientes"}, output.ExitDenied, `coluna "cpf" não está liberada`, "query", "barrado", `coluna "cpf" não está liberada`, false},
		{"SQL inválido", []string{"query", "SELEC 1"}, output.ExitParse, "SQL inválido", "query", "invalido", "syntax error", false},
		{"aceito sem senha", []string{"query", "SELECT id FROM pedidos"}, output.ExitConfig, "segredo ausente", "query", "erro", "senha não encontrada", false},
		{"explain barrado", []string{"explain", "SELECT * FROM audit_log"}, output.ExitDenied, "negada pela política", "explain", "barrado", "negada pela política", false},
		{"exec em coluna não gravável", []string{"exec", "UPDATE pedidos SET total = 0 WHERE id = 1"}, output.ExitDenied, `coluna "total" não pode ser alterada`, "exec", "barrado", "total", false},
		{"exec dry-run sem senha", []string{"exec", "DELETE FROM pedido_itens WHERE id = 1", "--dry-run"}, output.ExitConfig, "segredo ausente", "exec", "erro", "senha", true},
		{"query não aceita escrita", []string{"query", "DELETE FROM pedido_itens WHERE id = 1"}, output.ExitDenied, "query só aceita SELECT", "query", "barrado", "query só aceita SELECT", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := withCache(t, vendasPolicy)
			code, out, errOut := runBase(t, c.args...)
			if code != c.code || !strings.Contains(errOut, c.stderr) {
				t.Fatalf("código %d, esperava %d com %q\nstdout: %s\nstderr: %s", code, c.code, c.stderr, out, errOut)
			}
			if out != "" {
				t.Errorf("recusa não pode escrever no stdout: %q", out)
			}
			entries := auditEntries(t, home, "vendas")
			if len(entries) != 1 {
				t.Fatalf("esperava 1 linha de auditoria, veio %d", len(entries))
			}
			e := entries[0]
			if e.Command != c.command || e.Decision != c.decision || !strings.Contains(e.Reason, c.reason) || e.Exit != c.code || e.DryRun != c.dry {
				t.Errorf("auditoria inesperada: %+v", e)
			}
			if e.SQL != c.args[1] || e.Time.IsZero() {
				t.Errorf("auditoria sem o SQL original ou sem hora: %+v", e)
			}
		})
	}
}

// A regra que barrou fica registrada com a linha da política.
func TestAuditRecordsDenyingRule(t *testing.T) {
	home := withCache(t, vendasPolicy)
	runBase(t, "query", "SELECT cpf FROM clientes")
	e := auditEntries(t, home, "vendas")[0]
	if len(e.Rules) != 1 || e.Rules[0] != "clientes (policy:23)" {
		t.Errorf("regras na auditoria: %v", e.Rules)
	}
}

// Falha ao gravar a auditoria avisa, mas não muda o resultado do comando.
func TestAuditFailureDoesNotChangeOutcome(t *testing.T) {
	withCache(t, vendasPolicy)
	blocker := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", blocker) // ~/.crivo/logs não pode ser criado dentro de um arquivo
	t.Setenv("USERPROFILE", blocker)
	code, _, errOut := runBase(t, "query", "SELECT cpf FROM clientes")
	if code != output.ExitDenied || !strings.Contains(errOut, "aviso: log de auditoria falhou") {
		t.Fatalf("código %d\n%s", code, errOut)
	}
}

func TestJSONErrors(t *testing.T) {
	withCache(t, vendasPolicy)
	code, _, errOut := runBase(t, "--json-errors", "query", "SELECT cpf FROM clientes")
	var m map[string]any
	if err := json.Unmarshal([]byte(errOut), &m); err != nil || code != output.ExitDenied {
		t.Fatalf("código %d, stderr não é JSON (%v): %s", code, err, errOut)
	}
	if m["erro"] != "barrado pelo crivo" || m["ref"] != "policy:23" || m["codigo"] != float64(output.ExitDenied) {
		t.Errorf("JSON inesperado: %v", m)
	}
}

func TestQueryReadsSQLFromFile(t *testing.T) {
	withCache(t, vendasPolicy)
	f := filepath.Join(t.TempDir(), "q.sql")
	if err := os.WriteFile(f, []byte("SELECT cpf FROM clientes"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runBase(t, "query", "-f", f)
	if code != output.ExitDenied || !strings.Contains(errOut, "cpf") {
		t.Fatalf("código %d\n%s", code, errOut)
	}
	code, _, errOut = runBase(t, "query", "SELECT 1", "-f", f)
	if code != output.ExitConfig || !strings.Contains(errOut, "não os dois") {
		t.Fatalf("SQL e -f juntos: código %d\n%s", code, errOut)
	}
}

// Política só de leitura não tem o comando exec: a IA nem o vê.
func TestReadOnlyPolicyHasNoExec(t *testing.T) {
	testenv.Isolate(t)
	src := "name ro\nabout \"x\"\nenv dev\nconnect postgres://u@localhost/x\nsecret keychain\npedidos read\n"
	var out, errOut bytes.Buffer
	code := mainWith([]byte(src), []string{"exec", "DELETE FROM pedidos WHERE id = 1"}, &out, &errOut)
	if code != output.ExitConfig || !strings.Contains(errOut.String(), "unexpected argument exec") {
		t.Fatalf("código %d\n%s", code, errOut.String())
	}
	mainWith([]byte(src), nil, &out, &errOut)
	if strings.Contains(out.String(), "exec") {
		t.Errorf("a ajuda de uma política só de leitura cita exec:\n%s", out.String())
	}
}

func TestInvalidEmbeddedPolicy(t *testing.T) {
	testenv.Isolate(t)
	var out, errOut bytes.Buffer
	code := mainWith([]byte("name x\n"), []string{"tables"}, &out, &errOut)
	if code != output.ExitConfig || !strings.Contains(errOut.String(), "política embutida inválida") {
		t.Fatalf("código %d\n%s", code, errOut.String())
	}
}

// ---------- skill ----------

// O comando só liga a política ao gerador; o conteúdo tem golden próprio
// em internal/skill. Aqui conferimos que a saída é exatamente a dele.
func TestSkillPrintVSCodeAndMCPMatchGenerators(t *testing.T) {
	testenv.Isolate(t)
	p := testenv.LoadPolicy(t, vendasPolicy)
	want, err := skill.Generate(p, skill.Options{Bin: "vendas"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"skill", "--bin", "vendas"}, want},
		{[]string{"skill", "vscode", "--bin", "vendas"}, skill.VSCodeSettings(p, "vendas")},
		{[]string{"skill", "mcp", "--bin", "vendas"}, skill.MCPConfig(p, "vendas", false)},
		{[]string{"skill", "mcp", "--bin", "vendas", "--allow-exec"}, skill.MCPConfig(p, "vendas", true)},
	}
	for _, c := range cases {
		code, out, errOut := runBase(t, c.args...)
		if code != output.ExitOK || out != c.want {
			t.Errorf("%v: código %d\nstderr: %s\nobtido:\n%s\nesperado:\n%s", c.args, code, errOut, out, c.want)
		}
	}
}

func TestSkillWithSchemaUsesCache(t *testing.T) {
	withCache(t, vendasPolicy)
	code, out, _ := runBase(t, "skill", "--bin", "vendas", "--with-schema")
	if code != output.ExitOK || !strings.Contains(out, "| email |") || strings.Contains(out, "| cpf |") {
		t.Fatalf("código %d\n%s", code, out)
	}
}

func TestSkillInstall(t *testing.T) {
	home := testenv.Isolate(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "crivo-vendas", "SKILL.md")

	code, out, _ := runBase(t, "skill", "install", "--dir", dir, "--bin", "vendas")
	if code != output.ExitOK || !strings.Contains(out, "✓ "+path) {
		t.Fatalf("install: código %d\n%s", code, out)
	}
	got, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(got), "---\nname: crivo-vendas\n") {
		t.Fatalf("SKILL.md: %v\n%s", err, got)
	}
	// não sobrescreve sem --force: a pessoa pode ter editado a skill
	if code, _, errOut := runBase(t, "skill", "install", "--dir", dir, "--bin", "vendas"); code != output.ExitConfig || !strings.Contains(errOut, "--force") {
		t.Fatalf("reinstalar sem --force: código %d\n%s", code, errOut)
	}
	if code, _, _ := runBase(t, "skill", "install", "--dir", dir, "--bin", "vendas", "--force"); code != output.ExitOK {
		t.Fatalf("reinstalar com --force: código %d", code)
	}
	if code, _, errOut := runBase(t, "skill", "install", "--personal", "--dir", dir); code != output.ExitConfig || !strings.Contains(errOut, "não os dois") {
		t.Fatalf("--personal com --dir: código %d\n%s", code, errOut)
	}
	// --personal grava na HOME (aqui, a isolada)
	code, out, _ = runBase(t, "skill", "install", "--personal", "--bin", "vendas")
	personal := filepath.Join(home, ".copilot", "skills", "crivo-vendas", "SKILL.md")
	if _, err := os.Stat(personal); err != nil || code != output.ExitOK {
		t.Fatalf("--personal: código %d, %v\n%s", code, err, out)
	}
}
