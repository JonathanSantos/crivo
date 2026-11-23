package base

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/skill"
	"crivo/internal/sqlguard"
	"crivo/internal/testenv"
)

const namedQueries = "## Pedidos de um cliente, mais novos primeiro\n" +
	"query pedidos_do_cliente(cliente_id int) \"SELECT id, status FROM pedidos WHERE cliente_id = $1 ORDER BY id DESC\"\n" +
	"query clientes_da_cidade(cidade text) \"SELECT nome, email FROM clientes WHERE cidade = $1\"\n"

// ---------- consultas nomeadas ----------

func TestRunListsAndValidatesNamedQueries(t *testing.T) {
	testenv.Isolate(t)
	src := policyWith(t, namedQueries)
	seed(t, src)
	code, out, _ := runSrc(src, "run")
	if code != output.ExitOK || !strings.Contains(out, "pedidos_do_cliente\tcliente_id int\tPedidos de um cliente, mais novos primeiro") || !strings.Contains(out, "uso: vendas run <consulta> nome=valor") {
		t.Fatalf("lista: código %d\n%s", code, out)
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"run", "nao_existe"}, `consulta "nao_existe" não existe`},
		{[]string{"run", "pedidos_do_cliente"}, "falta o parâmetro cliente_id (int)"},
		{[]string{"run", "pedidos_do_cliente", "cliente_id=1 OR 1=1"}, "cliente_id precisa ser um inteiro"},
		{[]string{"run", "pedidos_do_cliente", "cliente_id"}, "precisa ser nome=valor"},
		{[]string{"run", "pedidos_do_cliente", "cliente_id=1", "extra=2"}, "não tem o parâmetro extra"},
		// válido: passa pelo guard e só para na senha (o mock não tem)
		{[]string{"run", "pedidos_do_cliente", "cliente_id=7"}, "segredo ausente"},
	}
	for _, c := range cases {
		code, _, errOut := runSrc(src, c.args...)
		if code != output.ExitConfig || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: código %d, esperava 5 com %q\n%s", c.args, code, c.want, errOut)
		}
	}
	// sem consultas na política, o comando nem existe
	if code, _, errOut := runBase(t, "run"); code != output.ExitConfig || !strings.Contains(errOut, "unexpected argument run") {
		t.Errorf("run sem consultas: código %d\n%s", code, errOut)
	}
}

// A auditoria registra o SQL já ligado e o comando run.
func TestRunIsAuditedWithBoundSQL(t *testing.T) {
	home := testenv.Isolate(t)
	src := policyWith(t, namedQueries)
	seed(t, src)
	runSrc(src, "run", "clientes_da_cidade", "cidade=São Paulo")
	e := auditEntries(t, home, "vendas")
	if len(e) != 1 || e[0].Command != "run" || e[0].SQL != "SELECT nome, email FROM clientes WHERE cidade = 'São Paulo'" {
		t.Fatalf("auditoria: %+v", e)
	}
}

func TestNamedQueryMCPTool(t *testing.T) {
	testenv.Isolate(t)
	src := policyWith(t, namedQueries)
	p := seed(t, src)
	cs := connect(t, &mcpServer{p: p, format: output.TSV})
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var tool *mcp.Tool
	for _, tl := range tools.Tools {
		if tl.Name == "q_pedidos_do_cliente" {
			tool = tl
		}
	}
	if tool == nil || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
		t.Fatalf("ferramenta q_pedidos_do_cliente ausente ou sem readOnly: %+v", tool)
	}
	schema, _ := json.Marshal(tool.InputSchema)
	if !strings.Contains(string(schema), `"cliente_id":{"description":"cliente_id","type":"integer"}`) || !strings.Contains(string(schema), `"required":["cliente_id"]`) {
		t.Errorf("schema de entrada: %s", schema)
	}
	call := func(args map[string]any) string {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "q_pedidos_do_cliente", Arguments: args})
		if err != nil {
			return "erro de protocolo: " + err.Error()
		}
		return text(res)
	}
	if got := call(map[string]any{"cliente_id": 7}); !strings.Contains(got, "segredo ausente") {
		t.Errorf("chamada válida deveria chegar até a senha: %s", got)
	}
	if got := call(map[string]any{"cliente_id": "1 OR 1=1"}); strings.Contains(got, "segredo") {
		t.Errorf("argumento inválido não pode chegar ao banco: %s", got)
	}
}

func connect(t *testing.T, s *mcpServer) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	go func() { _ = s.server().Run(ctx, st) }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "teste", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// ---------- aprovação de escrita ----------

func approvalEnv(t *testing.T) (*env, []byte) {
	t.Helper()
	src := policyWith(t, "approval writes\n")
	p := seed(t, src)
	var out, errOut bytes.Buffer
	return &env{p: p, stdout: &out, stderr: &errOut, format: output.TSV}, src
}

func fakeTerminal(t *testing.T, tty bool, typed string) {
	t.Helper()
	oldI, oldC := interactive, confirmIn
	interactive = func() bool { return tty }
	confirmIn = strings.NewReader(typed)
	t.Cleanup(func() { interactive, confirmIn = oldI, oldC })
}

// approve fora de um terminal (como a IA chamaria) nunca executa.
func TestApproveRefusesWithoutTerminal(t *testing.T) {
	testenv.Isolate(t)
	_, src := approvalEnv(t)
	fakeTerminal(t, false, "")
	code, _, errOut := runSrc(src, "approve", "a1b2c3")
	if code != output.ExitConfig || !strings.Contains(errOut, "approve só roda num terminal interativo") {
		t.Fatalf("código %d\n%s", code, errOut)
	}
}

func TestApproveFlow(t *testing.T) {
	testenv.Isolate(t)
	e, src := approvalEnv(t)
	v := &sqlguard.Verdict{SQL: "DELETE FROM pedido_itens WHERE id = 1"}
	pd, err := e.savePending("DELETE FROM pedido_itens WHERE id = 1", v, 1)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".crivo", "pending", "vendas", pd.ID+".json")); err != nil || !regexp.MustCompile(`^[0-9a-f]{6}$`).MatchString(pd.ID) {
		t.Fatalf("pendência não gravada: %v %v", fi, err)
	}
	code, out, _ := runSrc(src, "pending")
	if code != output.ExitOK || !strings.Contains(out, pd.ID+"\t") || !strings.Contains(out, "DELETE FROM pedido_itens WHERE id = 1") {
		t.Fatalf("pending: código %d\n%s", code, out)
	}

	// confirmação errada: nada acontece e a pendência continua
	fakeTerminal(t, true, "zzzzzz\n")
	code, out, errOut := runSrc(src, "approve", pd.ID)
	if code != output.ExitConfig || !strings.Contains(errOut, "não confirmado") || !strings.Contains(out, "digite o id de novo") {
		t.Fatalf("confirmação errada: código %d\n%s\n%s", code, out, errOut)
	}
	// confirmação certa: revalida pelo guard e só para na senha (sem banco aqui)
	fakeTerminal(t, true, pd.ID+"\n")
	code, _, errOut = runSrc(src, "approve", pd.ID)
	if code != output.ExitConfig || !strings.Contains(errOut, "segredo ausente") {
		t.Fatalf("confirmação certa: código %d\n%s", code, errOut)
	}

	// reject descarta
	if code, out, _ = runSrc(src, "reject", pd.ID); code != output.ExitOK || !strings.Contains(out, "descartada") {
		t.Fatalf("reject: código %d\n%s", code, out)
	}
	if code, _, errOut = runSrc(src, "reject", pd.ID); code != output.ExitConfig || !strings.Contains(errOut, "não há escrita pendente") {
		t.Fatalf("reject de novo: código %d\n%s", code, errOut)
	}
}

// Na aprovação o SQL original passa pelo guard de novo: uma pendência
// adulterada no disco (SQL que a política não permite) é recusada.
func TestApproveRevalidatesOriginalSQL(t *testing.T) {
	testenv.Isolate(t)
	e, src := approvalEnv(t)
	pd, err := e.savePending("DELETE FROM pedidos WHERE id = 1", &sqlguard.Verdict{SQL: "x"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	fakeTerminal(t, true, pd.ID+"\n")
	code, _, errOut := runSrc(src, "approve", pd.ID)
	if code != output.ExitDenied || !strings.Contains(errOut, "não permite delete") {
		t.Fatalf("código %d\n%s", code, errOut)
	}
}

func TestPendingExpiresAndRejectsBadIDs(t *testing.T) {
	testenv.Isolate(t)
	e, src := approvalEnv(t)
	pd, _ := e.savePending("DELETE FROM pedido_itens WHERE id = 1", &sqlguard.Verdict{}, 1)
	old := now
	now = func() time.Time { return time.Now().Add(PendingTTL + time.Minute) }
	t.Cleanup(func() { now = old })
	fakeTerminal(t, true, pd.ID+"\n")
	if code, _, errOut := runSrc(src, "approve", pd.ID); code != output.ExitConfig || !strings.Contains(errOut, "expirou") {
		t.Fatalf("pendência vencida: código %d\n%s", code, errOut)
	}
	now = old
	for _, id := range []string{"../../x", "ABCDEF", "abc", "a1b2c3d4"} {
		if code, _, errOut := runSrc(src, "approve", id); code != output.ExitConfig || !strings.Contains(errOut, "id inválido") {
			t.Errorf("%q: código %d\n%s", id, code, errOut)
		}
	}
}

// approve só existe com approval writes; approve nunca é liberado sem clique
// no VS Code; pending é leitura livre.
func TestApprovalCommandsAndVSCodeRules(t *testing.T) {
	testenv.Isolate(t)
	if code, _, errOut := runBase(t, "approve", "a1b2c3"); code != output.ExitConfig || !strings.Contains(errOut, "unexpected argument approve") {
		t.Errorf("approve sem a diretiva: código %d\n%s", code, errOut)
	}
	src := policyWith(t, "approval writes\n")
	p, _ := policy.Parse("policy", string(src))
	rules := skill.VSCodeSettings(p, "vendas")
	if !strings.Contains(rules, `"/^vendas approve\\b/": false`) || !strings.Contains(rules, "|pending|") {
		t.Fatalf("regras:\n%s", rules)
	}
	for _, line := range strings.Split(rules, "\n") {
		if !strings.HasSuffix(strings.TrimSuffix(line, ","), "true") {
			continue
		}
		k := line[strings.Index(line, `"`)+1 : strings.LastIndex(line, `"`)]
		var pattern string
		_ = json.Unmarshal([]byte(`"`+k+`"`), &pattern)
		re := regexp.MustCompile(strings.Trim(pattern, "/"))
		for _, cmd := range []string{"vendas approve a1b2c3", "vendas reject a1b2c3", `vendas exec "DELETE FROM pedido_itens WHERE id = 1"`} {
			if re.MatchString(cmd) {
				t.Errorf("regra %s aprovaria sem clique: %s", pattern, cmd)
			}
		}
	}
}

// Pelo MCP, com approval writes, dry_run=false vira pendência (não precisa de
// --allow-exec) e o resultado não é erro: traz o próximo passo.
func TestMCPExecWithApprovalCreatesPending(t *testing.T) {
	testenv.Isolate(t)
	src := policyWith(t, "approval writes\n")
	p := seed(t, src)
	cs := connect(t, &mcpServer{p: p, format: output.TSV})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "exec", Arguments: map[string]any{"sql": "DELETE FROM pedido_itens WHERE id = 1", "dry_run": false}})
	if err != nil {
		t.Fatal(err)
	}
	// sem banco, para na senha; o importante é não ser "escrita real desligada"
	if got := text(res); strings.Contains(got, "desligada") || !strings.Contains(got, "segredo ausente") {
		t.Fatalf("exec real pelo MCP com aprovação: %s", got)
	}
	tools, _ := cs.ListTools(context.Background(), nil)
	for _, tl := range tools.Tools {
		if tl.Name == "approve" || tl.Name == "pending" || tl.Name == "reject" {
			t.Errorf("o MCP não pode expor %s", tl.Name)
		}
		if tl.Name == "exec" && !strings.Contains(tl.Description, "vendas approve <id>") {
			t.Errorf("descrição do exec sem o fluxo de aprovação: %s", tl.Description)
		}
	}
}

// ---------- exportação ----------

func TestExportCommand(t *testing.T) {
	testenv.Isolate(t)
	// lê os arquivos de exemplo antes de mudar de pasta (o export grava na atual)
	plain := policyWith(t, "")
	src := policyWith(t, "export 1000 rows\n")
	seedAt(t, src)
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	// sem a diretiva, o comando nem existe
	if code, _, errOut := runSrc(plain, "export", "SELECT id FROM pedidos", "-o", "x.csv"); code != output.ExitConfig || !strings.Contains(errOut, "unexpected argument export") {
		t.Fatalf("export sem diretiva: código %d\n%s", code, errOut)
	}
	if err := os.WriteFile("existe.csv", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"export", "SELECT id FROM pedidos", "-o", "/tmp/fora.csv"}, output.ExitConfig, "caminho relativo dentro da pasta atual"},
		{[]string{"export", "SELECT id FROM pedidos", "-o", "../fora.csv"}, output.ExitConfig, "caminho relativo dentro da pasta atual"},
		{[]string{"export", "SELECT id FROM pedidos", "-o", "existe.csv"}, output.ExitConfig, "já existe; use --force"},
		{[]string{"export", "SELECT id FROM pedidos"}, output.ExitConfig, "missing flags: --output"},
		{[]string{"export", "SELECT cpf FROM clientes", "-o", "c.csv"}, output.ExitDenied, `coluna "cpf" não está liberada`},
		// válido: passa pelo guard e para na senha (sem banco aqui), sem criar arquivo
		{[]string{"export", "SELECT id, email FROM clientes", "-o", "c.csv"}, output.ExitConfig, "segredo ausente"},
	}
	for _, c := range cases {
		code, _, errOut := runSrc(src, c.args...)
		if code != c.code || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: código %d, esperava %d com %q\n%s", c.args, code, c.code, c.want, errOut)
		}
	}
	if _, err := os.Stat("c.csv"); err == nil {
		t.Error("export que falhou não pode deixar arquivo")
	}
}

// seedAt semeia o cache da política (a HOME já está isolada).
func seedAt(t *testing.T, src []byte) {
	t.Helper()
	seed(t, src)
}

// O teto da exportação substitui o limit no SQL reescrito.
func TestExportUsesItsOwnCap(t *testing.T) {
	testenv.Isolate(t)
	src := policyWith(t, "export 1000 rows\n")
	p := seed(t, src)
	g, err := sqlguard.New(p, testenv.SchemaFromDDL(t, p, vendasDDL))
	if err != nil {
		t.Fatal(err)
	}
	v, err := g.CheckExport("SELECT id FROM pedidos", p.ExportRows)
	if err != nil || v.Cap != 1000 || !strings.HasSuffix(v.SQL, "LIMIT 1001") {
		t.Fatalf("CheckExport: %+v %v", v, err)
	}
	if q, _ := g.Check(sqlguard.CmdQuery, "SELECT id FROM pedidos"); q.Cap != 500 {
		t.Errorf("query continua com o limit da política: %d", q.Cap)
	}
}
