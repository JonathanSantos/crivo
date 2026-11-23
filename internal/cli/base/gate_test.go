package base

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"crivo/internal/audit"
	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/testenv"
)

// policyWith devolve a política de exemplo com diretivas extras logo depois
// do timeout (sem mudar as linhas das regras para quem lê o arquivo).
func policyWith(t *testing.T, extra string) []byte {
	t.Helper()
	src, err := os.ReadFile(vendasPolicy)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(string(src), "timeout 5s\n", "timeout 5s\n"+extra, 1))
}

func runSrc(src []byte, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := mainWith(src, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// seed grava um cache fresco de schema para a política dada em texto.
func seed(t *testing.T, src []byte) *policy.Policy {
	t.Helper()
	p, diags := policy.Parse("policy", string(src))
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	testenv.SeedCache(t, p, testenv.SchemaFromDDL(t, p, vendasDDL), 0)
	return p
}

// Política vencida: todo comando que toca o banco (ou o schema) recusa com 5;
// policy, skill e ajuda continuam, para a pessoa entender o que houve.
func TestExpiredPolicyBlocksDataCommands(t *testing.T) {
	testenv.Isolate(t)
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	src := policyWith(t, "expires "+yesterday+"\n")
	seed(t, src)
	for _, args := range [][]string{
		{"query", "SELECT id FROM pedidos"},
		{"explain", "SELECT id FROM pedidos"},
		{"exec", "DELETE FROM pedido_itens WHERE id = 1", "--dry-run"},
		{"describe", "clientes"},
		{"tables"},
		{"refresh"},
	} {
		code, _, errOut := runSrc(src, args...)
		if code != output.ExitConfig || !strings.Contains(errOut, "a política venceu em "+yesterday) {
			t.Errorf("%v: código %d\n%s", args, code, errOut)
		}
	}
	for _, args := range [][]string{{"policy"}, {"skill", "--bin", "vendas"}, {"--help"}} {
		if code, _, errOut := runSrc(src, args...); code != output.ExitOK {
			t.Errorf("%v deveria funcionar mesmo vencida: código %d\n%s", args, code, errOut)
		}
	}
	// vale até o fim do dia: hoje ainda funciona
	today := policyWith(t, "expires "+time.Now().Format("2006-01-02")+"\n")
	seed(t, today)
	if code, _, errOut := runSrc(today, "describe", "clientes"); code != output.ExitOK {
		t.Errorf("no último dia ainda vale: código %d\n%s", code, errOut)
	}
}

// O MCP passa pelo mesmo portão a cada chamada (o servidor fica aberto).
func TestExpiredPolicyBlocksMCPTools(t *testing.T) {
	testenv.Isolate(t)
	src := policyWith(t, "expires "+time.Now().AddDate(0, 0, -1).Format("2006-01-02")+"\n")
	p := seed(t, src)
	s := &mcpServer{p: p, format: output.TSV}
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	go func() { _ = s.server().Run(ctx, st) }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "teste", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	for name, args := range map[string]map[string]any{
		"query":    {"sql": "SELECT id FROM pedidos"},
		"describe": {"table": "clientes"},
		"tables":   {},
	} {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(text(res), "a política venceu") {
			t.Errorf("%s pelo MCP: %s", name, text(res))
		}
	}
}

// rate e quota contam pela auditoria. Execuções aceitas há menos de um
// minuto e linhas de hoje entram na conta; recusas e dias anteriores não.
func TestRateAndQuotaFromAudit(t *testing.T) {
	cases := []struct {
		name    string
		extra   string
		entries []audit.Entry
		code    int
		want    string
	}{
		{"abaixo do rate", "rate 3/min\n", recent(2, 0), output.ExitParse, "SQL inválido"},
		{"rate atingido", "rate 3/min\n", recent(3, 0), output.ExitDenied, "limite de 3 execuções por minuto"},
		{"recusas não contam", "rate 1/min\n", []audit.Entry{{Time: time.Now(), Command: "query", Decision: "barrado"}}, output.ExitParse, "SQL inválido"},
		{"MCP conta junto", "rate 1/min\n", []audit.Entry{{Time: time.Now(), Command: "mcp:query", Decision: "aceito"}}, output.ExitDenied, "limite de 1"},
		{"execução antiga não conta", "rate 1/min\n", []audit.Entry{{Time: time.Now().Add(-2 * time.Minute), Command: "query", Decision: "aceito"}}, output.ExitParse, "SQL inválido"},
		{"quota atingida", "quota 100 rows/day\n", recent(1, 100), output.ExitDenied, "cota de 100 linhas por dia atingida (100 hoje)"},
		{"quota com folga", "quota 100 rows/day\n", recent(1, 99), output.ExitParse, "SQL inválido"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testenv.Isolate(t)
			src := policyWith(t, c.extra)
			seed(t, src)
			for _, e := range c.entries {
				if err := audit.Write("vendas", e); err != nil {
					t.Fatal(err)
				}
			}
			// SQL inválido mostra que o portão deixou passar (e não conectou)
			code, _, errOut := runSrc(src, "query", "SELEC 1")
			if code != c.code || !strings.Contains(errOut, c.want) {
				t.Fatalf("código %d, esperava %d com %q\n%s", code, c.code, c.want, errOut)
			}
		})
	}
}

func recent(n int, rowsEach int64) []audit.Entry {
	var out []audit.Entry
	for i := 0; i < n; i++ {
		out = append(out, audit.Entry{Time: time.Now().Add(-time.Duration(i) * time.Second), Command: "query", Decision: "aceito", Rows: rowsEach})
	}
	return out
}

// Sem auditoria gravável não há como contar: com rate/quota, recusa.
func TestLimitsFailClosedWithoutAudit(t *testing.T) {
	testenv.Isolate(t)
	src := policyWith(t, "rate 10/min\n")
	seed(t, src)
	blocker := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", blocker)
	t.Setenv("USERPROFILE", blocker)
	code, _, errOut := runSrc(src, "query", "SELECT id FROM pedidos")
	if code != output.ExitConfig || !strings.Contains(errOut, "rate/quota dependem da auditoria") {
		t.Fatalf("código %d\n%s", code, errOut)
	}
}

// Com pseudonym na política e sem como guardar a chave, recusa antes de
// conectar (nunca mostra o valor nu nem um *** silencioso).
func TestPseudonymWithoutKeyRefuses(t *testing.T) {
	testenv.Isolate(t)
	src, err := os.ReadFile(vendasPolicy)
	if err != nil {
		t.Fatal(err)
	}
	withPseudo := []byte(strings.Replace(string(src), "mask(email: partial, telefone: redact)", "mask(email: partial, telefone: redact, nome: pseudonym)", 1))
	seed(t, withPseudo)
	keys := filepath.Join(os.Getenv("HOME"), ".crivo", "keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, nil, 0o600); err != nil { // keys é arquivo: não dá para criar a chave
		t.Fatal(err)
	}
	code, _, errOut := runSrc(withPseudo, "query", "SELECT nome FROM clientes")
	if code != output.ExitConfig || !strings.Contains(errOut, "chave do pseudonym indisponível") {
		t.Fatalf("código %d\n%s", code, errOut)
	}
}
