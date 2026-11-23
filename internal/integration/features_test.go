package integration

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// generatedWith gera o binário da política do fixture com diretivas extras
// logo depois do timeout.
func generatedWith(t *testing.T, f *fixture, extra string) (bin string, env []string, dir string) {
	t.Helper()
	_, env, dir = generated(t, f)
	crivo := filepath.Join(dir, "crivo"+exeSuffix())
	src := strings.Replace(f.policy.Source, "timeout 1s\n", "timeout 1s\n"+extra, 1)
	pol := filepath.Join(dir, "extra.crivo")
	if err := os.WriteFile(pol, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "vendas-extra"+exeSuffix())
	if out, code := runIn(t, env, dir, crivo, "build", pol, "-o", strings.TrimSuffix(bin, exeSuffix())); code != 0 {
		t.Fatalf("build: código %d\n%s", code, out)
	}
	return bin, env, dir
}

// O teto de custo recusa antes de executar; o explain continua livre.
func TestCostCeilingAgainstPostgres(t *testing.T) {
	f := setup(t)
	bin, env, dir := generatedWith(t, f, "cost 1\n")
	// o LIMIT que o Crivo acrescenta deixa a leitura simples barata; a
	// ordenação de uma tabela inteira não
	out, code := runIn(t, env, dir, bin, "query", "SELECT id FROM pedidos ORDER BY total")
	if code != 2 || !strings.Contains(out, "custo estimado") || !strings.Contains(out, "nada foi executado") {
		t.Fatalf("query cara: código %d\n%s", code, out)
	}
	if out, code = runIn(t, env, dir, bin, "query", "SELECT 1 AS x"); code != 0 {
		t.Fatalf("query barata: código %d\n%s", code, out)
	}
	if out, code = runIn(t, env, dir, bin, "explain", "SELECT id FROM pedidos"); code != 0 {
		t.Fatalf("explain: código %d\n%s", code, out)
	}
	logs, _ := os.ReadFile(filepath.Join(dir, ".crivo", "logs", "vendas-it.jsonl"))
	if !strings.Contains(string(logs), `"reason":"custo estimado`) {
		t.Errorf("auditoria sem a recusa por custo:\n%s", logs)
	}
}

// Consulta nomeada no banco: máscaras aplicadas e argumento malicioso
// tratado como texto (não traz linha nenhuma).
func TestNamedQueryAgainstPostgres(t *testing.T) {
	f := setup(t)
	bin, env, dir := generatedWith(t, f, "query da_cidade(cidade text) \"SELECT nome, email FROM clientes WHERE cidade = $1\"\n")
	out, code := runIn(t, env, dir, bin, "run", "da_cidade", "cidade=Campinas")
	if code != 0 || !strings.Contains(out, "co***@atlaslog.com.br") || strings.Contains(out, "contato@") || strings.Contains(out, "Atlas") {
		t.Fatalf("run: código %d\n%s", code, out)
	}
	out, code = runIn(t, env, dir, bin, "run", "da_cidade", "cidade=x' OR '1'='1")
	if code != 0 || strings.Contains(out, "@") {
		t.Fatalf("injeção virou SQL: código %d\n%s", code, out)
	}
}

// Aprovação de ponta a ponta: o exec só deixa pendente (banco intacto);
// approve fora de terminal recusa; num terminal de verdade, com o id
// digitado, executa.
func TestApprovalAgainstPostgres(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pseudo-terminal só em Unix")
	}
	f := setup(t)
	bin, env, dir := generatedWith(t, f, "approval writes\n")
	status := func() string {
		var s string
		c := adminConn(t, f)
		if err := c.QueryRow(context.Background(), "SELECT status FROM "+testSchemaName+".pedidos WHERE id = 1").Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := status()

	out, code := runIn(t, env, dir, bin, "exec", "UPDATE pedidos SET status = 'enviado' WHERE id = 1")
	m := regexp.MustCompile(`pendente #([0-9a-f]{6})`).FindStringSubmatch(out)
	if code != 6 || m == nil || !strings.Contains(out, "approve "+m[1]) {
		t.Fatalf("exec com aprovação: código %d\n%s", code, out)
	}
	id := m[1]
	if status() != before {
		t.Fatal("o exec com aprovação escreveu no banco")
	}
	if out, code = runIn(t, env, dir, bin, "pending"); code != 0 || !strings.Contains(out, id) {
		t.Fatalf("pending: código %d\n%s", code, out)
	}
	if out, code = runIn(t, env, dir, bin, "approve", id); code != 5 || !strings.Contains(out, "terminal interativo") {
		t.Fatalf("approve sem terminal: código %d\n%s", code, out)
	}

	cmd := exec.Command(bin, "approve", id)
	cmd.Env, cmd.Dir = env, dir
	tty, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	r := bufio.NewReader(tty)
	var seen strings.Builder
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(seen.String(), "digite o id de novo") {
		if time.Now().After(deadline) {
			t.Fatalf("prompt não apareceu:\n%s", seen.String())
		}
		b, err := r.ReadByte()
		if err != nil {
			t.Fatalf("lendo o terminal: %v\n%s", err, seen.String())
		}
		seen.WriteByte(b)
	}
	if _, err := io.WriteString(tty, id+"\n"); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("approve: %v\n%s%s", err, seen.String(), rest)
	}
	if got := status(); got != "enviado" {
		t.Fatalf("depois do approve o status é %q\n%s%s", got, seen.String(), rest)
	}
	if out, _ = runIn(t, env, dir, bin, "pending"); strings.Contains(out, id) {
		t.Errorf("a pendência aprovada continua listada:\n%s", out)
	}
	logs, _ := os.ReadFile(filepath.Join(dir, ".crivo", "logs", "vendas-it.jsonl"))
	if !strings.Contains(string(logs), `"command":"exec"`) || !strings.Contains(string(logs), `"decision":"pendente"`) || !strings.Contains(string(logs), `"command":"approve"`) {
		t.Errorf("auditoria incompleta:\n%s", logs)
	}
}

// describe --sample traz linhas reais já mascaradas, sem as colunas bloqueadas.
func TestDescribeSampleAgainstPostgres(t *testing.T) {
	f := setup(t)
	bin, env, dir := generated(t, f)
	out, code := runIn(t, env, dir, bin, "describe", "clientes", "--sample", "2")
	if code != 0 || !strings.Contains(out, "@atlaslog.com.br") || strings.Contains(out, "contato@") || strings.Contains(out, "123.456") || strings.Contains(out, "Atlas Log") {
		t.Fatalf("código %d\n%s", code, out)
	}
}
