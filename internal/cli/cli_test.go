package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jackc/pgx/v5/pgconn"

	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/run"
	"crivo/internal/schema"
	"crivo/internal/secret"
	"crivo/internal/sqlguard"
	"crivo/internal/testenv"
)

const vendas = "../../examples/vendas.crivo"

// O código de saída é o contrato com quem chama o binário (a IA e o
// auto-approve): cada tipo de erro precisa cair no código documentado no
// README, com título e motivo legíveis.
func TestReportMapsErrorsToExitCodes(t *testing.T) {
	p := testenv.LoadPolicy(t, vendas)
	rule := p.Resolve("public", "clientes")
	pgMissingColumn := &pgconn.PgError{Code: "42703", Message: `column "x" does not exist`}

	cases := []struct {
		name  string
		err   error
		code  int
		lines []string // trechos que a mensagem em texto precisa ter
	}{
		{"sucesso", nil, output.ExitOK, nil},
		{"código já reportado", &ExitError{Code: 7}, 7, nil},
		{"recusa com regra", &sqlguard.Denial{Rule: rule, Reason: `coluna "cpf" não está liberada`, Accepted: "id, nome"}, output.ExitDenied,
			[]string{"✗ barrado pelo crivo", "regra   clientes  read except(cpf)", "(vendas.crivo:23)", `motivo  coluna "cpf" não está liberada`, "aceito  id, nome"}},
		{"recusa sem regra", &sqlguard.Denial{Reason: "statement DROP não é aceito"}, output.ExitDenied,
			[]string{"✗ barrado pelo crivo", "motivo  statement DROP não é aceito"}},
		{"recusa embrulhada", fmt.Errorf("contexto: %w", &sqlguard.Denial{Reason: "x"}), output.ExitDenied, []string{"barrado pelo crivo"}},
		{"SQL inválido com posição", &sqlguard.ParseError{Message: "syntax error at or near \"FORM\"", Position: 10}, output.ExitParse,
			[]string{"✗ SQL inválido", "erro perto da posição 10"}},
		{"teto de escrita", &run.TooManyRows{Affected: 30, Max: 20}, output.ExitDenied,
			[]string{"a escrita afetaria 30 linhas; o máximo da regra é 20 (rollback feito)", "até 20 linhas"}},
		{"senha ausente", &secret.ErrMissing{Msg: "senha não encontrada no keychain; rode: crivo secret set vendas"}, output.ExitConfig,
			[]string{"✗ segredo ausente", "crivo secret set vendas"}},
		{"configuração", &ConfigError{Msg: "informe o SQL"}, output.ExitConfig, []string{"✗ configuração", "informe o SQL"}},
		{"conexão sem TLS", &run.InsecureError{Host: "pg.remoto", Mode: "disable"}, output.ExitConfig,
			[]string{"✗ configuração", "pg.remoto", "edite a diretiva connect"}},
		{"erro do banco", &run.DBError{Err: errors.New("conexão:\n  recusada")}, output.ExitDB,
			[]string{"✗ erro do banco", "motivo  conexão: recusada"}},
		{"schema mudou no banco", &run.DBError{Err: pgMissingColumn}, output.ExitDB,
			[]string{"o cache de schema foi renovado"}},
		{"erro inesperado", errors.New("boom"), output.ExitBug, []string{"✗ erro inesperado", "boom"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if got := Report(&buf, p, c.err, false); got != c.code {
				t.Fatalf("código %d, esperava %d", got, c.code)
			}
			for _, l := range c.lines {
				if !strings.Contains(buf.String(), l) {
					t.Errorf("mensagem sem %q:\n%s", l, buf.String())
				}
			}
			if c.err == nil || c.lines == nil {
				if buf.Len() != 0 {
					t.Errorf("não deveria imprimir nada, imprimiu %q", buf.String())
				}
			}
		})
	}
}

// Com --json-errors a IA recebe um objeto por erro, com o mesmo código de
// saída e campos opcionais nulos em vez de strings vazias.
func TestReportJSON(t *testing.T) {
	p := testenv.LoadPolicy(t, vendas)
	var buf bytes.Buffer
	err := &sqlguard.Denial{Rule: p.Resolve("public", "clientes"), Reason: "coluna bloqueada"}
	if code := Report(&buf, p, err, true); code != output.ExitDenied {
		t.Fatalf("código %d", code)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("saída não é JSON: %v\n%s", err, buf.String())
	}
	if m["erro"] != "barrado pelo crivo" || m["motivo"] != "coluna bloqueada" || m["codigo"] != float64(output.ExitDenied) {
		t.Errorf("campos inesperados: %v", m)
	}
	if m["ref"] != "vendas.crivo:23" || m["aceito"] != nil || m["dica"] != nil {
		t.Errorf("ref/opcionais inesperados: %v", m)
	}
}

func TestReadSQL(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "q.sql")
	if err := os.WriteFile(file, []byte("SELECT 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, arg, file string
		want, errHas    string
	}{
		{"argumento", "SELECT id FROM pedidos", "", "SELECT id FROM pedidos", ""},
		{"arquivo", "", file, "SELECT 1", ""},
		{"os dois", "SELECT 1", file, "", "não os dois"},
		{"vazio", "  \n", "", "", "informe o SQL"},
		{"arquivo inexistente", "", filepath.Join(dir, "nao-existe.sql"), "", "lendo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ReadSQL(c.arg, c.file)
			if c.errHas != "" {
				var cfg *ConfigError
				if !errors.As(err, &cfg) || !strings.Contains(cfg.Msg, c.errHas) {
					t.Fatalf("esperava ConfigError com %q, veio %v", c.errHas, err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("ReadSQL = %q, %v; esperava %q", got, err, c.want)
			}
		})
	}
}

// -f - lê o SQL do stdin (útil para SQL com aspas difíceis de escapar).
func TestReadSQLFromStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })
	go func() { _, _ = w.WriteString("SELECT 'a;b'"); w.Close() }()
	got, err := ReadSQL("", "-")
	if err != nil || got != "SELECT 'a;b'" {
		t.Fatalf("ReadSQL(-) = %q, %v", got, err)
	}
}

// A sessão decide de onde vem o schema. Os casos abaixo nunca conectam: ou o
// cache serve, ou o pedido para no segredo ausente, antes de qualquer rede.
func TestSessionLoadSchemaModes(t *testing.T) {
	cases := []struct {
		name        string
		age         time.Duration
		seed        bool
		mode        SchemaMode
		wantStale   bool
		wantMissing bool // precisou do banco e parou na senha
	}{
		{"cache fresco serve a qualquer modo", 0, true, SchemaFresh, false, false},
		{"cache vencido serve ao check/test", schema.TTL + time.Minute, true, SchemaAnyCache, true, false},
		{"cache vencido não serve ao binário", schema.TTL + time.Minute, true, SchemaFresh, false, true},
		{"refresh sempre vai ao banco", 0, true, SchemaRefresh, false, true},
		{"sem cache vai ao banco", 0, false, SchemaAnyCache, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testenv.Isolate(t)
			p := testenv.LoadPolicy(t, vendas)
			if c.seed {
				testenv.SeedCache(t, p, testenv.SchemaFromDDL(t, p, "../../testdata/schema.sql"), c.age)
			}
			var stderr bytes.Buffer
			s := NewSession(p, &stderr)
			defer s.Close()
			sc, err := s.LoadSchema(c.mode)
			if c.wantMissing {
				var miss *secret.ErrMissing
				if !errors.As(err, &miss) {
					t.Fatalf("esperava parar na senha ausente, veio %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if sc.Table("public", "clientes") == nil {
				t.Fatal("schema do cache sem a tabela clientes")
			}
			if s.SchemaStale != c.wantStale || s.SchemaFromDB {
				t.Errorf("stale=%v fromDB=%v, esperava stale=%v fromDB=false", s.SchemaStale, s.SchemaFromDB, c.wantStale)
			}
			again, _ := s.LoadSchema(c.mode)
			if again != sc {
				t.Error("a segunda carga na mesma sessão deveria reaproveitar o schema")
			}
		})
	}
}

// Cache de outra base (outra URL) nunca é usado, mesmo com o mesmo nome.
func TestSessionIgnoresCacheFromAnotherSource(t *testing.T) {
	testenv.Isolate(t)
	p := testenv.LoadPolicy(t, vendas)
	other := *p
	other.Connect = "postgres://svc_app@outro-host:5432/vendas?sslmode=verify-full"
	testenv.SeedCache(t, &other, testenv.SchemaFromDDL(t, p, "../../testdata/schema.sql"), 0)
	s := NewSession(p, &bytes.Buffer{})
	defer s.Close()
	var miss *secret.ErrMissing
	if _, err := s.LoadSchema(SchemaAnyCache); !errors.As(err, &miss) {
		t.Fatalf("deveria ignorar o cache de outra origem e ir ao banco; veio %v", err)
	}
}

// A senha é buscada uma vez por sessão (o prompt não pode aparecer duas vezes).
func TestSessionPasswordFromEnvIsCached(t *testing.T) {
	testenv.Isolate(t)
	p, diags := policy.Parse("x.crivo", "name x\nabout \"teste\"\nenv dev\nconnect postgres://u@localhost/x\nsecret env:CRIVO_TEST_PW\npedidos read\n")
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	t.Setenv("CRIVO_TEST_PW", "s3nha")
	s := NewSession(p, &bytes.Buffer{})
	defer s.Close()
	if pw, err := s.Password(); err != nil || pw != "s3nha" {
		t.Fatalf("Password = %q, %v", pw, err)
	}
	t.Setenv("CRIVO_TEST_PW", "outra")
	if pw, _ := s.Password(); pw != "s3nha" {
		t.Errorf("a senha deveria vir do cache da sessão, veio %q", pw)
	}
}

func TestRuleTextAndParserVersion(t *testing.T) {
	p := testenv.LoadPolicy(t, vendas)
	if got := RuleText(p.Resolve("public", "pedidos")); got != "pedidos  read, update(status, observacao) max 20" {
		t.Errorf("RuleText = %q", got)
	}
	if v := ParserVersion(); !regexp.MustCompile(`^\d+\.\d+$`).MatchString(v) {
		t.Errorf("ParserVersion = %q", v)
	}
}

// Só o pânico de saída do kong é recuperado; qualquer outro é bug e sobe.
func TestParseRepanicsForeignPanics(t *testing.T) {
	var root struct {
		Boom boomCmd `cmd:""`
	}
	parser, err := kong.New(&root, KongExit())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("esperava o pânico original, veio %v", r)
		}
	}()
	Parse(parser, []string{"boom", "--x"}, &bytes.Buffer{})
	t.Fatal("deveria ter entrado em pânico")
}

type boomFlag bool

func (boomFlag) Decode(*kong.DecodeContext) error { panic("boom") }
func (boomFlag) IsBool() bool                     { return true }

type boomCmd struct {
	X boomFlag `name:"x"`
}
