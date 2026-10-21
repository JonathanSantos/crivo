// Package cli tem o que os dois modos (ferramenta e base) compartilham:
// conexão, carga do schema, mapeamento de erros para códigos de saída.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/run"
	"crivo/internal/schema"
	"crivo/internal/secret"
	"crivo/internal/sqlguard"
)

// Version do Crivo; sobrescrita com -ldflags "-X crivo/internal/cli.Version=...".
var Version = "0.1.0-dev"

// ParserVersion devolve a versão do Postgres do parser embutido.
func ParserVersion() string {
	tree, err := pg_query.Parse("SELECT 1")
	if err != nil {
		return "?"
	}
	v := tree.Version
	return fmt.Sprintf("%d.%d", v/10000, v%100)
}

// ExitError carrega um código de saída já reportado ao usuário.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit %d", e.Code) }

// ConfigError é erro de configuração (código 5).
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return e.Msg }

// Session reúne política, senha, conexão e schema, carregados sob demanda.
type Session struct {
	Policy   *policy.Policy
	Stderr   io.Writer
	password *string
	conn     *pgx.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	Schema   *schema.Schema
	// SchemaFromDB diz se o schema veio do banco nesta execução.
	SchemaFromDB bool
	// SchemaStale diz se o schema veio de um cache vencido.
	SchemaStale bool
}

// NewSession cria a sessão.
func NewSession(p *policy.Policy, stderr io.Writer) *Session {
	ctx, cancel := run.Context(p)
	return &Session{Policy: p, Stderr: stderr, ctx: ctx, cancel: cancel}
}

// Ctx devolve o contexto da sessão.
func (s *Session) Ctx() context.Context { return s.ctx }

// Close fecha a conexão.
func (s *Session) Close() {
	if s.conn != nil {
		s.conn.Close(context.Background()) //nolint:errcheck
	}
	s.cancel()
}

// Password busca a senha uma vez.
func (s *Session) Password() (string, error) {
	if s.password != nil {
		return *s.password, nil
	}
	pw, err := secret.Get(s.Policy)
	if err != nil {
		return "", err
	}
	s.password = &pw
	return pw, nil
}

// Conn abre (uma vez) a conexão.
func (s *Session) Conn() (*pgx.Conn, error) {
	if s.conn != nil {
		return s.conn, nil
	}
	pw, err := s.Password()
	if err != nil {
		return nil, err
	}
	conn, err := run.Connect(s.ctx, s.Policy.Connect, s.Policy.Name, pw)
	if err != nil {
		return nil, err
	}
	s.conn = conn
	return conn, nil
}

// SchemaMode diz como carregar o schema.
type SchemaMode int

const (
	// SchemaFresh usa o cache dentro do TTL; senão lê do banco.
	SchemaFresh SchemaMode = iota
	// SchemaAnyCache usa qualquer cache; só lê do banco se não houver (check, test).
	SchemaAnyCache
	// SchemaRefresh sempre lê do banco.
	SchemaRefresh
)

func (s *Session) sourceKey() string {
	return schema.SourceKey(s.Policy.Connect, s.Policy.Schemas())
}

// LoadSchema carrega o schema conforme o modo.
func (s *Session) LoadSchema(mode SchemaMode) (*schema.Schema, error) {
	if s.Schema != nil && mode != SchemaRefresh {
		return s.Schema, nil
	}
	if mode != SchemaRefresh {
		cached, fresh, err := schema.LoadCache(s.Policy.Name, s.sourceKey())
		if err == nil && (fresh || mode == SchemaAnyCache) {
			s.Schema, s.SchemaStale = cached, !fresh
			return cached, nil
		}
	}
	conn, err := s.Conn()
	if err != nil {
		return nil, err
	}
	sc, err := schema.Fetch(s.ctx, conn, s.Policy.Schemas())
	if err != nil {
		return nil, &run.DBError{Err: fmt.Errorf("lendo o catálogo: %w", err)}
	}
	sc.Source = s.sourceKey()
	if err := schema.SaveCache(s.Policy.Name, sc); err != nil {
		fmt.Fprintf(s.Stderr, "aviso: não foi possível gravar o cache de schema: %v\n", err)
	}
	s.Schema, s.SchemaFromDB, s.SchemaStale = sc, true, false
	return sc, nil
}

// RuleText formata a regra como nas mensagens: "pedidos  read, update(...)".
func RuleText(r *policy.Rule) string {
	return r.Label() + "  " + r.Body
}

// Report imprime o erro e devolve o código de saída.
func Report(w io.Writer, p *policy.Policy, err error, asJSON bool) int {
	if err == nil {
		return output.ExitOK
	}
	var (
		ee     *ExitError
		denial *sqlguard.Denial
		perr   *sqlguard.ParseError
		many   *run.TooManyRows
		dberr  *run.DBError
		miss   *secret.ErrMissing
		cfg    *ConfigError
		insec  *run.InsecureError
	)
	switch {
	case errors.As(err, &ee):
		return ee.Code
	case errors.As(err, &insec):
		output.WriteMessage(w, output.Message{Title: "configuração", Reason: insec.Error(), Hint: "edite a diretiva connect da política e gere o binário de novo", Code: output.ExitConfig}, asJSON)
		return output.ExitConfig
	case errors.As(err, &denial):
		m := output.Message{Title: "barrado pelo crivo", Reason: denial.Reason, Accepted: denial.Accepted, Code: output.ExitDenied}
		if denial.Rule != nil {
			m.Rule = RuleText(denial.Rule)
			if p != nil {
				m.RuleRef = p.RuleRef(denial.Rule)
			}
		}
		output.WriteMessage(w, m, asJSON)
		return output.ExitDenied
	case errors.As(err, &perr):
		m := output.Message{Title: "SQL inválido", Reason: perr.Message, Code: output.ExitParse}
		if perr.Position > 0 {
			m.Hint = fmt.Sprintf("erro perto da posição %d", perr.Position)
		}
		output.WriteMessage(w, m, asJSON)
		return output.ExitParse
	case errors.As(err, &many):
		output.WriteMessage(w, output.Message{
			Title: "barrado pelo crivo", Reason: many.Error() + " (rollback feito)",
			Accepted: fmt.Sprintf("um WHERE mais restrito, que afete até %d linhas", many.Max), Code: output.ExitDenied,
		}, asJSON)
		return output.ExitDenied
	case errors.As(err, &miss):
		output.WriteMessage(w, output.Message{Title: "segredo ausente", Reason: miss.Msg, Code: output.ExitConfig}, asJSON)
		return output.ExitConfig
	case errors.As(err, &cfg):
		output.WriteMessage(w, output.Message{Title: "configuração", Reason: cfg.Msg, Code: output.ExitConfig}, asJSON)
		return output.ExitConfig
	case errors.As(err, &dberr):
		m := output.Message{Title: "erro do banco", Reason: oneLine(dberr.Error()), Code: output.ExitDB}
		if run.SchemaChanged(err) {
			m.Hint = "o cache de schema foi renovado; confira as colunas com describe e tente de novo"
		}
		output.WriteMessage(w, m, asJSON)
		return output.ExitDB
	}
	output.WriteMessage(w, output.Message{Title: "erro inesperado", Reason: oneLine(err.Error()), Code: output.ExitBug}, asJSON)
	return output.ExitBug
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// ReadSQL devolve o SQL do argumento ou do arquivo (-f).
func ReadSQL(arg, file string) (string, error) {
	switch {
	case file != "" && arg != "":
		return "", &ConfigError{"use o SQL no argumento ou -f arquivo.sql, não os dois"}
	case file == "-":
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", &ConfigError{fmt.Sprintf("lendo %s: %v", file, err)}
		}
		return string(b), nil
	case strings.TrimSpace(arg) == "":
		return "", &ConfigError{"informe o SQL entre aspas ou com -f arquivo.sql"}
	}
	return arg, nil
}
