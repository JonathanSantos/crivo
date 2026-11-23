// Package run executa SQL já validado: uma conexão nova por execução, uma
// transação com SET LOCAL de timeouts e search_path, teto de linhas e
// rollback conforme o comando. Não há pool nem processo residente.
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"crivo/internal/policy"
)

// Result é o resultado de uma execução, com valores em texto.
type Result struct {
	Columns   []string
	Types     []uint32
	Rows      [][]*string // nil: NULL
	Truncated bool        // veio a linha extra do LIMIT reescrito
	Affected  int64
}

// TooManyRows é a escrita que passou do teto; já houve rollback.
type TooManyRows struct {
	Affected int64
	Max      int
}

func (e *TooManyRows) Error() string {
	return fmt.Sprintf("a escrita afetaria %d linhas; o máximo da regra é %d", e.Affected, e.Max)
}

// TooCostly é a query cujo custo estimado pelo planner passa do teto da
// política (diretiva cost); nada foi executado.
type TooCostly struct {
	Cost float64
	Max  float64
}

func (e *TooCostly) Error() string {
	return fmt.Sprintf("custo estimado %.0f passa do teto %.0f da política", e.Cost, e.Max)
}

// DBError é um erro do banco (código de saída 4).
type DBError struct {
	Err error
}

func (e *DBError) Error() string { return e.Err.Error() }
func (e *DBError) Unwrap() error { return e.Err }

var quotedRe = regexp.MustCompile(`"[^"]*"|'[^']*'`)

// SafeMessage é o texto do erro para a IA e para a auditoria. Em erros de
// dado (SQLSTATE 22) e de restrição (23) o Postgres cita o valor, que pode
// vir de uma linha escondida pelo filtro ou de uma coluna mascarada: o que
// está entre aspas sai cortado.
func SafeMessage(err error) string {
	msg := err.Error()
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (strings.HasPrefix(pg.Code, "22") || strings.HasPrefix(pg.Code, "23")) {
		return quotedRe.ReplaceAllString(msg, `"…"`)
	}
	return msg
}

// SchemaChanged diz se o erro indica coluna ou tabela inexistente (cache velho).
func SchemaChanged(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "42703" || pg.Code == "42P01"
	}
	return false
}

// InsecureError é uma URL que permitiria conexão sem TLS a um host remoto
// (código de saída 5). O check da política já recusa; esta é a segunda
// camada, caso a política tenha sido alterada depois.
type InsecureError struct {
	Host string
	Mode string
}

func (e *InsecureError) Error() string {
	mode := e.Mode
	if mode == "" {
		mode = "(ausente)"
	}
	return fmt.Sprintf("conexão a %s recusada: sslmode=%s permite tráfego sem TLS; use sslmode=verify-full", e.Host, mode)
}

// Connect abre uma conexão identificada como crivo:<name>. Recusa URL sem
// TLS para host remoto.
func Connect(ctx context.Context, connect, name, password string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(connect)
	if err != nil {
		return nil, fmt.Errorf("URL de conexão inválida: %w", err)
	}
	if err := checkTLS(cfg, connect); err != nil {
		return nil, err
	}
	if password != "" {
		cfg.Password = password
	}
	cfg.ConnectTimeout = 10 * time.Second
	cfg.RuntimeParams["application_name"] = "crivo:" + name
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, &DBError{fmt.Errorf("conexão: %w", err)}
	}
	return conn, nil
}

// checkTLS confere o destino que o driver vai usar de fato, e não uma
// releitura da URL: parâmetros como ?host= trocam o host, e o sslmode=prefer
// (padrão sem sslmode) cria um destino alternativo sem TLS. Todo destino
// remoto, inclusive os alternativos, precisa de TLS.
func checkTLS(cfg *pgx.ConnConfig, connect string) error {
	mode := ""
	if u, err := url.Parse(connect); err == nil {
		mode = u.Query().Get("sslmode")
	}
	targets := []*pgconn.FallbackConfig{{Host: cfg.Host, Port: cfg.Port, TLSConfig: cfg.TLSConfig}}
	targets = append(targets, cfg.Fallbacks...)
	for _, t := range targets {
		if t.TLSConfig == nil && !localTarget(t.Host) {
			return &InsecureError{Host: t.Host, Mode: mode}
		}
	}
	return nil
}

// localTarget é host da própria máquina ou socket unix (caminho absoluto).
func localTarget(host string) bool {
	return policy.IsLocalHost(host) || strings.HasPrefix(host, "/")
}

// Context devolve um contexto com folga sobre o statement_timeout.
func Context(p *policy.Policy) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), p.Timeout+30*time.Second)
}

func quoteIdent(s string) string { return pgx.Identifier{s}.Sanitize() }

func setLocal(ctx context.Context, tx pgx.Tx, p *policy.Policy) error {
	stmts := []string{
		fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", p.Timeout.Milliseconds()),
		"SET LOCAL lock_timeout = '2s'",
		"SET LOCAL idle_in_transaction_session_timeout = '10s'",
		"SET LOCAL search_path = " + quoteIdent(p.Schema),
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return &DBError{err}
		}
	}
	return nil
}

func collect(rows pgx.Rows, cap int) (*Result, error) {
	defer rows.Close()
	res := &Result{}
	for _, fd := range rows.FieldDescriptions() {
		res.Columns = append(res.Columns, fd.Name)
		res.Types = append(res.Types, fd.DataTypeOID)
	}
	for rows.Next() {
		if cap >= 0 && len(res.Rows) >= cap {
			res.Truncated = true
			continue // drena sem guardar
		}
		raw := rows.RawValues()
		row := make([]*string, len(raw))
		for i, v := range raw {
			if v != nil {
				s := string(v)
				row[i] = &s
			}
		}
		res.Rows = append(res.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, &DBError{err}
	}
	res.Affected = rows.CommandTag().RowsAffected()
	return res, nil
}

var textFormat = pgx.QueryResultFormats{pgx.TextFormatCode}

// checkCost pede o plano ao Postgres (sem executar) e recusa se o custo
// total estimado passar do teto da política.
func checkCost(ctx context.Context, tx pgx.Tx, p *policy.Policy, sql string) error {
	if p.MaxCost <= 0 {
		return nil
	}
	var raw string
	if err := tx.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+sql, textFormat).Scan(&raw); err != nil {
		return &DBError{err}
	}
	var plans []struct {
		Plan struct {
			TotalCost float64 `json:"Total Cost"`
		} `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(raw), &plans); err != nil || len(plans) == 0 {
		return &DBError{fmt.Errorf("plano do EXPLAIN ilegível: %v", err)}
	}
	if c := plans[0].Plan.TotalCost; c > p.MaxCost {
		return &TooCostly{Cost: c, Max: p.MaxCost}
	}
	return nil
}

// Query executa um SELECT em transação READ ONLY e sempre faz rollback.
// cap é o teto de linhas; o SQL já vem com LIMIT cap+1.
func Query(ctx context.Context, conn *pgx.Conn, p *policy.Policy, sql string, cap int) (*Result, error) {
	return query(ctx, conn, p, sql, cap, true)
}

func query(ctx context.Context, conn *pgx.Conn, p *policy.Policy, sql string, cap int, costCheck bool) (*Result, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, &DBError{err}
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := setLocal(ctx, tx, p); err != nil {
		return nil, err
	}
	if costCheck {
		if err := checkCost(ctx, tx, p, sql); err != nil {
			return nil, err
		}
	}
	rows, err := tx.Query(ctx, sql, textFormat)
	if err != nil {
		return nil, &DBError{err}
	}
	return collect(rows, cap)
}

// Explain devolve o plano (EXPLAIN sem ANALYZE) de um SELECT validado.
func Explain(ctx context.Context, conn *pgx.Conn, p *policy.Policy, sql string) (*Result, error) {
	return query(ctx, conn, p, "EXPLAIN "+sql, -1, false) // o próprio plano não tem custo
}

// Exec executa INSERT/UPDATE/DELETE numa transação. Faz rollback se for
// dry-run ou se as linhas afetadas passarem de max.
func Exec(ctx context.Context, conn *pgx.Conn, p *policy.Policy, sql string, max int, dryRun bool) (*Result, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, &DBError{err}
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := setLocal(ctx, tx, p); err != nil {
		return nil, err
	}
	if err := checkCost(ctx, tx, p, sql); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, textFormat)
	if err != nil {
		return nil, &DBError{err}
	}
	res, err := collect(rows, max)
	if err != nil {
		return nil, err
	}
	if res.Affected > int64(max) {
		return nil, &TooManyRows{Affected: res.Affected, Max: max}
	}
	if dryRun {
		return res, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, &DBError{err}
	}
	return res, nil
}
