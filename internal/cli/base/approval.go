package base

// Aprovação de escrita (diretiva approval writes): o exec real não escreve;
// ele valida, simula para contar as linhas e grava uma pendência. Só uma
// pessoa, num terminal interativo, executa com <name> approve <id>.
//
// O que impede a IA de aprovar sozinha não é o TTY (o terminal do VS Code é
// um TTY): é que approve nunca entra numa regra de auto-aprovação (o VS Code
// pede o clique), não existe no MCP e exige digitar o id de novo. Na
// aprovação o SQL original passa pelo guard outra vez, contra o schema atual;
// o SQL reescrito guardado na pendência é só informativo e nunca é executado.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"crivo/internal/cli"
	"crivo/internal/output"
	"crivo/internal/run"
	"crivo/internal/sqlguard"
)

// PendingTTL é quanto tempo uma pendência espera pela aprovação.
const PendingTTL = time.Hour

var pendingIDRe = regexp.MustCompile(`^[0-9a-f]{6}$`)

// pending é uma escrita esperando aprovação.
type pending struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	SQL       string    `json:"sql"`       // original, o que será revalidado
	Rewritten string    `json:"rewritten"` // informativo
	Affected  int64     `json:"affected"`  // na simulação
	Via       string    `json:"via"`       // "" (CLI) ou "mcp:"
}

// interactive diz se stdin e stdout são um terminal (trocado nos testes).
var interactive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// confirmIn é de onde vem a confirmação digitada (trocado nos testes).
var confirmIn io.Reader = os.Stdin

func pendingDir(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".crivo", "pending", name), nil
}

func (e *env) savePending(sql string, v *sqlguard.Verdict, affected int64) (*pending, error) {
	dir, err := pendingDir(e.p.Name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	pd := &pending{ID: hex.EncodeToString(b), Created: now().UTC(), SQL: sql, Rewritten: v.SQL, Affected: affected, Via: e.via}
	data, err := json.MarshalIndent(pd, "", "  ")
	if err != nil {
		return nil, err
	}
	return pd, os.WriteFile(filepath.Join(dir, pd.ID+".json"), data, 0o600)
}

func loadPending(name, id string) (*pending, error) {
	if !pendingIDRe.MatchString(id) {
		return nil, &cli.ConfigError{Msg: fmt.Sprintf("id inválido %q: use o id de 6 caracteres mostrado pelo exec", id)}
	}
	dir, err := pendingDir(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return nil, &cli.ConfigError{Msg: fmt.Sprintf("não há escrita pendente #%s (veja %s pending)", id, name)}
	}
	var pd pending
	if err := json.Unmarshal(data, &pd); err != nil || pd.ID != id {
		return nil, &cli.ConfigError{Msg: fmt.Sprintf("pendência #%s ilegível", id)}
	}
	if now().Sub(pd.Created) > PendingTTL {
		_ = removePending(name, id)
		return nil, &cli.ConfigError{Msg: fmt.Sprintf("a pendência #%s expirou (vale %s); rode o exec de novo", id, PendingTTL)}
	}
	return &pd, nil
}

func removePending(name, id string) error {
	dir, err := pendingDir(name)
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(dir, id+".json"))
}

// listPending devolve as pendências válidas, mais antigas primeiro, e apaga
// as expiradas.
func listPending(name string) ([]*pending, error) {
	dir, err := pendingDir(name)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*pending
	for _, de := range entries {
		id := strings.TrimSuffix(de.Name(), ".json")
		if !pendingIDRe.MatchString(id) {
			continue
		}
		if pd, err := loadPending(name, id); err == nil {
			out = append(out, pd)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// pendingWrite é o desfecho do exec com aprovação: a escrita ficou pendente.
func (e *env) pendingWrite(sql string, v *sqlguard.Verdict) error {
	conn, err := e.sess.Conn()
	if err != nil {
		return err
	}
	// a simulação conta as linhas e já aplica o teto (acima dele, nem pendência)
	res, err := run.Exec(e.sess.Ctx(), conn, e.p, v.SQL, v.MaxRows, true)
	if err != nil {
		var many *run.TooManyRows
		if errors.As(err, &many) {
			return &sqlguard.Denial{Rule: v.Target.Rule,
				Reason:   fmt.Sprintf("a escrita afetaria %d linhas; o máximo da regra é %d (rollback feito)", many.Affected, many.Max),
				Accepted: fmt.Sprintf("um WHERE mais restrito, que afete até %d linhas", many.Max)}
		}
		return e.onDBError(err)
	}
	pd, err := e.savePending(sql, v, res.Affected)
	if err != nil {
		return &cli.ConfigError{Msg: "não foi possível gravar a pendência: " + err.Error()}
	}
	fmt.Fprintf(e.stdout, "-- escrita pendente #%s: %s (simulação; nada foi gravado)\n", pd.ID, output.WriteFooter(res.Affected, true))
	fmt.Fprintf(e.stdout, "-- sql %s\n", v.SQL)
	fmt.Fprintf(e.stdout, "-- esta política exige aprovação humana: peça para a pessoa rodar, no terminal, %s approve %s (vale %s)\n", e.p.Name, pd.ID, PendingTTL)
	return &cli.PendingError{ID: pd.ID}
}

type approveCmd struct {
	ID string `arg:"" help:"Id da escrita pendente (mostrado pelo exec)."`
}

func (c *approveCmd) Run(e *env) (err error) {
	start := time.Now()
	if !interactive() {
		return &cli.ConfigError{Msg: "approve só roda num terminal interativo, digitado por uma pessoa"}
	}
	pd, err := loadPending(e.p.Name, c.ID)
	if err != nil {
		return err
	}
	var v *sqlguard.Verdict
	var n int64
	defer func() { e.audit("approve", pd.SQL, v, start, n, false, err) }()
	via := "CLI"
	if pd.Via != "" {
		via = strings.TrimSuffix(pd.Via, ":")
	}
	fmt.Fprintf(e.stdout, "-- escrita pendente #%s, pedida há %s via %s\n", pd.ID, now().Sub(pd.Created).Round(time.Second), via)
	fmt.Fprintf(e.stdout, "-- sql %s\n", pd.SQL)
	fmt.Fprintf(e.stdout, "-- na simulação: %s\n", output.WriteFooter(pd.Affected, true))
	fmt.Fprintf(e.stdout, "Para executar de verdade, digite o id de novo (%s): ", pd.ID)
	line, _ := bufio.NewReader(confirmIn).ReadString('\n')
	if strings.TrimSpace(line) != pd.ID {
		return &cli.ConfigError{Msg: "não confirmado; nada foi executado (a pendência continua até expirar)"}
	}
	if err = e.limits(); err != nil {
		return err
	}
	// revalida o SQL original contra a política e o schema de agora
	g, err := e.guard()
	if err != nil {
		return err
	}
	if v, err = g.Check(sqlguard.CmdExec, pd.SQL); err != nil {
		return err
	}
	m, err := e.masker(v)
	if err != nil {
		return err
	}
	conn, err := e.sess.Conn()
	if err != nil {
		return err
	}
	res, err := run.Exec(e.sess.Ctx(), conn, e.p, v.SQL, v.MaxRows, false)
	_ = removePending(e.p.Name, pd.ID) // aprovada uma vez só, dê certo ou não
	if err != nil {
		var many *run.TooManyRows
		if errors.As(err, &many) {
			return &sqlguard.Denial{Rule: v.Target.Rule,
				Reason:   fmt.Sprintf("a escrita afetaria %d linhas agora; o máximo da regra é %d (rollback feito)", many.Affected, many.Max),
				Accepted: fmt.Sprintf("um WHERE mais restrito, que afete até %d linhas", many.Max)}
		}
		return e.onDBError(err)
	}
	n = res.Affected
	rows := &output.Rows{Footer: output.WriteFooter(res.Affected, false)}
	if len(res.Columns) > 0 {
		rows.Columns, rows.Types, rows.Values = res.Columns, res.Types, masked(m, res, v)
	}
	fmt.Fprintln(e.stdout)
	return output.Write(e.stdout, e.format, rows)
}

type pendingCmd struct{}

func (c *pendingCmd) Run(e *env) error {
	list, err := listPending(e.p.Name)
	if err != nil {
		return err
	}
	rows := &output.Rows{Columns: []string{"id", "idade", "linhas", "via", "sql"}}
	for _, pd := range list {
		id, age := pd.ID, now().Sub(pd.Created).Round(time.Second).String()
		lines, via, sql := fmt.Sprint(pd.Affected), strings.TrimSuffix(pd.Via, ":"), pd.SQL
		if via == "" {
			via = "cli"
		}
		rows.Values = append(rows.Values, []*string{&id, &age, &lines, &via, &sql})
	}
	rows.Footer = fmt.Sprintf("%d pendente(s); aprovar: %s approve <id> (no terminal, por uma pessoa)", len(list), e.p.Name)
	return output.Write(e.stdout, e.format, rows)
}

type rejectCmd struct {
	ID string `arg:"" help:"Id da escrita pendente."`
}

func (c *rejectCmd) Run(e *env) error {
	if _, err := loadPending(e.p.Name, c.ID); err != nil {
		return err
	}
	if err := removePending(e.p.Name, c.ID); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "✓ pendência #%s descartada\n", c.ID)
	return nil
}
