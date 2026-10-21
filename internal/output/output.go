// Package output formata resultados (TSV, JSON, tabela), mensagens de
// bloqueio e códigos de saída. A saída é pensada para ser lida por um
// modelo: compacta, previsível e com o motivo de qualquer recusa.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Códigos de saída.
const (
	ExitOK     = 0
	ExitBug    = 1
	ExitDenied = 2
	ExitParse  = 3
	ExitDB     = 4
	ExitConfig = 5
)

// Limites de saída.
const (
	MaxValue = 2 << 10   // 2 KB por valor
	MaxTotal = 256 << 10 // 256 KB no total
)

// Format da saída.
type Format string

const (
	TSV   Format = "tsv"
	JSON  Format = "json"
	Table Format = "table"
)

// Rows é um resultado pronto para imprimir.
type Rows struct {
	Columns []string
	Types   []uint32
	Values  [][]*string
	Footer  string // texto do rodapé, sem o "-- "
}

// Footer monta o texto do rodapé de leitura.
func ReadFooter(n int, truncated, byRequest bool) string {
	s := plural(n, "linha", "linhas")
	switch {
	case truncated && byRequest:
		return s + " (LIMIT da query; pode haver mais)"
	case truncated:
		return s + " (truncado: refine o filtro ou agregue)"
	}
	return s
}

// WriteFooter monta o rodapé de escrita.
func WriteFooter(n int64, dryRun bool) string {
	if dryRun {
		return fmt.Sprintf("%d %s (dry-run, rollback)", n, pick(n == 1, "linha seria afetada", "linhas seriam afetadas"))
	}
	return fmt.Sprintf("%d %s", n, pick(n == 1, "linha afetada", "linhas afetadas"))
}

func plural(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, pick(n == 1, one, many))
}

func pick(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

func clip(s string) string {
	if len(s) <= MaxValue {
		return s
	}
	cut := MaxValue
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%s…(+%d bytes)", s[:cut], len(s)-cut)
}

func escapeTSV(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\t", `\t`, "\n", `\n`, "\r", `\r`)
	return r.Replace(s)
}

// capped é um writer que para depois de MaxTotal bytes.
type capped struct {
	w   io.Writer
	n   int
	cut bool
}

func (c *capped) line(s string) bool {
	if c.cut {
		return false
	}
	if c.n+len(s)+1 > MaxTotal {
		c.cut = true
		return false
	}
	c.n += len(s) + 1
	fmt.Fprintln(c.w, s)
	return true
}

// Write imprime o resultado no formato pedido.
func Write(w io.Writer, f Format, r *Rows) error {
	switch f {
	case JSON:
		return writeJSON(w, r)
	case Table:
		writeTable(w, r)
	default:
		writeTSV(w, r)
	}
	return nil
}

func writeTSV(w io.Writer, r *Rows) {
	c := &capped{w: w}
	if len(r.Columns) > 0 {
		hdr := make([]string, len(r.Columns))
		for i, h := range r.Columns {
			hdr[i] = escapeTSV(h)
		}
		c.line(strings.Join(hdr, "\t"))
	}
	shown := 0
	for _, row := range r.Values {
		cells := make([]string, len(row))
		for i, v := range row {
			if v == nil {
				cells[i] = "NULL"
			} else {
				cells[i] = escapeTSV(clip(*v))
			}
		}
		if !c.line(strings.Join(cells, "\t")) {
			break
		}
		shown++
	}
	footer(w, c, r, shown)
}

func footer(w io.Writer, c *capped, r *Rows, shown int) {
	if c.cut {
		fmt.Fprintf(w, "-- saída cortada em 256 KB depois de %d de %d linhas; selecione menos colunas ou agregue\n", shown, len(r.Values))
	}
	if r.Footer != "" {
		fmt.Fprintln(w, "-- "+r.Footer)
	}
}

func writeTable(w io.Writer, r *Rows) {
	widths := make([]int, len(r.Columns))
	cell := func(v *string) string {
		if v == nil {
			return "NULL"
		}
		return escapeTSV(clip(*v))
	}
	for i, h := range r.Columns {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range r.Values {
		for i, v := range row {
			if n := utf8.RuneCountInString(cell(v)); i < len(widths) && n > widths[i] {
				widths[i] = n
			}
		}
	}
	pad := func(cells []string) string {
		var b strings.Builder
		for i, s := range cells {
			if i > 0 {
				b.WriteString(" | ")
			}
			b.WriteString(s)
			if i < len(cells)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(s)))
			}
		}
		return b.String()
	}
	c := &capped{w: w}
	if len(r.Columns) > 0 {
		c.line(pad(r.Columns))
		seps := make([]string, len(widths))
		for i, n := range widths {
			seps[i] = strings.Repeat("-", n)
		}
		c.line(strings.ReplaceAll(pad(seps), " | ", "-+-"))
	}
	shown := 0
	for _, row := range r.Values {
		cells := make([]string, len(row))
		for i, v := range row {
			cells[i] = cell(v)
		}
		if !c.line(pad(cells)) {
			break
		}
		shown++
	}
	footer(w, c, r, shown)
}

// Tipos (OID) impressos como número ou literal JSON.
var numericOIDs = map[uint32]bool{20: true, 21: true, 23: true, 26: true, 700: true, 701: true, 1700: true}

const (
	oidBool  = 16
	oidJSON  = 114
	oidJSONB = 3802
)

func writeJSON(w io.Writer, r *Rows) error {
	type out struct {
		Columns   []string         `json:"columns"`
		Rows      []map[string]any `json:"rows"`
		Footer    string           `json:"footer,omitempty"`
		Truncated bool             `json:"output_truncated,omitempty"`
	}
	o := out{Columns: r.Columns, Rows: []map[string]any{}, Footer: r.Footer}
	total := 0
	for _, row := range r.Values {
		m := map[string]any{}
		for i, v := range row {
			if i >= len(r.Columns) {
				break
			}
			var val any
			if v != nil {
				s := clip(*v)
				val = s
				if i < len(r.Types) && s == *v {
					switch t := r.Types[i]; {
					case numericOIDs[t] && json.Valid([]byte(s)):
						val = json.RawMessage(s)
					case t == oidBool:
						val = s == "t" || s == "true"
					case (t == oidJSON || t == oidJSONB) && json.Valid([]byte(s)):
						val = json.RawMessage(s)
					}
				}
				total += len(s)
			}
			m[r.Columns[i]] = val
		}
		if total > MaxTotal {
			o.Truncated = true
			break
		}
		o.Rows = append(o.Rows, m)
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(o)
}

// Message é uma recusa ou erro para o stderr.
type Message struct {
	Title    string // "barrado pelo crivo", "SQL inválido", "erro do banco"
	Rule     string // "pedidos  read, update(...)   (policy:16)"
	RuleRef  string
	Reason   string
	Accepted string
	Hint     string
	Code     int
}

// WriteMessage imprime a mensagem em texto ou JSON.
func WriteMessage(w io.Writer, m Message, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{
			"erro": m.Title, "regra": nonEmpty(m.Rule), "ref": nonEmpty(m.RuleRef),
			"motivo": m.Reason, "aceito": nonEmpty(m.Accepted), "dica": nonEmpty(m.Hint), "codigo": m.Code,
		})
		return
	}
	fmt.Fprintln(w, "✗ "+m.Title)
	if m.Rule != "" {
		line := m.Rule
		if m.RuleRef != "" {
			line += "   (" + m.RuleRef + ")"
		}
		fmt.Fprintln(w, "  regra   "+line)
	}
	fmt.Fprintln(w, "  motivo  "+m.Reason)
	if m.Accepted != "" {
		fmt.Fprintln(w, "  aceito  "+m.Accepted)
	}
	if m.Hint != "" {
		fmt.Fprintln(w, "  dica    "+m.Hint)
	}
}

func nonEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
