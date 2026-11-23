// Package output formata resultados (TSV, JSON, tabela), mensagens de
// bloqueio e códigos de saída. A saída é pensada para ser lida por um
// modelo: compacta, previsível e com o motivo de qualquer recusa.
package output

import (
	"encoding/csv"
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
	// ExitPending: a escrita ficou pendente de aprovação humana (approval writes).
	ExitPending = 6
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
	// Markdown é uma tabela em markdown, legível direto no chat.
	Markdown Format = "markdown"
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
		return s + " (cortado no LIMIT da query: há mais linhas)"
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
	case Markdown:
		writeMarkdown(w, r)
	default:
		writeTSV(w, r)
	}
	return nil
}

// escapeMD deixa o valor numa célula só: barra vertical escapada, quebras
// de linha viram espaço.
func escapeMD(s string) string {
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "\r\n", " ", "\n", " ", "\r", " ").Replace(s)
}

func writeMarkdown(w io.Writer, r *Rows) {
	c := &capped{w: w}
	shown := 0
	if len(r.Columns) > 0 {
		hdr := make([]string, len(r.Columns))
		sep := make([]string, len(r.Columns))
		for i, h := range r.Columns {
			hdr[i], sep[i] = escapeMD(h), "---"
		}
		c.line("| " + strings.Join(hdr, " | ") + " |")
		c.line("| " + strings.Join(sep, " | ") + " |")
		for _, row := range r.Values {
			cells := make([]string, len(r.Columns))
			for i := range cells {
				switch {
				case i >= len(row):
				case row[i] == nil:
					cells[i] = "_NULL_"
				default:
					cells[i] = escapeMD(clip(*row[i]))
				}
			}
			if !c.line("| " + strings.Join(cells, " | ") + " |") {
				break
			}
			shown++
		}
	}
	if c.cut {
		fmt.Fprintf(w, "\n_saída cortada em 256 KB depois de %d de %d linhas; selecione menos colunas ou agregue_\n", shown, len(r.Values))
	}
	if r.Footer != "" {
		fmt.Fprintf(w, "\n_%s_\n", strings.ReplaceAll(r.Footer, "_", `\_`))
	}
}

// WriteCSV grava as linhas em CSV (RFC 4180) com cabeçalho; NULL vira campo
// vazio. Sem corte de tamanho: é para arquivo, não para o chat.
func WriteCSV(w io.Writer, r *Rows) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(r.Columns); err != nil {
		return err
	}
	rec := make([]string, len(r.Columns))
	for _, row := range r.Values {
		for i := range rec {
			rec[i] = ""
			if i < len(row) && row[i] != nil {
				rec[i] = *row[i]
			}
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
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
	keys := uniqueKeys(r.Columns)
	o := out{Columns: keys, Rows: []map[string]any{}, Footer: r.Footer}
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
			m[keys[i]] = val
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

// uniqueKeys dá nomes únicos às colunas repetidas (id, id_2, id_3...): cada
// linha do JSON é um objeto, e SELECT a.id, b.id perderia o primeiro valor.
func uniqueKeys(cols []string) []string {
	seen := map[string]bool{}
	for _, c := range cols {
		seen[c] = true
	}
	count := map[string]int{}
	out := make([]string, len(cols))
	for i, c := range cols {
		count[c]++
		if count[c] == 1 {
			out[i] = c
			continue
		}
		k := fmt.Sprintf("%s_%d", c, count[c])
		for seen[k] {
			count[c]++
			k = fmt.Sprintf("%s_%d", c, count[c])
		}
		seen[k] = true
		out[i] = k
	}
	return out
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
	if m.Reason != "" {
		fmt.Fprintln(w, "  motivo  "+m.Reason)
	}
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
