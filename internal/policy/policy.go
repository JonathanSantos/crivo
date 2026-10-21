// Package policy implementa a linguagem .crivo: lexer, parser, validação
// semântica (sem schema), resolução de regra por tabela e impressão.
package policy

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Verb é uma das quatro ações da política.
type Verb string

const (
	Read   Verb = "read"
	Insert Verb = "insert"
	Update Verb = "update"
	Delete Verb = "delete"
)

// IsWrite diz se o verbo altera dados.
func (v Verb) IsWrite() bool { return v == Insert || v == Update || v == Delete }

// MaskMode é o modo de mascaramento de uma coluna.
type MaskMode string

const (
	MaskPartial MaskMode = "partial"
	MaskRedact  MaskMode = "redact"
	MaskHash    MaskMode = "hash"
)

// Valores padrão das diretivas.
const (
	DefaultSchema  = "public"
	DefaultLimit   = 500
	DefaultTimeout = 5 * time.Second
	DefaultMaxRows = 50
)

// SecretKind diz de onde vem a senha.
type SecretKind string

const (
	SecretKeychain SecretKind = "keychain"
	SecretEnv      SecretKind = "env"
	SecretPrompt   SecretKind = "prompt"
)

// Pos é uma posição no arquivo (1-based).
type Pos struct {
	Line int
	Col  int
}

// Policy é um arquivo .crivo já parseado.
type Policy struct {
	File   string // nome usado nas mensagens ("vendas.crivo" ou "policy")
	Source string // texto original

	Name      string
	About     string
	Env       string
	Connect   string
	Secret    SecretKind
	SecretVar string // para secret env:VAR
	Schema    string
	Limit     int
	Timeout   time.Duration
	Functions []string

	Rules []*Rule

	directives map[string]Pos
}

// Rule é uma linha de tabela.
type Rule struct {
	Pos     Pos
	Schema  string // vazio: schema padrão da política
	Pattern string // nome exato ou padrão com *
	Deny    bool
	Actions []*Action
	Doc     string // texto dos comentários ## acima da regra
	Body    string // corpo da regra normalizado, para mensagens
}

// Action é um verbo com colunas e modificadores.
type Action struct {
	Pos      Pos
	Verb     Verb
	Cols     []string // nil: todas
	Except   bool     // Cols é lista de exclusão
	Where    string   // expressão SQL do filtro de linha
	WherePos Pos
	Max      int // 0: não definido
	Limit    int // 0: não definido
	Masks    []Mask
}

// Mask associa uma coluna a um modo.
type Mask struct {
	Pos    Pos
	Column string
	Mode   MaskMode
}

// IsPattern diz se a regra usa curinga.
func (r *Rule) IsPattern() bool { return strings.Contains(r.Pattern, "*") }

// Action devolve a ação do verbo, ou nil.
func (r *Rule) Action(v Verb) *Action {
	if r == nil || r.Deny {
		return nil
	}
	for _, a := range r.Actions {
		if a.Verb == v {
			return a
		}
	}
	return nil
}

// HasWrite diz se a regra tem alguma ação de escrita.
func (r *Rule) HasWrite() bool {
	for _, a := range r.Actions {
		if a.Verb.IsWrite() {
			return true
		}
	}
	return false
}

// Label é o nome da tabela como aparece na regra (com schema, se houver).
func (r *Rule) Label() string {
	if r.Schema != "" {
		return r.Schema + "." + r.Pattern
	}
	return r.Pattern
}

// Verbs lista os verbos da regra na ordem em que aparecem.
func (r *Rule) Verbs() []string {
	var out []string
	for _, a := range r.Actions {
		out = append(out, string(a.Verb))
	}
	return out
}

// AllowsCol diz se a coluna é alcançada pela ação.
func (a *Action) AllowsCol(col string) bool {
	if a == nil {
		return false
	}
	if a.Cols == nil {
		return true
	}
	in := false
	for _, c := range a.Cols {
		if c == col {
			in = true
			break
		}
	}
	if a.Except {
		return !in
	}
	return in
}

// AllowedCols filtra a lista de colunas da tabela pelas colunas da ação,
// mantendo a ordem da tabela.
func (a *Action) AllowedCols(all []string) []string {
	var out []string
	for _, c := range all {
		if a.AllowsCol(c) {
			out = append(out, c)
		}
	}
	return out
}

// MaskOf devolve o modo de máscara da coluna, ou "".
func (a *Action) MaskOf(col string) MaskMode {
	if a == nil {
		return ""
	}
	for _, m := range a.Masks {
		if m.Column == col {
			return m.Mode
		}
	}
	return ""
}

// MaxRows é o teto de linhas afetadas de uma escrita.
func (a *Action) MaxRows() int {
	if a.Max > 0 {
		return a.Max
	}
	return DefaultMaxRows
}

// ColsText descreve a lista de colunas como na política.
func (a *Action) ColsText() string {
	if a.Cols == nil {
		return ""
	}
	s := "(" + strings.Join(a.Cols, ", ") + ")"
	if a.Except {
		return " except" + s
	}
	return s
}

// String reconstrói o texto da ação como na política.
func (a *Action) String() string {
	s := string(a.Verb) + a.ColsText()
	if len(a.Masks) > 0 {
		var ms []string
		for _, m := range a.Masks {
			ms = append(ms, m.Column+": "+string(m.Mode))
		}
		s += " mask(" + strings.Join(ms, ", ") + ")"
	}
	if a.Limit > 0 {
		s += fmt.Sprintf(" limit %d", a.Limit)
	}
	if a.Max > 0 {
		s += fmt.Sprintf(" max %d", a.Max)
	}
	if a.Where != "" {
		s += " where " + a.Where
	}
	return s
}

// HasRead diz se alguma regra permite leitura.
func (p *Policy) HasRead() bool {
	for _, r := range p.Rules {
		if r.Action(Read) != nil {
			return true
		}
	}
	return false
}

// HasWrite diz se alguma regra permite escrita.
func (p *Policy) HasWrite() bool {
	for _, r := range p.Rules {
		if !r.Deny && r.HasWrite() {
			return true
		}
	}
	return false
}

// Schemas lista os schemas citados pela política (padrão primeiro).
func (p *Policy) Schemas() []string {
	seen := map[string]bool{p.Schema: true}
	out := []string{p.Schema}
	for _, r := range p.Rules {
		if r.Schema != "" && !seen[r.Schema] {
			seen[r.Schema] = true
			out = append(out, r.Schema)
		}
	}
	return out
}

// SchemaOf devolve o schema efetivo da regra.
func (p *Policy) SchemaOf(r *Rule) string {
	if r.Schema != "" {
		return r.Schema
	}
	return p.Schema
}

// AlwaysBlocked diz se o objeto é de catálogo e, portanto, sempre bloqueado.
func AlwaysBlocked(schema, table string) bool {
	return schema == "pg_catalog" || schema == "information_schema" ||
		strings.HasPrefix(schema, "pg_") || strings.HasPrefix(table, "pg_")
}

// Resolve devolve a regra que decide a tabela, ou nil (tabela inexistente
// para a IA). Precedência: nome exato; maior prefixo literal; deny no empate.
func (p *Policy) Resolve(schema, table string) *Rule {
	if schema == "" {
		schema = p.Schema
	}
	if AlwaysBlocked(schema, table) {
		return nil
	}
	var best *Rule
	bestPrefix := -1
	for _, r := range p.Rules {
		if p.SchemaOf(r) != schema {
			continue
		}
		if !r.IsPattern() {
			if r.Pattern == table {
				return r
			}
			continue
		}
		ok, err := path.Match(r.Pattern, table)
		if err != nil || !ok {
			continue
		}
		prefix := strings.Index(r.Pattern, "*")
		switch {
		case prefix > bestPrefix:
			best, bestPrefix = r, prefix
		case prefix == bestPrefix && r.Deny && !best.Deny:
			best = r
		}
	}
	return best
}

// MatchingTables devolve, dentre as tabelas dadas, as que a regra decide.
func (p *Policy) MatchingTables(r *Rule, schema string, tables []string) []string {
	var out []string
	for _, t := range tables {
		if p.Resolve(schema, t) == r {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// RuleRef formata a referência "policy:16" usada nas mensagens.
func (p *Policy) RuleRef(r *Rule) string {
	return fmt.Sprintf("%s:%d", p.File, r.Pos.Line)
}

// EnvLabel é o rótulo legível do ambiente.
func (p *Policy) EnvLabel() string {
	switch p.Env {
	case "dev":
		return "desenvolvimento"
	case "preprod":
		return "pré-produção"
	case "prod":
		return "produção"
	}
	return p.Env
}

// Numbered devolve o texto da política com números de linha.
func (p *Policy) Numbered() string {
	lines := strings.Split(strings.TrimRight(p.Source, "\n"), "\n")
	width := len(fmt.Sprint(len(lines)))
	var b strings.Builder
	for i, l := range lines {
		fmt.Fprintf(&b, "%*d  %s\n", width, i+1, strings.TrimRight(l, "\r"))
	}
	return b.String()
}
