// Package sqlguard valida SQL contra a política usando o parser real do
// Postgres (pg_query), reescreve o AST e devolve o SQL que pode ser executado.
//
// Pipeline: parse → forma (nós, funções, operadores, casts) → statement →
// tabelas e colunas → reescritas → deparse → re-parse → todas as checagens
// de novo sobre o resultado. A string original nunca é executada.
package sqlguard

import (
	"errors"
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	pgparser "github.com/pganalyze/pg_query_go/v6/parser"
	"google.golang.org/protobuf/reflect/protoreflect"

	"crivo/internal/policy"
	"crivo/internal/schema"
)

// Command é o comando do binário que recebeu o SQL.
type Command int

const (
	// CmdQuery aceita só SELECT (query e explain).
	CmdQuery Command = iota
	// CmdExec aceita só INSERT, UPDATE e DELETE.
	CmdExec
	// CmdAny aceita os dois (crivo test).
	CmdAny
)

// Kind é o tipo do statement raiz.
type Kind string

const (
	KindSelect Kind = "SELECT"
	KindInsert Kind = "INSERT"
	KindUpdate Kind = "UPDATE"
	KindDelete Kind = "DELETE"
)

// Denial é uma recusa com a regra que decidiu e o que seria aceito.
type Denial struct {
	Rule     *policy.Rule
	Reason   string
	Accepted string
}

func (d *Denial) Error() string { return d.Reason }

// ParseError é SQL que o parser do Postgres não aceita.
type ParseError struct {
	Message  string
	Position int
}

func (e *ParseError) Error() string { return e.Message }

// RuleUse registra que uma tabela foi decidida por uma regra.
type RuleUse struct {
	Table string // como apareceu (alias ou nome)
	Name  string // schema.tabela real
	Rule  *policy.Rule
	Verb  policy.Verb
}

// OutputMask diz que a coluna de saída na posição Index sai mascarada.
type OutputMask struct {
	Index  int
	Label  string // ex.: c.email
	Mode   policy.MaskMode
	Column string // tabela.coluna de origem
}

// Verdict é o resultado de uma validação aceita.
type Verdict struct {
	Kind     Kind
	SQL      string // deparse do AST validado e reescrito
	Original string
	Rules    []RuleUse
	Masks    []OutputMask
	// Leitura: teto de linhas (min(LIMIT pedido, política)); o SQL usa Cap+1.
	Cap          int
	CapByRequest bool // o teto veio do LIMIT da própria query
	// Escrita: tabela alvo e teto de linhas afetadas.
	Target  *RuleUse
	MaxRows int
}

// Guard valida SQL contra uma política e um schema.
type Guard struct {
	Policy  *policy.Policy
	Schema  *schema.Schema
	filters map[*policy.Action]*pg_query.Node
	funcs   map[string]bool
}

// New prepara um Guard: compila os filtros where e a allowlist de funções.
func New(p *policy.Policy, s *schema.Schema) (*Guard, error) {
	g := &Guard{Policy: p, Schema: s, filters: map[*policy.Action]*pg_query.Node{}, funcs: map[string]bool{}}
	for name := range defaultFunctions {
		g.funcs[name] = true
	}
	for _, f := range p.Functions {
		if !policy.BlockedFunction(f) {
			g.funcs[f] = true
		}
	}
	for _, r := range p.Rules {
		for _, a := range r.Actions {
			if a.Where == "" {
				continue
			}
			n, err := g.compileFilter(a.Where)
			if err != nil {
				return nil, fmt.Errorf("%s:%d:%d: where inválido: %v", p.File, a.WherePos.Line, a.WherePos.Col, err)
			}
			g.filters[a] = n
		}
	}
	return g, nil
}

// compileFilter valida uma expressão where como "SELECT 1 WHERE <expr>".
func (g *Guard) compileFilter(expr string) (*pg_query.Node, error) {
	tree, err := pg_query.Parse("SELECT 1 WHERE " + expr)
	if err != nil {
		return nil, err
	}
	if len(tree.Stmts) != 1 {
		return nil, errors.New("a expressão precisa ser uma única condição")
	}
	sel := tree.Stmts[0].Stmt.GetSelectStmt()
	if sel == nil || sel.WhereClause == nil || len(sel.FromClause) > 0 || len(sel.GroupClause) > 0 ||
		sel.HavingClause != nil || len(sel.SortClause) > 0 || sel.LimitCount != nil || sel.LimitOffset != nil ||
		len(sel.WindowClause) > 0 || len(sel.LockingClause) > 0 || sel.Op != pg_query.SetOperation_SETOP_NONE {
		return nil, errors.New("a expressão precisa ser uma única condição, sem cláusulas extras")
	}
	sh := &shape{g: g, filter: true}
	if d := sh.walk(sel.WhereClause); d != nil {
		return nil, errors.New(d.Reason)
	}
	return sel.WhereClause, nil
}

// FilterNode devolve o filtro compilado de uma ação.
func (g *Guard) FilterNode(a *policy.Action) *pg_query.Node { return g.filters[a] }

// Check valida o SQL para o comando. Devolve *Denial, *ParseError ou outro
// erro (bug) quando não aceita.
func (g *Guard) Check(cmd Command, sql string) (v *Verdict, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("erro interno do sqlguard: %v", r)
		}
	}()
	if strings.TrimSpace(sql) == "" {
		return nil, &Denial{Reason: "SQL vazio", Accepted: "um único statement SQL"}
	}
	tree, err := pg_query.Parse(sql)
	if err != nil {
		pe := &ParseError{Message: err.Error()}
		var perr *pgparser.Error
		if errors.As(err, &perr) {
			pe.Message, pe.Position = perr.Message, perr.Cursorpos
		}
		return nil, pe
	}
	if len(tree.Stmts) != 1 {
		return nil, &Denial{Reason: "envie um único statement", Accepted: "um statement por chamada, sem ';' separando outros"}
	}

	// Primeira passada: checagens + coleta das reescritas.
	a := newAnalyzer(g, cmd, false)
	if d := a.run(tree.Stmts[0]); d != nil {
		return nil, d
	}
	for _, rw := range a.rewrites {
		if err := rw(); err != nil {
			return nil, err
		}
	}
	rewritten, err := pg_query.Deparse(tree)
	if err != nil {
		return nil, fmt.Errorf("deparse: %w", err)
	}

	// Segunda passada: o texto que vai ao banco é parseado e checado de novo.
	tree2, err := pg_query.Parse(rewritten)
	if err != nil {
		return nil, fmt.Errorf("re-parse do SQL reescrito: %w", err)
	}
	if len(tree2.Stmts) != 1 {
		return nil, errors.New("SQL reescrito virou mais de um statement")
	}
	if !sameTree(tree.Stmts[0], tree2.Stmts[0]) {
		return nil, &Denial{Reason: "a reescrita não é estável (o deparse muda o AST); simplifique a query", Accepted: "a mesma consulta escrita de forma mais simples"}
	}
	b := newAnalyzer(g, cmd, true)
	if d := b.run(tree2.Stmts[0]); d != nil {
		return nil, &Denial{Rule: d.Rule, Reason: "re-checagem do SQL reescrito falhou: " + d.Reason, Accepted: d.Accepted}
	}
	if len(b.rewrites) > 0 {
		return nil, errors.New("SQL reescrito ainda pede reescritas")
	}

	v = b.verdict()
	v.SQL = rewritten
	v.Original = sql
	return v, nil
}

// CheckPolicy valida os filtros where da política (sintaxe, funções,
// operadores) e devolve diagnósticos com posição.
func CheckPolicy(p *policy.Policy) policy.Diags {
	var out policy.Diags
	g := &Guard{Policy: p, filters: map[*policy.Action]*pg_query.Node{}, funcs: map[string]bool{}}
	for name := range defaultFunctions {
		g.funcs[name] = true
	}
	for _, f := range p.Functions {
		g.funcs[f] = true
	}
	for _, r := range p.Rules {
		for _, a := range r.Actions {
			if a.Where == "" {
				continue
			}
			if _, err := g.compileFilter(a.Where); err != nil {
				out = append(out, policy.Diag{File: p.File, Pos: a.WherePos, Msg: "where inválido: " + err.Error()})
			}
		}
	}
	return out
}

// FilterColumns devolve as colunas não qualificadas citadas no filtro (fora
// de subqueries), para conferir contra o schema.
func FilterColumns(expr string) []string {
	tree, err := pg_query.Parse("SELECT 1 WHERE " + expr)
	if err != nil || len(tree.Stmts) != 1 {
		return nil
	}
	sel := tree.Stmts[0].Stmt.GetSelectStmt()
	if sel == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	var walk func(m protoreflect.Message)
	walk = func(m protoreflect.Message) {
		switch v := m.Interface().(type) {
		case *pg_query.SubLink:
			return
		case *pg_query.ColumnRef:
			if f, ok := refFields(v); ok && len(f) >= 1 && f[len(f)-1] != "*" {
				c := f[len(f)-1]
				if !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
			return
		}
		m.Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
			switch {
			case fd.IsList() && fd.Message() != nil:
				l := val.List()
				for i := 0; i < l.Len(); i++ {
					walk(l.Get(i).Message())
				}
			case fd.Message() != nil && !fd.IsMap():
				walk(val.Message())
			}
			return true
		})
	}
	walk(sel.WhereClause.ProtoReflect())
	return out
}
