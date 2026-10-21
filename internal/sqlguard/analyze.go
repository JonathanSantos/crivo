package sqlguard

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"

	"crivo/internal/policy"
	"crivo/internal/schema"
)

// useCtx diz em que posição uma coluna é usada; decide o que máscaras aceitam.
type useCtx int

const (
	useGeneral useCtx = iota // filtro, junção, ordenação, expressão
	useBare                  // nua na lista de um SELECT cujo resultado sai
	useGroup                 // GROUP BY, DISTINCT ON, count(DISTINCT x): aceito com hash
)

// origin é a coluna de tabela de onde um valor vem.
type origin struct {
	t   *tableRef
	col string
}

// column é uma coluna visível num escopo (de tabela, CTE ou subquery).
type column struct {
	name    string
	label   string   // referência como escrita (ex.: c.email), para mensagens
	origins []origin // vazio: valor livre (expressão ou constante)
}

type tableRef struct {
	schema, name string
	info         *schema.Table
	rule         *policy.Rule
	read         *policy.Action
}

func (t *tableRef) qualified() string { return t.schema + "." + t.name }

// entry é um item do FROM.
type entry struct {
	name   string
	table  *tableRef // tabela base; nil para derivadas
	cols   []column  // derivadas
	target bool      // alvo de UPDATE/DELETE
	refs   int       // referências resolvidas para esta entrada
}

func (c column) labelOrName() string {
	if c.label != "" {
		return c.label
	}
	return c.name
}

func (e *entry) columns() []column {
	if e.table == nil {
		return e.cols
	}
	out := make([]column, len(e.table.info.Columns))
	for i, c := range e.table.info.Columns {
		out[i] = column{name: c.Name, origins: []origin{{e.table, c.Name}}}
	}
	return out
}

func (e *entry) find(name string) (column, int) {
	var found column
	n := 0
	for _, c := range e.columns() {
		if c.name == name {
			if n == 0 {
				found = c
			}
			n++
		}
	}
	return found, n
}

type scope struct {
	parent  *scope
	entries []*entry
	merged  map[string][]*entry // colunas unidas por JOIN USING / NATURAL
}

type cteEnv struct {
	parent *cteEnv
	name   string
	cols   []column
}

func (c *cteEnv) lookup(name string) *cteEnv {
	for ; c != nil; c = c.parent {
		if c.name == name {
			return c
		}
	}
	return nil
}

type denialPanic struct{ d *Denial }

type analyzer struct {
	g        *Guard
	cmd      Command
	recheck  bool
	rewrites []func() error
	visited  map[any]bool
	skipped  map[any]bool

	kind      Kind
	rules     []RuleUse
	masks     []OutputMask
	cap       int
	capByReq  bool
	policyCap int
	target    *RuleUse
	maxRows   int
}

func newAnalyzer(g *Guard, cmd Command, recheck bool) *analyzer {
	return &analyzer{g: g, cmd: cmd, recheck: recheck, visited: map[any]bool{}, skipped: map[any]bool{}, policyCap: g.Policy.Limit}
}

func (a *analyzer) deny(d *Denial) { panic(denialPanic{d}) }

func (a *analyzer) denyf(rule *policy.Rule, accepted, format string, args ...any) {
	a.deny(&Denial{Rule: rule, Reason: fmt.Sprintf(format, args...), Accepted: accepted})
}

func (a *analyzer) run(raw *pg_query.RawStmt) (denial *Denial) {
	defer func() {
		if r := recover(); r != nil {
			if dp, ok := r.(denialPanic); ok {
				denial = dp.d
				return
			}
			panic(r)
		}
	}()
	stmt := raw.Stmt
	if d := (&shape{g: a.g}).walkRoot(stmt); d != nil {
		return d
	}
	switch n := stmt.Node.(type) {
	case *pg_query.Node_SelectStmt:
		if a.cmd == CmdExec {
			a.denyf(nil, "SELECT vai pelo comando query", "exec só aceita INSERT, UPDATE ou DELETE")
		}
		a.kind = KindSelect
		a.rootSelect(n.SelectStmt)
	case *pg_query.Node_InsertStmt:
		a.requireExec()
		a.kind = KindInsert
		a.insertStmt(n.InsertStmt)
	case *pg_query.Node_UpdateStmt:
		a.requireExec()
		a.kind = KindUpdate
		a.updateStmt(n.UpdateStmt)
	case *pg_query.Node_DeleteStmt:
		a.requireExec()
		a.kind = KindDelete
		a.deleteStmt(n.DeleteStmt)
	default:
		a.denyf(nil, "", "statement %s não é aceito", StmtLabel(stmt))
	}
	a.coverage(stmt)
	return nil
}

func (a *analyzer) requireExec() {
	if a.cmd == CmdQuery {
		a.denyf(nil, "INSERT, UPDATE e DELETE vão pelo comando exec (com --dry-run antes)", "query só aceita SELECT")
	}
}

// coverage garante que toda coluna, tabela e função do AST passou pela
// análise semântica. Se um campo novo do parser carregar uma coluna que o
// analisador não percorreu, a query é recusada (fail closed).
func (a *analyzer) coverage(n *pg_query.Node) {
	var walk func(m protoreflect.Message)
	walk = func(m protoreflect.Message) {
		iface := m.Interface()
		if a.skipped[iface] {
			return
		}
		switch iface.(type) {
		case *pg_query.ColumnRef, *pg_query.RangeVar, *pg_query.FuncCall:
			if !a.visited[iface] {
				a.denyf(nil, "", "parte da query não foi analisada (%s); simplifique a query", m.Descriptor().Name())
			}
		}
		m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			switch {
			case fd.IsList() && fd.Message() != nil:
				l := v.List()
				for i := 0; i < l.Len(); i++ {
					walk(l.Get(i).Message())
				}
			case fd.Message() != nil && !fd.IsMap():
				walk(v.Message())
			}
			return true
		})
	}
	walk(n.ProtoReflect())
}

func (a *analyzer) skip(m interface{ ProtoReflect() protoreflect.Message }) {
	if m != nil {
		a.skipped[m.ProtoReflect().Interface()] = true
	}
}

func (a *analyzer) addRule(label string, t *tableRef, v policy.Verb) {
	for _, u := range a.rules {
		if u.Name == t.qualified() && u.Verb == v {
			return
		}
	}
	a.rules = append(a.rules, RuleUse{Table: label, Name: t.qualified(), Rule: t.rule, Verb: v})
}

func (a *analyzer) verdict() *Verdict {
	return &Verdict{
		Kind: a.kind, Rules: a.rules, Masks: a.masks,
		Cap: a.cap, CapByRequest: a.capByReq,
		Target: a.target, MaxRows: a.maxRows,
	}
}

// ---------- tabelas ----------

// allowedTables lista as tabelas que a política libera para o verbo.
func (a *analyzer) allowedTables(v policy.Verb) string {
	var out []string
	for _, r := range a.g.Policy.Rules {
		if r.Action(v) != nil {
			out = append(out, r.Label())
		}
	}
	if len(out) == 0 {
		return "nenhuma tabela permite " + string(v)
	}
	return strings.Join(out, ", ")
}

// resolveTable aplica a política a uma tabela citada.
func (a *analyzer) resolveTable(rv *pg_query.RangeVar, v policy.Verb) *tableRef {
	a.visited[rv] = true
	if rv.Catalogname != "" {
		a.denyf(nil, "tabela sem nome de banco", "referência a outro banco não é aceita: %s", rv.Catalogname)
	}
	sch := rv.Schemaname
	if sch == "" {
		sch = a.g.Policy.Schema
	}
	label := rv.Relname
	if rv.Schemaname != "" {
		label = rv.Schemaname + "." + rv.Relname
	}
	if policy.AlwaysBlocked(sch, rv.Relname) {
		a.denyf(nil, "use os comandos tables e describe para conhecer o schema", "tabela %q é de catálogo do Postgres e sempre bloqueada", label)
	}
	rule := a.g.Policy.Resolve(sch, rv.Relname)
	if rule == nil {
		a.denyf(nil, a.allowedTables(policy.Read), "tabela %q não existe para a IA (nenhuma regra na política)", label)
	}
	if rule.Deny {
		a.denyf(rule, a.allowedTables(policy.Read), "tabela %q é negada pela política", label)
	}
	act := rule.Action(v)
	if act == nil {
		if v == policy.Read {
			a.denyf(rule, "a regra só permite: "+strings.Join(rule.Verbs(), ", "), "tabela %q não permite leitura", label)
		}
		a.denyf(rule, "a regra só permite: "+strings.Join(rule.Verbs(), ", "), "tabela %q não permite %s", label, v)
	}
	info := a.g.Schema.Table(sch, rv.Relname)
	if info == nil {
		a.denyf(rule, "rode o comando refresh se a tabela acabou de ser criada", "tabela %q está na política mas não existe no banco (cache de schema)", label)
	}
	t := &tableRef{schema: sch, name: rv.Relname, info: info, rule: rule, read: rule.Action(policy.Read)}
	if t.read != nil && t.read.Limit > 0 && t.read.Limit < a.policyCap && v == policy.Read {
		a.policyCap = t.read.Limit
	}
	return t
}

// ---------- colunas ----------

func (a *analyzer) readableCols(t *tableRef) []string {
	if t.read == nil {
		return nil
	}
	return t.read.AllowedCols(t.info.ColumnNames())
}

func (a *analyzer) checkOrigin(o origin, ctx useCtx, label string) {
	act := o.t.read
	if act == nil {
		a.denyf(o.t.rule, "a regra só permite: "+strings.Join(o.t.rule.Verbs(), ", "),
			"coluna %q não pode ser lida: a regra de %s não tem read", label, o.t.name)
	}
	if !act.AllowsCol(o.col) {
		a.denyf(o.t.rule, strings.Join(a.readableCols(o.t), ", "), "coluna %q não está liberada", label)
	}
	switch act.MaskOf(o.col) {
	case "":
	case policy.MaskHash:
		if ctx == useGeneral {
			a.denyf(o.t.rule, "a coluna nua na lista do SELECT, em GROUP BY ou em count(DISTINCT ...)",
				"coluna %q é mascarada (hash) e não pode ser usada em filtro, junção, ordenação ou expressão", label)
		}
	default:
		if ctx != useBare {
			a.denyf(o.t.rule, "a coluna nua na lista do SELECT, sem funções em volta",
				"coluna %q é mascarada (%s) e só pode aparecer nua na lista do SELECT", label, act.MaskOf(o.col))
		}
	}
}

func (a *analyzer) checkColumn(c column, ctx useCtx, label string) {
	for _, o := range c.origins {
		a.checkOrigin(o, ctx, label)
	}
}

func refFields(ref *pg_query.ColumnRef) ([]string, bool) {
	var out []string
	for i, f := range ref.Fields {
		if f.GetAStar() != nil {
			if i != len(ref.Fields)-1 {
				return nil, false
			}
			out = append(out, "*")
			continue
		}
		s := f.GetString_()
		if s == nil {
			return nil, false
		}
		out = append(out, s.Sval)
	}
	return out, true
}

func refLabel(ref *pg_query.ColumnRef) string {
	f, _ := refFields(ref)
	return strings.Join(f, ".")
}

func isStar(n *pg_query.Node) bool {
	ref := n.GetColumnRef()
	if ref == nil || len(ref.Fields) == 0 {
		return false
	}
	return ref.Fields[len(ref.Fields)-1].GetAStar() != nil
}

// lookup procura uma coluna não qualificada subindo os escopos.
func (a *analyzer) lookup(s *scope, name string) (*entry, column, bool) {
	for sc := s; sc != nil; sc = sc.parent {
		if ents, ok := sc.merged[name]; ok {
			var col column
			col.name = name
			for _, e := range ents {
				c, _ := e.find(name)
				col.origins = append(col.origins, c.origins...)
				e.refs++
			}
			// outra entrada (fora do USING) com a mesma coluna também é ambígua
			for _, e := range sc.entries {
				if _, n := e.find(name); n > 0 && !containsEntry(ents, e) {
					a.denyf(nil, "qualifique a coluna com o alias da tabela", "coluna %q é ambígua", name)
				}
			}
			return ents[0], col, true
		}
		var found *entry
		var col column
		var names []string
		for _, e := range sc.entries {
			c, n := e.find(name)
			if n > 1 {
				a.denyf(nil, "dê nomes distintos às colunas da subquery", "coluna %q é ambígua em %s", name, e.name)
			}
			if n == 1 {
				if found != nil {
					names = append(names, e.name)
					continue
				}
				found, col = e, c
				names = append(names, e.name)
			}
		}
		if len(names) > 1 {
			var hints []string
			for _, n := range names {
				hints = append(hints, n+"."+name)
			}
			a.denyf(nil, "qualifique: "+strings.Join(hints, " ou "), "coluna %q é ambígua", name)
		}
		if found != nil {
			found.refs++
			return found, col, true
		}
	}
	return nil, column{}, false
}

func containsEntry(list []*entry, e *entry) bool {
	for _, x := range list {
		if x == e {
			return true
		}
	}
	return false
}

func (a *analyzer) entryByName(s *scope, name string) *entry {
	for sc := s; sc != nil; sc = sc.parent {
		var found *entry
		for _, e := range sc.entries {
			if e.name == name {
				if found != nil {
					a.denyf(nil, "use aliases distintos", "alias %q aparece duas vezes no FROM", name)
				}
				found = e
			}
		}
		if found != nil {
			return found
		}
	}
	return nil
}

// columnRef resolve e checa uma referência de coluna (não estrela).
func (a *analyzer) columnRef(s *scope, ref *pg_query.ColumnRef, ctx useCtx) column {
	col, ok := a.tryColumnRef(s, ref, ctx)
	if !ok {
		fields, _ := refFields(ref)
		name := fields[len(fields)-1]
		if len(fields) == 1 && a.entryByName(s, name) != nil {
			a.denyf(nil, "liste as colunas explicitamente", "referência à linha inteira de %q não é aceita", name)
		}
		a.denyf(nil, "use o comando describe para ver as colunas", "coluna %q não existe nas tabelas da query", strings.Join(fields, "."))
	}
	return col
}

// tryColumnRef devolve ok=false quando a coluna não foi encontrada.
func (a *analyzer) tryColumnRef(s *scope, ref *pg_query.ColumnRef, ctx useCtx) (column, bool) {
	a.visited[ref] = true
	fields, ok := refFields(ref)
	if !ok {
		a.denyf(nil, "", "referência de coluna não suportada")
	}
	if fields[len(fields)-1] == "*" {
		a.denyf(nil, "SELECT * ou t.* só na lista do SELECT", "* não é aceito nesta posição")
	}
	label := strings.Join(fields, ".")
	switch len(fields) {
	case 1:
		_, col, found := a.lookup(s, fields[0])
		if !found {
			return column{}, false
		}
		a.checkColumn(col, ctx, label)
		return col, true
	case 2:
		e := a.entryByName(s, fields[0])
		if e == nil {
			a.denyf(nil, "use um alias que esteja no FROM", "tabela ou alias %q não está no FROM", fields[0])
		}
		col, n := e.find(fields[1])
		if n == 0 {
			a.denyf(nil, "use o comando describe para ver as colunas", "coluna %q não existe em %s", fields[1], fields[0])
		}
		if n > 1 {
			a.denyf(nil, "dê nomes distintos às colunas da subquery", "coluna %q é ambígua em %s", fields[1], fields[0])
		}
		e.refs++
		a.checkColumn(col, ctx, label)
		return col, true
	default:
		a.denyf(nil, "use alias.coluna", "referência %q com schema não é aceita", label)
	}
	return column{}, false
}

// ---------- expressões ----------

func (a *analyzer) exprs(s *scope, ctes *cteEnv, nodes []*pg_query.Node, ctx useCtx) {
	for _, n := range nodes {
		a.expr(s, ctes, n, ctx)
	}
}

func (a *analyzer) expr(s *scope, ctes *cteEnv, n *pg_query.Node, ctx useCtx) {
	if n == nil || n.Node == nil {
		return
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_ColumnRef:
		a.columnRef(s, v.ColumnRef, ctx)
	case *pg_query.Node_AConst, *pg_query.Node_SqlvalueFunction, *pg_query.Node_SetToDefault:
	case *pg_query.Node_TypeCast:
		a.expr(s, ctes, v.TypeCast.Arg, useGeneral)
	case *pg_query.Node_AExpr:
		a.expr(s, ctes, v.AExpr.Lexpr, useGeneral)
		a.expr(s, ctes, v.AExpr.Rexpr, useGeneral)
	case *pg_query.Node_List:
		a.exprs(s, ctes, v.List.Items, useGeneral)
	case *pg_query.Node_BoolExpr:
		a.exprs(s, ctes, v.BoolExpr.Args, useGeneral)
	case *pg_query.Node_FuncCall:
		a.funcCall(s, ctes, v.FuncCall)
	case *pg_query.Node_SubLink:
		sl := v.SubLink
		a.expr(s, ctes, sl.Testexpr, useGeneral)
		sel := sl.Subselect.GetSelectStmt()
		if sel == nil {
			a.denyf(nil, "", "subquery precisa ser SELECT")
		}
		tctx := useGeneral
		if sl.SubLinkType == pg_query.SubLinkType_EXISTS_SUBLINK {
			tctx = useBare // o resultado do EXISTS não sai; só a existência
		}
		a.selectStmt(sel, s, ctes, selOpts{targetCtx: tctx})
	case *pg_query.Node_CaseExpr:
		c := v.CaseExpr
		a.expr(s, ctes, c.Arg, useGeneral)
		for _, w := range c.Args {
			cw := w.GetCaseWhen()
			if cw == nil {
				a.denyf(nil, "", "CASE malformado")
			}
			a.expr(s, ctes, cw.Expr, useGeneral)
			a.expr(s, ctes, cw.Result, useGeneral)
		}
		a.expr(s, ctes, c.Defresult, useGeneral)
	case *pg_query.Node_CoalesceExpr:
		a.exprs(s, ctes, v.CoalesceExpr.Args, useGeneral)
	case *pg_query.Node_MinMaxExpr:
		a.exprs(s, ctes, v.MinMaxExpr.Args, useGeneral)
	case *pg_query.Node_NullTest:
		a.expr(s, ctes, v.NullTest.Arg, useGeneral)
	case *pg_query.Node_BooleanTest:
		a.expr(s, ctes, v.BooleanTest.Arg, useGeneral)
	case *pg_query.Node_AArrayExpr:
		a.exprs(s, ctes, v.AArrayExpr.Elements, useGeneral)
	case *pg_query.Node_RowExpr:
		a.exprs(s, ctes, v.RowExpr.Args, useGeneral)
	case *pg_query.Node_AIndirection:
		a.expr(s, ctes, v.AIndirection.Arg, useGeneral)
		for _, ind := range v.AIndirection.Indirection {
			switch iv := ind.Node.(type) {
			case *pg_query.Node_AIndices:
				a.expr(s, ctes, iv.AIndices.Lidx, useGeneral)
				a.expr(s, ctes, iv.AIndices.Uidx, useGeneral)
			case *pg_query.Node_String_:
			default:
				a.denyf(nil, "", "indireção não suportada")
			}
		}
	case *pg_query.Node_CollateClause:
		a.expr(s, ctes, v.CollateClause.Arg, useGeneral)
	case *pg_query.Node_NamedArgExpr:
		a.expr(s, ctes, v.NamedArgExpr.Arg, useGeneral)
	default:
		a.denyf(nil, "", "expressão não suportada: %s", nodeName(n))
	}
}

func (a *analyzer) funcCall(s *scope, ctes *cteEnv, fc *pg_query.FuncCall) {
	a.visited[fc] = true
	name, _ := funcName(fc)
	argCtx := useGeneral
	if name == "count" && fc.AggDistinct && len(fc.Args) == 1 && fc.Args[0].GetColumnRef() != nil {
		argCtx = useGroup // count(DISTINCT x) não expõe o valor
	}
	a.exprs(s, ctes, fc.Args, argCtx)
	for _, o := range fc.AggOrder {
		sb := o.GetSortBy()
		if sb == nil {
			a.denyf(nil, "", "ORDER BY de agregação malformado")
		}
		a.expr(s, ctes, sb.Node, useGeneral)
	}
	a.expr(s, ctes, fc.AggFilter, useGeneral)
	if fc.Over != nil {
		a.windowDef(s, ctes, fc.Over)
	}
}

func (a *analyzer) windowDef(s *scope, ctes *cteEnv, w *pg_query.WindowDef) {
	a.exprs(s, ctes, w.PartitionClause, useGeneral)
	for _, o := range w.OrderClause {
		sb := o.GetSortBy()
		if sb == nil {
			a.denyf(nil, "", "ORDER BY de janela malformado")
		}
		a.expr(s, ctes, sb.Node, useGeneral)
	}
	a.constOrNull(w.StartOffset, "offset de janela")
	a.constOrNull(w.EndOffset, "offset de janela")
}

func intConst(n *pg_query.Node) (int, bool) {
	c := n.GetAConst()
	if c == nil || c.Isnull {
		return 0, false
	}
	if iv, ok := c.Val.(*pg_query.A_Const_Ival); ok {
		return int(iv.Ival.Ival), true
	}
	if fv, ok := c.Val.(*pg_query.A_Const_Fval); ok {
		if v, err := strconv.Atoi(fv.Fval.Fval); err == nil {
			return v, true
		}
	}
	return 0, false
}

func isNullConst(n *pg_query.Node) bool {
	c := n.GetAConst()
	return c != nil && c.Isnull
}

func (a *analyzer) constOrNull(n *pg_query.Node, what string) {
	if n == nil || n.GetAConst() != nil {
		return
	}
	if tc := n.GetTypeCast(); tc != nil && tc.Arg.GetAConst() != nil {
		return
	}
	a.denyf(nil, "um número escrito na query", "%s precisa ser constante", what)
}

// ---------- SELECT ----------

type selOpts struct {
	targetCtx useCtx // contexto de coluna nua na lista do SELECT
}

func (a *analyzer) rootSelect(sel *pg_query.SelectStmt) {
	cols := a.selectStmt(sel, nil, nil, selOpts{targetCtx: useBare})
	a.rootLimit(sel)
	for i, c := range cols {
		for _, o := range c.origins {
			if m := o.t.read.MaskOf(o.col); m != "" {
				a.masks = append(a.masks, OutputMask{Index: i, Label: c.labelOrName(), Mode: m, Column: o.t.name + "." + o.col})
				break
			}
		}
	}
}

func (a *analyzer) rootLimit(sel *pg_query.SelectStmt) {
	requested := -1
	if sel.LimitCount != nil && !isNullConst(sel.LimitCount) {
		v, ok := intConst(sel.LimitCount)
		if !ok || v < 0 {
			a.denyf(nil, "LIMIT n com n inteiro", "LIMIT precisa ser um número inteiro")
		}
		requested = v
	}
	pcap := a.policyCap
	if a.recheck {
		if requested < 1 || requested-1 > pcap {
			a.denyf(nil, "", "LIMIT ausente ou acima do teto após a reescrita")
		}
		a.cap = requested - 1
		a.capByReq = a.cap < pcap
		return
	}
	a.cap, a.capByReq = pcap, false
	if requested >= 0 && requested < pcap {
		a.cap, a.capByReq = requested, true
	}
	limit := a.cap + 1
	a.rewrites = append(a.rewrites, func() error {
		sel.LimitCount = pg_query.MakeAConstIntNode(int64(limit), 0)
		if sel.LimitOption == pg_query.LimitOption_LIMIT_OPTION_DEFAULT {
			sel.LimitOption = pg_query.LimitOption_LIMIT_OPTION_COUNT
		}
		return nil
	})
}

func (a *analyzer) limitOffset(sel *pg_query.SelectStmt) {
	for _, n := range []*pg_query.Node{sel.LimitCount, sel.LimitOffset} {
		if n == nil || isNullConst(n) {
			continue
		}
		if _, ok := intConst(n); !ok {
			a.denyf(nil, "LIMIT e OFFSET com números inteiros", "LIMIT/OFFSET precisam ser números inteiros")
		}
	}
}

func colName(rt *pg_query.ResTarget) string {
	if rt.Name != "" {
		return rt.Name
	}
	switch v := rt.Val.Node.(type) {
	case *pg_query.Node_ColumnRef:
		f, _ := refFields(v.ColumnRef)
		if len(f) > 0 {
			return f[len(f)-1]
		}
	case *pg_query.Node_FuncCall:
		if n, ok := funcName(v.FuncCall); ok {
			return n
		}
	case *pg_query.Node_TypeCast:
		return colName(&pg_query.ResTarget{Val: v.TypeCast.Arg})
	}
	return "?column?"
}

func (a *analyzer) withClause(wc *pg_query.WithClause, outer *scope, ctes *cteEnv) *cteEnv {
	if wc == nil {
		return ctes
	}
	for _, n := range wc.Ctes {
		cte := n.GetCommonTableExpr()
		if cte == nil {
			a.denyf(nil, "", "WITH malformado")
		}
		sel := cte.Ctequery.GetSelectStmt()
		if sel == nil {
			a.denyf(nil, "CTE só com SELECT; escrita só pelo exec, como statement raiz", "escrita dentro de CTE não é aceita")
		}
		aliases, _ := stringList(cte.Aliascolnames)
		var cols []column
		if wc.Recursive && sel.Op != pg_query.SetOperation_SETOP_NONE {
			// o termo não recursivo define as colunas; o recursivo enxerga a CTE
			left := a.selectStmt(sel.Larg, outer, ctes, selOpts{targetCtx: useBare})
			self := &cteEnv{parent: ctes, name: cte.Ctename, cols: renameCols(left, aliases)}
			right := a.selectStmt(sel.Rarg, outer, self, selOpts{targetCtx: useBare})
			cols = a.combineSetOp(sel, left, right)
			a.limitOffset(sel)
			if len(sel.SortClause) > 0 {
				a.denyf(nil, "", "ORDER BY em CTE recursiva não é aceito")
			}
		} else {
			cols = a.selectStmt(sel, outer, ctes, selOpts{targetCtx: useBare})
		}
		ctes = &cteEnv{parent: ctes, name: cte.Ctename, cols: renameCols(cols, aliases)}
	}
	return ctes
}

func renameCols(cols []column, names []string) []column {
	out := make([]column, len(cols))
	copy(out, cols)
	for i := range out {
		if i < len(names) {
			out[i].name = names[i]
		}
	}
	return out
}

func (a *analyzer) combineSetOp(sel *pg_query.SelectStmt, left, right []column) []column {
	if len(left) != len(right) {
		a.denyf(nil, "", "os lados de %s têm números de colunas diferentes", setOpName(sel))
	}
	out := make([]column, len(left))
	for i := range left {
		out[i] = column{name: left[i].name, origins: append(append([]origin{}, left[i].origins...), right[i].origins...)}
		mo := maskedOrigin(out[i].origins)
		if mo == nil {
			continue
		}
		// UNION, INTERSECT e EXCEPT comparam valores: com máscara seria oráculo
		if !(sel.Op == pg_query.SetOperation_SETOP_UNION && sel.All) {
			a.denyf(mo.t.rule, "UNION ALL", "coluna mascarada %q não pode passar por %s (compara valores)", mo.col, setOpName(sel))
		}
		// UNION ALL: a máscara de saída é aplicada por posição a todas as
		// linhas, com a mesma chave. Se o outro lado trouxer um valor escolhido
		// na query (constante, outra coluna), a IA receberia a máscara desse
		// valor e poderia confirmar palpites. Os dois lados precisam vir
		// exatamente da mesma coluna.
		if !sameOrigins(left[i].origins, right[i].origins) {
			a.denyf(mo.t.rule, "UNION ALL com a mesma coluna mascarada nos dois lados",
				"coluna mascarada %q não pode ser unida a outro valor na mesma posição (a máscara seria aplicada ao valor escolhido na query)", mo.col)
		}
	}
	return out
}

// maskedOrigin devolve a primeira origem com máscara, ou nil.
func maskedOrigin(origins []origin) *origin {
	for i := range origins {
		o := &origins[i]
		if o.t.read != nil && o.t.read.MaskOf(o.col) != "" {
			return o
		}
	}
	return nil
}

// sameOrigins diz se os dois conjuntos de origens são a mesma lista de
// tabela.coluna (independente do alias), e não vazios.
func sameOrigins(x, y []origin) bool {
	if len(x) == 0 || len(y) == 0 {
		return false
	}
	key := func(os []origin) map[string]bool {
		m := map[string]bool{}
		for _, o := range os {
			m[o.t.qualified()+"."+o.col] = true
		}
		return m
	}
	kx, ky := key(x), key(y)
	if len(kx) != len(ky) {
		return false
	}
	for k := range kx {
		if !ky[k] {
			return false
		}
	}
	return true
}

func setOpName(sel *pg_query.SelectStmt) string {
	name := map[pg_query.SetOperation]string{
		pg_query.SetOperation_SETOP_UNION: "UNION", pg_query.SetOperation_SETOP_INTERSECT: "INTERSECT",
		pg_query.SetOperation_SETOP_EXCEPT: "EXCEPT",
	}[sel.Op]
	if sel.All {
		name += " ALL"
	}
	return name
}

func (a *analyzer) selectStmt(sel *pg_query.SelectStmt, outer *scope, ctes *cteEnv, opts selOpts) []column {
	ctes = a.withClause(sel.WithClause, outer, ctes)

	if sel.Op != pg_query.SetOperation_SETOP_NONE {
		left := a.selectStmt(sel.Larg, outer, ctes, opts)
		right := a.selectStmt(sel.Rarg, outer, ctes, opts)
		cols := a.combineSetOp(sel, left, right)
		for _, o := range sel.SortClause {
			sb := o.GetSortBy()
			if sb == nil {
				a.denyf(nil, "", "ORDER BY malformado")
			}
			a.sortByOutput(sb.Node, cols, nil, nil, true)
		}
		a.limitOffset(sel)
		return cols
	}

	if len(sel.ValuesLists) > 0 {
		var width int
		for i, row := range sel.ValuesLists {
			l := row.GetList()
			if l == nil {
				a.denyf(nil, "", "VALUES malformado")
			}
			if i == 0 {
				width = len(l.Items)
			}
			a.exprs(&scope{parent: outer}, ctes, l.Items, useGeneral)
		}
		cols := make([]column, width)
		for i := range cols {
			cols[i] = column{name: fmt.Sprintf("column%d", i+1)}
		}
		a.limitOffset(sel)
		return cols
	}

	s := &scope{parent: outer, merged: map[string][]*entry{}}
	for _, f := range sel.FromClause {
		a.fromItem(f, s, ctes)
	}
	a.expr(s, ctes, sel.WhereClause, useGeneral)

	// lista do SELECT
	var cols []column
	var expanded []*pg_query.Node
	hasStar := false
	for _, t := range sel.TargetList {
		rt := t.GetResTarget()
		if rt == nil || rt.Val == nil {
			a.denyf(nil, "", "lista do SELECT malformada")
		}
		if isStar(rt.Val) {
			hasStar = true
			ref := rt.Val.GetColumnRef()
			a.visited[ref] = true
			if a.recheck {
				a.denyf(nil, "", "* sobrou depois da reescrita")
			}
			ecols, nodes := a.expandStar(s, ref, opts.targetCtx)
			cols = append(cols, ecols...)
			expanded = append(expanded, nodes...)
			continue
		}
		expanded = append(expanded, t)
		if ref := rt.Val.GetColumnRef(); ref != nil {
			c := a.columnRef(s, ref, opts.targetCtx)
			cols = append(cols, column{name: colName(rt), label: refLabel(ref), origins: c.origins})
			continue
		}
		a.expr(s, ctes, rt.Val, useGeneral)
		cols = append(cols, column{name: colName(rt)})
	}
	if hasStar {
		a.rewrites = append(a.rewrites, func() error {
			sel.TargetList = expanded
			return nil
		})
	}

	// DISTINCT / DISTINCT ON
	if !(len(sel.DistinctClause) == 1 && sel.DistinctClause[0].Node == nil) {
		for _, d := range sel.DistinctClause {
			a.groupItem(s, ctes, d, cols)
		}
	}
	for _, g := range sel.GroupClause {
		a.groupItem(s, ctes, g, cols)
	}
	a.expr(s, ctes, sel.HavingClause, useGeneral)
	for _, w := range sel.WindowClause {
		wd := w.GetWindowDef()
		if wd == nil {
			a.denyf(nil, "", "WINDOW malformado")
		}
		a.windowDef(s, ctes, wd)
	}
	for _, o := range sel.SortClause {
		sb := o.GetSortBy()
		if sb == nil {
			a.denyf(nil, "", "ORDER BY malformado")
		}
		a.sortByOutput(sb.Node, cols, s, ctes, false)
	}
	a.limitOffset(sel)
	return cols
}

// expandStar troca * ou t.* pelas colunas permitidas.
func (a *analyzer) expandStar(s *scope, ref *pg_query.ColumnRef, ctx useCtx) ([]column, []*pg_query.Node) {
	fields, _ := refFields(ref)
	var ents []*entry
	switch len(fields) {
	case 1:
		ents = s.entries
		if len(ents) == 0 {
			a.denyf(nil, "", "SELECT * sem FROM")
		}
	case 2:
		e := a.entryByName(s, fields[0])
		if e == nil {
			a.denyf(nil, "use um alias que esteja no FROM", "tabela ou alias %q não está no FROM", fields[0])
		}
		ents = []*entry{e}
	default:
		a.denyf(nil, "use alias.*", "* com schema não é aceito")
	}
	var cols []column
	var nodes []*pg_query.Node
	for _, e := range ents {
		if e.name == "" {
			a.denyf(nil, "dê um alias à subquery: (SELECT ...) AS s", "subquery sem alias no FROM")
		}
		e.refs++
		for _, c := range e.columns() {
			if e.table != nil && (e.table.read == nil || !e.table.read.AllowsCol(c.name)) {
				continue
			}
			a.checkColumn(c, ctx, e.name+"."+c.name)
			c.label = e.name + "." + c.name
			cols = append(cols, c)
			nodes = append(nodes, &pg_query.Node{Node: &pg_query.Node_ResTarget{ResTarget: &pg_query.ResTarget{
				Val: pg_query.MakeColumnRefNode([]*pg_query.Node{pg_query.MakeStrNode(e.name), pg_query.MakeStrNode(c.name)}, 0),
			}}})
		}
	}
	if len(nodes) == 0 {
		a.denyf(nil, "", "nenhuma coluna liberada para *")
	}
	return cols, nodes
}

// groupItem trata um item de GROUP BY ou DISTINCT ON.
func (a *analyzer) groupItem(s *scope, ctes *cteEnv, n *pg_query.Node, out []column) {
	if n == nil || n.Node == nil {
		return
	}
	if gs := n.GetGroupingSet(); gs != nil {
		for _, c := range gs.Content {
			a.groupItem(s, ctes, c, out)
		}
		return
	}
	if l := n.GetList(); l != nil {
		for _, c := range l.Items {
			a.groupItem(s, ctes, c, out)
		}
		return
	}
	if v, ok := intConst(n); ok {
		if v < 1 || v > len(out) {
			a.denyf(nil, "", "posição %d fora da lista do SELECT", v)
		}
		a.checkColumn(out[v-1], useGroup, out[v-1].name)
		return
	}
	if ref := n.GetColumnRef(); ref != nil {
		if _, ok := a.tryColumnRef(s, ref, useGroup); ok {
			return
		}
		// GROUP BY por nome da saída
		fields, _ := refFields(ref)
		if len(fields) == 1 {
			for _, c := range out {
				if c.name == fields[0] {
					a.checkColumn(c, useGroup, c.name)
					return
				}
			}
		}
		a.columnRef(s, ref, useGroup)
		return
	}
	a.expr(s, ctes, n, useGeneral)
}

// sortByOutput trata um item de ORDER BY: posição, nome da saída ou expressão.
func (a *analyzer) sortByOutput(n *pg_query.Node, out []column, s *scope, ctes *cteEnv, outputOnly bool) {
	if v, ok := intConst(n); ok {
		if v < 1 || v > len(out) {
			a.denyf(nil, "", "posição %d fora da lista do SELECT", v)
		}
		a.checkColumn(out[v-1], useGeneral, out[v-1].name)
		return
	}
	if ref := n.GetColumnRef(); ref != nil {
		fields, ok := refFields(ref)
		if ok && len(fields) == 1 {
			for _, c := range out {
				if c.name == fields[0] {
					a.visited[ref] = true
					a.checkColumn(c, useGeneral, c.name)
					return
				}
			}
		}
	}
	if outputOnly {
		a.denyf(nil, "ORDER BY com nome ou posição de coluna da saída", "ORDER BY de UNION/INTERSECT/EXCEPT precisa usar colunas da saída")
	}
	a.expr(s, ctes, n, useGeneral)
}

// ---------- FROM ----------

func aliasNames(al *pg_query.Alias) []string {
	if al == nil {
		return nil
	}
	n, _ := stringList(al.Colnames)
	return n
}

func (a *analyzer) fromItem(n *pg_query.Node, s *scope, ctes *cteEnv) []*entry {
	switch v := n.Node.(type) {
	case *pg_query.Node_RangeVar:
		rv := v.RangeVar
		if rv.Schemaname == "" {
			if cte := ctes.lookup(rv.Relname); cte != nil {
				a.visited[rv] = true
				name := rv.Relname
				if rv.Alias != nil {
					name = rv.Alias.Aliasname
				}
				e := &entry{name: name, cols: renameCols(cte.cols, aliasNames(rv.Alias))}
				s.entries = append(s.entries, e)
				return []*entry{e}
			}
		}
		t := a.resolveTable(rv, policy.Read)
		name := rv.Relname
		if rv.Alias != nil {
			if len(rv.Alias.Colnames) > 0 {
				a.denyf(t.rule, "alias só para a tabela: FROM t AS x", "alias de colunas em tabela não é aceito")
			}
			name = rv.Alias.Aliasname
		}
		a.addRule(name, t, policy.Read)
		e := &entry{name: name, table: t}
		s.entries = append(s.entries, e)
		if filter := a.g.filters[t.read]; filter != nil {
			if a.recheck {
				a.denyf(t.rule, "", "tabela %q com filtro de linha apareceu sem o filtro depois da reescrita", t.name)
			}
			wrap, err := a.wrapperSelect(t, rv)
			if err != nil {
				a.denyf(t.rule, "", "não foi possível aplicar o filtro de %s: %v", t.name, err)
			}
			a.rewrites = append(a.rewrites, func() error {
				n.Node = &pg_query.Node_RangeSubselect{RangeSubselect: &pg_query.RangeSubselect{
					Subquery: wrap,
					Alias:    &pg_query.Alias{Aliasname: name},
				}}
				return nil
			})
		}
		return []*entry{e}

	case *pg_query.Node_RangeSubselect:
		rs := v.RangeSubselect
		sel := rs.Subquery.GetSelectStmt()
		if sel == nil {
			a.denyf(nil, "", "subquery no FROM precisa ser SELECT")
		}
		if rs.Alias == nil || rs.Alias.Aliasname == "" {
			a.denyf(nil, "dê um alias à subquery: (SELECT ...) AS s", "subquery sem alias no FROM")
		}
		if a.recheck {
			if t := a.matchWrapper(sel); t != nil {
				if len(rs.Alias.Colnames) > 0 {
					a.denyf(t.rule, "", "filtro reescrito com alias de colunas")
				}
				a.addRule(rs.Alias.Aliasname, t, policy.Read)
				a.skip(sel)
				e := &entry{name: rs.Alias.Aliasname, table: t}
				s.entries = append(s.entries, e)
				return []*entry{e}
			}
		}
		outer := s.parent
		if rs.Lateral {
			outer = s
		}
		cols := a.selectStmt(sel, outer, ctes, selOpts{targetCtx: useBare})
		e := &entry{name: rs.Alias.Aliasname, cols: renameCols(cols, aliasNames(rs.Alias))}
		s.entries = append(s.entries, e)
		return []*entry{e}

	case *pg_query.Node_RangeFunction:
		rf := v.RangeFunction
		if len(rf.Functions) != 1 {
			a.denyf(nil, "uma função por item do FROM", "ROWS FROM com várias funções não é aceito")
		}
		item := rf.Functions[0].GetList()
		if item == nil || len(item.Items) == 0 {
			a.denyf(nil, "", "função no FROM malformada")
		}
		fc := item.Items[0].GetFuncCall()
		if fc == nil {
			a.denyf(nil, "função da allowlist, ex.: generate_series(1, 10) AS g(n)", "item de função no FROM não suportado")
		}
		for _, extra := range item.Items[1:] {
			if l := extra.GetList(); extra.Node != nil && (l == nil || len(l.Items) > 0) {
				a.denyf(nil, "", "lista de definição de colunas não é aceita")
			}
		}
		// funções no FROM enxergam os itens anteriores (LATERAL implícito)
		a.funcCall(s, ctes, fc)
		fname, _ := funcName(fc)
		name := fname
		colname := fname
		if rf.Alias != nil {
			name = rf.Alias.Aliasname
			colname = rf.Alias.Aliasname
		}
		names := aliasNames(rf.Alias)
		if len(names) > 0 {
			colname = names[0]
		}
		cols := []column{{name: colname}}
		if rf.Ordinality {
			oc := "ordinality"
			if len(names) > 1 {
				oc = names[1]
			}
			cols = append(cols, column{name: oc})
		}
		e := &entry{name: name, cols: cols}
		s.entries = append(s.entries, e)
		return []*entry{e}

	case *pg_query.Node_JoinExpr:
		j := v.JoinExpr
		if j.Alias != nil || j.JoinUsingAlias != nil {
			a.denyf(nil, "aliases nas tabelas, não no JOIN", "alias em JOIN não é aceito")
		}
		left := a.fromItem(j.Larg, s, ctes)
		right := a.fromItem(j.Rarg, s, ctes)
		subtree := append(append([]*entry{}, left...), right...)
		using, _ := stringList(j.UsingClause)
		if j.IsNatural {
			using = commonColumns(left, right)
		}
		for _, name := range using {
			l := a.usingSide(left, name)
			r := a.usingSide(right, name)
			for _, side := range []*entry{l, r} {
				c, _ := side.find(name)
				a.checkColumn(c, useGeneral, side.name+"."+name)
				side.refs++
			}
			prev := s.merged[name]
			ents := []*entry{}
			if containsEntry(prev, l) {
				ents = append(ents, prev...)
			} else {
				ents = append(ents, l)
			}
			s.merged[name] = append(ents, r)
		}
		if j.Quals != nil {
			js := &scope{parent: s.parent, entries: subtree, merged: s.merged}
			a.expr(js, ctes, j.Quals, useGeneral)
		}
		return subtree
	}
	a.denyf(nil, "tabela, subquery, função da allowlist ou JOIN", "item de FROM não suportado: %s", nodeName(n))
	return nil
}

func (a *analyzer) usingSide(ents []*entry, name string) *entry {
	var found *entry
	for _, e := range ents {
		if _, n := e.find(name); n > 0 {
			if found != nil {
				a.denyf(nil, "", "coluna %q do USING é ambígua", name)
			}
			found = e
		}
	}
	if found == nil {
		a.denyf(nil, "", "coluna %q do USING não existe nos dois lados do JOIN", name)
	}
	return found
}

func commonColumns(left, right []*entry) []string {
	in := map[string]bool{}
	for _, e := range left {
		for _, c := range e.columns() {
			in[c.name] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range right {
		for _, c := range e.columns() {
			if in[c.name] && !seen[c.name] {
				seen[c.name] = true
				out = append(out, c.name)
			}
		}
	}
	sort.Strings(out)
	return out
}
