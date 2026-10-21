package sqlguard

import (
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"crivo/internal/policy"
)

// ---------- INSERT ----------

func (a *analyzer) insertStmt(ins *pg_query.InsertStmt) {
	ctes := a.withClause(ins.WithClause, nil, nil)
	t := a.resolveTable(ins.Relation, policy.Insert)
	act := t.rule.Action(policy.Insert)
	name := ins.Relation.Relname
	if ins.Relation.Alias != nil {
		name = ins.Relation.Alias.Aliasname
	}
	a.addRule(name, t, policy.Insert)
	a.target = &RuleUse{Table: name, Name: t.qualified(), Rule: t.rule, Verb: policy.Insert}
	a.maxRows = act.MaxRows()

	accepted := strings.Join(act.AllowedCols(t.info.ColumnNames()), ", ")
	if len(ins.Cols) == 0 {
		a.denyf(t.rule, fmt.Sprintf("INSERT INTO %s (%s) VALUES (...)", t.name, accepted), "INSERT precisa da lista de colunas explícita")
	}
	for _, c := range ins.Cols {
		rt := c.GetResTarget()
		if rt == nil || len(rt.Indirection) > 0 {
			a.denyf(t.rule, accepted, "coluna de INSERT com indireção não é aceita")
		}
		if t.info.Column(rt.Name) == nil {
			a.denyf(t.rule, accepted, "coluna %q não existe em %s", rt.Name, t.name)
		}
		if !act.AllowsCol(rt.Name) {
			a.denyf(t.rule, accepted, "coluna %q não pode receber valor", rt.Name)
		}
	}
	if ins.Override != pg_query.OverridingKind_OVERRIDING_NOT_SET && ins.Override != pg_query.OverridingKind_OVERRIDING_KIND_UNDEFINED {
		a.denyf(t.rule, "INSERT sem OVERRIDING", "OVERRIDING SYSTEM/USER VALUE não é aceito")
	}

	sel := ins.SelectStmt.GetSelectStmt()
	if sel == nil {
		a.denyf(t.rule, "INSERT ... VALUES (...) ou INSERT ... SELECT", "INSERT sem VALUES não é aceito")
	}
	if len(sel.ValuesLists) > 0 && len(sel.FromClause) == 0 && sel.WithClause == nil {
		for _, row := range sel.ValuesLists {
			l := row.GetList()
			if l == nil {
				a.denyf(nil, "", "VALUES malformado")
			}
			if len(l.Items) != len(ins.Cols) {
				a.denyf(t.rule, "", "VALUES com %d valores para %d colunas", len(l.Items), len(ins.Cols))
			}
			a.exprs(&scope{}, ctes, l.Items, useGeneral)
		}
		a.limitOffset(sel)
	} else {
		// o resultado vai para a tabela, não para a saída: máscara não pode ser copiada
		a.selectStmt(sel, nil, ctes, selOpts{targetCtx: useGeneral})
	}

	target := &entry{name: name, table: t, target: true}
	if oc := ins.OnConflictClause; oc != nil {
		if oc.Infer != nil {
			for _, ie := range oc.Infer.IndexElems {
				el := ie.GetIndexElem()
				if el == nil || el.Expr != nil || el.Name == "" {
					a.denyf(t.rule, "ON CONFLICT (coluna)", "ON CONFLICT com expressão não é aceito")
				}
				if t.info.Column(el.Name) == nil {
					a.denyf(t.rule, "", "coluna %q não existe em %s", el.Name, t.name)
				}
			}
			a.expr(&scope{entries: []*entry{target}}, ctes, oc.Infer.WhereClause, useGeneral)
		}
		if oc.Action == pg_query.OnConflictAction_ONCONFLICT_UPDATE {
			up := t.rule.Action(policy.Update)
			if up == nil {
				a.denyf(t.rule, "ON CONFLICT DO NOTHING", "ON CONFLICT DO UPDATE exige update em %s", t.name)
			}
			excluded := &entry{name: "excluded"}
			for _, c := range t.info.Columns {
				excluded.cols = append(excluded.cols, column{name: c.Name})
			}
			cs := &scope{entries: []*entry{target, excluded}, merged: map[string][]*entry{}}
			a.setList(cs, ctes, t, up, oc.TargetList)
			a.expr(cs, ctes, oc.WhereClause, useGeneral)
			a.addRule(name, t, policy.Update)
		}
	}
	a.returning(&scope{entries: []*entry{target}}, ctes, ins.ReturningList, func(l []*pg_query.Node) { ins.ReturningList = l })
}

// ---------- UPDATE ----------

func (a *analyzer) updateStmt(up *pg_query.UpdateStmt) {
	ctes := a.withClause(up.WithClause, nil, nil)
	t := a.resolveTable(up.Relation, policy.Update)
	act := t.rule.Action(policy.Update)
	name := up.Relation.Relname
	if up.Relation.Alias != nil {
		name = up.Relation.Alias.Aliasname
	}
	a.addRule(name, t, policy.Update)
	a.target = &RuleUse{Table: name, Name: t.qualified(), Rule: t.rule, Verb: policy.Update}
	a.maxRows = act.MaxRows()

	target := &entry{name: name, table: t, target: true}
	s := &scope{entries: []*entry{target}, merged: map[string][]*entry{}}
	for _, f := range up.FromClause {
		a.fromItem(f, s, ctes)
	}
	a.setList(s, ctes, t, act, up.TargetList)
	a.writeWhere(s, ctes, target, act, up.WhereClause, "UPDATE", func(n *pg_query.Node) { up.WhereClause = n })
	a.returning(s, ctes, up.ReturningList, func(l []*pg_query.Node) { up.ReturningList = l })
}

// setList checa SET coluna = valor.
func (a *analyzer) setList(s *scope, ctes *cteEnv, t *tableRef, act *policy.Action, list []*pg_query.Node) {
	accepted := strings.Join(act.AllowedCols(t.info.ColumnNames()), ", ")
	for _, n := range list {
		rt := n.GetResTarget()
		if rt == nil {
			a.denyf(t.rule, "", "SET malformado")
		}
		if len(rt.Indirection) > 0 {
			a.denyf(t.rule, accepted, "SET em parte de coluna (campo ou índice) não é aceito")
		}
		if t.info.Column(rt.Name) == nil {
			a.denyf(t.rule, accepted, "coluna %q não existe em %s", rt.Name, t.name)
		}
		if !act.AllowsCol(rt.Name) {
			a.denyf(t.rule, accepted, "coluna %q não pode ser alterada", rt.Name)
		}
		if mar := rt.Val.GetMultiAssignRef(); mar != nil {
			if mar.Colno == 1 {
				a.expr(s, ctes, mar.Source, useGeneral)
			}
			continue
		}
		a.expr(s, ctes, rt.Val, useGeneral)
	}
}

// ---------- DELETE ----------

func (a *analyzer) deleteStmt(del *pg_query.DeleteStmt) {
	ctes := a.withClause(del.WithClause, nil, nil)
	t := a.resolveTable(del.Relation, policy.Delete)
	act := t.rule.Action(policy.Delete)
	name := del.Relation.Relname
	if del.Relation.Alias != nil {
		name = del.Relation.Alias.Aliasname
	}
	a.addRule(name, t, policy.Delete)
	a.target = &RuleUse{Table: name, Name: t.qualified(), Rule: t.rule, Verb: policy.Delete}
	a.maxRows = act.MaxRows()

	target := &entry{name: name, table: t, target: true}
	s := &scope{entries: []*entry{target}, merged: map[string][]*entry{}}
	for _, f := range del.UsingClause {
		a.fromItem(f, s, ctes)
	}
	a.writeWhere(s, ctes, target, act, del.WhereClause, "DELETE", func(n *pg_query.Node) { del.WhereClause = n })
	a.returning(s, ctes, del.ReturningList, func(l []*pg_query.Node) { del.ReturningList = l })
}

// writeWhere exige WHERE com coluna da tabela alvo e injeta os filtros
// where da política (da ação de escrita e da leitura) com AND.
func (a *analyzer) writeWhere(s *scope, ctes *cteEnv, target *entry, act *policy.Action, where *pg_query.Node, verb string, set func(*pg_query.Node)) {
	t := target.table
	if where == nil {
		a.denyf(t.rule, fmt.Sprintf("%s ... WHERE <coluna de %s> = ...", verb, t.name), "%s sem WHERE não é aceito", verb)
	}
	filters := a.writeFilters(t, act, target.name)
	userWhere := where
	if a.recheck && len(filters) > 0 {
		be := where.GetBoolExpr()
		if be == nil || be.Boolop != pg_query.BoolExprType_AND_EXPR || len(be.Args) <= len(filters) {
			a.denyf(t.rule, "", "filtro de linha ausente depois da reescrita")
		}
		tail := be.Args[len(be.Args)-len(filters):]
		for i, f := range filters {
			if !sameNode(tail[i], f) {
				a.denyf(t.rule, "", "filtro de linha divergente depois da reescrita")
			}
			a.skip(tail[i])
		}
		head := be.Args[:len(be.Args)-len(filters)]
		if len(head) == 1 {
			userWhere = head[0]
		} else {
			userWhere = &pg_query.Node{Node: &pg_query.Node_BoolExpr{BoolExpr: &pg_query.BoolExpr{Boolop: pg_query.BoolExprType_AND_EXPR, Args: head}}}
		}
	}
	before := target.refs
	a.expr(s, ctes, userWhere, useGeneral)
	if target.refs == before {
		a.denyf(t.rule, fmt.Sprintf("WHERE com uma coluna de %s, ex.: WHERE id = 42", t.name), "o WHERE precisa usar ao menos uma coluna de %s", t.name)
	}
	if !a.recheck && len(filters) > 0 {
		args := flattenAnd(where)
		args = append(args, filters...)
		a.rewrites = append(a.rewrites, func() error {
			set(&pg_query.Node{Node: &pg_query.Node_BoolExpr{BoolExpr: &pg_query.BoolExpr{Boolop: pg_query.BoolExprType_AND_EXPR, Args: args}}})
			return nil
		})
	}
}

func flattenAnd(n *pg_query.Node) []*pg_query.Node {
	if be := n.GetBoolExpr(); be != nil && be.Boolop == pg_query.BoolExprType_AND_EXPR {
		return append([]*pg_query.Node{}, be.Args...)
	}
	return []*pg_query.Node{n}
}

// writeFilters devolve os filtros (já qualificados com o alias do alvo) que
// entram no WHERE de UPDATE/DELETE: o da escrita e o da leitura, porque uma
// linha invisível para leitura também não deve ser alterada.
func (a *analyzer) writeFilters(t *tableRef, act *policy.Action, alias string) []*pg_query.Node {
	var out []*pg_query.Node
	for _, ac := range []*policy.Action{act, t.read} {
		f := a.g.filters[ac]
		if f == nil {
			continue
		}
		q := proto.Clone(f).(*pg_query.Node)
		qualify(q, alias)
		out = append(out, flattenAnd(q)...)
	}
	return out
}

// qualify prefixa com o alias as colunas não qualificadas do filtro (fora de
// subqueries), para que o filtro não resolva para outra tabela do FROM.
func qualify(n *pg_query.Node, alias string) {
	var walk func(m protoreflect.Message)
	walk = func(m protoreflect.Message) {
		switch v := m.Interface().(type) {
		case *pg_query.SubLink:
			return
		case *pg_query.ColumnRef:
			if len(v.Fields) == 1 && v.Fields[0].GetString_() != nil {
				v.Fields = append([]*pg_query.Node{pg_query.MakeStrNode(alias)}, v.Fields...)
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
	walk(n.ProtoReflect())
}

// returning checa RETURNING como uma lista de SELECT cuja saída é visível.
func (a *analyzer) returning(s *scope, ctes *cteEnv, list []*pg_query.Node, set func([]*pg_query.Node)) {
	if len(list) == 0 {
		return
	}
	var cols []column
	var expanded []*pg_query.Node
	hasStar := false
	for _, n := range list {
		rt := n.GetResTarget()
		if rt == nil || rt.Val == nil {
			a.denyf(nil, "", "RETURNING malformado")
		}
		if isStar(rt.Val) {
			hasStar = true
			ref := rt.Val.GetColumnRef()
			a.visited[ref] = true
			if a.recheck {
				a.denyf(nil, "", "* sobrou depois da reescrita")
			}
			ec, nodes := a.expandStar(s, ref, useBare)
			cols = append(cols, ec...)
			expanded = append(expanded, nodes...)
			continue
		}
		expanded = append(expanded, n)
		if ref := rt.Val.GetColumnRef(); ref != nil {
			c := a.columnRef(s, ref, useBare)
			cols = append(cols, column{name: colName(rt), label: refLabel(ref), origins: c.origins})
			continue
		}
		a.expr(s, ctes, rt.Val, useGeneral)
		cols = append(cols, column{name: colName(rt)})
	}
	if hasStar {
		a.rewrites = append(a.rewrites, func() error { set(expanded); return nil })
	}
	for i, c := range cols {
		for _, o := range c.origins {
			if m := o.t.read.MaskOf(o.col); m != "" {
				a.masks = append(a.masks, OutputMask{Index: i, Label: c.labelOrName(), Mode: m, Column: o.t.name + "." + o.col})
				break
			}
		}
	}
}

// ---------- filtro de leitura ----------

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// wrapperSelect monta "SELECT <colunas legíveis> FROM <tabela> WHERE <filtro>",
// que substitui a tabela no FROM mantendo o alias. Lista as colunas em vez de
// * para funcionar também com GRANT por coluna no banco.
func (a *analyzer) wrapperSelect(t *tableRef, rv *pg_query.RangeVar) (*pg_query.Node, error) {
	cols := a.readableCols(t)
	if len(cols) == 0 {
		return nil, fmt.Errorf("nenhuma coluna legível")
	}
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = quoteIdent(c)
	}
	rel := quoteIdent(rv.Relname)
	if rv.Schemaname != "" {
		rel = quoteIdent(rv.Schemaname) + "." + rel
	}
	sql := "SELECT " + strings.Join(q, ", ") + " FROM " + rel + " WHERE " + t.read.Where
	tree, err := pg_query.Parse(sql)
	if err != nil {
		return nil, err
	}
	if len(tree.Stmts) != 1 || tree.Stmts[0].Stmt.GetSelectStmt() == nil {
		return nil, fmt.Errorf("filtro malformado")
	}
	return tree.Stmts[0].Stmt, nil
}

// matchWrapper reconhece, na re-checagem, uma subquery que é exatamente o
// filtro de leitura de uma tabela, e devolve a tabela.
func (a *analyzer) matchWrapper(sel *pg_query.SelectStmt) *tableRef {
	if len(sel.FromClause) != 1 || sel.WhereClause == nil || sel.WithClause != nil {
		return nil
	}
	rv := sel.FromClause[0].GetRangeVar()
	if rv == nil || rv.Alias != nil {
		return nil
	}
	sch := rv.Schemaname
	if sch == "" {
		sch = a.g.Policy.Schema
	}
	rule := a.g.Policy.Resolve(sch, rv.Relname)
	read := rule.Action(policy.Read)
	if read == nil || a.g.filters[read] == nil {
		return nil
	}
	info := a.g.Schema.Table(sch, rv.Relname)
	if info == nil {
		return nil
	}
	t := &tableRef{schema: sch, name: rv.Relname, info: info, rule: rule, read: read}
	want, err := a.wrapperSelect(t, rv)
	if err != nil || !sameNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: sel}}, want) {
		return nil
	}
	if read.Limit > 0 && read.Limit < a.policyCap {
		a.policyCap = read.Limit
	}
	return t
}

// ---------- comparação de AST ----------

var locationFields = map[protoreflect.Name]bool{"location": true, "stmt_location": true, "stmt_len": true}

func clearLocations(m protoreflect.Message) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case locationFields[fd.Name()]:
			m.Clear(fd)
		case fd.IsList() && fd.Message() != nil:
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				clearLocations(l.Get(i).Message())
			}
		case fd.Message() != nil && !fd.IsMap():
			clearLocations(v.Message())
		}
		return true
	})
}

func sameNode(x, y proto.Message) bool {
	cx, cy := proto.Clone(x), proto.Clone(y)
	clearLocations(cx.ProtoReflect())
	clearLocations(cy.ProtoReflect())
	return proto.Equal(cx, cy)
}

// sameTree compara o AST reescrito com o re-parse do seu deparse.
func sameTree(x, y *pg_query.RawStmt) bool { return sameNode(x, y) }
