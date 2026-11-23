package schema

import (
	"fmt"
	"slices"
	"strings"
	"time"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// FromDDL monta o schema a partir de um script DDL (CREATE TABLE, CREATE VIEW,
// CREATE MATERIALIZED VIEW, ALTER TABLE ... ADD CONSTRAINT e COMMENT ON), como
// o de `pg_dump --schema-only`. Serve para check e test sem acesso ao banco.
// Outros statements (INSERT, SET, sequências, índices, OWNER TO) são
// ignorados. warnings lista o que não deu para entender, como uma view com
// colunas que só o banco saberia resolver.
func FromDDL(src string, schemas []string) (s *Schema, warnings []string, err error) {
	tree, err := pg_query.Parse(src)
	if err != nil {
		return nil, nil, fmt.Errorf("DDL inválido: %w", err)
	}
	b := &ddlBuilder{
		s:       &Schema{Version: cacheVersion, FetchedAt: time.Now().UTC(), Source: "ddl", Tables: map[string]*Table{}},
		schemas: schemas,
	}
	for _, raw := range tree.Stmts {
		b.stmt(raw.Stmt)
	}
	return b.s, b.warnings, nil
}

type ddlBuilder struct {
	s        *Schema
	schemas  []string
	warnings []string
}

func (b *ddlBuilder) warn(format string, a ...any) {
	b.warnings = append(b.warnings, fmt.Sprintf(format, a...))
}

func (b *ddlBuilder) stmt(n *pg_query.Node) {
	switch {
	case n.GetCreateStmt() != nil:
		b.createTable(n.GetCreateStmt())
	case n.GetAlterTableStmt() != nil:
		b.alterTable(n.GetAlterTableStmt())
	case n.GetViewStmt() != nil:
		v := n.GetViewStmt()
		b.view(v.View, "view", v.Aliases, v.Query)
	case n.GetCreateTableAsStmt() != nil:
		c := n.GetCreateTableAsStmt()
		if c.Objtype == pg_query.ObjectType_OBJECT_MATVIEW && c.Into != nil {
			b.view(c.Into.Rel, "matview", c.Into.ColNames, c.Query)
		}
	case n.GetCommentStmt() != nil:
		b.comment(n.GetCommentStmt())
	}
}

// key devolve "schema.tabela" e se o schema está entre os da política.
func (b *ddlBuilder) key(rv *pg_query.RangeVar) (string, bool) {
	sch := rv.Schemaname
	if sch == "" {
		sch = "public"
	}
	return sch + "." + rv.Relname, slices.Contains(b.schemas, sch)
}

func (b *ddlBuilder) createTable(c *pg_query.CreateStmt) {
	if c.Partbound != nil {
		return // partição: o catálogo também só mostra a tabela-mãe
	}
	k, ok := b.key(c.Relation)
	if !ok {
		return
	}
	t := &Table{Schema: strings.SplitN(k, ".", 2)[0], Name: c.Relation.Relname, Kind: "table"}
	if c.Partspec != nil {
		t.Kind = "partitioned"
	}
	for _, el := range c.TableElts {
		if col := el.GetColumnDef(); col != nil {
			b.column(t, col)
		}
		if con := el.GetConstraint(); con != nil {
			b.constraint(t, con, nil)
		}
	}
	for _, con := range c.Constraints {
		if cc := con.GetConstraint(); cc != nil {
			b.constraint(t, cc, nil)
		}
	}
	b.s.Tables[k] = t
}

func (b *ddlBuilder) column(t *Table, col *pg_query.ColumnDef) {
	typ, serial := typeText(col.TypeName)
	c := Column{Name: col.Colname, Type: typ, NotNull: col.IsNotNull || serial}
	t.Columns = append(t.Columns, c)
	for _, n := range col.Constraints {
		if con := n.GetConstraint(); con != nil {
			b.constraint(t, con, &t.Columns[len(t.Columns)-1])
		}
	}
}

// constraint aplica PK, FK e NOT NULL. col é a coluna quando a restrição foi
// escrita na própria definição dela.
func (b *ddlBuilder) constraint(t *Table, con *pg_query.Constraint, col *Column) {
	switch con.Contype {
	case pg_query.ConstrType_CONSTR_NOTNULL:
		if col != nil {
			col.NotNull = true
		}
	case pg_query.ConstrType_CONSTR_PRIMARY:
		keys := names(con.Keys)
		if col != nil {
			keys = []string{col.Name}
		}
		t.PrimaryKey = keys
		for i := range t.Columns {
			if slices.Contains(keys, t.Columns[i].Name) {
				t.Columns[i].NotNull = true
			}
		}
	case pg_query.ConstrType_CONSTR_FOREIGN:
		if con.Pktable == nil {
			return
		}
		cols := names(con.FkAttrs)
		if col != nil {
			cols = []string{col.Name}
		}
		ref, _ := b.key(con.Pktable)
		rsch, rtbl, _ := strings.Cut(ref, ".")
		t.ForeignKeys = append(t.ForeignKeys, ForeignKey{Columns: cols, RefSchema: rsch, RefTable: rtbl, RefColumns: names(con.PkAttrs)})
	}
}

func (b *ddlBuilder) alterTable(a *pg_query.AlterTableStmt) {
	k, ok := b.key(a.Relation)
	t := b.s.Tables[k]
	if !ok || t == nil {
		return
	}
	for _, n := range a.Cmds {
		cmd := n.GetAlterTableCmd()
		if cmd == nil || cmd.Subtype != pg_query.AlterTableType_AT_AddConstraint || cmd.Def.GetConstraint() == nil {
			continue
		}
		b.constraint(t, cmd.Def.GetConstraint(), nil)
	}
}

// view deduz as colunas pela lista explícita ou pelo SELECT: nomes/aliases,
// colunas citadas e * de uma única tabela já conhecida.
func (b *ddlBuilder) view(rv *pg_query.RangeVar, kind string, aliases []*pg_query.Node, query *pg_query.Node) {
	k, ok := b.key(rv)
	if !ok {
		return
	}
	t := &Table{Schema: strings.SplitN(k, ".", 2)[0], Name: rv.Relname, Kind: kind}
	cols := names(aliases)
	if len(cols) == 0 {
		var err error
		if cols, err = b.selectColumns(query.GetSelectStmt()); err != nil {
			b.warn("%s %s ignorada: %v; liste as colunas no SELECT", kind, k, err)
			return
		}
	}
	for _, c := range cols {
		t.Columns = append(t.Columns, Column{Name: c})
	}
	b.s.Tables[k] = t
}

func (b *ddlBuilder) selectColumns(sel *pg_query.SelectStmt) ([]string, error) {
	if sel == nil || len(sel.TargetList) == 0 {
		return nil, fmt.Errorf("SELECT não suportado")
	}
	var out []string
	for _, n := range sel.TargetList {
		rt := n.GetResTarget()
		if rt.GetName() != "" {
			out = append(out, rt.Name)
			continue
		}
		ref := rt.GetVal().GetColumnRef()
		if ref == nil {
			return nil, fmt.Errorf("expressão sem alias")
		}
		last := ref.Fields[len(ref.Fields)-1]
		if last.GetAStar() == nil {
			out = append(out, last.GetString_().GetSval())
			continue
		}
		if len(sel.FromClause) != 1 || sel.FromClause[0].GetRangeVar() == nil {
			return nil, fmt.Errorf("* fora de um FROM com uma única tabela")
		}
		src, _ := b.key(sel.FromClause[0].GetRangeVar())
		st := b.s.Tables[src]
		if st == nil {
			return nil, fmt.Errorf("* de %s, que não está no DDL", src)
		}
		out = append(out, st.ColumnNames()...)
	}
	return out, nil
}

func (b *ddlBuilder) comment(c *pg_query.CommentStmt) {
	parts := names(c.Object.GetList().GetItems())
	switch c.Objtype {
	case pg_query.ObjectType_OBJECT_TABLE, pg_query.ObjectType_OBJECT_VIEW, pg_query.ObjectType_OBJECT_MATVIEW:
		if t := b.lookup(parts); t != nil {
			t.Comment = c.Comment
		}
	case pg_query.ObjectType_OBJECT_COLUMN:
		if len(parts) < 2 {
			return
		}
		t := b.lookup(parts[:len(parts)-1])
		if t == nil {
			return
		}
		for i := range t.Columns {
			if t.Columns[i].Name == parts[len(parts)-1] {
				t.Columns[i].Comment = c.Comment
			}
		}
	}
}

func (b *ddlBuilder) lookup(parts []string) *Table {
	switch len(parts) {
	case 1:
		return b.s.Tables["public."+parts[0]]
	case 2:
		return b.s.Tables[parts[0]+"."+parts[1]]
	}
	return nil
}

func names(nodes []*pg_query.Node) []string {
	var out []string
	for _, n := range nodes {
		if s := n.GetString_(); s != nil {
			out = append(out, s.Sval)
		}
	}
	return out
}

// typeAliases traduz os nomes internos para os do format_type do Postgres.
var typeAliases = map[string]string{
	"int2": "smallint", "int4": "integer", "int8": "bigint", "int": "integer",
	"float4": "real", "float8": "double precision", "bool": "boolean", "decimal": "numeric",
	"varchar": "character varying", "bpchar": "character",
	"timestamptz": "timestamp with time zone", "timestamp": "timestamp without time zone",
	"timetz": "time with time zone", "time": "time without time zone",
}

var serials = map[string]string{
	"serial": "integer", "serial4": "integer", "bigserial": "bigint",
	"serial8": "bigint", "smallserial": "smallint", "serial2": "smallint",
}

// typeText devolve o tipo como texto e se é serial (que implica NOT NULL).
func typeText(tn *pg_query.TypeName) (string, bool) {
	parts := names(tn.GetNames())
	if len(parts) == 0 {
		return "?", false
	}
	name := parts[len(parts)-1]
	if s, ok := serials[name]; ok {
		return s, true
	}
	if a, ok := typeAliases[name]; ok {
		name = a
	}
	var mods []string
	for _, m := range tn.Typmods {
		if c := m.GetAConst(); c != nil && c.GetIval() != nil {
			mods = append(mods, fmt.Sprint(c.GetIval().Ival))
		}
	}
	if len(mods) > 0 {
		if base, zone, ok := strings.Cut(name, " with"); ok {
			name = base + "(" + strings.Join(mods, ",") + ") with" + zone
		} else {
			name += "(" + strings.Join(mods, ",") + ")"
		}
	}
	return name + strings.Repeat("[]", len(tn.ArrayBounds)), false
}
