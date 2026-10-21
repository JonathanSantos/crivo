package sqlguard

import (
	"fmt"
	"sort"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"

	"crivo/internal/policy"
)

// Grupos da allowlist padrão de funções.
var FunctionGroups = []struct {
	Name  string
	Funcs []string
}{
	{"Agregação", []string{"count", "sum", "avg", "min", "max", "string_agg", "array_agg", "bool_and", "bool_or"}},
	{"Janela", []string{"row_number", "rank", "dense_rank", "lag", "lead", "first_value", "last_value", "ntile"}},
	{"Matemática", []string{"abs", "round", "ceil", "floor", "greatest", "least", "coalesce", "nullif", "mod"}},
	{"Texto", []string{"lower", "upper", "trim", "length", "substring", "replace", "concat", "left", "right", "split_part", "position", "initcap", "lpad", "rpad"}},
	{"Data", []string{"now", "current_date", "date_trunc", "date_part", "extract", "age", "to_char", "to_date", "to_timestamp", "make_date", "generate_series"}},
	{"JSON", []string{"json_build_object", "jsonb_build_object", "json_agg", "jsonb_agg", "jsonb_extract_path_text", "jsonb_array_length"}},
}

// Nomes internos em que a gramática do Postgres transforma funções da
// allowlist: trim(x) vira btrim, "AT TIME ZONE" vira timezone, SIMILAR TO
// usa similar_to_escape.
var internalFunctions = []string{"btrim", "ltrim", "rtrim", "timezone", "similar_to_escape"}

var defaultFunctions = func() map[string]bool {
	m := map[string]bool{}
	for _, g := range FunctionGroups {
		for _, f := range g.Funcs {
			m[f] = true
		}
	}
	for _, f := range internalFunctions {
		m[f] = true
	}
	return m
}()

// Operadores aceitos (os do próprio Postgres para tipos comuns).
var allowedOperators = func() map[string]bool {
	m := map[string]bool{}
	for _, op := range strings.Fields(`= <> != < > <= >= + - * / % ^ || |/ ||/ @ & | # ~ << >>
		~~ !~~ ~~* !~~* ~ ~* !~ !~* -> ->> #> #>> @> <@ ? ?| ?& && @@ @? #-`) {
		m[op] = true
	}
	return m
}()

// Tipos aceitos em cast.
var allowedTypes = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.Fields(`bool boolean int2 int4 int8 smallint integer int bigint numeric decimal
		float4 float8 real text varchar bpchar char character date time timetz timestamp timestamptz
		interval json jsonb uuid money inet cidr`) {
		m[t] = true
	}
	return m
}()

var allowedSQLValueFunctions = map[pg_query.SQLValueFunctionOp]bool{
	pg_query.SQLValueFunctionOp_SVFOP_CURRENT_DATE:        true,
	pg_query.SQLValueFunctionOp_SVFOP_CURRENT_TIME:        true,
	pg_query.SQLValueFunctionOp_SVFOP_CURRENT_TIME_N:      true,
	pg_query.SQLValueFunctionOp_SVFOP_CURRENT_TIMESTAMP:   true,
	pg_query.SQLValueFunctionOp_SVFOP_CURRENT_TIMESTAMP_N: true,
	pg_query.SQLValueFunctionOp_SVFOP_LOCALTIME:           true,
	pg_query.SQLValueFunctionOp_SVFOP_LOCALTIME_N:         true,
	pg_query.SQLValueFunctionOp_SVFOP_LOCALTIMESTAMP:      true,
	pg_query.SQLValueFunctionOp_SVFOP_LOCALTIMESTAMP_N:    true,
}

// Nós aceitos dentro de um statement. Qualquer outro é recusado (fail
// closed): uma versão nova do parser com nó novo é barrada até ser tratada.
var allowedNodes = map[protoreflect.Name]bool{
	"select_stmt": true, "res_target": true, "column_ref": true, "a_star": true, "a_const": true,
	"string": true, "integer": true, "float": true, "boolean": true, "bit_string": true, "list": true,
	"range_var": true, "alias": true, "join_expr": true, "range_subselect": true, "range_function": true,
	"a_expr": true, "bool_expr": true, "func_call": true, "type_cast": true, "type_name": true,
	"sub_link": true, "case_expr": true, "case_when": true, "coalesce_expr": true, "min_max_expr": true,
	"null_test": true, "boolean_test": true, "sort_by": true, "window_def": true, "with_clause": true,
	"common_table_expr": true, "a_array_expr": true, "row_expr": true, "a_indirection": true,
	"a_indices": true, "collate_clause": true, "named_arg_expr": true, "sqlvalue_function": true,
	"grouping_set": true, "set_to_default": true, "multi_assign_ref": true, "on_conflict_clause": true,
	"infer_clause": true, "index_elem": true,
}

// Nós aceitos só como raiz.
var rootNodes = map[protoreflect.Name]bool{
	"select_stmt": true, "insert_stmt": true, "update_stmt": true, "delete_stmt": true,
}

// Nomes legíveis dos statements que sempre são barrados.
var stmtNames = map[protoreflect.Name]string{
	"create_stmt": "CREATE TABLE", "drop_stmt": "DROP", "alter_table_stmt": "ALTER TABLE",
	"truncate_stmt": "TRUNCATE", "copy_stmt": "COPY", "call_stmt": "CALL", "do_stmt": "DO",
	"variable_set_stmt": "SET", "variable_show_stmt": "SHOW", "grant_stmt": "GRANT", "grant_role_stmt": "GRANT",
	"vacuum_stmt": "VACUUM", "listen_stmt": "LISTEN", "notify_stmt": "NOTIFY", "unlisten_stmt": "UNLISTEN",
	"prepare_stmt": "PREPARE", "execute_stmt": "EXECUTE", "explain_stmt": "EXPLAIN",
	"transaction_stmt": "BEGIN/COMMIT/ROLLBACK", "lock_stmt": "LOCK", "merge_stmt": "MERGE",
	"create_table_as_stmt": "CREATE TABLE AS", "index_stmt": "CREATE INDEX", "view_stmt": "CREATE VIEW",
	"create_function_stmt": "CREATE FUNCTION", "rename_stmt": "ALTER ... RENAME", "comment_stmt": "COMMENT",
	"declare_cursor_stmt": "DECLARE", "fetch_stmt": "FETCH", "discard_stmt": "DISCARD", "load_stmt": "LOAD",
	"refresh_mat_view_stmt": "REFRESH MATERIALIZED VIEW", "check_point_stmt": "CHECKPOINT", "cluster_stmt": "CLUSTER",
	"reindex_stmt": "REINDEX", "create_role_stmt": "CREATE ROLE", "alter_role_stmt": "ALTER ROLE",
	"createdb_stmt": "CREATE DATABASE", "dropdb_stmt": "DROP DATABASE", "alter_system_stmt": "ALTER SYSTEM",
}

// nodeName devolve o nome do campo oneof preenchido de um Node.
func nodeName(n *pg_query.Node) protoreflect.Name {
	m := n.ProtoReflect()
	od := m.Descriptor().Oneofs().ByName("node")
	fd := m.WhichOneof(od)
	if fd == nil {
		return ""
	}
	return fd.Name()
}

// StmtLabel é o nome legível de um statement raiz.
func StmtLabel(n *pg_query.Node) string {
	name := nodeName(n)
	if s, ok := stmtNames[name]; ok {
		return s
	}
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSuffix(string(name), "_stmt"), "_", " "))
}

// shape faz a checagem estrutural: percorre o AST inteiro por reflexão e
// recusa nós desconhecidos, funções fora da allowlist, operadores e casts
// estranhos, parâmetros, INTO e travas de linha.
type shape struct {
	g      *Guard
	filter bool // validando filtro da política
}

func (sh *shape) walk(n *pg_query.Node) *Denial {
	if n == nil {
		return nil
	}
	return sh.walkMsg(n.ProtoReflect(), false)
}

func (sh *shape) walkRoot(n *pg_query.Node) *Denial {
	name := nodeName(n)
	if !rootNodes[name] {
		return &Denial{Reason: fmt.Sprintf("statement %s não é aceito", StmtLabel(n)), Accepted: "SELECT (query, explain) ou INSERT, UPDATE, DELETE (exec)"}
	}
	return sh.walkMsg(n.ProtoReflect(), true)
}

func (sh *shape) walkMsg(m protoreflect.Message, root bool) *Denial {
	switch v := m.Interface().(type) {
	case *pg_query.Node:
		name := nodeName(v)
		if name == "" {
			return nil
		}
		if !root && (name == "insert_stmt" || name == "update_stmt" || name == "delete_stmt" || name == "merge_stmt") {
			return &Denial{Reason: "escrita dentro de CTE ou subquery não é aceita", Accepted: "CTE só com SELECT; escrita só pelo exec, como statement raiz"}
		}
		if !allowedNodes[name] && !(root && rootNodes[name]) {
			return sh.nodeDenial(name)
		}
	case *pg_query.SelectStmt:
		if v.IntoClause != nil {
			return &Denial{Reason: "SELECT ... INTO cria tabela e não é aceito", Accepted: "SELECT sem INTO"}
		}
		if len(v.LockingClause) > 0 {
			return &Denial{Reason: "FOR UPDATE/FOR SHARE trava linhas e não é aceito", Accepted: "SELECT sem cláusula de trava"}
		}
		if v.LimitOption == pg_query.LimitOption_LIMIT_OPTION_WITH_TIES {
			return &Denial{Reason: "FETCH ... WITH TIES não é aceito", Accepted: "LIMIT n ou FETCH FIRST n ROWS ONLY"}
		}
	case *pg_query.FuncCall:
		if d := sh.checkFunc(v); d != nil {
			return d
		}
	case *pg_query.A_Expr:
		if d := sh.checkOperator(v); d != nil {
			return d
		}
	case *pg_query.TypeName:
		if d := sh.checkType(v); d != nil {
			return d
		}
	case *pg_query.SQLValueFunction:
		if !allowedSQLValueFunctions[v.Op] {
			return &Denial{Reason: "função de sessão não é aceita (current_user, current_schema...)", Accepted: "current_date, current_time, current_timestamp, localtime, localtimestamp"}
		}
	case *pg_query.SubLink:
		if v.SubLinkType == pg_query.SubLinkType_CTE_SUBLINK {
			return &Denial{Reason: "subquery desse tipo não é aceita"}
		}
		if len(v.OperName) > 1 {
			return &Denial{Reason: "operador qualificado não é aceito"}
		}
	case *pg_query.CommonTableExpr:
		if v.SearchClause != nil || v.CycleClause != nil {
			return &Denial{Reason: "SEARCH/CYCLE em CTE não é aceito", Accepted: "CTE simples"}
		}
	case *pg_query.SortBy:
		if len(v.UseOp) > 0 {
			return &Denial{Reason: "ORDER BY ... USING operador não é aceito", Accepted: "ORDER BY coluna ASC|DESC"}
		}
	case *pg_query.CollateClause:
		if len(v.Collname) > 1 {
			return &Denial{Reason: "collation qualificada não é aceita", Accepted: `COLLATE "C" ou outra collation sem schema`}
		}
	case *pg_query.RangeFunction:
		if len(v.Coldeflist) > 0 || v.IsRowsfrom {
			return &Denial{Reason: "ROWS FROM e lista de definição de colunas não são aceitos", Accepted: "função na allowlist no FROM, ex.: generate_series(1, 10) AS g(n)"}
		}
	}

	var denial *Denial
	m.Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			l := val.List()
			for i := 0; i < l.Len(); i++ {
				if denial = sh.walkMsg(l.Get(i).Message(), false); denial != nil {
					return false
				}
			}
		case fd.IsMap():
			denial = &Denial{Reason: "estrutura de AST inesperada"}
			return false
		case fd.Message() != nil:
			if denial = sh.walkMsg(val.Message(), false); denial != nil {
				return false
			}
		}
		return true
	})
	return denial
}

func (sh *shape) nodeDenial(name protoreflect.Name) *Denial {
	switch name {
	case "param_ref":
		return &Denial{Reason: "parâmetros ($1) não são aceitos", Accepted: "SQL completo, com os valores escritos na query"}
	case "locking_clause":
		return &Denial{Reason: "FOR UPDATE/FOR SHARE trava linhas e não é aceito", Accepted: "SELECT sem cláusula de trava"}
	case "into_clause":
		return &Denial{Reason: "SELECT ... INTO cria tabela e não é aceito", Accepted: "SELECT sem INTO"}
	}
	if s, ok := stmtNames[name]; ok {
		return &Denial{Reason: fmt.Sprintf("statement %s não é aceito", s)}
	}
	return &Denial{Reason: fmt.Sprintf("construção SQL não suportada pelo crivo: %s", name), Accepted: "SELECT com JOIN, subquery, CTE, agregação, janela, CASE, cast e funções comuns"}
}

func stringList(nodes []*pg_query.Node) ([]string, bool) {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		s := n.GetString_()
		if s == nil {
			return nil, false
		}
		out = append(out, s.Sval)
	}
	return out, true
}

// FuncName normaliza o nome de uma função: aceita só pg_catalog como schema.
func funcName(fc *pg_query.FuncCall) (string, bool) {
	parts, ok := stringList(fc.Funcname)
	if !ok || len(parts) == 0 || len(parts) > 2 {
		return "", false
	}
	if len(parts) == 2 && parts[0] != "pg_catalog" {
		return "", false
	}
	return parts[len(parts)-1], true
}

func (sh *shape) checkFunc(fc *pg_query.FuncCall) *Denial {
	name, ok := funcName(fc)
	if !ok {
		parts, _ := stringList(fc.Funcname)
		return &Denial{Reason: fmt.Sprintf("função qualificada %q não é aceita", strings.Join(parts, ".")), Accepted: "funções da allowlist sem schema"}
	}
	if policy.BlockedFunction(name) {
		return &Denial{Reason: fmt.Sprintf("função %q é sempre bloqueada", name), Accepted: allowedFunctionsHint()}
	}
	if !sh.g.funcs[name] {
		return &Denial{Reason: fmt.Sprintf("função %q fora da allowlist", name), Accepted: allowedFunctionsHint()}
	}
	if fc.FuncVariadic {
		return &Denial{Reason: "chamada VARIADIC não é aceita", Accepted: "argumentos explícitos"}
	}
	return nil
}

func allowedFunctionsHint() string {
	return "agregação, janela, texto, data, matemática e JSON (veja a lista com o comando policy)"
}

// AllowedFunctionList devolve a allowlist efetiva, ordenada (para o policy).
func (g *Guard) AllowedFunctionList() []string {
	var out []string
	for f := range g.funcs {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func (sh *shape) checkOperator(e *pg_query.A_Expr) *Denial {
	switch e.Kind {
	case pg_query.A_Expr_Kind_AEXPR_BETWEEN, pg_query.A_Expr_Kind_AEXPR_NOT_BETWEEN,
		pg_query.A_Expr_Kind_AEXPR_BETWEEN_SYM, pg_query.A_Expr_Kind_AEXPR_NOT_BETWEEN_SYM:
		return nil
	}
	parts, ok := stringList(e.Name)
	if !ok || len(parts) == 0 || len(parts) > 2 || len(parts) == 2 && parts[0] != "pg_catalog" {
		return &Denial{Reason: "operador qualificado não é aceito", Accepted: "operadores comuns (=, <>, <, >, +, ||, LIKE, ->> ...)"}
	}
	op := parts[len(parts)-1]
	if !allowedOperators[op] {
		return &Denial{Reason: fmt.Sprintf("operador %q não é aceito", op), Accepted: "operadores comuns (=, <>, <, >, +, ||, LIKE, ->> ...)"}
	}
	return nil
}

func (sh *shape) checkType(t *pg_query.TypeName) *Denial {
	parts, ok := stringList(t.Names)
	if !ok || len(parts) == 0 || len(parts) > 2 || len(parts) == 2 && parts[0] != "pg_catalog" {
		return &Denial{Reason: "cast para tipo qualificado não é aceito", Accepted: "cast para tipos comuns (int, numeric, text, date, timestamp, jsonb ...)"}
	}
	name := parts[len(parts)-1]
	if t.Setof || t.PctType || !allowedTypes[name] {
		return &Denial{Reason: fmt.Sprintf("cast para o tipo %q não é aceito", name), Accepted: "int, bigint, numeric, real, text, varchar, boolean, date, time, timestamp, timestamptz, interval, json, jsonb, uuid"}
	}
	return nil
}
