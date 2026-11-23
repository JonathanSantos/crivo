package sqlguard

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"crivo/internal/policy"
)

// ParamError é um argumento de consulta nomeada inválido (faltando, sobrando
// ou fora do tipo). Quem chama mapeia para erro de configuração.
type ParamError struct{ Msg string }

func (e *ParamError) Error() string { return e.Msg }

var numericRe = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)

// SampleValue é um valor válido do tipo, usado para validar a consulta no
// check (a forma do SQL não depende do valor).
func SampleValue(t policy.ParamType) string {
	switch t {
	case policy.ParamInt:
		return "1"
	case policy.ParamNumeric:
		return "1.5"
	case policy.ParamDate:
		return "2000-01-01"
	case policy.ParamBool:
		return "true"
	}
	return "x"
}

// constFor converte o valor no nó constante do tipo. O valor nunca vira texto
// SQL: ele entra na árvore como constante e o deparse cuida das aspas.
func constFor(p policy.Param, v string) (*pg_query.Node, error) {
	bad := func(want string) error {
		return &ParamError{fmt.Sprintf("parâmetro %s precisa ser %s: %q", p.Name, want, v)}
	}
	str := func(s string) *pg_query.Node {
		return &pg_query.Node{Node: &pg_query.Node_AConst{AConst: &pg_query.A_Const{Val: &pg_query.A_Const_Sval{Sval: &pg_query.String{Sval: s}}}}}
	}
	switch p.Type {
	case policy.ParamInt:
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return nil, bad("um inteiro")
		}
		return &pg_query.Node{Node: &pg_query.Node_AConst{AConst: &pg_query.A_Const{Val: &pg_query.A_Const_Fval{Fval: &pg_query.Float{Fval: v}}}}}, nil
	case policy.ParamNumeric:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || !numericRe.MatchString(v) || math.IsInf(f, 0) {
			return nil, bad("um número (ex.: 12.50)")
		}
		return &pg_query.Node{Node: &pg_query.Node_AConst{AConst: &pg_query.A_Const{Val: &pg_query.A_Const_Fval{Fval: &pg_query.Float{Fval: v}}}}}, nil
	case policy.ParamBool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, bad("true ou false")
		}
		return &pg_query.Node{Node: &pg_query.Node_AConst{AConst: &pg_query.A_Const{Val: &pg_query.A_Const_Boolval{Boolval: &pg_query.Boolean{Boolval: b}}}}}, nil
	case policy.ParamDate:
		if _, err := time.Parse("2006-01-02", v); err != nil {
			return nil, bad("uma data AAAA-MM-DD")
		}
		return &pg_query.Node{Node: &pg_query.Node_TypeCast{TypeCast: &pg_query.TypeCast{
			Arg:      str(v),
			TypeName: &pg_query.TypeName{Names: []*pg_query.Node{{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: "date"}}}}},
		}}}, nil
	case policy.ParamText:
		if strings.ContainsRune(v, 0) {
			return nil, bad("texto sem byte nulo")
		}
		return str(v), nil
	}
	return nil, &ParamError{fmt.Sprintf("parâmetro %s tem tipo desconhecido %q", p.Name, p.Type)}
}

// Bind troca $1..$n da consulta nomeada pelos valores, como constantes na
// árvore, e devolve o SQL. O resultado ainda precisa passar por Check: Bind
// não dá privilégio nenhum à consulta.
func Bind(q *policy.NamedQuery, values map[string]string) (string, error) {
	known := map[string]bool{}
	consts := make([]*pg_query.Node, len(q.Params))
	for i, p := range q.Params {
		known[p.Name] = true
		v, ok := values[p.Name]
		if !ok {
			return "", &ParamError{fmt.Sprintf("falta o parâmetro %s (%s) da consulta %s", p.Name, p.Type, q.Name)}
		}
		c, err := constFor(p, v)
		if err != nil {
			return "", err
		}
		consts[i] = c
	}
	var extra []string
	for k := range values {
		if !known[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return "", &ParamError{fmt.Sprintf("a consulta %s não tem o parâmetro %s", q.Name, strings.Join(extra, ", "))}
	}
	tree, err := pg_query.Parse(q.SQL)
	if err != nil {
		return "", &ParseError{Message: err.Error()}
	}
	var bindErr error
	var walk func(m protoreflect.Message)
	walk = func(m protoreflect.Message) {
		if n, ok := m.Interface().(*pg_query.Node); ok {
			if pr := n.GetParamRef(); pr != nil {
				if pr.Number < 1 || int(pr.Number) > len(consts) {
					bindErr = &ParamError{fmt.Sprintf("a consulta %s usa $%d, mas só tem %d parâmetro(s)", q.Name, pr.Number, len(consts))}
					return
				}
				n.Node = clone(consts[pr.Number-1]).Node
				return
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
	walk(tree.ProtoReflect())
	if bindErr != nil {
		return "", bindErr
	}
	sql, err := pg_query.Deparse(tree)
	if err != nil {
		return "", &ParseError{Message: err.Error()}
	}
	return sql, nil
}

func clone(n *pg_query.Node) *pg_query.Node { return proto.Clone(n).(*pg_query.Node) }

// CheckNamedQueries confere a forma das consultas nomeadas sem schema: um
// único SELECT, $n dentro da lista de parâmetros, todo parâmetro usado.
func CheckNamedQueries(p *policy.Policy) policy.Diags {
	var out policy.Diags
	errf := func(pos policy.Pos, sev policy.Severity, format string, a ...any) {
		out = append(out, policy.Diag{File: p.File, Pos: pos, Severity: sev, Msg: fmt.Sprintf(format, a...)})
	}
	for _, q := range p.Queries {
		tree, err := pg_query.Parse(q.SQL)
		if err != nil {
			errf(q.SQLPos, policy.SevError, "query %s: SQL inválido: %v", q.Name, err)
			continue
		}
		if len(tree.Stmts) != 1 || tree.Stmts[0].Stmt.GetSelectStmt() == nil {
			errf(q.SQLPos, policy.SevError, "query %s precisa ser um único SELECT (consultas nomeadas são só leitura)", q.Name)
			continue
		}
		used := map[int32]bool{}
		var walk func(m protoreflect.Message)
		walk = func(m protoreflect.Message) {
			if pr, ok := m.Interface().(*pg_query.ParamRef); ok {
				used[pr.Number] = true
				return
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
		walk(tree.ProtoReflect())
		var nums []int
		for n := range used {
			nums = append(nums, int(n))
		}
		sort.Ints(nums)
		for _, n := range nums {
			if n < 1 || n > len(q.Params) {
				errf(q.SQLPos, policy.SevError, "query %s usa $%d, mas declara %d parâmetro(s)", q.Name, n, len(q.Params))
			}
		}
		for i, prm := range q.Params {
			if !used[int32(i+1)] {
				errf(q.Pos, policy.SevWarning, "query %s: o parâmetro %s ($%d) não é usado no SQL", q.Name, prm.Name, i+1)
			}
		}
	}
	return out
}

// SampleValues monta valores válidos para todos os parâmetros da consulta.
func SampleValues(q *policy.NamedQuery) map[string]string {
	out := map[string]string{}
	for _, p := range q.Params {
		out[p.Name] = SampleValue(p.Type)
	}
	return out
}
