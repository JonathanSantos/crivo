// Package pii reconhece, pelo nome da coluna (e da tabela), dados pessoais
// ou segredos e sugere como a política deve tratá-los. É uma heurística de
// nome: não lê dados. Serve para o init já nascer com sugestões e para o
// check avisar quando uma coluna sensível sai sem máscara.
package pii

import (
	"regexp"
	"sort"
	"strings"

	"crivo/internal/policy"
)

// Suggestion é o tratamento sugerido para uma coluna.
type Suggestion struct {
	Column string
	Kind   string // descrição curta: "documento", "e-mail", "segredo"...
	Except bool   // nunca deve sair (except)
	Mask   policy.Mask
}

type rule struct {
	re     *regexp.Regexp
	kind   string
	except bool
	mask   policy.Mask
}

// palavras inteiras separadas por _ (cpf, cpf_cliente, cliente_cpf; não cpfx)
func words(alts string) *regexp.Regexp {
	return regexp.MustCompile(`(^|_)(` + alts + `)(_|$)`)
}

var rules = []rule{
	{words(`senha|password|passwd|pwd|secret|segredo|token|api_?key|apikey|private_?key|salt|otp|pin`), "segredo", true, policy.Mask{}},
	{words(`cartao|card|cc|pan|cvv|cvc`), "cartão", true, policy.Mask{}},
	{words(`cpf|rg|ssn|passaporte|passport|cnh|pis|nis|titulo_eleitor`), "documento", true, policy.Mask{}},
	{words(`cnpj`), "documento de empresa", false, policy.Mask{Mode: policy.MaskLast4}},
	{words(`e?mail|email_\w+`), "e-mail", false, policy.Mask{Mode: policy.MaskEmail}},
	{words(`telefone|fone|celular|phone|mobile|whatsapp|tel`), "telefone", false, policy.Mask{Mode: policy.MaskLast4}},
	{words(`nascimento|data_nascimento|dt_nascimento|nasc|birth|birthdate|birthday|dob`), "data de nascimento", false, policy.Mask{Mode: policy.MaskMonth}},
	{words(`salario|salary|renda|income|remuneracao`), "renda", false, policy.Mask{Mode: policy.MaskBucket, Arg: 1000}},
	{words(`endereco|address|logradouro|rua|street|cep|zip|zipcode|complemento|bairro`), "endereço", false, policy.Mask{Mode: policy.MaskRedact}},
	{words(`ip|ip_address|ipaddr|user_agent|useragent`), "rastro de acesso", false, policy.Mask{Mode: policy.MaskRedact}},
	{words(`nome_completo|full_name|first_name|last_name|sobrenome|nome_social|nome_mae|nome_pai`), "nome de pessoa", false, policy.Mask{Mode: policy.MaskPseudonym}},
}

// tabelas de pessoas: nelas "nome" e "name" também são nome de pessoa
var personTable = words(`clientes?|usuarios?|users?|pessoas?|people|person|funcionarios?|employees?|pacientes?|alunos?|students?|contatos?|contacts?|customers?|membros?|members?|titulares?|dependentes?|motoristas?|drivers?`)

var personName = words(`nome|name`)

// Suggest devolve as sugestões para as colunas da tabela, na ordem das colunas.
func Suggest(table string, columns []string) []Suggestion {
	person := personTable.MatchString(strings.ToLower(table))
	var out []Suggestion
	for _, c := range columns {
		if sug, ok := classify(c, person); ok {
			out = append(out, sug)
		}
	}
	return out
}

func classify(col string, person bool) (Suggestion, bool) {
	lc := strings.ToLower(col)
	for _, r := range rules {
		if r.re.MatchString(lc) {
			m := r.mask
			m.Column = col
			return Suggestion{Column: col, Kind: r.kind, Except: r.except, Mask: m}, true
		}
	}
	if person && personName.MatchString(lc) {
		return Suggestion{Column: col, Kind: "nome de pessoa", Mask: policy.Mask{Column: col, Mode: policy.MaskPseudonym}}, true
	}
	return Suggestion{}, false
}

// ReadRule monta o corpo de regra sugerido (read com except e mask), ou ""
// se não há nada sensível.
func ReadRule(sugs []Suggestion) string {
	var except, masks []string
	for _, s := range sugs {
		if s.Except {
			except = append(except, s.Column)
			continue
		}
		masks = append(masks, s.Column+": "+s.Mask.Text())
	}
	if len(except) == 0 && len(masks) == 0 {
		return ""
	}
	b := "read"
	if len(except) > 0 {
		b += " except(" + strings.Join(except, ", ") + ")"
	}
	if len(masks) > 0 {
		b += " mask(" + strings.Join(masks, ", ") + ")"
	}
	return b
}

// Exposed devolve as colunas sensíveis que a ação de leitura deixa sair sem
// máscara (nem except), em ordem alfabética.
func Exposed(table string, columns []string, read *policy.Action) []Suggestion {
	if read == nil {
		return nil
	}
	var out []Suggestion
	for _, s := range Suggest(table, columns) {
		if !read.AllowsCol(s.Column) {
			continue
		}
		if _, masked := read.MaskFor(s.Column); masked {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Column < out[j].Column })
	return out
}
