package pii

import (
	"testing"

	"crivo/internal/policy"
)

func TestSuggest(t *testing.T) {
	cases := []struct {
		table, col string
		want       string // "" sem sugestão; "except"; ou o modo da máscara
	}{
		{"clientes", "cpf", "except"},
		{"clientes", "cpf_titular", "except"},
		{"usuarios", "senha_hash", "except"},
		{"api", "api_key", "except"},
		{"pagamentos", "cartao_numero", "except"},
		{"empresas", "cnpj", "last4"},
		{"clientes", "email", "email"},
		{"clientes", "email_secundario", "email"},
		{"contatos", "telefone", "last4"},
		{"clientes", "celular", "last4"},
		{"pessoas", "data_nascimento", "month"},
		{"funcionarios", "salario", "bucket 1000"},
		{"clientes", "endereco", "redact"},
		{"clientes", "cep", "redact"},
		{"acessos", "ip", "redact"},
		{"clientes", "nome", "pseudonym"}, // tabela de pessoas
		{"produtos", "nome", ""},          // nome de produto não é dado pessoal
		{"pedidos", "nome_completo", "pseudonym"},
		{"pedidos", "status", ""},
		{"hoteis", "hotel_id", ""}, // "tel" só como palavra inteira
		{"logs", "pinned", ""},     // "pin" só como palavra inteira
		{"produtos", "descricao_email", "email"},
	}
	for _, c := range cases {
		sugs := Suggest(c.table, []string{c.col})
		got := ""
		if len(sugs) == 1 {
			if sugs[0].Except {
				got = "except"
			} else {
				got = sugs[0].Mask.Text()
			}
		}
		if got != c.want {
			t.Errorf("%s.%s: %q, esperava %q", c.table, c.col, got, c.want)
		}
	}
}

func TestReadRule(t *testing.T) {
	got := ReadRule(Suggest("clientes", []string{"id", "nome", "cpf", "email", "telefone", "cidade"}))
	if want := "read except(cpf) mask(nome: pseudonym, email: email, telefone: last4)"; got != want {
		t.Errorf("ReadRule = %q, esperava %q", got, want)
	}
	if ReadRule(Suggest("produtos", []string{"id", "nome", "preco"})) != "" {
		t.Error("tabela sem dado sensível não ganha sugestão")
	}
	// a sugestão é uma regra válida da linguagem
	p, diags := policy.Parse("x.crivo", "name x\nabout \"x\"\nenv dev\nconnect postgres://u@localhost/x\nsecret keychain\nclientes "+got+"\n")
	if diags.HasErrors() || len(p.Rules) != 1 {
		t.Fatalf("sugestão inválida: %s", diags.Error())
	}
}

func TestExposed(t *testing.T) {
	cols := []string{"id", "nome", "cpf", "email", "telefone", "rg"}
	p, _ := policy.Parse("x.crivo", "name x\nabout \"x\"\nenv dev\nconnect postgres://u@localhost/x\nsecret keychain\nclientes read except(cpf) mask(email: partial)\n")
	var got []string
	for _, s := range Exposed("clientes", cols, p.Rules[0].Action(policy.Read)) {
		got = append(got, s.Column)
	}
	// cpf está no except, email mascarado; nome, rg e telefone saem nus
	if len(got) != 3 || got[0] != "nome" || got[1] != "rg" || got[2] != "telefone" {
		t.Errorf("Exposed = %v", got)
	}
	if Exposed("clientes", cols, nil) != nil {
		t.Error("sem read nada é exposto")
	}
}
