package policy

import (
	"strings"
	"testing"
	"time"
)

const gateHeader = "name x\nabout \"x\"\nenv dev\nconnect postgres://u@localhost/x\nsecret keychain\n"

func TestGateDirectives(t *testing.T) {
	p, diags := Parse("x.crivo", gateHeader+"expires 2030-06-15\ncost 25000.5\nrate 30/min\nquota 20000 rows/day\napproval writes\naudit syslog\npedidos read\n")
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	// expires vale até o fim do dia indicado (hora local)
	if want := time.Date(2030, 6, 16, 0, 0, 0, 0, time.Local); !p.Expires.Equal(want) {
		t.Errorf("Expires = %v, esperava %v", p.Expires, want)
	}
	if p.MaxCost != 25000.5 || p.RatePerMinute != 30 || p.QuotaRowsDay != 20000 || !p.ApprovalWrites || !p.AuditSyslog {
		t.Errorf("diretivas não aplicadas: %+v", p)
	}
	// sem as diretivas, tudo desligado
	q, _ := Parse("x.crivo", gateHeader+"pedidos read\n")
	if !q.Expires.IsZero() || q.MaxCost != 0 || q.RatePerMinute != 0 || q.QuotaRowsDay != 0 || q.ApprovalWrites || q.AuditSyslog {
		t.Errorf("portões deveriam nascer desligados: %+v", q)
	}
}

func TestGateDirectivesRejectBadValues(t *testing.T) {
	cases := map[string]string{
		"expires 31/12/2030":   "expires precisa de uma data AAAA-MM-DD",
		"expires 2030-02-30":   "expires precisa de uma data",
		"cost 0":               "cost precisa do custo máximo",
		"cost muito":           "cost precisa",
		"rate 30":              "rate precisa de execuções por minuto",
		"rate 30/hour":         "rate precisa",
		"rate 0/min":           "rate precisa",
		"quota 100":            `quota precisa terminar com "rows/day"`,
		"quota -5 rows/day":    "quota precisa de um inteiro positivo",
		"approval all":         `approval só aceita "writes"`,
		"audit file":           `audit só aceita "syslog"`,
		"expires 2030-01-01 x": "texto inesperado depois de expires",
	}
	for line, want := range cases {
		_, diags := Parse("x.crivo", gateHeader+line+"\npedidos read\n")
		if !diags.HasErrors() || !strings.Contains(diags.Error(), want) {
			t.Errorf("%q: esperava erro com %q, veio:\n%s", line, want, diags.Error())
		}
	}
}

// Os nomes novos de diretiva deixam de valer como nome de tabela (mudança
// incompatível registrada no ADR 0001).
func TestNewDirectiveNamesAreReserved(t *testing.T) {
	for _, name := range []string{"expires", "cost", "rate", "quota", "approval", "audit", "query"} {
		_, diags := Parse("x.crivo", gateHeader+name+" read\n")
		if !diags.HasErrors() {
			t.Errorf("%q como tabela deveria ser lido como diretiva e falhar", name)
		}
	}
}

func TestNewMaskModes(t *testing.T) {
	p, diags := Parse("x.crivo", gateHeader+"clientes read mask(email: email, cpf: last4, nascimento: month, renda: bucket 1000, nome: pseudonym, x: hash)\n")
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	rd := p.Rules[0].Action(Read)
	want := map[string]string{"email": "email", "cpf": "last4", "nascimento": "month", "renda": "bucket 1000", "nome": "pseudonym", "x": "hash"}
	for col, text := range want {
		m, ok := rd.MaskFor(col)
		if !ok || m.Text() != text {
			t.Errorf("máscara de %s = %q (%v), esperava %q", col, m.Text(), ok, text)
		}
	}
	if !p.HasMask(MaskPseudonym) || p.HasMask(MaskRedact) {
		t.Error("HasMask errado")
	}
	if !MaskPseudonym.EqualityStable() || !MaskHash.EqualityStable() || MaskEmail.EqualityStable() || MaskBucket.EqualityStable() {
		t.Error("só hash e pseudonym preservam igualdade")
	}
	for _, bad := range []string{"mask(renda: bucket)", "mask(renda: bucket 0)", "mask(renda: bucket x)", "mask(x: blur)"} {
		_, diags := Parse("x.crivo", gateHeader+"clientes read "+bad+"\n")
		if !diags.HasErrors() {
			t.Errorf("%q deveria falhar", bad)
		}
	}
}
