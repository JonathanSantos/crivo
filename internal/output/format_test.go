package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTableAlignsByRuneWidth(t *testing.T) {
	// Largura em runas: "ação" ocupa 4 colunas, não 6 bytes. NULL e escapes
	// entram na largura como são impressos.
	var b bytes.Buffer
	err := Write(&b, Table, &Rows{
		Columns: []string{"id", "nome", "obs"},
		Values: [][]*string{
			{s("1"), s("ação"), nil},
			{s("10"), s("x"), s("a\tb")},
		},
		Footer: ReadFooter(2, false, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "id | nome | obs\n" +
		"---+------+-----\n" +
		"1  | ação | NULL\n" +
		"10 | x    | a\\tb\n" +
		"-- 2 linhas\n"
	if b.String() != want {
		t.Fatalf("obtido:\n%s\nquero:\n%s", b.String(), want)
	}
}

func TestTableWithoutColumnsPrintsOnlyFooter(t *testing.T) {
	// Escrita sem RETURNING: não há cabeçalho, só o rodapé.
	var b bytes.Buffer
	if err := Write(&b, Table, &Rows{Footer: WriteFooter(3, false)}); err != nil {
		t.Fatal(err)
	}
	if want := "-- 3 linhas afetadas\n"; b.String() != want {
		t.Fatalf("obtido %q, quero %q", b.String(), want)
	}
}

func TestTableCutAt256KBReportsRowsShown(t *testing.T) {
	var rows [][]*string
	for i := 0; i < 300; i++ {
		rows = append(rows, []*string{s(strings.Repeat("y", 1500))})
	}
	var b bytes.Buffer
	if err := Write(&b, Table, &Rows{Columns: []string{"v"}, Values: rows, Footer: ReadFooter(300, true, false)}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if b.Len() > MaxTotal+500 {
		t.Fatalf("teto total não aplicado: %d bytes", b.Len())
	}
	shown := strings.Count(out, strings.Repeat("y", 1500)+"\n")
	// O número na mensagem precisa bater com as linhas realmente impressas.
	msg := fmt.Sprintf("-- saída cortada em 256 KB depois de %d de 300 linhas; selecione menos colunas ou agregue\n", shown)
	if shown == 0 || shown == 300 || !strings.Contains(out, msg) {
		t.Fatalf("mensagem de corte ausente ou com contagem errada (%d linhas impressas)", shown)
	}
	if !strings.HasSuffix(out, msg+"-- 300 linhas (truncado: refine o filtro ou agregue)\n") {
		t.Fatal("rodapé não vem depois da mensagem de corte")
	}
}

func TestJSONTypesByOID(t *testing.T) {
	// Números, booleanos e json saem como valores JSON nativos; o resto
	// como string. "<" não é escapado: quem lê é um modelo, não um browser.
	var b bytes.Buffer
	err := Write(&b, JSON, &Rows{
		Columns: []string{"id", "preco", "ativo", "dados", "txt", "nada"},
		Types:   []uint32{20, 1700, 16, 3802, 25, 23},
		Values:  [][]*string{{s("42"), s("1.50"), s("t"), s(`{"a": [1, 2]}`), s("<b>"), nil}},
		Footer:  ReadFooter(1, false, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"columns":["id","preco","ativo","dados","txt","nada"],"rows":[{"ativo":true,"dados":{"a":[1,2]},"id":42,"nada":null,"preco":1.50,"txt":"<b>"}],"footer":"1 linha"}` + "\n"
	if b.String() != want {
		t.Fatalf("obtido %s\nquero  %s", b.String(), want)
	}
}

func TestJSONEmitsNativeValuesOnlyForValidTypedCells(t *testing.T) {
	long := strings.Repeat("9", MaxValue+10)
	cases := []struct {
		name string
		oid  uint32
		in   *string
		want string // valor JSON exato da célula
	}{
		{"int2", 21, s("-7"), `-7`},
		{"int4", 23, s("7"), `7`},
		{"oid", 26, s("16384"), `16384`},
		{"float4", 700, s("1.5"), `1.5`},
		{"float8", 701, s("-2.25e-10"), `-2.25e-10`},
		// numeric grande sai byte a byte, sem passar por float64.
		{"numeric big", 1700, s("123456789012345678901234567890.000001"), `123456789012345678901234567890.000001`},
		// Valores que não são JSON válido continuam string.
		{"numeric NaN", 1700, s("NaN"), `"NaN"`},
		{"float8 Infinity", 701, s("Infinity"), `"Infinity"`},
		{"bool true", 16, s("t"), `true`},
		{"bool false", 16, s("f"), `false`},
		{"json", 114, s(`[1, {"b": null}]`), `[1,{"b":null}]`},
		{"jsonb scalar", 3802, s(`"x"`), `"x"`},
		{"jsonb invalid", 3802, s(`{oops`), `"{oops"`},
		{"json invalid", 114, s(`not json`), `"not json"`},
		{"text", 25, s("42"), `"42"`},
		{"null numeric", 20, nil, `null`},
		{"null bool", 16, nil, `null`},
		// Valor cortado em 2 KB não é mais um número: vira string com o aviso.
		{"numeric clipped", 1700, &long, fmt.Sprintf("%q", long[:MaxValue]+"…(+10 bytes)")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := Write(&b, JSON, &Rows{Columns: []string{"v"}, Types: []uint32{tc.oid}, Values: [][]*string{{tc.in}}}); err != nil {
				t.Fatal(err)
			}
			want := `{"columns":["v"],"rows":[{"v":` + tc.want + `}]}` + "\n"
			if b.String() != want {
				t.Fatalf("obtido %s\nquero  %s", b.String(), want)
			}
		})
	}
}

func TestJSONToleratesMismatchedLengths(t *testing.T) {
	// Sem tipo para a coluna: string. Valor sem coluna: descartado.
	var b bytes.Buffer
	err := Write(&b, JSON, &Rows{
		Columns: []string{"a", "b"},
		Types:   []uint32{23},
		Values:  [][]*string{{s("1"), s("2"), s("extra")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"columns":["a","b"],"rows":[{"a":1,"b":"2"}]}` + "\n"
	if b.String() != want {
		t.Fatalf("obtido %s\nquero  %s", b.String(), want)
	}
}

func TestJSONEmptyResultHasEmptyRowsArray(t *testing.T) {
	// "rows": [] e não null: o modelo não precisa tratar dois casos.
	var b bytes.Buffer
	if err := Write(&b, JSON, &Rows{Columns: []string{"id"}, Footer: ReadFooter(0, false, false)}); err != nil {
		t.Fatal(err)
	}
	want := `{"columns":["id"],"rows":[],"footer":"0 linhas"}` + "\n"
	if b.String() != want {
		t.Fatalf("obtido %s\nquero  %s", b.String(), want)
	}
}

func TestJSONTruncatesPastMaxTotal(t *testing.T) {
	var rows [][]*string
	for i := 0; i < 300; i++ {
		rows = append(rows, []*string{s(strings.Repeat("y", 1500))})
	}
	var b bytes.Buffer
	if err := Write(&b, JSON, &Rows{Columns: []string{"v"}, Types: []uint32{25}, Values: rows, Footer: "x"}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Rows      []map[string]any `json:"rows"`
		Footer    string           `json:"footer"`
		Truncated *bool            `json:"output_truncated"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("saída não é JSON válido: %v", err)
	}
	if got.Truncated == nil || !*got.Truncated {
		t.Fatal("output_truncated ausente")
	}
	// Só entram linhas cujo total acumulado cabe em MaxTotal.
	if want := MaxTotal / 1500; len(got.Rows) != want {
		t.Errorf("%d linhas no JSON, quero %d", len(got.Rows), want)
	}
	if got.Footer != "x" {
		t.Errorf("rodapé %q perdido no corte", got.Footer)
	}

	// Abaixo do teto, a flag nem aparece.
	b.Reset()
	if err := Write(&b, JSON, &Rows{Columns: []string{"v"}, Values: rows[:10]}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "output_truncated") {
		t.Error("output_truncated presente sem corte")
	}
}

func TestMessageJSONUsesNullForEmptyOptionalFields(t *testing.T) {
	cases := []struct {
		name string
		m    Message
		want string
	}{
		{
			name: "only required",
			m:    Message{Title: "erro do banco", Reason: "canceling statement due to statement timeout", Code: ExitDB},
			want: `{"aceito":null,"codigo":4,"dica":null,"erro":"erro do banco","motivo":"canceling statement due to statement timeout","ref":null,"regra":null}`,
		},
		{
			name: "all fields",
			m: Message{Title: "barrado pelo crivo", Rule: "pedidos  read, update(status)", RuleRef: "policy:16",
				Reason: `coluna "total" <não> pode ser alterada`, Accepted: "status", Hint: "rode: crivo explain", Code: ExitDenied},
			want: `{"aceito":"status","codigo":2,"dica":"rode: crivo explain","erro":"barrado pelo crivo","motivo":"coluna \"total\" <não> pode ser alterada","ref":"policy:16","regra":"pedidos  read, update(status)"}`,
		},
		// Motivo vazio continua string vazia: é campo obrigatório.
		{
			name: "empty reason",
			m:    Message{Title: "SQL inválido", Code: ExitParse},
			want: `{"aceito":null,"codigo":3,"dica":null,"erro":"SQL inválido","motivo":"","ref":null,"regra":null}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			WriteMessage(&b, tc.m, true)
			if b.String() != tc.want+"\n" {
				t.Fatalf("obtido %s\nquero  %s", b.String(), tc.want)
			}
		})
	}
}

func TestMessageTextOmitsEmptyLines(t *testing.T) {
	cases := []struct {
		name string
		m    Message
		want string
	}{
		{
			name: "reason and hint",
			m:    Message{Title: "senha ausente", Reason: "senha não encontrada no keychain", Hint: "rode: crivo secret set dev", Code: ExitConfig},
			want: "✗ senha ausente\n  motivo  senha não encontrada no keychain\n  dica    rode: crivo secret set dev\n",
		},
		{
			// Regra sem referência: sem o "(...)" vazio no fim.
			name: "rule without ref",
			m:    Message{Title: "barrado pelo crivo", Rule: "clientes  read", Reason: "escrita não permitida"},
			want: "✗ barrado pelo crivo\n  regra   clientes  read\n  motivo  escrita não permitida\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			WriteMessage(&b, tc.m, false)
			if b.String() != tc.want {
				t.Fatalf("obtido %q\nquero  %q", b.String(), tc.want)
			}
		})
	}
}
