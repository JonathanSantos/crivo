package schema

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestFromDDLHandWritten(t *testing.T) {
	src, err := os.ReadFile("../../testdata/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	s, warns, err := FromDDL(string(src), []string{"public"})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) > 0 {
		t.Errorf("avisos inesperados: %v", warns)
	}
	want := []string{"audit_log", "clientes", "pagamentos", "pedido_itens", "pedidos", "produtos", "usuarios"}
	if got := s.TableNames("public"); !reflect.DeepEqual(got, want) {
		t.Fatalf("tabelas %v, esperava %v", got, want)
	}
	cli := s.Table("public", "clientes")
	if got := cli.ColumnNames(); !reflect.DeepEqual(got, []string{"id", "nome", "cpf", "email", "telefone", "cidade"}) {
		t.Errorf("colunas de clientes: %v", got)
	}
	if cli.Comment != "Clientes PJ" || !cli.IsPK("id") {
		t.Errorf("clientes: comentário %q, pk %v", cli.Comment, cli.PrimaryKey)
	}
	if c := cli.Column("id"); c.Type != "integer" || !c.NotNull {
		t.Errorf("serial deveria virar integer NOT NULL: %+v", c)
	}
	ped := s.Table("public", "pedidos")
	if fk := ped.FKOf("cliente_id"); fk == nil || fk.RefTable != "clientes" {
		t.Errorf("FK de pedidos.cliente_id: %+v", fk)
	}
	if c := ped.Column("total"); c.Type != "numeric(12,2)" || !c.NotNull {
		t.Errorf("pedidos.total: %+v", c)
	}
	if c := ped.Column("criado_em"); c.Type != "timestamp without time zone" {
		t.Errorf("pedidos.criado_em: %+v", c)
	}
}

// Formato do pg_dump --schema-only: chaves em ALTER TABLE, nomes
// qualificados, SETs e sequências no meio.
func TestFromDDLPgDump(t *testing.T) {
	src := `
SET statement_timeout = 0;
SELECT pg_catalog.set_config('search_path', '', false);
CREATE SCHEMA vendas;
CREATE TABLE vendas.pedidos (
    id integer NOT NULL,
    status character varying(20) NOT NULL,
    tags text[],
    pago_em timestamp(3) with time zone
);
ALTER TABLE vendas.pedidos OWNER TO app;
COMMENT ON TABLE vendas.pedidos IS 'Pedidos';
COMMENT ON COLUMN vendas.pedidos.status IS 'aberto | pago';
CREATE SEQUENCE vendas.pedidos_id_seq AS integer START WITH 1;
CREATE TABLE vendas.itens (id bigint NOT NULL, pedido_id integer);
ALTER TABLE ONLY vendas.pedidos ADD CONSTRAINT pedidos_pkey PRIMARY KEY (id);
ALTER TABLE ONLY vendas.itens
    ADD CONSTRAINT itens_pedido_fk FOREIGN KEY (pedido_id) REFERENCES vendas.pedidos(id);
CREATE VIEW vendas.abertos AS SELECT id, status AS situacao FROM vendas.pedidos;
CREATE VIEW vendas.tudo AS SELECT * FROM vendas.pedidos;
CREATE VIEW vendas.calc AS SELECT id + 1 FROM vendas.pedidos;
CREATE TABLE outro.ignorada (id int);
`
	s, warns, err := FromDDL(src, []string{"vendas"})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.TableNames("vendas"); !reflect.DeepEqual(got, []string{"abertos", "itens", "pedidos", "tudo"}) {
		t.Fatalf("tabelas %v", got)
	}
	if s.Table("outro", "ignorada") != nil {
		t.Error("tabela fora dos schemas da política entrou")
	}
	p := s.Table("vendas", "pedidos")
	if !p.IsPK("id") || p.Comment != "Pedidos" || p.Column("status").Comment != "aberto | pago" {
		t.Errorf("pedidos: %+v", p)
	}
	for col, typ := range map[string]string{"status": "character varying(20)", "tags": "text[]", "pago_em": "timestamp(3) with time zone"} {
		if got := p.Column(col).Type; got != typ {
			t.Errorf("tipo de %s: %q, esperava %q", col, got, typ)
		}
	}
	if fk := s.Table("vendas", "itens").FKOf("pedido_id"); fk == nil || fk.RefSchema != "vendas" || fk.RefTable != "pedidos" {
		t.Errorf("FK de itens: %+v", fk)
	}
	if got := s.Table("vendas", "abertos").ColumnNames(); !reflect.DeepEqual(got, []string{"id", "situacao"}) {
		t.Errorf("view abertos: %v", got)
	}
	if got := s.Table("vendas", "tudo").ColumnNames(); !reflect.DeepEqual(got, []string{"id", "status", "tags", "pago_em"}) {
		t.Errorf("view tudo: %v", got)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "vendas.calc") {
		t.Errorf("esperava um aviso sobre vendas.calc, veio %v", warns)
	}
}

func TestFromDDLInvalid(t *testing.T) {
	if _, _, err := FromDDL("CREATE TABLE (", []string{"public"}); err == nil {
		t.Fatal("DDL inválido deveria falhar")
	}
}
