package output

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// Cada linha do JSON é um objeto; com colunas de mesmo nome (SELECT a.id,
// b.id) a segunda chave apagava a primeira e o valor sumia sem aviso.
func TestJSONKeepsDuplicateColumns(t *testing.T) {
	s := func(v string) *string { return &v }
	r := &Rows{
		Columns: []string{"id", "id", "id_2", "id"},
		Types:   []uint32{23, 23, 23, 23},
		Values:  [][]*string{{s("1"), s("2"), s("3"), s("4")}},
	}
	var buf bytes.Buffer
	if err := Write(&buf, JSON, r); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Columns []string         `json:"columns"`
		Rows    []map[string]int `json:"rows"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	wantCols := []string{"id", "id_3", "id_2", "id_4"} // id_2 já existe: a repetição pula para id_3
	if !reflect.DeepEqual(got.Columns, wantCols) {
		t.Errorf("columns = %v, esperava %v", got.Columns, wantCols)
	}
	want := map[string]int{"id": 1, "id_3": 2, "id_2": 3, "id_4": 4}
	if len(got.Rows) != 1 || !reflect.DeepEqual(got.Rows[0], want) {
		t.Errorf("rows = %v, esperava %v", got.Rows, want)
	}
}

func TestUniqueKeysLeavesDistinctNamesAlone(t *testing.T) {
	in := []string{"a", "b", "c"}
	if got := uniqueKeys(in); !reflect.DeepEqual(got, in) {
		t.Errorf("uniqueKeys(%v) = %v", in, got)
	}
}
