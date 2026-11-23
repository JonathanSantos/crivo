package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// isolate aponta HOME (e USERPROFILE, lido no Windows) para uma pasta
// temporária: os testes nunca escrevem no ~/.crivo de verdade.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		out = append(out, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDirIsUnderHomeCrivoLogs(t *testing.T) {
	home := isolate(t)
	got, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".crivo", "logs"); got != want {
		t.Fatalf("Dir() = %q, quero %q", got, want)
	}
}

func TestDirFailsWithoutHome(t *testing.T) {
	// Sem pasta pessoal não há onde gravar: o erro precisa subir em vez de
	// o log ir parar no diretório corrente.
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if _, err := Dir(); err == nil {
		t.Fatal("Dir() sem HOME deveria falhar")
	}
	if err := Write("dev", Entry{Command: "query"}); err == nil {
		t.Fatal("Write() sem HOME deveria falhar")
	}
}

func TestWriteAppendsOneJSONLinePerCall(t *testing.T) {
	home := isolate(t)
	first := Entry{
		Time:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Command:   "exec",
		SQL:       "update pedidos set status = 'x' where id = 1",
		Rewritten: "UPDATE pedidos SET status = 'x' WHERE id = 1",
		Decision:  "aceito",
		Rules:     []string{"pedidos", "policy:16"},
		Reason:    "dentro da regra",
		Rows:      1,
		DryRun:    true,
		Duration:  42,
		Exit:      0,
	}
	second := Entry{
		Time:     time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC),
		Command:  "query",
		SQL:      "select * from clientes",
		Decision: "barrado",
		Reason:   "coluna mascarada",
		Exit:     2,
	}
	for _, e := range []Entry{first, second} {
		if err := Write("dev", e); err != nil {
			t.Fatal(err)
		}
	}

	lines := readLines(t, filepath.Join(home, ".crivo", "logs", "dev.jsonl"))
	if len(lines) != 2 {
		t.Fatalf("esperava 2 linhas, veio %d", len(lines))
	}
	for i, want := range []Entry{first, second} {
		var got Entry
		if err := json.Unmarshal(lines[i], &got); err != nil {
			t.Fatalf("linha %d não é JSON: %v\n%s", i+1, err, lines[i])
		}
		if !got.Time.Equal(want.Time) {
			t.Errorf("linha %d: time %v, quero %v", i+1, got.Time, want.Time)
		}
		got.Time, want.Time = time.Time{}, time.Time{}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("linha %d:\nobtido %+v\nquero  %+v", i+1, got, want)
		}
	}
}

func TestWriteKeepsLogsSeparatedByName(t *testing.T) {
	// Cada política tem seu próprio arquivo; um log não pode vazar no outro.
	home := isolate(t)
	if err := Write("dev", Entry{Command: "query", Decision: "aceito"}); err != nil {
		t.Fatal(err)
	}
	if err := Write("staging", Entry{Command: "exec", Decision: "barrado"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".crivo", "logs")
	for name, cmd := range map[string]string{"dev": "query", "staging": "exec"} {
		lines := readLines(t, filepath.Join(dir, name+".jsonl"))
		if len(lines) != 1 {
			t.Fatalf("%s: esperava 1 linha, veio %d", name, len(lines))
		}
		var e Entry
		if err := json.Unmarshal(lines[0], &e); err != nil {
			t.Fatal(err)
		}
		if e.Command != cmd {
			t.Errorf("%s: command %q, quero %q", name, e.Command, cmd)
		}
	}
}

func TestWriteFillsZeroTimeWithNowInUTCMilliseconds(t *testing.T) {
	home := isolate(t)
	before := time.Now().Truncate(time.Millisecond)
	if err := Write("dev", Entry{Command: "query"}); err != nil {
		t.Fatal(err)
	}
	after := time.Now()

	lines := readLines(t, filepath.Join(home, ".crivo", "logs", "dev.jsonl"))
	var raw struct {
		Time string `json:"time"`
	}
	if err := json.Unmarshal(lines[0], &raw); err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339Nano, raw.Time)
	if err != nil {
		t.Fatal(err)
	}
	if got.Before(before) || got.After(after) {
		t.Fatalf("time %v fora de [%v, %v]", got, before, after)
	}
	if _, off := got.Zone(); off != 0 || raw.Time[len(raw.Time)-1] != 'Z' {
		t.Errorf("time %q não está em UTC", raw.Time)
	}
	if got.Nanosecond()%int(time.Millisecond) != 0 {
		t.Errorf("time %q tem precisão abaixo de milissegundo", raw.Time)
	}
}

func TestWriteNormalizesGivenTimeToUTCMilliseconds(t *testing.T) {
	// Hora local com nanossegundos vira UTC truncado: o log fica comparável
	// entre máquinas e sem ruído de precisão.
	home := isolate(t)
	zone := time.FixedZone("BRT", -3*60*60)
	in := time.Date(2026, 5, 6, 7, 8, 9, 123456789, zone)
	if err := Write("dev", Entry{Time: in, Command: "query"}); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, filepath.Join(home, ".crivo", "logs", "dev.jsonl"))
	var raw struct {
		Time string `json:"time"`
	}
	if err := json.Unmarshal(lines[0], &raw); err != nil {
		t.Fatal(err)
	}
	if want := "2026-05-06T10:08:09.123Z"; raw.Time != want {
		t.Fatalf("time %q, quero %q", raw.Time, want)
	}
}

func TestWriteOmitsEmptyOptionalFields(t *testing.T) {
	// Campos opcionais vazios somem da linha; rows, duration_ms e exit
	// ficam sempre, mesmo zerados, porque quem lê o log conta com eles.
	home := isolate(t)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := Write("dev", Entry{Time: at, Command: "query", Decision: "invalido"}); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, filepath.Join(home, ".crivo", "logs", "dev.jsonl"))
	want := `{"time":"2026-01-02T03:04:05Z","command":"query","decision":"invalido","rows":0,"duration_ms":0,"exit":0}`
	if string(lines[0]) != want {
		t.Fatalf("obtido %s\nquero  %s", lines[0], want)
	}
}

func TestWriteCreatesPrivateDirAndFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissões Unix não se aplicam no Windows")
	}
	home := isolate(t)
	if err := Write("dev", Entry{Command: "query"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".crivo", "logs")
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("pasta com permissão %o, quero 700", got)
	}
	fi, err := os.Stat(filepath.Join(dir, "dev.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("arquivo com permissão %o, quero 600", got)
	}
}
