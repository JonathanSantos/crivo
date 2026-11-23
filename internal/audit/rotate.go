package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxSize é o tamanho a partir do qual o log é rotacionado; Keep é quantos
// arquivos antigos (.1, .2, ...) ficam.
var (
	MaxSize int64 = 10 << 20
	Keep          = 3
)

// rotate move <name>.jsonl para .1 (e .1 para .2...) quando passa de MaxSize.
func rotate(path string) error {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < MaxSize {
		return nil
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", path, Keep))
	for i := Keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	return os.Rename(path, path+".1")
}

// files devolve o log atual e os rotacionados, do mais antigo ao mais novo.
func files(name string) ([]string, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	base := filepath.Join(dir, name+".jsonl")
	var out []string
	for i := Keep; i >= 1; i-- {
		out = append(out, fmt.Sprintf("%s.%d", base, i))
	}
	return append(out, base), nil
}

// Read devolve as entradas gravadas a partir de since, da mais antiga à mais
// nova, incluindo os arquivos rotacionados. Linhas ilegíveis são ignoradas.
func Read(name string, since time.Time) ([]Entry, error) {
	paths, err := files(name)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, p := range paths {
		f, err := os.Open(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if fi, err := f.Stat(); err == nil && !since.IsZero() && fi.ModTime().Before(since) {
			f.Close()
			continue // o arquivo inteiro é anterior
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			if !e.Time.Before(since) {
				out = append(out, e)
			}
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Usage soma o uso que conta para os limites da política: execuções aceitas
// (query, explain, exec, run, approve; pelo CLI ou pelo MCP) no último minuto
// e linhas lidas ou afetadas desde a meia-noite local.
func Usage(name string, now time.Time) (lastMinute int, rowsToday int64, err error) {
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	since := midnight
	if m := now.Add(-time.Minute); m.Before(since) {
		since = m
	}
	entries, err := Read(name, since)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		if e.Decision != "aceito" || !counts(e.Command) {
			continue
		}
		if !e.Time.Before(now.Add(-time.Minute)) {
			lastMinute++
		}
		if !e.Time.Before(midnight) {
			rowsToday += e.Rows
		}
	}
	return lastMinute, rowsToday, nil
}

func counts(cmd string) bool {
	switch strings.TrimPrefix(cmd, "mcp:") {
	case "query", "explain", "exec", "run", "approve", "describe-sample":
		return true
	}
	return false
}

// Writable confere se o log pode ser gravado (os limites dependem dele).
func Writable(name string) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, name+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}
