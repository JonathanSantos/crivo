// Package audit grava uma linha JSON por execução em ~/.crivo/logs/<name>.jsonl.
// Nunca grava dados do resultado.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Entry é uma linha do log.
type Entry struct {
	Time      time.Time `json:"time"`
	Command   string    `json:"command"`
	SQL       string    `json:"sql,omitempty"`
	Rewritten string    `json:"rewritten,omitempty"`
	Decision  string    `json:"decision"` // aceito, barrado, invalido, erro
	Rules     []string  `json:"rules,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Rows      int64     `json:"rows"`
	DryRun    bool      `json:"dry_run,omitempty"`
	Duration  int64     `json:"duration_ms"`
	Exit      int       `json:"exit"`
}

// Dir é a pasta dos logs.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".crivo", "logs"), nil
}

// Write acrescenta a entrada ao log. Falha de log não interrompe a execução.
func Write(name string, e Entry) error {
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
	defer f.Close()
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC().Truncate(time.Millisecond)
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	return err
}
