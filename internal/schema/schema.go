// Package schema introspecta o pg_catalog e mantém o cache em disco.
package schema

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// TTL do cache em disco.
const TTL = 10 * time.Minute

const cacheVersion = 1

// Schema é o retrato do catálogo usado para resolver colunas.
type Schema struct {
	Version   int               `json:"version"`
	FetchedAt time.Time         `json:"fetched_at"`
	Source    string            `json:"source"` // hash da URL + schemas
	Tables    map[string]*Table `json:"tables"` // "schema.tabela"
}

// Table descreve uma tabela ou view.
type Table struct {
	Schema      string       `json:"schema"`
	Name        string       `json:"name"`
	Kind        string       `json:"kind"` // table, view, matview, partitioned, foreign
	Comment     string       `json:"comment,omitempty"`
	Columns     []Column     `json:"columns"`
	PrimaryKey  []string     `json:"primary_key,omitempty"`
	ForeignKeys []ForeignKey `json:"foreign_keys,omitempty"`
}

// Column descreve uma coluna.
type Column struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	NotNull bool   `json:"not_null"`
	Comment string `json:"comment,omitempty"`
}

// ForeignKey descreve uma chave estrangeira.
type ForeignKey struct {
	Columns    []string `json:"columns"`
	RefSchema  string   `json:"ref_schema"`
	RefTable   string   `json:"ref_table"`
	RefColumns []string `json:"ref_columns"`
}

// Table devolve a tabela, ou nil.
func (s *Schema) Table(schema, name string) *Table {
	if s == nil {
		return nil
	}
	return s.Tables[schema+"."+name]
}

// TableNames lista as tabelas de um schema, ordenadas.
func (s *Schema) TableNames(schema string) []string {
	var out []string
	for _, t := range s.Tables {
		if t.Schema == schema {
			out = append(out, t.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Column devolve a coluna, ou nil.
func (t *Table) Column(name string) *Column {
	for i := range t.Columns {
		if t.Columns[i].Name == name {
			return &t.Columns[i]
		}
	}
	return nil
}

// ColumnNames lista as colunas na ordem da tabela.
func (t *Table) ColumnNames() []string {
	out := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		out[i] = c.Name
	}
	return out
}

// IsPK diz se a coluna faz parte da chave primária.
func (t *Table) IsPK(col string) bool {
	for _, c := range t.PrimaryKey {
		if c == col {
			return true
		}
	}
	return false
}

// FKOf devolve a chave estrangeira de coluna única que começa na coluna.
func (t *Table) FKOf(col string) *ForeignKey {
	for i, fk := range t.ForeignKeys {
		for _, c := range fk.Columns {
			if c == col {
				return &t.ForeignKeys[i]
			}
		}
	}
	return nil
}

// SourceKey identifica a origem do cache (URL sem senha + schemas).
func SourceKey(connect string, schemas []string) string {
	h := sha256.Sum256([]byte(connect + "|" + strings.Join(schemas, ",")))
	return hex.EncodeToString(h[:8])
}

const tablesQuery = `
SELECT n.nspname, c.relname,
       CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned' WHEN 'v' THEN 'view'
                      WHEN 'm' THEN 'matview' WHEN 'f' THEN 'foreign' END,
       coalesce(obj_description(c.oid, 'pg_class'), '')
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND NOT c.relispartition
ORDER BY 1, 2`

const columnsQuery = `
SELECT n.nspname, c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod),
       a.attnotnull, coalesce(col_description(c.oid, a.attnum), '')
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND NOT c.relispartition
  AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY 1, 2, a.attnum`

const keysQuery = `
SELECT n.nspname, c.relname, k.contype,
       ARRAY(SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY u(attnum, ord)
             JOIN pg_catalog.pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum ORDER BY u.ord),
       coalesce(rn.nspname, ''), coalesce(rc.relname, ''),
       coalesce(ARRAY(SELECT a.attname FROM unnest(k.confkey) WITH ORDINALITY u(attnum, ord)
             JOIN pg_catalog.pg_attribute a ON a.attrelid = k.confrelid AND a.attnum = u.attnum ORDER BY u.ord), '{}')
FROM pg_catalog.pg_constraint k
JOIN pg_catalog.pg_class c ON c.oid = k.conrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_class rc ON rc.oid = k.confrelid
LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
WHERE n.nspname = ANY($1) AND k.contype IN ('p', 'f')
ORDER BY 1, 2, k.conname`

// Fetch lê o catálogo numa transação READ ONLY.
func Fetch(ctx context.Context, conn *pgx.Conn, schemas []string) (*Schema, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	s := &Schema{Version: cacheVersion, FetchedAt: time.Now().UTC(), Tables: map[string]*Table{}}
	rows, err := tx.Query(ctx, tablesQuery, schemas)
	if err != nil {
		return nil, fmt.Errorf("lendo tabelas: %w", err)
	}
	for rows.Next() {
		t := &Table{}
		if err := rows.Scan(&t.Schema, &t.Name, &t.Kind, &t.Comment); err != nil {
			return nil, err
		}
		s.Tables[t.Schema+"."+t.Name] = t
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, columnsQuery, schemas)
	if err != nil {
		return nil, fmt.Errorf("lendo colunas: %w", err)
	}
	for rows.Next() {
		var sch, tbl string
		var c Column
		if err := rows.Scan(&sch, &tbl, &c.Name, &c.Type, &c.NotNull, &c.Comment); err != nil {
			return nil, err
		}
		if t := s.Tables[sch+"."+tbl]; t != nil {
			t.Columns = append(t.Columns, c)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, keysQuery, schemas)
	if err != nil {
		return nil, fmt.Errorf("lendo chaves: %w", err)
	}
	for rows.Next() {
		var sch, tbl, typ, rsch, rtbl string
		var cols, rcols []string
		if err := rows.Scan(&sch, &tbl, &typ, &cols, &rsch, &rtbl, &rcols); err != nil {
			return nil, err
		}
		t := s.Tables[sch+"."+tbl]
		if t == nil {
			continue
		}
		if typ == "p" {
			t.PrimaryKey = cols
		} else {
			t.ForeignKeys = append(t.ForeignKeys, ForeignKey{Columns: cols, RefSchema: rsch, RefTable: rtbl, RefColumns: rcols})
		}
	}
	return s, rows.Err()
}

// CacheDir é a pasta de cache: $XDG_CACHE_HOME/crivo ou ~/.cache/crivo.
func CacheDir() (string, error) {
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "crivo"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "crivo"), nil
}

func cachePath(name string) (string, error) {
	d, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name, "schema.json"), nil
}

// ErrNoCache indica que não há cache utilizável.
var ErrNoCache = errors.New("sem cache de schema")

// LoadCache lê o cache. fresh diz se está dentro do TTL.
func LoadCache(name, source string) (s *Schema, fresh bool, err error) {
	p, err := cachePath(name)
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, ErrNoCache
		}
		return nil, false, err
	}
	s = &Schema{}
	if err := json.Unmarshal(data, s); err != nil || s.Version != cacheVersion || s.Source != source {
		return nil, false, ErrNoCache
	}
	return s, time.Since(s.FetchedAt) < TTL, nil
}

// SaveCache grava o cache (permissão 0600: contém nomes de colunas e comentários).
func SaveCache(name string, s *Schema) error {
	p, err := cachePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ClearCache apaga o cache.
func ClearCache(name string) error {
	p, err := cachePath(name)
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
