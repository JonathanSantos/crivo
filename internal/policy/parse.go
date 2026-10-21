package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Severity de um diagnóstico.
type Severity int

const (
	SevError Severity = iota
	SevWarning
)

// Diag é um erro ou aviso com posição.
type Diag struct {
	File     string
	Pos      Pos
	Severity Severity
	Msg      string
}

func (d Diag) String() string {
	kind := "erro"
	if d.Severity == SevWarning {
		kind = "aviso"
	}
	if d.Pos.Line == 0 {
		return fmt.Sprintf("%s: %s: %s", d.File, kind, d.Msg)
	}
	return fmt.Sprintf("%s:%d:%d: %s: %s", d.File, d.Pos.Line, d.Pos.Col, kind, d.Msg)
}

// Diags é uma lista de diagnósticos.
type Diags []Diag

// HasErrors diz se há algum erro.
func (ds Diags) HasErrors() bool {
	for _, d := range ds {
		if d.Severity == SevError {
			return true
		}
	}
	return false
}

// Errors devolve só os erros.
func (ds Diags) Errors() Diags {
	var out Diags
	for _, d := range ds {
		if d.Severity == SevError {
			out = append(out, d)
		}
	}
	return out
}

// Error implementa error com todos os erros, um por linha.
func (ds Diags) Error() string {
	var lines []string
	for _, d := range ds.Errors() {
		lines = append(lines, d.String())
	}
	return strings.Join(lines, "\n")
}

// Sort ordena por posição.
func (ds Diags) Sort() {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Pos.Line != ds[j].Pos.Line {
			return ds[i].Pos.Line < ds[j].Pos.Line
		}
		return ds[i].Pos.Col < ds[j].Pos.Col
	})
}

var directiveNames = map[string]bool{
	"name": true, "about": true, "env": true, "connect": true, "secret": true,
	"schema": true, "limit": true, "timeout": true, "functions": true,
}

// BlockedFunction diz se a função é bloqueada mesmo quando listada em functions.
func BlockedFunction(name string) bool {
	for _, p := range []string{"pg_", "lo_", "dblink", "txid_", "query_to_xml"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	switch name {
	case "set_config", "current_setting", "nextval", "setval", "currval":
		return true
	}
	return false
}

// logical é uma linha lógica: linha física mais continuações, com a posição
// original de cada byte.
type logical struct {
	text string
	pos  []Pos
	doc  string
	line int
}

func (l *logical) at(i int) Pos {
	if i < len(l.pos) {
		return l.pos[i]
	}
	if len(l.pos) == 0 {
		return Pos{Line: l.line, Col: 1}
	}
	last := l.pos[len(l.pos)-1]
	return Pos{Line: last.Line, Col: last.Col + 1}
}

type parser struct {
	p     *Policy
	diags Diags
}

func (ps *parser) errf(pos Pos, format string, args ...any) {
	ps.diags = append(ps.diags, Diag{File: ps.p.File, Pos: pos, Severity: SevError, Msg: fmt.Sprintf(format, args...)})
}

func (ps *parser) warnf(pos Pos, format string, args ...any) {
	ps.diags = append(ps.diags, Diag{File: ps.p.File, Pos: pos, Severity: SevWarning, Msg: fmt.Sprintf(format, args...)})
}

// Parse lê o texto de uma política. Devolve a política (mesmo parcial) e os
// diagnósticos; a política só é utilizável se não houver erros.
func Parse(file, src string) (*Policy, Diags) {
	p := &Policy{
		File:       file,
		Source:     src,
		Secret:     SecretKeychain,
		Schema:     DefaultSchema,
		Limit:      DefaultLimit,
		Timeout:    DefaultTimeout,
		directives: map[string]Pos{},
	}
	ps := &parser{p: p}
	for _, l := range ps.logicalLines(src) {
		ps.parseLogical(l)
	}
	ps.validate()
	ps.diags.Sort()
	return p, ps.diags
}

func (ps *parser) logicalLines(src string) []*logical {
	var out []*logical
	var cur *logical
	var doc []string
	flush := func() {
		if cur != nil {
			out = append(out, cur)
			cur = nil
		}
	}
	lines := strings.Split(src, "\n")
	for i, raw := range lines {
		lineNo := i + 1
		raw = strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(raw)
		switch {
		case trimmed == "":
			flush()
			doc = nil
		case strings.HasPrefix(trimmed, "##"):
			flush()
			doc = append(doc, strings.TrimSpace(strings.TrimPrefix(trimmed, "##")))
		case strings.HasPrefix(trimmed, "#"):
			doc = nil
		case raw[0] == ' ' || raw[0] == '\t':
			start := len(raw) - len(strings.TrimLeft(raw, " \t"))
			if cur == nil {
				ps.errf(Pos{lineNo, start + 1}, "linha de continuação sem regra anterior")
				continue
			}
			if directiveNames[firstWord(cur.text)] {
				ps.errf(Pos{lineNo, start + 1}, "diretivas não aceitam continuação de linha")
				continue
			}
			content := strings.TrimRight(raw[start:], " \t")
			cur.text += " "
			cur.pos = append(cur.pos, Pos{lineNo, start})
			for j := 0; j < len(content); j++ {
				cur.pos = append(cur.pos, Pos{lineNo, start + j + 1})
			}
			cur.text += content
		default:
			flush()
			content := strings.TrimRight(raw, " \t")
			cur = &logical{text: content, line: lineNo}
			for j := 0; j < len(content); j++ {
				cur.pos = append(cur.pos, Pos{lineNo, j + 1})
			}
			if len(doc) > 0 {
				cur.doc = strings.Join(doc, " ")
				doc = nil
			}
		}
	}
	flush()
	return out
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// scanner percorre uma linha lógica.
type scanner struct {
	l *logical
	i int
}

func (s *scanner) skipSpace() {
	for s.i < len(s.l.text) && (s.l.text[s.i] == ' ' || s.l.text[s.i] == '\t') {
		s.i++
	}
}

func (s *scanner) eof() bool {
	s.skipSpace()
	return s.i >= len(s.l.text)
}

func (s *scanner) pos() Pos { return s.l.at(s.i) }

func (s *scanner) peek() byte {
	s.skipSpace()
	if s.i >= len(s.l.text) {
		return 0
	}
	return s.l.text[s.i]
}

func isWordByte(c byte, extra string) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || strings.IndexByte(extra, c) >= 0
}

// word lê uma palavra; extra lista bytes adicionais aceitos.
func (s *scanner) word(extra string) (string, Pos) {
	s.skipSpace()
	start := s.i
	for s.i < len(s.l.text) && isWordByte(s.l.text[s.i], extra) {
		s.i++
	}
	return s.l.text[start:s.i], s.l.at(start)
}

func (s *scanner) peekWord() string {
	save := s.i
	w, _ := s.word("")
	s.i = save
	return w
}

func (s *scanner) accept(c byte) bool {
	if s.peek() == c {
		s.i++
		return true
	}
	return false
}

func (s *scanner) rest() (string, Pos) {
	s.skipSpace()
	p := s.pos()
	r := strings.TrimSpace(s.l.text[s.i:])
	s.i = len(s.l.text)
	return r, p
}

var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

func (ps *parser) ident(s *scanner, what string) (string, Pos, bool) {
	w, pos := s.word("")
	if w == "" {
		ps.errf(pos, "esperava %s", what)
		return "", pos, false
	}
	if w != strings.ToLower(w) {
		ps.errf(pos, "%s %q: use minúsculas (identificadores com maiúsculas não são aceitos na v1)", what, w)
		return "", pos, false
	}
	if !identRe.MatchString(w) {
		ps.errf(pos, "%s inválido: %q", what, w)
		return "", pos, false
	}
	return w, pos, true
}

func (ps *parser) expectEOL(s *scanner, after string) {
	if !s.eof() {
		ps.errf(s.pos(), "texto inesperado depois de %s: %q", after, strings.TrimSpace(s.l.text[s.i:]))
	}
}

func (ps *parser) parseLogical(l *logical) {
	s := &scanner{l: l}
	w := s.peekWord()
	if directiveNames[w] {
		if l.doc != "" {
			ps.warnf(l.at(0), "comentário ## antes de diretiva é ignorado (só vale antes de regra)")
		}
		ps.parseDirective(s)
		return
	}
	ps.parseRule(s)
}

func (ps *parser) parseDirective(s *scanner) {
	p := ps.p
	name, pos := s.word("")
	if prev, dup := p.directives[name]; dup {
		ps.errf(pos, "diretiva %q repetida (primeira na linha %d)", name, prev.Line)
		return
	}
	p.directives[name] = pos
	switch name {
	case "name":
		w, wpos := s.word("-")
		if !nameRe.MatchString(w) {
			ps.errf(wpos, "name precisa ter minúsculas, dígitos e hífen, começando por letra: %q", w)
		} else if len("crivo-"+w) > 64 {
			ps.errf(wpos, "name longo demais: a skill crivo-%s passaria de 64 caracteres", w)
		}
		p.Name = w
		ps.expectEOL(s, "name")
	case "about":
		s.skipSpace()
		str, ok := ps.quoted(s)
		if ok {
			if strings.TrimSpace(str) == "" {
				ps.errf(pos, "about não pode ser vazio")
			}
			p.About = str
		}
		ps.expectEOL(s, "about")
	case "env":
		w, wpos := s.word("")
		switch w {
		case "dev", "preprod", "prod":
			p.Env = w
		default:
			ps.errf(wpos, "env precisa ser dev, preprod ou prod: %q", w)
		}
		ps.expectEOL(s, "env")
	case "connect":
		u, upos := s.rest()
		if strings.ContainsAny(u, " \t") {
			ps.errf(upos, "connect aceita uma única URL, sem espaços")
		}
		ps.checkURL(u, upos)
		p.Connect = u
	case "secret":
		w, wpos := s.word(":")
		switch {
		case w == "keychain":
			p.Secret = SecretKeychain
		case w == "prompt":
			p.Secret = SecretPrompt
		case strings.HasPrefix(w, "env:"):
			v := strings.TrimPrefix(w, "env:")
			if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(v) {
				ps.errf(wpos, "secret env: precisa de um nome de variável: %q", w)
			}
			p.Secret, p.SecretVar = SecretEnv, v
		default:
			ps.errf(wpos, "secret precisa ser keychain, env:VAR ou prompt: %q", w)
		}
		ps.expectEOL(s, "secret")
	case "schema":
		if v, _, ok := ps.ident(s, "schema"); ok {
			if AlwaysBlocked(v, "") {
				ps.errf(pos, "schema %q é de catálogo e sempre bloqueado", v)
			}
			p.Schema = v
		}
		ps.expectEOL(s, "schema")
	case "limit":
		n, npos := s.word("")
		v, err := strconv.Atoi(n)
		if err != nil || v <= 0 {
			ps.errf(npos, "limit precisa de um inteiro positivo: %q", n)
		} else {
			p.Limit = v
		}
		if u, upos := s.word(""); u != "rows" {
			ps.errf(upos, `limit precisa terminar com "rows" (ex.: limit 500 rows)`)
		}
		ps.expectEOL(s, "limit")
	case "timeout":
		w, wpos := s.word(".")
		d, err := time.ParseDuration(w)
		if err != nil || d <= 0 {
			ps.errf(wpos, "timeout precisa de uma duração (ex.: 5s, 1500ms): %q", w)
		} else {
			p.Timeout = d
		}
		ps.expectEOL(s, "timeout")
	case "functions":
		for {
			f, fpos, ok := ps.ident(s, "nome de função")
			if !ok {
				return
			}
			if BlockedFunction(f) {
				ps.errf(fpos, "função %q é sempre bloqueada e não pode ser liberada", f)
			}
			p.Functions = append(p.Functions, f)
			if !s.accept(',') {
				break
			}
		}
		ps.expectEOL(s, "functions")
		ps.warnf(pos, "functions libera funções da aplicação: elas podem ter efeito colateral (o READ ONLY ainda segura escrita em query)")
	}
}

func (ps *parser) quoted(s *scanner) (string, bool) {
	start := s.pos()
	if !s.accept('"') {
		ps.errf(start, `esperava texto entre aspas duplas`)
		return "", false
	}
	var b strings.Builder
	for s.i < len(s.l.text) {
		c := s.l.text[s.i]
		s.i++
		switch c {
		case '\\':
			if s.i < len(s.l.text) {
				b.WriteByte(s.l.text[s.i])
				s.i++
			}
		case '"':
			return b.String(), true
		default:
			b.WriteByte(c)
		}
	}
	ps.errf(start, "aspas não fechadas")
	return "", false
}

func (ps *parser) checkURL(raw string, pos Pos) {
	u, err := url.Parse(raw)
	if err != nil {
		ps.errf(pos, "connect: URL inválida: %v", err)
		return
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		ps.errf(pos, "connect precisa começar com postgres:// (recebido %q)", u.Scheme)
	}
	if u.User != nil {
		if _, has := u.User.Password(); has {
			ps.errf(pos, "connect não pode conter senha; grave-a com: crivo secret set <name>")
		}
	}
	if u.Query().Has("password") {
		ps.errf(pos, "connect não pode conter senha (parâmetro password); grave-a com: crivo secret set <name>")
	}
	if u.Host == "" {
		ps.errf(pos, "connect precisa de host")
	}
	if strings.Trim(u.Path, "/") == "" {
		ps.errf(pos, "connect precisa do nome do banco (ex.: postgres://usuario@host:5432/banco)")
	}
	ps.checkTLS(u, pos)
}

// checkTLS exige TLS com validação de certificado. Sem sslmode, o driver
// usa "prefer" e aceita cair para texto puro, o que expõe a senha na rede.
// Host local é a única exceção, e ainda assim com aviso.
func (ps *parser) checkTLS(u *url.URL, pos Pos) {
	mode := u.Query().Get("sslmode")
	host := u.Hostname()
	local := IsLocalHost(host)
	switch {
	case TLSVerified(mode):
	case mode == "require":
		ps.warnf(pos, "connect: sslmode=require criptografa mas não valida o certificado do servidor; prefira sslmode=verify-full (com sslrootcert=... se a CA for interna)")
	case mode == "":
		if local {
			ps.warnf(pos, "connect sem sslmode: aceito só porque o host %s é local", host)
		} else {
			ps.errf(pos, "connect precisa de sslmode=verify-full (ou verify-ca): sem ele a conexão pode cair para texto puro e expor a senha")
		}
	case mode == "disable" || mode == "allow" || mode == "prefer":
		if local {
			ps.warnf(pos, "connect: sslmode=%s sem TLS; aceito só porque o host %s é local", mode, host)
		} else {
			ps.errf(pos, "connect: sslmode=%s permite conexão sem TLS; use sslmode=verify-full (ou verify-ca)", mode)
		}
	default:
		ps.errf(pos, "connect: sslmode %q desconhecido; use verify-full", mode)
	}
}

// TLSVerified diz se o sslmode valida o certificado do servidor.
func TLSVerified(mode string) bool { return mode == "verify-full" || mode == "verify-ca" }

// TLSEncrypted diz se o sslmode garante ao menos criptografia.
func TLSEncrypted(mode string) bool { return TLSVerified(mode) || mode == "require" }

// IsLocalHost diz se o host é a própria máquina (única exceção ao TLS).
func IsLocalHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return strings.HasSuffix(strings.ToLower(host), ".localhost")
}

func (ps *parser) parseRule(s *scanner) {
	r := &Rule{Pos: s.pos(), Doc: s.l.doc}
	pat, ppos := s.word("*.")
	if pat == "" {
		ps.errf(ppos, "esperava uma diretiva ou o nome de uma tabela")
		return
	}
	if pat != strings.ToLower(pat) {
		ps.errf(ppos, "tabela %q: use minúsculas (identificadores com maiúsculas não são aceitos na v1)", pat)
		return
	}
	if i := strings.IndexByte(pat, '.'); i >= 0 {
		r.Schema, pat = pat[:i], pat[i+1:]
		if !identRe.MatchString(r.Schema) {
			ps.errf(ppos, "schema inválido em %q", r.Schema+"."+pat)
			return
		}
	}
	if !regexp.MustCompile(`^[a-z0-9_*]+$`).MatchString(pat) || !regexp.MustCompile(`^[a-z_*]`).MatchString(pat) {
		ps.errf(ppos, "nome de tabela inválido: %q", pat)
		return
	}
	r.Pattern = pat
	bodyStart := s.i
	if s.eof() {
		ps.errf(s.pos(), "regra de %q sem ações (use deny ou read, insert, update, delete)", pat)
		return
	}
	r.Body = normalizeSpace(s.l.text[bodyStart:])
	if s.peekWord() == "deny" {
		s.word("")
		r.Deny = true
		ps.expectEOL(s, "deny")
		ps.p.Rules = append(ps.p.Rules, r)
		return
	}
	for {
		a := ps.parseAction(s)
		if a == nil {
			return
		}
		r.Actions = append(r.Actions, a)
		if s.eof() {
			break
		}
		if !s.accept(',') {
			ps.errf(s.pos(), "esperava vírgula ou fim da regra, encontrei %q", strings.TrimSpace(s.l.text[s.i:]))
			return
		}
	}
	ps.p.Rules = append(ps.p.Rules, r)
}

func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func (ps *parser) parseAction(s *scanner) *Action {
	w, pos := s.word("")
	a := &Action{Pos: pos, Verb: Verb(w)}
	switch a.Verb {
	case Read, Insert, Update, Delete:
	case "deny":
		ps.errf(pos, "deny precisa ser a única ação da regra")
		return nil
	case "":
		ps.errf(pos, "esperava uma ação (read, insert, update, delete)")
		return nil
	default:
		ps.errf(pos, "ação desconhecida %q (use read, insert, update, delete ou deny)", w)
		return nil
	}
	// colunas
	if s.peek() == '(' {
		cols, ok := ps.identList(s)
		if !ok {
			return nil
		}
		a.Cols = cols
	} else if s.peekWord() == "except" {
		epos := s.pos()
		s.word("")
		if s.peek() != '(' {
			ps.errf(epos, "except precisa de uma lista entre parênteses")
			return nil
		}
		cols, ok := ps.identList(s)
		if !ok {
			return nil
		}
		a.Cols, a.Except = cols, true
	}
	// modificadores
	for {
		if s.eof() || s.peek() == ',' {
			return a
		}
		m, mpos := s.word("")
		switch m {
		case "where":
			if a.Where != "" {
				ps.errf(mpos, "where repetido")
				return nil
			}
			expr, epos, ok := ps.sqlExpr(s)
			if !ok {
				return nil
			}
			a.Where, a.WherePos = expr, epos
		case "max", "limit":
			n, npos := s.word("")
			v, err := strconv.Atoi(n)
			if err != nil || v <= 0 {
				ps.errf(npos, "%s precisa de um inteiro positivo: %q", m, n)
				return nil
			}
			if m == "max" {
				if a.Max != 0 {
					ps.errf(mpos, "max repetido")
				}
				a.Max = v
			} else {
				if a.Limit != 0 {
					ps.errf(mpos, "limit repetido")
				}
				a.Limit = v
			}
		case "mask":
			if !ps.parseMasks(s, a) {
				return nil
			}
		case "":
			ps.errf(mpos, "esperava modificador (where, max, limit, mask), vírgula ou fim da regra; encontrei %q", strings.TrimSpace(s.l.text[s.i:]))
			return nil
		default:
			ps.errf(mpos, "modificador desconhecido %q (use where, max, limit ou mask)", m)
			return nil
		}
	}
}

func (ps *parser) identList(s *scanner) ([]string, bool) {
	open := s.pos()
	s.accept('(')
	var out []string
	for {
		c, _, ok := ps.ident(s, "nome de coluna")
		if !ok {
			return nil, false
		}
		out = append(out, c)
		if s.accept(',') {
			continue
		}
		if s.accept(')') {
			return out, true
		}
		ps.errf(open, "lista de colunas sem ')' de fechamento")
		return nil, false
	}
}

func (ps *parser) parseMasks(s *scanner, a *Action) bool {
	open := s.pos()
	if !s.accept('(') {
		ps.errf(open, "mask precisa de uma lista entre parênteses: mask(coluna: partial)")
		return false
	}
	for {
		c, cpos, ok := ps.ident(s, "nome de coluna")
		if !ok {
			return false
		}
		if !s.accept(':') {
			ps.errf(s.pos(), "esperava ':' depois de %q em mask (ex.: %s: partial)", c, c)
			return false
		}
		m, mpos := s.word("")
		mode := MaskMode(m)
		switch mode {
		case MaskPartial, MaskRedact, MaskHash:
		default:
			ps.errf(mpos, "modo de máscara desconhecido %q (use partial, redact ou hash)", m)
			return false
		}
		a.Masks = append(a.Masks, Mask{Pos: cpos, Column: c, Mode: mode})
		if s.accept(',') {
			continue
		}
		if s.accept(')') {
			return true
		}
		ps.errf(open, "mask sem ')' de fechamento")
		return false
	}
}

// sqlExpr lê até a próxima vírgula de nível zero ou o fim da regra,
// respeitando parênteses e aspas.
func (ps *parser) sqlExpr(s *scanner) (string, Pos, bool) {
	s.skipSpace()
	start := s.i
	pos := s.pos()
	depth := 0
	text := s.l.text
	for s.i < len(text) {
		c := text[s.i]
		switch c {
		case '\'', '"':
			end := s.i + 1
			for end < len(text) {
				if text[end] == c {
					if end+1 < len(text) && text[end+1] == c {
						end += 2
						continue
					}
					break
				}
				end++
			}
			if end >= len(text) {
				ps.errf(s.l.at(s.i), "aspas não fechadas no where")
				return "", pos, false
			}
			s.i = end + 1
			continue
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				ps.errf(s.l.at(s.i), "')' sem '(' correspondente no where")
				return "", pos, false
			}
		case ',':
			if depth == 0 {
				expr := strings.TrimSpace(text[start:s.i])
				if expr == "" {
					ps.errf(pos, "where sem expressão")
					return "", pos, false
				}
				return expr, pos, true
			}
		}
		s.i++
	}
	if depth != 0 {
		ps.errf(pos, "parênteses não fechados no where")
		return "", pos, false
	}
	expr := strings.TrimSpace(text[start:])
	if expr == "" {
		ps.errf(pos, "where sem expressão")
		return "", pos, false
	}
	return expr, pos, true
}

// validate aplica as regras semânticas que não dependem do schema.
func (ps *parser) validate() {
	p := ps.p
	for _, d := range []string{"name", "about", "env", "connect"} {
		if _, ok := p.directives[d]; !ok {
			ps.errf(Pos{}, "diretiva obrigatória ausente: %s", d)
		}
	}
	seen := map[string]*Rule{}
	for _, r := range p.Rules {
		key := p.SchemaOf(r) + "." + r.Pattern
		if prev, dup := seen[key]; dup {
			ps.errf(r.Pos, "regra repetida para %s (primeira na linha %d)", r.Label(), prev.Pos.Line)
		}
		seen[key] = r
		if AlwaysBlocked(p.SchemaOf(r), r.Pattern) && !r.Deny {
			ps.warnf(r.Pos, "%s é de catálogo e sempre bloqueado; a regra não tem efeito", r.Label())
		}
		verbs := map[Verb]bool{}
		for _, a := range r.Actions {
			if verbs[a.Verb] {
				ps.errf(a.Pos, "ação %s repetida na regra de %s", a.Verb, r.Label())
			}
			verbs[a.Verb] = true
			ps.validateAction(r, a)
		}
	}
}

func (ps *parser) validateAction(r *Rule, a *Action) {
	if a.Verb == Delete && a.Cols != nil {
		ps.errf(a.Pos, "delete não aceita lista de colunas")
	}
	if a.Verb == Insert && a.Where != "" {
		ps.errf(a.WherePos, "where não se aplica a insert")
	}
	if a.Verb != Read && len(a.Masks) > 0 {
		ps.errf(a.Pos, "mask só vale para read")
	}
	if a.Verb != Read && a.Limit != 0 {
		ps.errf(a.Pos, "limit só vale para read (para escrita use max)")
	}
	if a.Verb == Read && a.Max != 0 {
		ps.errf(a.Pos, "max só vale para insert, update e delete (para leitura use limit)")
	}
	if a.Cols != nil {
		dup := map[string]bool{}
		for _, c := range a.Cols {
			if dup[c] {
				ps.errf(a.Pos, "coluna %q repetida", c)
			}
			dup[c] = true
		}
	}
	mdup := map[string]bool{}
	for _, m := range a.Masks {
		if mdup[m.Column] {
			ps.errf(m.Pos, "coluna %q mascarada duas vezes", m.Column)
		}
		mdup[m.Column] = true
		if !a.AllowsCol(m.Column) {
			ps.errf(m.Pos, "coluna %q está mascarada mas não está liberada para leitura", m.Column)
		}
	}
	if r.IsPattern() && (a.Cols != nil || len(a.Masks) > 0) {
		ps.warnf(a.Pos, "colunas e máscaras num padrão (%s) valem para todas as tabelas que ele cobre", r.Label())
	}
}
