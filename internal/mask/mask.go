// Package mask aplica as máscaras da política (partial, redact, hash, email,
// last4, month, bucket e pseudonym) a valores de saída.
package mask

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"crivo/internal/policy"
)

// Masker aplica máscaras. O hash usa uma chave aleatória por execução: é
// estável dentro da execução (permite agrupar e comparar linhas) mas não
// permite confirmar um palpite (ex.: o hash de um email conhecido) entre
// execuções.
type Masker struct {
	key    []byte
	pseudo []byte // chave persistente do pseudonym; nil: pseudonym sai ***
}

// New cria um Masker com chave nova.
func New() *Masker {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return &Masker{key: k}
}

// WithPseudonymKey liga o modo pseudonym com a chave persistente da política.
func (m *Masker) WithPseudonymKey(key []byte) *Masker {
	m.pseudo = key
	return m
}

// Apply mascara um valor de texto (modos sem argumento).
func (m *Masker) Apply(mode policy.MaskMode, v string) string {
	return m.ApplyMask(policy.Mask{Mode: mode}, v)
}

// ApplyMask mascara um valor conforme a máscara da política. Qualquer modo
// desconhecido, argumento inválido ou valor que o modo não entende sai como
// *** (falha fechado).
func (m *Masker) ApplyMask(pm policy.Mask, v string) string {
	switch pm.Mode {
	case policy.MaskRedact:
		return "***"
	case policy.MaskHash:
		h := hmac.New(sha256.New, m.key)
		h.Write([]byte(v))
		return "h:" + hex.EncodeToString(h.Sum(nil))[:6]
	case policy.MaskPartial:
		return Partial(v)
	case policy.MaskEmail:
		return Email(v)
	case policy.MaskLast4:
		return Last4(v)
	case policy.MaskMonth:
		return Month(v)
	case policy.MaskBucket:
		return Bucket(v, pm.Arg)
	case policy.MaskPseudonym:
		if len(m.pseudo) == 0 {
			return "***"
		}
		h := hmac.New(sha256.New, m.pseudo)
		h.Write([]byte(v))
		return "p:" + strings.ToLower(base32.StdEncoding.EncodeToString(h.Sum(nil))[:8])
	}
	return "***"
}

// Email mantém só o que vem depois do primeiro @: ana@empresa.com.br →
// ***@empresa.com.br. É o primeiro (e não o último) para bater com
// split_part(email, '@', 2), que o guard aceita como derivação visível.
func Email(v string) string {
	i := strings.IndexByte(v, '@')
	if i <= 0 || i == len(v)-1 {
		return "***"
	}
	return "***" + v[i:]
}

// Last4 troca por * todo caractere alfanumérico menos os 4 últimos,
// mantendo a pontuação: 123.456.789-01 → ***.***.*89-01.
func Last4(v string) string {
	total := 0
	for _, c := range v {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			total++
		}
	}
	if total <= 4 {
		return "***"
	}
	var b strings.Builder
	seen := 0
	for _, c := range v {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			b.WriteRune(c)
			continue
		}
		seen++
		if seen > total-4 {
			b.WriteRune(c)
		} else {
			b.WriteByte('*')
		}
	}
	return b.String()
}

// Month reduz uma data ou timestamp (AAAA-MM-DD...) a AAAA-MM.
func Month(v string) string {
	if len(v) >= 10 && v[4] == '-' && v[7] == '-' {
		if _, err := strconv.Atoi(v[:4]); err == nil {
			if mm, err := strconv.Atoi(v[5:7]); err == nil && mm >= 1 && mm <= 12 {
				return v[:7]
			}
		}
	}
	return "***"
}

// Bucket troca o número pela faixa de tamanho size que o contém:
// 1890.50 com 100 → 1800..1900.
func Bucket(v string, size int) string {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || size <= 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return "***"
	}
	lo := math.Floor(f/float64(size)) * float64(size)
	return fmt.Sprintf("%s..%s", strconv.FormatFloat(lo, 'f', -1, 64), strconv.FormatFloat(lo+float64(size), 'f', -1, 64))
}

// ErrNoPseudonymKey indica que a chave do pseudonym não pôde ser lida nem criada.
var ErrNoPseudonymKey = errors.New("chave do pseudonym indisponível")

// PseudonymKey lê (ou cria, na primeira vez) a chave do pseudonym da
// política em ~/.crivo/keys/<name>.key, com permissão 0600. Ela fica na
// máquina: os pseudônimos são estáveis entre execuções aqui, e só aqui.
func PseudonymKey(name string) ([]byte, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPseudonymKey, err)
	}
	dir := filepath.Join(home, ".crivo", "keys")
	path := filepath.Join(dir, name+".key")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) < 32 {
			return nil, fmt.Errorf("%w: %s está corrompida", ErrNoPseudonymKey, path)
		}
		return b, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPseudonymKey, err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPseudonymKey, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		// outra execução criou ao mesmo tempo: usa a dela
		if b, rerr := os.ReadFile(path); rerr == nil && len(b) >= 32 {
			return b, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrNoPseudonymKey, err)
	}
	defer f.Close()
	if _, err := f.Write(k); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPseudonymKey, err)
	}
	return k, nil
}

// Partial mostra só o suficiente para reconhecer o valor:
// email → jo***@exemplo.com.br; telefone/documento → (11) 9****-**21; texto → ab***z.
func Partial(v string) string {
	if i := strings.LastIndexByte(v, '@'); i > 0 && i < len(v)-1 {
		local, domain := v[:i], v[i:]
		r := []rune(local)
		keep := 2
		if len(r) <= 2 {
			keep = 1
		}
		return string(r[:keep]) + "***" + domain
	}
	digits := 0
	for _, c := range v {
		if unicode.IsDigit(c) {
			digits++
		}
	}
	if digits >= 6 && digits*2 >= len([]rune(v)) {
		return partialDigits(v, digits)
	}
	r := []rune(v)
	if len(r) <= 4 {
		return "***"
	}
	return string(r[:2]) + "***" + string(r[len(r)-1:])
}

// partialDigits mantém a pontuação, os 3 primeiros e os 2 últimos dígitos.
func partialDigits(v string, total int) string {
	var b strings.Builder
	seen := 0
	for _, c := range v {
		if !unicode.IsDigit(c) {
			b.WriteRune(c)
			continue
		}
		seen++
		if seen <= 3 || seen > total-2 {
			b.WriteRune(c)
		} else {
			b.WriteByte('*')
		}
	}
	return b.String()
}
