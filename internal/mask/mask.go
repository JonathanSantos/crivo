// Package mask aplica as máscaras partial, redact e hash a valores de saída.
package mask

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"

	"crivo/internal/policy"
)

// Masker aplica máscaras. O hash usa uma chave aleatória por execução: é
// estável dentro da execução (permite agrupar e comparar linhas) mas não
// permite confirmar um palpite (ex.: o hash de um email conhecido) entre
// execuções.
type Masker struct {
	key []byte
}

// New cria um Masker com chave nova.
func New() *Masker {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return &Masker{key: k}
}

// Apply mascara um valor de texto.
func (m *Masker) Apply(mode policy.MaskMode, v string) string {
	switch mode {
	case policy.MaskRedact:
		return "***"
	case policy.MaskHash:
		h := hmac.New(sha256.New, m.key)
		h.Write([]byte(v))
		return "h:" + hex.EncodeToString(h.Sum(nil))[:6]
	case policy.MaskPartial:
		return Partial(v)
	}
	return "***"
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
