package mask

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"crivo/internal/policy"
)

func TestNewModes(t *testing.T) {
	m := New()
	cases := []struct {
		mask policy.Mask
		in   string
		want string
	}{
		{policy.Mask{Mode: policy.MaskEmail}, "ana.souza@empresa.com.br", "***@empresa.com.br"},
		{policy.Mask{Mode: policy.MaskEmail}, "sem-arroba", "***"},
		{policy.Mask{Mode: policy.MaskEmail}, "fim@", "***"},
		// corta no primeiro @, igual ao split_part(email, '@', 2) que o guard aceita
		{policy.Mask{Mode: policy.MaskEmail}, "a@b@c.com", "***@b@c.com"},
		{policy.Mask{Mode: policy.MaskLast4}, "123.456.789-01", "***.***.*89-01"},
		{policy.Mask{Mode: policy.MaskLast4}, "4111 1111 1111 1234", "**** **** **** 1234"},
		{policy.Mask{Mode: policy.MaskLast4}, "1234", "***"}, // curto demais: não sobra nada a esconder
		{policy.Mask{Mode: policy.MaskMonth}, "2026-10-14", "2026-10"},
		{policy.Mask{Mode: policy.MaskMonth}, "2026-10-14 09:12:03", "2026-10"},
		{policy.Mask{Mode: policy.MaskMonth}, "14/10/2026", "***"},
		{policy.Mask{Mode: policy.MaskMonth}, "2026-13-01", "***"},
		{policy.Mask{Mode: policy.MaskBucket, Arg: 100}, "1890.50", "1800..1900"},
		{policy.Mask{Mode: policy.MaskBucket, Arg: 1000}, "-250", "-1000..0"},
		{policy.Mask{Mode: policy.MaskBucket, Arg: 10}, "7", "0..10"},
		{policy.Mask{Mode: policy.MaskBucket, Arg: 100}, "abc", "***"},
		{policy.Mask{Mode: policy.MaskBucket, Arg: 0}, "10", "***"}, // sem faixa: fecha
		{policy.Mask{Mode: policy.MaskBucket, Arg: 100}, "NaN", "***"},
		{policy.Mask{Mode: policy.MaskPseudonym}, "Ana", "***"}, // sem chave: fecha
		{policy.Mask{Mode: "desconhecido"}, "x", "***"},
	}
	for _, c := range cases {
		if got := m.ApplyMask(c.mask, c.in); got != c.want {
			t.Errorf("%s(%q) = %q, esperava %q", c.mask.Text(), c.in, got, c.want)
		}
	}
}

// O pseudônimo é estável entre execuções (mesma chave) e muda com outra chave.
func TestPseudonymStableAcrossMaskers(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a := New().WithPseudonymKey(key).ApplyMask(policy.Mask{Mode: policy.MaskPseudonym}, "Ana Souza")
	b := New().WithPseudonymKey(key).ApplyMask(policy.Mask{Mode: policy.MaskPseudonym}, "Ana Souza")
	c := New().WithPseudonymKey(bytes.Repeat([]byte{8}, 32)).ApplyMask(policy.Mask{Mode: policy.MaskPseudonym}, "Ana Souza")
	d := New().WithPseudonymKey(key).ApplyMask(policy.Mask{Mode: policy.MaskPseudonym}, "Bruno")
	if a != b || !strings.HasPrefix(a, "p:") || len(a) != 10 {
		t.Errorf("pseudônimo instável ou mal formado: %q vs %q", a, b)
	}
	if a == c || a == d {
		t.Errorf("pseudônimo deveria depender da chave e do valor: %q %q %q", a, c, d)
	}
}

func TestPseudonymKeyCreatedOnceAndPrivate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	k1, err := PseudonymKey("vendas")
	if err != nil || len(k1) != 32 {
		t.Fatalf("PseudonymKey = %d bytes, %v", len(k1), err)
	}
	k2, err := PseudonymKey("vendas")
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatal("a chave precisa ser reaproveitada entre execuções")
	}
	other, _ := PseudonymKey("outra")
	if bytes.Equal(k1, other) {
		t.Error("cada política tem a própria chave")
	}
	path := filepath.Join(home, ".crivo", "keys", "vendas.key")
	if fi, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("chave com permissão errada: %v %v", fi.Mode().Perm(), err)
	}
	if err := os.WriteFile(path, []byte("curta"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PseudonymKey("vendas"); !errors.Is(err, ErrNoPseudonymKey) {
		t.Errorf("chave corrompida deveria falhar fechado, veio %v", err)
	}
}

func TestPseudonymKeyFailsWithoutHome(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", blocker)
	t.Setenv("USERPROFILE", blocker)
	if _, err := PseudonymKey("vendas"); !errors.Is(err, ErrNoPseudonymKey) {
		t.Errorf("esperava ErrNoPseudonymKey, veio %v", err)
	}
}
