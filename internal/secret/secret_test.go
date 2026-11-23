package secret

import (
	"errors"
	"os"
	"testing"

	"github.com/zalando/go-keyring"

	"crivo/internal/policy"
)

// TestMain troca o keychain do SO pelo mock antes de qualquer teste: com
// -shuffle a ordem muda, e nenhum teste pode tocar o keychain de verdade.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

// isolate zera o keychain (mock novo) e aponta HOME para uma pasta temporária.
func isolate(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func wantMissing(t *testing.T, err error, msg string) {
	t.Helper()
	var em *ErrMissing
	if !errors.As(err, &em) {
		t.Fatalf("erro %v (%T), quero *ErrMissing", err, err)
	}
	if em.Error() != msg {
		t.Fatalf("mensagem\nobtida %q\nquero  %q", em.Error(), msg)
	}
}

func TestGetFromEnvRequiresNonEmptyVariable(t *testing.T) {
	const name = "CRIVO_TEST_SECRET_PW"
	cases := []struct {
		name    string
		set     bool
		value   string
		want    string
		wantErr string
	}{
		{name: "present", set: true, value: "s3gr3do", want: "s3gr3do"},
		// Vazia conta como ausente: conectar com senha vazia esconderia o erro.
		{name: "empty", set: true, value: "", wantErr: "variável de ambiente CRIVO_TEST_SECRET_PW vazia ou ausente"},
		{name: "absent", set: false, wantErr: "variável de ambiente CRIVO_TEST_SECRET_PW vazia ou ausente"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolate(t)
			// Setenv antes de Unsetenv garante que o valor original volta no fim.
			t.Setenv(name, tc.value)
			if !tc.set {
				os.Unsetenv(name)
			}
			// Uma senha no keychain não pode ser usada quando a política pede env.
			if err := Set("dev", "do-keychain"); err != nil {
				t.Fatal(err)
			}
			got, err := Get(&policy.Policy{Name: "dev", Secret: policy.SecretEnv, SecretVar: name})
			if tc.wantErr != "" {
				wantMissing(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("Get() = %q, quero %q", got, tc.want)
			}
		})
	}
}

func TestGetFromPolicyEnvDirective(t *testing.T) {
	// A diretiva "secret env:VAR" da política leva ao mesmo caminho.
	isolate(t)
	src := "name dev\nabout \"base de teste\"\nenv preprod\nconnect postgres://app@localhost:5432/app?sslmode=verify-full\nsecret env:CRIVO_TEST_PARSED_PW\n\npedidos read\n"
	p, diags := policy.Parse("dev.crivo", src)
	if diags.HasErrors() {
		t.Fatalf("política de exemplo inválida: %v", diags)
	}
	if p.Secret != policy.SecretEnv || p.SecretVar != "CRIVO_TEST_PARSED_PW" {
		t.Fatalf("diretiva secret lida como %q/%q", p.Secret, p.SecretVar)
	}
	t.Setenv("CRIVO_TEST_PARSED_PW", "da-env")
	got, err := Get(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "da-env" {
		t.Fatalf("Get() = %q, quero %q", got, "da-env")
	}
}

func TestSetGetRemoveRoundTripInKeychain(t *testing.T) {
	isolate(t)
	// Keychain é o padrão: a política sem diretiva secret cai nele.
	for _, kind := range []policy.SecretKind{"", policy.SecretKeychain} {
		keyring.MockInit()
		p := &policy.Policy{Name: "dev", Secret: kind}
		if err := Set("dev", "s3gr3do"); err != nil {
			t.Fatal(err)
		}
		got, err := Get(p)
		if err != nil {
			t.Fatalf("secret %q: %v", kind, err)
		}
		if got != "s3gr3do" {
			t.Fatalf("secret %q: Get() = %q, quero %q", kind, got, "s3gr3do")
		}
		if err := Remove("dev"); err != nil {
			t.Fatal(err)
		}
		_, err = Get(p)
		wantMissing(t, err, "senha não encontrada no keychain; rode: crivo secret set dev")
	}
}

func TestSetOverwritesAndIsScopedByName(t *testing.T) {
	// Cada política tem sua senha; gravar de novo substitui a anterior.
	isolate(t)
	for _, kv := range [][2]string{{"dev", "um"}, {"staging", "dois"}, {"dev", "tres"}} {
		if err := Set(kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]string{"dev": "tres", "staging": "dois"} {
		got, err := Get(&policy.Policy{Name: name, Secret: policy.SecretKeychain})
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: Get() = %q, quero %q", name, got, want)
		}
	}
	// A senha fica sob o serviço "crivo", que é o que o usuário vê no keychain.
	if got, err := keyring.Get("crivo", "dev"); err != nil || got != "tres" {
		t.Errorf("keyring.Get(crivo, dev) = %q, %v", got, err)
	}
}

func TestGetMissingInKeychainTellsHowToFix(t *testing.T) {
	isolate(t)
	_, err := Get(&policy.Policy{Name: "dev", Secret: policy.SecretKeychain})
	wantMissing(t, err, "senha não encontrada no keychain; rode: crivo secret set dev")
}

func TestRemoveMissingIsErrMissing(t *testing.T) {
	isolate(t)
	wantMissing(t, Remove("dev"), "não havia senha de dev no keychain")
}

func TestKeychainUnavailableBecomesErrMissingOnlyInGet(t *testing.T) {
	isolate(t)
	keyring.MockInitWithError(errors.New("dbus fora do ar"))
	t.Cleanup(keyring.MockInit)

	// Falha do keychain vira ErrMissing (código 5) com a causa e a saída.
	_, err := Get(&policy.Policy{Name: "dev", Secret: policy.SecretKeychain})
	wantMissing(t, err, "keychain indisponível (dbus fora do ar); rode: crivo secret set dev")

	// Set e Remove devolvem o erro cru: não é "senha ausente".
	if err := Set("dev", "x"); err == nil || err.Error() != "dbus fora do ar" {
		t.Errorf("Set() = %v, quero o erro do keychain", err)
	}
	err = Remove("dev")
	var em *ErrMissing
	if err == nil || errors.As(err, &em) || err.Error() != "dbus fora do ar" {
		t.Errorf("Remove() = %v (%T), quero o erro do keychain sem ErrMissing", err, err)
	}
}
