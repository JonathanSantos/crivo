// Package secret busca a senha do banco: keychain do SO, variável de
// ambiente ou prompt. A senha nunca fica na política nem no binário.
package secret

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"

	"crivo/internal/policy"
)

// Service é o serviço usado no keychain.
const Service = "crivo"

// ErrMissing indica senha ausente (código de saída 5).
type ErrMissing struct{ Msg string }

func (e *ErrMissing) Error() string { return e.Msg }

// Get devolve a senha conforme a diretiva secret da política.
func Get(p *policy.Policy) (string, error) {
	switch p.Secret {
	case policy.SecretEnv:
		v, ok := os.LookupEnv(p.SecretVar)
		if !ok || v == "" {
			return "", &ErrMissing{fmt.Sprintf("variável de ambiente %s vazia ou ausente", p.SecretVar)}
		}
		return v, nil
	case policy.SecretPrompt:
		return Prompt(fmt.Sprintf("senha de %s: ", p.Name))
	default:
		v, err := keyring.Get(Service, p.Name)
		if errors.Is(err, keyring.ErrNotFound) {
			return "", &ErrMissing{"senha não encontrada no keychain; rode: crivo secret set " + p.Name}
		}
		if err != nil {
			return "", &ErrMissing{fmt.Sprintf("keychain indisponível (%v); rode: crivo secret set %s", err, p.Name)}
		}
		return v, nil
	}
}

// Set grava a senha no keychain.
func Set(name, password string) error { return keyring.Set(Service, name, password) }

// Remove apaga a senha do keychain.
func Remove(name string) error {
	err := keyring.Delete(Service, name)
	if errors.Is(err, keyring.ErrNotFound) {
		return &ErrMissing{"não havia senha de " + name + " no keychain"}
	}
	return err
}

// Prompt pede uma senha com input oculto no terminal.
func Prompt(label string) (string, error) {
	tty, err := os.OpenFile(ttyPath(), os.O_RDWR, 0)
	if err != nil {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", &ErrMissing{"sem terminal para pedir a senha"}
		}
		fmt.Fprint(os.Stderr, label)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return strings.TrimRight(string(b), "\r\n"), err
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
