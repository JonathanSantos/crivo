//go:build !windows

package console

// Processes só importa no Windows; nos outros sistemas não há duplo clique
// que crie um console, então nunca pausa.
func Processes() int { return 0 }
