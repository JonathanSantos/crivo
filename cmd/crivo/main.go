// Comando crivo: um único executável com dois modos. Sem política no slot
// embutido, roda como ferramenta (init, check, test, build, secret). Com
// política, roda como o binário da base (query, exec, skill...). Não existe
// flag nem variável de ambiente que troque de modo.
package main

import (
	"os"
	"path/filepath"

	"golang.org/x/term"

	"crivo/internal/cli/base"
	"crivo/internal/cli/tool"
	"crivo/internal/console"
	"crivo/internal/slot"
)

func main() {
	args := os.Args[1:]
	code := dispatch(args)
	// Duplo clique no Explorer: sem isso a janela fecha antes de dar para ler.
	interactive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if console.ShouldPause(args, console.Processes(), interactive) {
		console.Pause(os.Stdout, os.Stdin, filepath.Base(os.Args[0]))
	}
	os.Exit(code)
}

func dispatch(args []string) int {
	if policy, ok := slot.Embedded(); ok {
		return base.Main(policy, args)
	}
	return tool.Main(args)
}
