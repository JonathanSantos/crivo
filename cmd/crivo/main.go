// Comando crivo: um único executável com dois modos. Sem política no slot
// embutido, roda como ferramenta (init, check, test, build, secret). Com
// política, roda como o binário da base (query, exec, skill...). Não existe
// flag nem variável de ambiente que troque de modo.
package main

import (
	"os"

	"crivo/internal/cli/base"
	"crivo/internal/cli/tool"
	"crivo/internal/slot"
)

func main() {
	if policy, ok := slot.Embedded(); ok {
		os.Exit(base.Main(policy, os.Args[1:]))
	}
	os.Exit(tool.Main(os.Args[1:]))
}
