package cli

import (
	"fmt"
	"io"

	"github.com/alecthomas/kong"

	"crivo/internal/output"
)

// exitSignal é o pânico usado pelo kong.Exit para interromper o parse.
type exitSignal struct{ code int }

// KongExit faz o kong interromper o parse quando pede para sair (o --help
// faz isso depois de imprimir a ajuda). Um Exit que só retorna deixaria o
// kong seguir adiante e rodar o comando: `exec "DELETE ..." --help` executaria
// o DELETE. Use sempre junto com Parse, que recupera o pânico.
func KongExit() kong.Option {
	return kong.Exit(func(code int) { panic(exitSignal{code}) })
}

// Parse roda o parser criado com KongExit. Sem argumentos (ou só "help"),
// imprime a ajuda. done diz que não há comando a rodar e code é o código de
// saída: ExitOK depois da ajuda, ExitConfig em argumento inválido.
func Parse(parser *kong.Kong, args []string, stderr io.Writer) (kctx *kong.Context, code int, done bool) {
	if len(args) == 0 || (len(args) == 1 && args[0] == "help") {
		args = []string{"--help"}
	}
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		sig, ok := r.(exitSignal)
		if !ok {
			panic(r)
		}
		kctx, code, done = nil, sig.code, true
	}()
	kctx, err := parser.Parse(args)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v (veja %s --help)\n", parser.Model.Name, err, parser.Model.Name)
		return nil, output.ExitConfig, true
	}
	if kctx.Command() == "" {
		return nil, output.ExitOK, true
	}
	return kctx, output.ExitOK, false
}
