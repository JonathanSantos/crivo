// Package console trata o caso de o binário ser aberto com duplo clique no
// Explorer do Windows: o console nasce só para ele e fecha junto, antes que
// dê para ler a ajuda. Nesse caso o Crivo explica e espera um Enter.
package console

import (
	"bufio"
	"fmt"
	"io"
)

// ShouldPause decide se é preciso segurar a janela: só sem argumentos, só
// com stdin e stdout num terminal (nunca quando a saída é capturada por um
// script, pelo CI ou por um cliente MCP) e só quando este processo é o único
// preso ao console (ele foi criado para nós: ninguém abriu um terminal antes).
func ShouldPause(args []string, consoleProcesses int, interactive bool) bool {
	return len(args) == 0 && interactive && consoleProcesses == 1
}

// Pause explica que o programa é de terminal e espera o Enter.
func Pause(w io.Writer, r io.Reader, name string) {
	fmt.Fprintf(w, "\n%s é um programa de linha de comando: aberto com duplo clique, ele só mostra esta ajuda.\n", name)
	fmt.Fprintf(w, "Abra o PowerShell ou o Terminal nesta pasta e rode: .\\%s --help\n\n", name)
	fmt.Fprint(w, "Pressione Enter para fechar...")
	_, _ = bufio.NewReader(r).ReadString('\n')
}
