// Programa de teste: imprime o modo e a política lida do slot.
package main

import (
	"fmt"

	"crivo/internal/slot"
)

func main() {
	if p, ok := slot.Embedded(); ok {
		fmt.Printf("base:%s", p)
		return
	}
	fmt.Print("ferramenta")
}
