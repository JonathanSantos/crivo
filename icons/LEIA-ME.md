# Ícones do Crivo

Três queries entram, a placa barra duas e só uma atravessa o furo.

| Pasta | Uso |
| --- | --- |
| `dark/` | Padrão: placa tinta (#0D1117), sinal verde (#3EE08F) |
| `light/` | Fundos escuros ou documentação clara: placa papel (#F2EFE6), verde (#16A35F) |

Cada pasta tem:

- `crivo-icon.svg`: mestre vetorial (grid de 64)
- `crivo-16.png` … `crivo-1024.png`: o 16 px tem geometria própria para ficar nítido
- `crivo.ico`: 16, 24, 32, 48, 64, 128 e 256 px (Windows)
- `crivo.icns`: macOS, se um dia virar app empacotado

## Ícone no executável Windows

Com [go-winres](https://github.com/tc-hib/go-winres), na raiz do módulo, antes do `go build`:

```sh
go install github.com/tc-hib/go-winres@latest
go-winres simply --icon icons/dark/crivo-256.png --product-name Crivo
go build ./cmd/crivo
```

O comando gera arquivos `.syso` que o `go build` embute sozinho. Os binários gerados pelo `crivo build` são cópias do `crivo.exe`, então herdam o ícone.

macOS e Linux não mostram ícone em executáveis de linha de comando.
