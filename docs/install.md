# Instalação

O Crivo é um binário único, sem dependências em tempo de execução. Há quatro caminhos: Homebrew (macOS e Linux), Scoop (Windows), download direto do GitHub Releases ou compilação a partir do fonte.

## Plataformas

| Plataforma | Asset do release | Homebrew | Scoop |
|---|---|---|---|
| macOS Apple Silicon | `crivo-macos-arm64` | sim | — |
| macOS Intel | `crivo-macos-amd64` | sim | — |
| Linux x86_64 | `crivo-linux-amd64` | sim | — |
| Linux arm64 | `crivo-linux-arm64` | sim (a partir do release seguinte ao v0.1.4) | — |
| Windows x86_64 | `crivo-windows-amd64.exe` | — | sim |
| Windows arm64 | não publicado | — | — |

Todos os binários são compilados nativamente no runner de cada sistema, com cgo (o parser `pg_query` é C). O `crivo-macos-amd64` é a exceção: sai do runner arm64 do macOS, cross-compilado pelo clang da Apple.

**Linux arm64** é gerado no runner `ubuntu-24.04-arm` do GitHub. O v0.1.4 não tem esse asset; ele aparece no primeiro release depois dele.

**Windows arm64** está adiado: o toolchain C (cgo) no runner Windows ARM do GitHub ainda não foi verificado, e uma perna de build quebrada bloquearia todos os releases. Em máquinas Windows arm64, o `crivo-windows-amd64.exe` baixado direto deve rodar pela emulação x64 do Windows 11, mas isso não foi testado.

## Homebrew (macOS e Linux)

A fórmula fica neste próprio repositório (`Formula/crivo.rb`). Por isso o `brew tap` recebe a URL do repo:

```bash
brew tap JonathanSantos/crivo https://github.com/JonathanSantos/crivo
brew install crivo
crivo version
```

Para atualizar, use `brew update && brew upgrade crivo`. A fórmula baixa o binário do release com a URL da versão (`releases/download/vX.Y.Z/...`) e confere o SHA-256. Como é um download pelo terminal, o macOS não aplica a quarentena do Gatekeeper.

## Scoop (Windows)

O manifesto fica em `bucket/crivo.json`, também neste repositório:

```powershell
scoop bucket add crivo https://github.com/JonathanSantos/crivo
scoop install crivo
crivo version
```

O Scoop instala o `crivo-windows-amd64.exe` com o atalho `crivo` no `PATH`. Para atualizar, use `scoop update; scoop update crivo`. O manifesto tem `checkver` e `autoupdate`, então o `scoop` também consegue achar versões novas por conta própria.

## Download direto

Os links `/releases/latest/download/<asset>` sempre apontam para o release mais recente:

```bash
# troque o nome do asset conforme a tabela acima
curl -fsSL https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-macos-arm64 -o crivo
chmod +x crivo && sudo mv crivo /usr/local/bin/
crivo version
```

No Windows, baixe o `crivo-windows-amd64.exe`, renomeie para `crivo.exe` e coloque o arquivo numa pasta do `PATH`.

## Verificando o download

Todo release traz um `checksums.txt` com o SHA-256 de cada binário:

```bash
curl -fsSLO https://github.com/JonathanSantos/crivo/releases/latest/download/checksums.txt
sha256sum --ignore-missing -c checksums.txt     # Linux
shasum -a 256 --ignore-missing -c checksums.txt # macOS
```

### Proveniência (attestation)

A partir do release seguinte ao v0.1.4, o job `release` do CI assina uma atestação de proveniência SLSA para cada binário, usando o `actions/attest-build-provenance`. A atestação prova que o arquivo saiu do workflow deste repositório, a partir daquele commit e daquela tag. Para conferir, use o [GitHub CLI](https://cli.github.com/):

```bash
gh attestation verify crivo-macos-arm64 --repo JonathanSantos/crivo
```

O v0.1.4 e os releases anteriores não têm atestação. Para eles, use o `checksums.txt`.

## Compilando do fonte

Você vai precisar de Go 1.26+ e de um compilador C: Xcode CLT no macOS, `gcc` no Linux ou MinGW-w64 no Windows.

```bash
make build        # gera bin/crivo
```

## Como o release é montado

1. `make tag TAG=vX.Y.Z` cria e publica a tag.
2. O job `test` do `.github/workflows/ci.yml` compila e testa em cada plataforma: `go vet`, testes unitários e smoke test do binário. Os testes de integração (Postgres via testcontainers) rodam só na perna Linux x86_64.
3. O job `release` calcula o `checksums.txt`, gera a atestação de proveniência e publica o GitHub Release.
4. Por último, `scripts/packages.py` regenera `Formula/crivo.rb` e `bucket/crivo.json` com a versão e os SHA-256 do release, e o `github-actions[bot]` commita os dois arquivos na `main`. Pré-releases (tags com `-`) pulam essa etapa.

Como o bot commita na `main`, rode `git pull` depois de cada release, antes da próxima tag. Sem isso, o `git push origin main` do `make tag` é rejeitado.

Para regenerar os pacotes à mão:

```bash
gh release download vX.Y.Z -R JonathanSantos/crivo -p checksums.txt -D /tmp/crivo-rel
python3 scripts/packages.py vX.Y.Z /tmp/crivo-rel/checksums.txt
```

Se faltar algum asset no `checksums.txt`, o script pula a plataforma e avisa. É o caso do Linux arm64 no v0.1.4: a fórmula passa a exigir x86_64 no Linux.

## Ainda não disponível

- **Assinatura de código** (Apple Developer ID com notarização, Authenticode no Windows): depende de certificados pagos que o projeto não tem.
- **winget**: exige um PR para o repositório externo `microsoft/winget-pkgs`.
- **Windows arm64**: ver [Plataformas](#plataformas).
