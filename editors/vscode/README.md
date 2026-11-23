# Crivo para VS Code

Extensão mínima para editar políticas `.crivo` no VS Code:

- **Realce de sintaxe**: diretivas (`name`, `about`, `env`, `connect`, `secret`, `schema`, `limit`, `timeout`, `functions`, `expires`, `cost`, `rate`, `quota`, `approval`, `audit`, `query`), comentários `#` e comentários de documentação `##`, tabelas (`schema.tabela`, padrões com `*`), ações (`read`, `insert`, `update`, `delete`, `deny`), modificadores (`(colunas)`, `except(...)`, `where ...`, `max N`, `limit N`, `mask(...)`), modos de máscara (`partial`, `redact`, `hash`, `email`, `last4`, `month`, `bucket N`, `pseudonym`) e linhas de continuação (começando com espaço). O `where` e o SQL do `query` recebem um realce de SQL próprio, que respeita a regra do Crivo de que o `where` termina na próxima vírgula fora de parênteses e aspas.
- **Diagnósticos**: ao abrir e ao salvar um `.crivo`, roda `crivo check <arquivo> --json` e mostra erros e avisos no editor e no painel Problemas. Também há o comando **Crivo: Check policy** (paleta de comandos), que salva o arquivo e roda a checagem.

Não tem dependências nem etapa de build: é JavaScript puro (CommonJS).

## Instalar sem o marketplace

Pré-requisito: o `crivo` no `PATH` (ou configure `crivo.path`).

**Opção 1: copiar ou linkar a pasta** para o diretório de extensões do VS Code (a partir da raiz do repositório):

```bash
# link simbólico (edições na pasta valem depois de recarregar a janela)
ln -s "$PWD/editors/vscode" ~/.vscode/extensions/crivo-policy-0.1.0

# ou cópia
cp -R editors/vscode ~/.vscode/extensions/crivo-policy-0.1.0
```

Depois, no VS Code: **Developer: Reload Window**. Se a extensão não aparecer (versões recentes do VS Code registram as extensões instaladas em `~/.vscode/extensions/extensions.json` e podem ignorar pastas soltas), use a opção 2 ou o modo de desenvolvimento abaixo. No VS Code Insiders a pasta é `~/.vscode-insiders/extensions`; no Windows, `%USERPROFILE%\.vscode\extensions`.

**Opção 2: gerar um `.vsix`** (precisa de rede para baixar o `vsce`):

```bash
cd editors/vscode
npx @vscode/vsce package          # gera crivo-policy-0.1.0.vsix
code --install-extension crivo-policy-0.1.0.vsix
```

O `vsce` pode reclamar da falta de um arquivo LICENSE; responda `y` ou acrescente um antes de empacotar.

**Para desenvolver**: abra `editors/vscode` no VS Code e aperte F5 (Extension Development Host).

## Configurações

| Configuração | Padrão | O que faz |
| --- | --- | --- |
| `crivo.path` | `"crivo"` | Executável do `crivo`: nome no `PATH` ou caminho. `~` é expandido; caminho relativo (ex.: `./bin/crivo`) parte da pasta do workspace. |
| `crivo.checkArgs` | `["--offline"]` | Argumentos extras depois de `check <arquivo> --json`. `${workspaceFolder}` e `${fileDirname}` são expandidos. |
| `crivo.checkOnSave` | `true` | Roda a checagem ao abrir e ao salvar. Desligado, só o comando **Crivo: Check policy** checa. |

O `crivo check` roda **sem shell**, com a pasta do workspace como diretório de trabalho (ou a pasta do arquivo, fora de workspace), então caminhos relativos em `checkArgs` partem dela. Exemplo para conferir contra um DDL em vez do banco:

```json
{
  "crivo.checkArgs": ["--schema-sql", "testdata/schema.sql"]
}
```

O padrão `--offline` não conecta ao banco (usa só o cache de schema, se existir). Sem ele, o `check` lê o catálogo real, o que pode pedir o segredo e demorar; a checagem é abortada em 10 s.

## Comportamento

- A checagem lê o arquivo **do disco**: alterações não salvas não entram (o comando salva antes de checar).
- Linha e coluna vêm do `crivo` (1-based, coluna em bytes UTF-8) e são convertidas para a posição do editor. Diagnóstico sem posição (linha 0) fica na linha 1.
- Se o executável não for encontrado, aparece um aviso uma única vez (de novo só depois de mudar a configuração). Saída que não é JSON (versão antiga do `crivo`, argumento inválido em `checkArgs`) vira um erro na linha 1, com o detalhe no canal de saída **Crivo**.
- Em workspace não confiável, `crivo.path` e `crivo.checkArgs` definidos pelo workspace são ignorados: vale só o que está nas configurações do usuário.

## Testes

```bash
node --test editors/vscode/test/
```

Testam o mapeamento JSON → diagnóstico (`diagnostics.js`, sem `vscode`) e a gramática: o JSON parseia, todo regex compila, todo `#include` existe, e um mini-tokenizador TextMate confere os escopos de `examples/vendas.crivo` e das construções novas. O mini-tokenizador não é o motor do VS Code (vscode-textmate + Oniguruma, que exigiria `npm install`); a palavra final é abrir um `.crivo` no VS Code e usar **Developer: Inspect Editor Tokens and Scopes**.
