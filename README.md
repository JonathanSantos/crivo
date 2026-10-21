<h1 align="center"><img src="docs/img/hero.pt.svg" width="100%" alt="Crivo: toda query passa pelo crivo"></h1>

<p align="center">
<a href="https://github.com/JonathanSantos/crivo/releases/latest"><img src="https://img.shields.io/github/v/release/JonathanSantos/crivo?label=download&logo=github" alt="Download"></a>
<a href="https://github.com/JonathanSantos/crivo/actions/workflows/ci.yml"><img src="https://github.com/JonathanSantos/crivo/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
</p>

<p align="center"><a href="#instalação">Instalação</a> · <a href="#fluxo">Fluxo</a> · <a href="#a-política">Política</a> · <a href="#comandos">Comandos</a> · <a href="#usuário-read-only-a-estratégia-recomendada">Usuário read-only</a> · <a href="#integração-com-o-copilot">Copilot</a> · <a href="#mcp-opcional">MCP</a></p>

**Download do binário pronto** ([todas as versões](https://github.com/JonathanSantos/crivo/releases)): [macOS Apple Silicon](https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-macos-arm64) · [macOS Intel](https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-macos-amd64) · [Linux x86_64](https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-linux-amd64) · [Windows x86_64](https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-windows-amd64.exe)

**Toda query passa pelo crivo.** O Crivo transforma um arquivo de política (`.crivo`) num CLI local de acesso a um Postgres de pré-produção, mais uma skill que ensina o GitHub Copilot do VS Code a usá-lo. Toda query que a IA envia passa pelo parser real do Postgres (pg_query) antes de chegar ao banco, e só executa o que a política permite.

- **Deny por padrão:** o que a política não cita não existe para a IA.
- **Fail closed:** coluna ambígua, nó de AST desconhecido ou função fora da lista: recusa.
- **Executa o que validou:** o banco recebe o deparse do AST validado e reescrito, nunca a string original. Esse deparse é parseado e checado de novo.
- **Camadas:** AST + transação `READ ONLY` + `statement_timeout` + TLS obrigatório (+ usuário de privilégio mínimo, ver abaixo).
- **Erros que ensinam:** toda recusa diz a regra, o motivo e o que seria aceito.
- **MCP opcional:** o mesmo binário serve a política como servidor MCP (`vendas mcp`) para qualquer cliente de IA. O modo principal continua sendo CLI + skill.

<p align="center"><img src="docs/img/guard.pt.svg" width="100%" alt="O caminho de uma query: parse, política, reescrita, re-checagem, execução e máscara"></p>

> [!WARNING]
> O adversário é a IA, não uma pessoa. Quem tem acesso à máquina consegue extrair a senha do keychain ou alterar o binário. Nunca use credenciais de produção e não distribua binários gerados.

## Instalação

**Binário pronto** (sem Go nem compilador C): baixe o arquivo da sua plataforma na [página de releases](https://github.com/JonathanSantos/crivo/releases/latest) ou com `curl`. Baixar pelo terminal evita a quarentena do Gatekeeper no macOS, que recusa binários sem assinatura de desenvolvedor vindos do navegador.

```bash
# macOS Apple Silicon (troque por crivo-macos-amd64 em Intel, crivo-linux-amd64 no Linux)
curl -fsSL https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-macos-arm64 -o crivo
chmod +x crivo && sudo mv crivo /usr/local/bin/
crivo version
```

No Windows, baixe o `crivo-windows-amd64.exe`, renomeie para `crivo.exe` e coloque numa pasta do `PATH`. Cada release traz um `checksums.txt` com o SHA-256 de todos os binários.

**Compilando do fonte:** precisa de Go 1.26+ e de um compilador C (o pg_query usa cgo): Xcode CLT no macOS, `gcc` no Linux, MinGW-w64 no Windows.

```bash
make build        # gera bin/crivo
```

O CI (`.github/workflows/ci.yml`) compila e testa nativamente em Linux, macOS e Windows a cada push. Uma tag `vX.Y.Z` (`make tag TAG=vX.Y.Z`) dispara o job `release`, que publica os binários das três plataformas no GitHub Releases.

## Fluxo

<p align="center"><img src="docs/img/flow.pt.svg" width="100%" alt="Fluxo do Crivo, de crivo init até o Copilot consultando o Postgres"></p>

```bash
crivo init "postgres://svc_app@pg-hml.interno:5432/vendas?sslmode=verify-full"   # gera vendas.crivo, tudo negado
$EDITOR vendas.crivo                                                           # libera o que a IA pode fazer
crivo secret set vendas                                                        # senha no keychain do SO
crivo check vendas.crivo                                                       # sintaxe, semântica e schema real
crivo test vendas.crivo "SELECT * FROM clientes"                               # decisão + SQL reescrito
crivo build vendas.crivo                                                       # gera ./vendas
./vendas skill install                                                         # .github/skills/crivo-vendas/SKILL.md
./vendas skill vscode                                                          # trecho de auto-approve do settings.json
./vendas skill mcp                                                             # (opcional) configuração do servidor MCP
```

A partir daí o Copilot (agent mode) consulta o banco chamando `vendas` no terminal. Quem preferir MCP aponta o cliente para `vendas mcp` (ver [MCP](#mcp-opcional)).

## A política

```
name    vendas
about   "Base do e-commerce B2B: pedidos, itens, clientes e pagamentos"
env     preprod
connect postgres://svc_app@pg-hml.interno:5432/vendas?sslmode=verify-full
secret  keychain
limit   500 rows
timeout 5s

## Pedidos de venda. status: aberto | pago | enviado | cancelado
pedidos         read, update(status, observacao) max 20
pedido_itens    read, insert, delete max 5
produtos        read
## Clientes PJ. CPF nunca sai do banco; email e telefone saem mascarados
clientes        read except(cpf) mask(email: partial, telefone: redact)
pagamentos      read where status <> 'estornado'
audit_*         deny
```

Exemplo completo em [examples/vendas.crivo](examples/vendas.crivo) e casos de teste em [examples/queries.sql](examples/queries.sql) (`crivo test vendas.crivo -f queries.sql`).

| Construção | Efeito |
| --- | --- |
| `connect` | URL sem senha, com TLS validado: `sslmode=verify-full` (ou `verify-ca`). `require` passa com aviso (não valida o certificado). Sem `sslmode`, ou com `disable`/`prefer`, só para host local, com aviso. CA interna: acrescente `sslrootcert=/caminho/ca.crt`. |
| `read`, `insert`, `update`, `delete` | As quatro ações. DDL, `TRUNCATE`, `COPY`, `CALL`, `DO`, `SET`, `GRANT`... nunca passam. |
| `(a, b)` / `except(x)` | Colunas que a ação alcança. Coluna bloqueada não pode nem aparecer em filtro. |
| `where <expr>` | Filtro de linha: em leitura a tabela vira subquery filtrada (mantendo o alias); em `update`/`delete` entra com `AND` no `WHERE`. Vai até a próxima vírgula de nível zero. |
| `max N` | Teto de linhas afetadas por escrita (padrão 50). Acima disso: rollback e bloqueio. |
| `limit N` | Teto de linhas por query para a tabela (menor que o global). |
| `mask(col: partial\|redact\|hash)` | Máscara aplicada no resultado. Coluna mascarada só aparece nua na lista do SELECT. |
| `deny` / sem regra | A tabela não existe para a IA. `pg_*`, `pg_catalog` e `information_schema` são sempre bloqueados. |
| `## texto` | Descrição da tabela na skill e no `describe` (precisa estar logo acima da regra). |
| linha começando com espaço | Continua a regra anterior. |

Precedência: nome exato vence padrão; entre padrões, o de maior prefixo literal; empate, `deny` vence.

## Comandos

**Ferramenta (`crivo`, sem política embutida):** `init`, `check`, `test`, `build`, `grants`, `secret set|rm`, `version`. Nenhum executa SQL da IA.

**Binário gerado (`vendas`, modo base):** `policy`, `tables`, `describe <tabela>`, `query "<sql>"`, `explain "<sql>"`, `exec "<sql>" [--dry-run]`, `skill [install|vscode|mcp]`, `refresh`, `mcp [--allow-exec]`. Flags: `--format tsv|json|table`, `--json-errors`, `-f arquivo.sql`. O modo é decidido pelo slot embutido; não há flag nem variável que troque de modo, então a IA não alcança `build` por um binário gerado.

Códigos de saída: `0` sucesso, `1` bug, `2` barrado pelo Crivo, `3` SQL inválido, `4` erro do banco, `5` configuração ou segredo ausente.

## Usuário read-only: a estratégia recomendada

A política funciona sozinha, mas fica muito mais forte como **segunda camada** sobre um usuário de banco com privilégio mínimo. Por isso o Crivo ajuda nas duas pontas:

<p align="center"><img src="docs/img/layers.pt.svg" width="100%" alt="Camadas de defesa do Crivo"></p>

1. **`crivo check` audita o usuário de conexão.** Quando conecta ao banco, avisa se o usuário é superuser, dono de tabelas, tem `BYPASSRLS`, ou se pode `INSERT/UPDATE/DELETE/TRUNCATE` além do que a política permite.
2. **`crivo grants vendas.crivo` gera o SQL do usuário ideal** a partir da própria política: `GRANT SELECT` só nas tabelas liberadas, `GRANT SELECT (colunas)` quando há `except` (o banco passa a recusar `cpf` sozinho), `GRANT UPDATE (status, observacao)`, `DELETE` só onde há `delete`, `default_transaction_read_only = on` quando a política não tem escrita, `statement_timeout` no papel, e sugestões de RLS para os filtros `where`.

Recomendação por cenário:

| Cenário | Usuário |
| --- | --- |
| Política só com `read` | Usuário read-only (`crivo grants` gera com `default_transaction_read_only`). O comando `exec` nem existe no binário. |
| Política com escrita | Usuário com os GRANTs por tabela/coluna gerados pelo `crivo grants`. O `READ ONLY` continua protegendo `query`/`explain`. |
| DBA não cria usuário | Funciona, mas o `check` avisa o excesso de privilégio. Nesse caso mantenha `max` baixos e o auto-approve de `exec` desligado. |

O Crivo lista as colunas no lugar de `*` (inclusive dentro das subqueries de filtro), então funciona com `GRANT` por coluna.

## Integração com o Copilot

`vendas skill install` grava `<raiz do workspace>/.github/skills/crivo-vendas/SKILL.md` (ou `--personal` para `~/.copilot/skills`, `--dir` para outra pasta). A skill é gerada da política embutida, é determinística e nunca contém host, usuário ou URL. `--with-schema` anexa as colunas permitidas.

`vendas skill vscode` imprime as regras de `chat.tools.terminal.autoApprove`: leitura e `--dry-run` sem confirmação, `exec` real sempre pedindo o clique do usuário. Confira na sua versão do VS Code se as regras são respeitadas ([microsoft/vscode#324059](https://github.com/microsoft/vscode/issues/324059)).

## MCP (opcional)

O binário gerado também fala [MCP](https://modelcontextprotocol.io) por stdio: `vendas mcp`. As ferramentas são as mesmas operações do CLI (`tables`, `describe`, `policy`, `query`, `explain`, `exec`), passando pelo mesmo guard, com as mesmas mensagens de recusa (que chegam ao modelo como resultado de erro da ferramenta) e a mesma auditoria (comando prefixado com `mcp:`). As instruções do servidor são o equivalente curto da skill.

```bash
./vendas skill mcp                 # imprime a configuração para VS Code (.vscode/mcp.json), Claude Code e Claude Desktop
./vendas mcp                       # o que o cliente executa; escrita só simulada (dry_run)
./vendas mcp --allow-exec          # permite dry_run=false na ferramenta exec
```

Diferença importante em relação ao CLI: no terminal, o `exec` real passa pelo clique de aprovação do VS Code. No MCP não existe esse clique por padrão, por isso a escrita real fica **desligada** até o usuário iniciar o servidor com `--allow-exec`. Mesmo com a flag, a ferramenta vem anotada como destrutiva e as instruções mandam o modelo simular primeiro e pedir confirmação. Cada chamada abre e fecha sua própria conexão; não há processo residente com conexão aberta.

A IA não alcança a flag: ela está na configuração do cliente, que só o usuário edita.

## Plataformas

- **macOS:** o `build` re-assina o binário com `codesign --force --sign -` (o patch é in-place no slot, sem anexar bytes, por isso a assinatura continua possível). Senha no Keychain.
- **Linux:** senha via Secret Service (gnome-keyring/KWallet). Sem keyring, use `secret env:VAR` só para testes.
- **Windows:** senha no Credential Manager. O ícone vem de `cmd/crivo/winres/winres.json` (`make winres` regenera os `.syso`); os binários gerados herdam o ícone por serem cópias.

Arquivos locais: cache de schema em `~/.cache/crivo/<name>/schema.json` (TTL 10 min, respeita `XDG_CACHE_HOME`), auditoria em `~/.crivo/logs/<name>.jsonl` (sem dados do resultado).

## Desenvolvimento

```bash
make test                                                    # unidade, golden files, slot com binário real
CRIVO_TEST_DSN=postgres://postgres:senha@localhost:5432/postgres make test-integration
make fuzz                                                    # go test -fuzz no sqlguard.Guard
```

Os testes de integração usam `CRIVO_TEST_DSN` (o teste cria e apaga o schema `crivo_it`) ou, sem ela, testcontainers-go quando há Docker; sem nenhum dos dois, são pulados. Eles exercitam o binário gerado nos dois modos, CLI e MCP (este último como subprocesso, via cliente MCP real). Os golden files se regravam com `go test ./internal/policy ./internal/skill -update`.

```
cmd/crivo            lê o slot e despacha: modo ferramenta ou modo base
internal/slot        slot de 64 KiB, leitura e patch in-place
internal/policy      lexer, parser, validação, resolução de regra
internal/sqlguard    pg_query, checagens, reescritas, deparse e re-checagem
internal/schema      introspecção do pg_catalog e cache em disco
internal/run         pgx, transações, SET LOCAL, teto de linhas
internal/mask        partial, redact, hash
internal/output      TSV/JSON/tabela, mensagens, códigos de saída
internal/secret      keychain, env, prompt
internal/skill       SKILL.md, install, settings.json
internal/audit       log JSONL
internal/cli/...     CLIs (kong) dos dois modos; base/mcp.go é o servidor MCP
```

Em inglês: [README.en.md](README.en.md).

## Decisões de implementação

Pontos em que a especificação deixava espaço, e o que foi escolhido:

- **Re-checagem do deparse:** além de rodar todas as checagens no SQL reescrito, o Crivo exige que o re-parse produza exatamente o mesmo AST (ignorando posições). Se não produzir, recusa.
- **Cobertura do AST:** depois da análise, toda coluna, tabela e função da árvore precisa ter passado pelo analisador; se um campo novo do parser carregar algo não analisado, a query é recusada.
- **Filtro de leitura** vira `(SELECT <colunas legíveis> FROM t WHERE ...) AS t` em vez de `SELECT *`, para funcionar com `GRANT` por coluna.
- **`update`/`delete` também recebem o filtro do `read`:** linha invisível para leitura também não é alterada (nem serve de oráculo pelo número de linhas afetadas).
- **Colunas citadas em `WHERE`, `SET` e `RETURNING` de escrita precisam de `read`**, pelo mesmo motivo.
- **Máscaras:** `hash` é HMAC-SHA256 com chave aleatória por execução (estável dentro da execução, sem permitir confirmar palpites entre execuções). Coluna mascarada não passa por `UNION`/`INTERSECT`/`EXCEPT`, nem pela lista de subqueries escalares/`IN` (só `EXISTS`), nem por `INSERT ... SELECT`. Em `UNION ALL` os dois lados precisam ser exatamente a mesma coluna: a máscara de saída é aplicada por posição a todas as linhas, então um valor escolhido na query do outro lado (`UNION ALL SELECT 'palpite'`) receberia a mesma máscara e viraria um oráculo dentro da execução.
- **TLS em duas camadas:** o `check` recusa `connect` sem `sslmode=verify-full`/`verify-ca` para host remoto (`require` passa com aviso), e o binário gerado recusa de novo na hora de conectar, caso a política tenha sido alterada depois. `crivo init` grava `verify-full` quando a URL não traz `sslmode`.
- **MCP sem clique:** a escrita real pelo servidor MCP exige `--allow-exec` na linha de comando do servidor, porque no MCP não há a aprovação por comando que o VS Code dá ao terminal.
- **`LIMIT`/`OFFSET`** precisam ser constantes inteiras; `WITH TIES` é recusado. O rodapé diferencia o teto da política (`truncado`) do `LIMIT` da própria query.
- **`crivo test -f`** aceita `-- espera: aceito|barrado` antes de cada statement e sai com 2 se algo divergir.
- Tabelas com nome de diretiva (`name`, `limit`, ...) não podem ter regra na v1; partições não aparecem no schema (consulte a tabela-mãe).
