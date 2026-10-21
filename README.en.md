<h1 align="center"><img src="docs/img/hero.en.svg" width="100%" alt="Crivo: every query goes through the sieve"></h1>

<p align="center">
<a href="https://github.com/JonathanSantos/crivo/releases/latest"><img src="https://img.shields.io/github/v/release/JonathanSantos/crivo?label=download&logo=github" alt="Download"></a>
<a href="https://github.com/JonathanSantos/crivo/actions/workflows/ci.yml"><img src="https://github.com/JonathanSantos/crivo/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
</p>

<p align="center"><a href="#installation">Installation</a> · <a href="#workflow">Workflow</a> · <a href="#the-policy">Policy</a> · <a href="#commands">Commands</a> · <a href="#read-only-user-the-recommended-strategy">Read-only user</a> · <a href="#copilot-integration">Copilot</a> · <a href="#mcp-optional">MCP</a></p>

**Download a prebuilt binary** ([all versions](https://github.com/JonathanSantos/crivo/releases)): [macOS Apple Silicon](https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-macos-arm64) · [macOS Intel](https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-macos-amd64) · [Linux x86_64](https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-linux-amd64) · [Windows x86_64](https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-windows-amd64.exe)

*Crivo* is Portuguese for "sieve". **Every query goes through the sieve.** Crivo turns a policy file (`.crivo`) into a local CLI for a pre-production Postgres, plus a skill that teaches GitHub Copilot in VS Code how to use it. Every query the AI sends goes through the real Postgres parser (pg_query) before it reaches the database, and only what the policy allows is executed.

- **Deny by default:** what the policy does not mention does not exist for the AI.
- **Fail closed:** ambiguous column, unknown AST node or function outside the allowlist: refused.
- **Executes what it validated:** the database receives the deparse of the validated and rewritten AST, never the original string. That deparse is parsed and checked again.
- **Layers:** AST + `READ ONLY` transaction + `statement_timeout` + mandatory TLS (+ least-privilege user, see below).
- **Errors that teach:** every refusal states the rule, the reason and what would be accepted.
- **Optional MCP:** the same binary serves the policy as an MCP server (`vendas mcp`) for any AI client. CLI + skill remains the primary mode.

<p align="center"><img src="docs/img/guard.en.svg" width="100%" alt="The path of a query: parse, policy, rewrite, re-check, execute and mask"></p>

> [!WARNING]
> The adversary is the AI, not a person. Anyone with access to the machine can pull the password from the keychain or tamper with the binary. Never use production credentials and do not distribute generated binaries.

## Installation

**Prebuilt binary** (no Go or C compiler needed): grab the file for your platform from the [releases page](https://github.com/JonathanSantos/crivo/releases/latest) or with `curl`. Downloading from the terminal avoids macOS Gatekeeper quarantine, which refuses binaries without a developer signature when they come from a browser.

```bash
# macOS Apple Silicon (use crivo-macos-amd64 on Intel, crivo-linux-amd64 on Linux)
curl -fsSL https://github.com/JonathanSantos/crivo/releases/latest/download/crivo-macos-arm64 -o crivo
chmod +x crivo && sudo mv crivo /usr/local/bin/
crivo version
```

On Windows, download `crivo-windows-amd64.exe`, rename it to `crivo.exe` and put it in a folder on your `PATH`. Every release ships a `checksums.txt` with the SHA-256 of all binaries.

**Building from source:** requires Go 1.26+ and a C compiler (pg_query uses cgo): Xcode CLT on macOS, `gcc` on Linux, MinGW-w64 on Windows.

```bash
make build        # produces bin/crivo
```

CI (`.github/workflows/ci.yml`) builds and tests natively on Linux, macOS and Windows on every push. A `vX.Y.Z` tag (`make tag TAG=vX.Y.Z`) triggers the `release` job, which publishes the binaries for the three platforms on GitHub Releases.

## Workflow

<p align="center"><img src="docs/img/flow.en.svg" width="100%" alt="Crivo workflow, from crivo init to Copilot querying Postgres"></p>

```bash
crivo init "postgres://svc_app@pg-hml.internal:5432/vendas?sslmode=verify-full"   # writes vendas.crivo, everything denied
$EDITOR vendas.crivo                                                             # open up what the AI may do
crivo secret set vendas                                                          # password in the OS keychain
crivo check vendas.crivo                                                         # syntax, semantics and real schema
crivo test vendas.crivo "SELECT * FROM clientes"                                 # decision + rewritten SQL
crivo build vendas.crivo                                                         # produces ./vendas
./vendas skill install                                                           # .github/skills/crivo-vendas/SKILL.md
./vendas skill vscode                                                            # auto-approve snippet for settings.json
./vendas skill mcp                                                               # (optional) MCP server configuration
```

From then on Copilot (agent mode) queries the database by calling `vendas` in the terminal. If you prefer MCP, point your client at `vendas mcp` (see [MCP](#mcp-optional)).

## The policy

```
name    vendas
about   "B2B e-commerce database: orders, items, customers and payments"
env     preprod
connect postgres://svc_app@pg-hml.internal:5432/vendas?sslmode=verify-full
secret  keychain
limit   500 rows
timeout 5s

## Sales orders. status: aberto | pago | enviado | cancelado
pedidos         read, update(status, observacao) max 20
pedido_itens    read, insert, delete max 5
produtos        read
## Business customers. CPF never leaves the database; email and phone come out masked
clientes        read except(cpf) mask(email: partial, telefone: redact)
pagamentos      read where status <> 'estornado'
audit_*         deny
```

Full example in [examples/vendas.crivo](examples/vendas.crivo) and test cases in [examples/queries.sql](examples/queries.sql) (`crivo test vendas.crivo -f queries.sql`). The policy language keywords are English; messages, the generated skill and the CLI help are in Portuguese.

| Construct | Effect |
| --- | --- |
| `connect` | URL without a password, with verified TLS: `sslmode=verify-full` (or `verify-ca`). `require` passes with a warning (it does not verify the certificate). No `sslmode`, or `disable`/`prefer`, is accepted only for a local host, with a warning. Internal CA: add `sslrootcert=/path/ca.crt`. |
| `read`, `insert`, `update`, `delete` | The four actions. DDL, `TRUNCATE`, `COPY`, `CALL`, `DO`, `SET`, `GRANT`... never pass. |
| `(a, b)` / `except(x)` | Columns the action reaches. A blocked column cannot even appear in a filter. |
| `where <expr>` | Row filter: on reads the table becomes a filtered subquery (keeping the alias); on `update`/`delete` it is `AND`ed into the `WHERE`. Extends to the next top-level comma. |
| `max N` | Cap on rows affected by a write (default 50). Above it: rollback and refusal. |
| `limit N` | Per-table cap on rows per query (lower than the global one). |
| `mask(col: partial\|redact\|hash)` | Mask applied to the result. A masked column may only appear bare in the SELECT list. |
| `deny` / no rule | The table does not exist for the AI. `pg_*`, `pg_catalog` and `information_schema` are always blocked. |
| `## text` | Table description for the skill and for `describe` (must sit right above the rule). |
| line starting with a space | Continues the previous rule. |

Precedence: exact name beats pattern; among patterns, the longest literal prefix; on a tie, `deny` wins.

## Commands

**Tool (`crivo`, no embedded policy):** `init`, `check`, `test`, `build`, `grants`, `secret set|rm`, `version`. None of them executes SQL from the AI.

**Generated binary (`vendas`, base mode):** `policy`, `tables`, `describe <table>`, `query "<sql>"`, `explain "<sql>"`, `exec "<sql>" [--dry-run]`, `skill [install|vscode|mcp]`, `refresh`, `mcp [--allow-exec]`. Flags: `--format tsv|json|table`, `--json-errors`, `-f file.sql`. The mode is decided by the embedded slot; there is no flag or variable that switches modes, so the AI cannot reach `build` through a generated binary.

Exit codes: `0` success, `1` bug, `2` refused by Crivo, `3` invalid SQL, `4` database error, `5` missing configuration or secret.

## Read-only user: the recommended strategy

The policy works on its own, but it is much stronger as a **second layer** on top of a least-privilege database user. Crivo helps on both ends:

<p align="center"><img src="docs/img/layers.en.svg" width="100%" alt="Crivo defense layers"></p>

1. **`crivo check` audits the connection user.** When it connects, it warns if the user is a superuser, owns tables, has `BYPASSRLS`, or can `INSERT/UPDATE/DELETE/TRUNCATE` beyond what the policy allows.
2. **`crivo grants vendas.crivo` generates the SQL for the ideal user** from the policy itself: `GRANT SELECT` only on the allowed tables, `GRANT SELECT (columns)` where there is an `except` (the database itself then refuses `cpf`), `GRANT UPDATE (status, observacao)`, `DELETE` only where there is `delete`, `default_transaction_read_only = on` when the policy has no writes, `statement_timeout` on the role, and RLS suggestions for the `where` filters.

Recommendation by scenario:

| Scenario | User |
| --- | --- |
| Read-only policy | Read-only user (`crivo grants` generates it with `default_transaction_read_only`). The `exec` command does not even exist in the binary. |
| Policy with writes | User with the per-table/per-column GRANTs generated by `crivo grants`. `READ ONLY` keeps protecting `query`/`explain`. |
| DBA will not create a user | Works, but `check` warns about the excess privilege. In that case keep `max` low and leave `exec` auto-approve off. |

Crivo lists columns instead of `*` (including inside filter subqueries), so it works with per-column `GRANT`.

## Copilot integration

`vendas skill install` writes `<workspace root>/.github/skills/crivo-vendas/SKILL.md` (or `--personal` for `~/.copilot/skills`, `--dir` for another folder). The skill is generated from the embedded policy, is deterministic and never contains host, user or URL. `--with-schema` appends the allowed columns.

`vendas skill vscode` prints the `chat.tools.terminal.autoApprove` rules: reads and `--dry-run` without confirmation, real `exec` always asking for the user's click. Check that your VS Code version honours the rules ([microsoft/vscode#324059](https://github.com/microsoft/vscode/issues/324059)).

## MCP (optional)

The generated binary also speaks [MCP](https://modelcontextprotocol.io) over stdio: `vendas mcp`. The tools are the same operations as the CLI (`tables`, `describe`, `policy`, `query`, `explain`, `exec`), going through the same guard, with the same refusal messages (delivered to the model as tool error results) and the same audit log (command prefixed with `mcp:`). The server instructions are the short equivalent of the skill.

```bash
./vendas skill mcp                 # prints the configuration for VS Code (.vscode/mcp.json), Claude Code and Claude Desktop
./vendas mcp                       # what the client runs; writes are simulated only (dry_run)
./vendas mcp --allow-exec          # allows dry_run=false on the exec tool
```

One important difference from the CLI: in the terminal, a real `exec` goes through the VS Code approval click. MCP has no such click by default, so real writes stay **off** until the user starts the server with `--allow-exec`. Even with the flag, the tool is annotated as destructive and the instructions tell the model to simulate first and ask for confirmation. Each call opens and closes its own connection; there is no resident process holding a connection.

The AI cannot reach the flag: it lives in the client configuration, which only the user edits.

## Platforms

- **macOS:** `build` re-signs the binary with `codesign --force --sign -` (the patch is in-place in the slot, without appending bytes, which is why signing remains possible). Password in the Keychain.
- **Linux:** password via Secret Service (gnome-keyring/KWallet). Without a keyring, use `secret env:VAR` for tests only.
- **Windows:** password in Credential Manager. The icon comes from `cmd/crivo/winres/winres.json` (`make winres` regenerates the `.syso` files); generated binaries inherit the icon because they are copies.

Local files: schema cache in `~/.cache/crivo/<name>/schema.json` (10 min TTL, honours `XDG_CACHE_HOME`), audit log in `~/.crivo/logs/<name>.jsonl` (no result data).

## Development

```bash
make test                                                    # unit, golden files, slot with a real binary
CRIVO_TEST_DSN=postgres://postgres:password@localhost:5432/postgres make test-integration
make fuzz                                                    # go test -fuzz on sqlguard.Guard
```

Integration tests use `CRIVO_TEST_DSN` (the test creates and drops the `crivo_it` schema) or, without it, testcontainers-go when Docker is available; with neither, they are skipped. They exercise the generated binary in both modes, CLI and MCP (the latter as a subprocess, through a real MCP client). Golden files are regenerated with `go test ./internal/policy ./internal/skill -update`.

```
cmd/crivo            reads the slot and dispatches: tool mode or base mode
internal/slot        64 KiB slot, read and in-place patch
internal/policy      lexer, parser, validation, rule resolution
internal/sqlguard    pg_query, checks, rewrites, deparse and re-check
internal/schema      pg_catalog introspection and on-disk cache
internal/run         pgx, transactions, SET LOCAL, row caps
internal/mask        partial, redact, hash
internal/output      TSV/JSON/table, messages, exit codes
internal/secret      keychain, env, prompt
internal/skill       SKILL.md, install, settings.json, MCP config
internal/audit       JSONL log
internal/cli/...     CLIs (kong) for both modes; base/mcp.go is the MCP server
```

## Implementation decisions

Places where the specification left room, and what was chosen:

- **Re-checking the deparse:** besides running every check on the rewritten SQL, Crivo requires the re-parse to produce exactly the same AST (ignoring positions). If it does not, it refuses.
- **AST coverage:** after analysis, every column, table and function in the tree must have gone through the analyzer; if a new parser field carries something unanalyzed, the query is refused.
- **Read filter** becomes `(SELECT <readable columns> FROM t WHERE ...) AS t` instead of `SELECT *`, so it works with per-column `GRANT`.
- **`update`/`delete` also get the `read` filter:** a row invisible to reads is not changed either (nor does it serve as an oracle through the affected-row count).
- **Columns named in a write's `WHERE`, `SET` and `RETURNING` need `read`**, for the same reason.
- **Masks:** `hash` is HMAC-SHA256 with a random key per execution (stable within the execution, without allowing guesses to be confirmed across executions). A masked column does not pass through `UNION`/`INTERSECT`/`EXCEPT`, nor through scalar/`IN` subquery lists (only `EXISTS`), nor through `INSERT ... SELECT`. In `UNION ALL` both sides must be exactly the same column: the output mask is applied by position to every row, so a value chosen in the query on the other side (`UNION ALL SELECT 'guess'`) would receive the same mask and become an oracle within the execution.
- **TLS in two layers:** `check` refuses a `connect` without `sslmode=verify-full`/`verify-ca` for a remote host (`require` passes with a warning), and the generated binary refuses again when connecting, in case the policy was changed afterwards. `crivo init` writes `verify-full` when the URL has no `sslmode`.
- **MCP without a click:** real writes through the MCP server require `--allow-exec` on the server command line, because MCP has no per-command approval like the one VS Code gives the terminal.
- **`LIMIT`/`OFFSET`** must be integer constants; `WITH TIES` is refused. The footer distinguishes the policy cap (`truncado`) from the query's own `LIMIT`.
- **`crivo test -f`** accepts `-- espera: aceito|barrado` before each statement and exits with 2 if anything diverges.
- Tables named like a directive (`name`, `limit`, ...) cannot have a rule in v1; partitions do not appear in the schema (query the parent table).
