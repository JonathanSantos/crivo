# ADR 0001: portões no binário, consultas nomeadas e aprovação de escrita

Data: 2026-11-23. Situação: aceito.

## Contexto

Até a v0.1.4, o único controle além do guard era o clique de aprovação do VS Code para o `exec` real. No MCP não há clique, então a escrita real ficava desligada (ou liberada de vez com `--allow-exec`). Faltavam também prazo de acesso, limite de uso, teto de custo e um jeito de oferecer consultas revisadas para a IA.

## Decisões

1. **Portões abaixo do CLI e do MCP.** `expires`, `rate`, `quota`, `cost` e `approval` são conferidos dentro dos comandos (que o servidor MCP também chama), a cada chamada. O teto de custo fica no pacote `run`, dentro da transação, com `EXPLAIN (FORMAT JSON)` antes de executar; vale para `query`, `exec`, `run` e `describe --sample` (não para `explain`).
2. **Os recursos são opcionais.** Sem as diretivas novas, os comandos e a política funcionam como na v0.1.4, exceto pelas correções de segurança dos itens 7 e 8, que mudam o SQL reescrito, o desempenho de tabelas com `where` e recusam alguns `NATURAL JOIN`. Mudança incompatível: `expires`, `cost`, `rate`, `quota`, `approval`, `audit` e `query` passam a ser diretivas e não podem mais ser nome de tabela.
3. **Consultas nomeadas são só leitura e não ganham privilégio.** O SQL usa `$1..$n`; a cada chamada os valores viram constantes tipadas na árvore do parser (nunca substituição de texto) e o resultado passa pelo guard inteiro. O `check` valida cada consulta com valores de exemplo contra o schema.
4. **Aprovação de escrita.** Com `approval writes`, o `exec` real valida, simula (aplicando o teto de linhas) e grava uma pendência local (`~/.crivo/pending/<name>/<id>.json`, 1 hora). `approve` exige terminal interativo e o id digitado de novo, não existe no MCP e tem regra explícita de clique no `skill vscode`. O SQL original é revalidado na aprovação; o reescrito guardado é só informativo. Código de saída novo: `6`.
5. **`rate` e `quota` contam pela auditoria**, que passa a ter rotação (10 MB, 3 arquivos) lida inteira na contagem. Sem auditoria legível e gravável, a execução é recusada. São travas contra IA em loop, não fronteira de segurança: quem tem a máquina apaga o log.
6. **Máscaras novas falham fechado.** Valor que o modo não entende sai `***`. `pseudonym` usa uma chave aleatória por política em `~/.crivo/keys/<name>.key`: é estável entre execuções nesta máquina, o que permite cruzar resultados e comparar igualdade entre execuções (o `hash` continua estável só dentro de uma execução). Sem a chave, a query é recusada.

7. **Filtro de linha como barreira de otimização** (achado pelo fuzz de vazamentos e confirmado no Postgres). Na leitura, a subquery do filtro termina em `OFFSET 0`; na escrita, o `WHERE` da IA vai em `CASE WHEN <filtros> THEN <where> ELSE false END`. Sem isso, o planner avaliava funções da query em linhas escondidas, e o erro (ou a falta dele) e a mensagem do erro revelavam essas linhas. Mensagens de erro de dado e de restrição saem sem os valores entre aspas.

   **Custo medido** (1 milhão de linhas, 10% escondidas pelo filtro, Postgres 16 local): leitura por chave primária 0,016 ms → 80 ms; por índice 0,2 ms → 88 ms; agregação 25 ms → 96 ms (perde o paralelismo); `UPDATE` por chave 0,19 ms → 42 ms. A barreira impede o uso de índice pela condição da query na tabela filtrada, e o custo estimado sobe junto (afeta a diretiva `cost`). Tabelas sem `where` não mudam. Alternativa a estudar: copiar para dentro da barreira só as condições simples e à prova de vazamento (comparação de coluna com constante usando operadores `leakproof`), que recuperaria o índice nos casos comuns.

8. **Nomes de coluna como o Postgres** (achado pelo fuzz). `NATURAL JOIN` com uma coluna que o guard nomeava `?column?` e o Postgres chamava de `coalesce` comparava uma coluna mascarada sem checagem. O guard segue o FigureColname do Postgres e recusa `NATURAL JOIN` com coluna sem nome.

9. **Simulação com agentes** (cinco cenários com Sonnet 5.5, ver o relatório da sessão). Viraram mudanças:
   - **`export N rows`:** caminho legítimo para resultados grandes, com teto próprio, CSV, cota e auditoria. A skill passa a dizer que juntar faixas da mesma consulta para passar do teto é contornar o limite.
   - **Derivações visíveis:** o domínio de uma coluna com máscara `email` (`split_part(col, '@', 2)`) e o ano, trimestre ou mês de uma com máscara `month` (`date_trunc`, `extract`, `date_part`) podem filtrar, juntar e agrupar, porque só revelam o que a máscara já mostra. Para isso, a máscara `email` passou a cortar no primeiro `@`, igual ao `split_part`. Um teste de integração confere, linha a linha, que a derivação é igual à saída mascarada.
   - **Textos:** a pendência diz "nada foi gravado ainda" e quem aprova; o rodapé do `LIMIT` diz que há mais linhas; a lista de consultas prontas mostra o SQL; a skill fala de pseudônimo e de pressão do usuário.

## Fora do escopo

Assinatura de código (precisa de certificados), winget (PR externo) e Windows arm64 (toolchain cgo não verificado no runner ARM).
