---
name: crivo-vendas
description: "Consulta a base vendas (Postgres, pré-produção) via CLI `vendas`. Base do e-commerce B2B: pedidos, itens, clientes e pagamentos. Use para investigar pedidos, pedido_itens, produtos, clientes e pagamentos, conferir dados de teste ou validar o efeito de uma mudança. Toda query passa pelo Crivo, que valida e pode recusar."
---

# Base vendas (pré-produção)

Você acessa esta base **somente** pelo comando `vendas` no terminal. Toda query passa pelo Crivo: ele analisa o SQL antes de executar e recusa o que a política não permite.

## Comandos

- `vendas tables`: tabelas que você pode usar e o que pode fazer em cada uma.
- `vendas describe <tabela>`: colunas permitidas, tipos e máscaras.
- `vendas query "<SELECT>"`: executa leitura. Saída em TSV com cabeçalho.
- `vendas explain "<SELECT>"`: plano da query, sem executar.
- `vendas exec "<INSERT|UPDATE|DELETE>" --dry-run`: simula uma escrita.
- `vendas exec "<INSERT|UPDATE|DELETE>"`: executa a escrita (pede confirmação ao usuário).
- `vendas policy`: a política completa, com a lista de funções liberadas.

Para SQL com aspas ou várias linhas, grave num arquivo e use `-f arquivo.sql`. Para saída em JSON, use `--format json`.

## O que você pode fazer

| Tabela | Leitura | Escrita | Observações |
| --- | --- | --- | --- |
| pedidos | todas as colunas | update de status, observacao (máx. 20 linhas) | Pedidos de venda. status: aberto \| pago \| enviado \| cancelado |
| pedido_itens | todas as colunas | insert; delete (máx. 5 linhas) | Itens de cada pedido; quantidade sempre > 0 |
| produtos | todas as colunas | — |  |
| clientes | todas menos cpf | — | Clientes PJ. CPF nunca sai do banco; email e telefone saem mascarados; email sai mascarado (parcial); telefone sai como *** |
| pagamentos | todas as colunas | — | Pagamentos confirmados (estornos ficam de fora); só linhas com `status <> 'estornado'`; as demais nunca aparecem |

Qualquer outra tabela não existe para você.

## Regras aplicadas automaticamente

- No máximo 500 linhas por query. Se o rodapé disser `truncado`, refine o filtro ou agregue.
- Timeout de 5s por execução.
- `pagamentos` já vem filtrado (`status <> 'estornado'`). Linhas fora do filtro não aparecem: não conclua que elas não existem.
- Colunas mascaradas (`clientes.email` e `clientes.telefone`) só podem aparecer na lista do SELECT, sem funções em volta, e não podem ser usadas em WHERE, JOIN, ORDER BY ou GROUP BY.
- Colunas bloqueadas (`clientes.cpf`) não podem ser citadas em nenhuma parte da query, nem em filtro.
- `SELECT *` é expandido para as colunas permitidas; prefira listar as colunas que você precisa.
- Só funções comuns de agregação, texto, data, matemática e JSON. Use `vendas policy` se precisar da lista.
- Um statement por chamada, sem `$1`: escreva os valores direto na query.
- UPDATE e DELETE exigem WHERE com uma coluna da tabela; INSERT exige a lista de colunas. Escritas sem teto explícito afetam no máximo 50 linhas; acima do teto o Crivo desfaz tudo.

## Como trabalhar

1. Rode `vendas describe <tabela>` antes de consultar uma tabela pela primeira vez.
2. Comece com consultas pequenas (`LIMIT 20`) e refine.
3. Prefira agregações (`count`, `sum`, `GROUP BY`) a trazer muitas linhas.
4. Use `vendas explain` antes de joins grandes.

## Quando o Crivo recusar

A mensagem traz o motivo, a regra e o que seria aceito. Ajuste a query e tente de novo. Não repita a mesma query. Se a tarefa exigir algo que a política não permite, explique ao usuário qual permissão faltaria e pare: só ele pode mudar a política.

## Escrita

1. Rode sempre `vendas exec "..." --dry-run` primeiro.
2. Mostre ao usuário o SQL e o número de linhas afetadas.
3. Só rode o `exec` real depois da confirmação dele.

## Nunca faça

- Não use `psql`, drivers ou outros clientes para acessar esta base.
- Não tente ler a senha (keychain, variáveis de ambiente, arquivos de configuração).
- Não edite, gere ou recompile a política ou o binário.
- Não divida uma operação recusada em várias menores para contornar o limite.

## Colunas permitidas

### pedidos

| Coluna | Tipo | Nulo | Chave | Máscara |
| --- | --- | --- | --- | --- |
| id | integer | não | PK |  |
| cliente_id | integer | não | FK → clientes.id |  |
| status | text | não |  |  |
| total | numeric(12,2) | não |  |  |
| observacao | text | sim |  |  |

### pedido_itens

| Coluna | Tipo | Nulo | Chave | Máscara |
| --- | --- | --- | --- | --- |
| id | integer | não |  |  |
| quantidade | integer | não |  |  |

### produtos

| Coluna | Tipo | Nulo | Chave | Máscara |
| --- | --- | --- | --- | --- |
| id | integer | não |  |  |
| nome | text | não |  |  |

### clientes

| Coluna | Tipo | Nulo | Chave | Máscara |
| --- | --- | --- | --- | --- |
| id | integer | não | PK |  |
| nome | text | não |  |  |
| email | text | sim |  | partial |
| telefone | text | sim |  | redact |

### pagamentos

| Coluna | Tipo | Nulo | Chave | Máscara |
| --- | --- | --- | --- | --- |
| id | integer | não |  |  |
| status | text | não |  |  |
