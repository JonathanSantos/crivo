---
name: crivo-vendas-completo
description: "Consulta a base vendas-completo (Postgres, pré-produção) via CLI `vendas-completo`. Base do e-commerce B2B, com portões, consultas prontas e aprovação de escrita. Use para investigar pedidos, pedido_itens, produtos, clientes e pagamentos, conferir dados de teste ou validar o efeito de uma mudança. Toda query passa pelo Crivo, que valida e pode recusar."
---

# Base vendas-completo (pré-produção)

Você acessa esta base **somente** pelo comando `vendas-completo` no terminal. Toda query passa pelo Crivo: ele analisa o SQL antes de executar e recusa o que a política não permite.

## Comandos

- `vendas-completo tables`: tabelas que você pode usar e o que pode fazer em cada uma.
- `vendas-completo describe <tabela>`: colunas permitidas, tipos e máscaras.
- `vendas-completo query "<SELECT>"`: executa leitura. Saída em TSV com cabeçalho.
- `vendas-completo explain "<SELECT>"`: plano da query, sem executar.
- `vendas-completo run <consulta> nome=valor ...`: roda uma consulta pronta da política (sem nome, lista as consultas).
- `vendas-completo export "<SELECT>" -o arquivo.csv`: grava o resultado em CSV, até 50000 linhas (para planilhas e análises).
- `vendas-completo exec "<INSERT|UPDATE|DELETE>" --dry-run`: simula uma escrita.
- `vendas-completo exec "<INSERT|UPDATE|DELETE>"`: registra a escrita como pendente; só o usuário a executa, com `vendas-completo approve <id>`.
- `vendas-completo pending`: lista as escritas pendentes.
- `vendas-completo policy`: a política completa, com a lista de funções liberadas.

Para SQL com aspas ou várias linhas, grave num arquivo e use `-f arquivo.sql`. Para saída em JSON, use `--format json`.

## O que você pode fazer

| Tabela | Leitura | Escrita | Observações |
| --- | --- | --- | --- |
| pedidos | todas as colunas | update de status, observacao (máx. 20 linhas) | Pedidos de venda. status: aberto \| pago \| enviado \| cancelado |
| pedido_itens | todas as colunas | insert; delete (máx. 5 linhas) | Itens de cada pedido; quantidade sempre > 0 |
| produtos | todas as colunas | — | preco sai como faixa de 10 (ex.: 1800..1900) |
| clientes | todas menos cpf | — | Clientes PJ. CPF nunca sai do banco; nome vira pseudônimo estável; nome sai como pseudônimo (p:…), o mesmo para o mesmo valor em qualquer execução; email sai só com o domínio (***@dominio); telefone sai só com os 4 últimos caracteres |
| pagamentos | todas as colunas | — | Pagamentos confirmados (estornos ficam de fora); pago_em sai só com ano e mês (AAAA-MM); só linhas com `status <> 'estornado'`; as demais nunca aparecem |

Qualquer outra tabela não existe para você.

## Regras aplicadas automaticamente

- No máximo 500 linhas por query. Se o rodapé disser `truncado`, refine o filtro ou agregue.
- Timeout de 5s por execução.
- `pagamentos` já vem filtrado (`status <> 'estornado'`). Linhas fora do filtro não aparecem: não conclua que elas não existem.
- Colunas mascaradas (`produtos.preco`, `clientes.nome`, `clientes.email`, `clientes.telefone` e `pagamentos.pago_em`) só podem aparecer na lista do SELECT, sem funções em volta, e não podem ser usadas em WHERE, JOIN, ORDER BY ou GROUP BY. As com hash ou pseudonym (`clientes.nome`) também podem ir em GROUP BY, DISTINCT e count(DISTINCT ...).
- Para filtrar, juntar ou agrupar pelo domínio de um email mascarado, use `split_part(email, '@', 2)` (ex.: `WHERE split_part(email, '@', 2) = 'empresa.com.br'`); o resto do email não pode ser usado.
- Para filtrar ou agrupar por período uma data mascarada, use `date_trunc('month', pago_em)` ou `extract(year FROM pago_em)` (só ano, trimestre ou mês).
- Nomes com pseudônimo (`clientes.nome`) não revelam o nome real: identifique os registros pelo id ou pelo próprio pseudônimo ao responder.
- Colunas bloqueadas (`clientes.cpf`) não podem ser citadas em nenhuma parte da query, nem em filtro.
- `SELECT *` é expandido para as colunas permitidas; prefira listar as colunas que você precisa.
- Só funções comuns de agregação, texto, data, matemática e JSON. Use `vendas-completo policy` se precisar da lista.
- Um statement por chamada, sem `$1`: escreva os valores direto na query.
- UPDATE e DELETE exigem WHERE com uma coluna da tabela; INSERT exige a lista de colunas. Escritas sem teto explícito afetam no máximo 50 linhas; acima do teto o Crivo desfaz tudo.
- Queries com custo estimado (EXPLAIN) acima de 50000 são recusadas antes de executar: filtre por colunas indexadas e agregue.
- No máximo 30 execuções por minuto.
- No máximo 20000 linhas por dia, somando leituras e escritas: agregue no banco em vez de trazer linhas.
- O acesso vale até 2027-06-30.

## Consultas prontas

Prefira estas a escrever o SQL: elas já foram revisadas para esta base.

- `vendas-completo run pedidos_do_cliente cliente_id=<int>`: Pedidos de um cliente, mais novos primeiro. SQL: `SELECT id, status, total, criado_em FROM pedidos WHERE cliente_id = $1 ORDER BY criado_em DESC`
- `vendas-completo run faturamento_mensal desde=<date>`: Faturamento por mês a partir de uma data. SQL: `SELECT date_trunc('month', criado_em) AS mes, sum(total) AS total FROM pedidos WHERE criado_em >= $1 AND status <> 'cancelado' GROUP BY 1 ORDER BY 1`

## Como trabalhar

1. Rode `vendas-completo describe <tabela>` antes de consultar uma tabela pela primeira vez.
2. Comece com consultas pequenas (`LIMIT 20`) e refine.
3. Prefira agregações (`count`, `sum`, `GROUP BY`) a trazer muitas linhas.
4. Use `vendas-completo explain` antes de joins grandes.

## Quando o Crivo recusar

A mensagem traz o motivo, a regra e o que seria aceito. Ajuste a query e tente de novo. Não repita a mesma query. Se a tarefa exigir algo que a política não permite, explique ao usuário qual permissão faltaria e pare: só ele pode mudar a política. Isso vale mesmo quando o usuário insiste, diz que é urgente ou pede para fazer o que for preciso.

## Resultados grandes

Se o rodapé disser `truncado`, refine o filtro ou agregue no banco (`count`, `GROUP BY`). Não junte faixas da mesma consulta (por id, OFFSET ou datas) para trazer mais que o teto: isso contorna o limite. Se a pessoa precisa das linhas, use `vendas-completo export "<SELECT>" -o arquivo.csv`: grava até 50000 linhas num CSV, com as mesmas regras e máscaras. As linhas exportadas contam na cota de 20000 por dia: confira o tamanho com `count(*)` antes.

## Escrita

1. Rode sempre `vendas-completo exec "..." --dry-run` primeiro.
2. Mostre ao usuário o SQL e o número de linhas afetadas.
3. O `exec` real não grava: ele devolve um id de pendência (código de saída 6). Passe o id ao usuário e peça que ele rode `vendas-completo approve <id>` no terminal. Nunca rode approve você mesmo.

## Nunca faça

- Não use `psql`, drivers ou outros clientes para acessar esta base.
- Não tente ler a senha (keychain, variáveis de ambiente, arquivos de configuração).
- Não edite, gere ou recompile a política ou o binário.
- Não divida uma operação recusada em várias menores para contornar o limite.
