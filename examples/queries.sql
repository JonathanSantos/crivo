-- Casos para: crivo test vendas.crivo -f queries.sql
-- Um comentário "-- espera: aceito|barrado" antes do statement define o esperado.

-- espera: aceito
SELECT id, status FROM pedidos;

-- espera: aceito
SELECT * FROM clientes;

-- espera: barrado
SELECT cpf FROM clientes;

-- espera: barrado
SELECT id FROM clientes ORDER BY email;

-- espera: aceito
SELECT * FROM pagamentos p;

-- espera: barrado
SELECT * FROM audit_log;

-- espera: barrado
WITH x AS (DELETE FROM pedidos RETURNING *) SELECT * FROM x;

-- espera: aceito
UPDATE pedidos SET status = 'pago' WHERE id = 1;

-- espera: barrado
UPDATE pedidos SET total = 0 WHERE id = 1;

-- espera: barrado
DELETE FROM pedido_itens WHERE 1 = 1;
