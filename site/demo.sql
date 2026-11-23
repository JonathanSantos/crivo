-- Queries da demo do site. Uma por linha; o build roda cada uma com
-- `crivo test examples/vendas.crivo --schema-sql testdata/schema.sql` e grava
-- a saída real. Linhas com -- são ignoradas.
SELECT * FROM clientes
SELECT cpf FROM clientes
SELECT * FROM pagamentos
SELECT id FROM clientes ORDER BY email
UPDATE pedidos SET status = 'pago' WHERE id = 7
UPDATE pedidos SET total = 0 WHERE id = 7
DELETE FROM pedido_itens WHERE 1 = 1
SELECT * FROM audit_log
DROP TABLE pedidos
