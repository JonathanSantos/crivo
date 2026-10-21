-- Schema de exemplo para os testes de integração e para experimentar o Crivo.
CREATE TABLE clientes (
  id serial PRIMARY KEY,
  nome text NOT NULL,
  cpf text NOT NULL,
  email text,
  telefone text,
  cidade text
);
COMMENT ON TABLE clientes IS 'Clientes PJ';

CREATE TABLE produtos (
  id serial PRIMARY KEY,
  nome text NOT NULL,
  preco numeric(10,2) NOT NULL,
  ativo boolean NOT NULL DEFAULT true
);

CREATE TABLE pedidos (
  id serial PRIMARY KEY,
  cliente_id int NOT NULL REFERENCES clientes(id),
  status text NOT NULL,
  total numeric(12,2) NOT NULL,
  observacao text,
  criado_em timestamp NOT NULL DEFAULT now()
);
COMMENT ON TABLE pedidos IS 'Pedidos de venda';

CREATE TABLE pedido_itens (
  id serial PRIMARY KEY,
  pedido_id int NOT NULL REFERENCES pedidos(id),
  produto_id int NOT NULL REFERENCES produtos(id),
  quantidade int NOT NULL CHECK (quantidade > 0),
  preco numeric(10,2) NOT NULL DEFAULT 0
);

CREATE TABLE pagamentos (
  id serial PRIMARY KEY,
  pedido_id int NOT NULL REFERENCES pedidos(id),
  valor numeric(12,2) NOT NULL,
  status text NOT NULL,
  pago_em timestamp
);

CREATE TABLE audit_log (id serial PRIMARY KEY, acao text);
CREATE TABLE usuarios (id serial PRIMARY KEY, login text, senha_hash text);

INSERT INTO clientes (nome, cpf, email, telefone, cidade) VALUES
  ('Atlas Logística', '123.456.789-01', 'contato@atlaslog.com.br', '(11) 98765-4321', 'Campinas'),
  ('Norte Têxtil', '987.654.321-00', 'financeiro@nortetex.com.br', '(81) 99876-1234', 'Recife'),
  ('Sul Agro', '111.222.333-44', NULL, '(51) 3333-4444', 'Pelotas');

INSERT INTO produtos (nome, preco) VALUES ('Parafuso', 0.50), ('Porca', 0.30), ('Arruela', 0.10);

INSERT INTO pedidos (cliente_id, status, total, observacao, criado_em) VALUES
  (1, 'pago', 1890.00, NULL, '2026-10-14 09:12:03'),
  (2, 'aberto', 230.50, 'urgente', '2026-10-14 10:40:51'),
  (1, 'enviado', 4120.00, NULL, '2026-10-15 08:00:00'),
  (3, 'cancelado', 99.90, 'cliente desistiu', '2026-10-16 14:30:00');

INSERT INTO pedido_itens (pedido_id, produto_id, quantidade, preco) VALUES
  (1, 1, 100, 0.50), (1, 2, 100, 0.30), (2, 3, 50, 0.10), (3, 1, 10, 0.50);

INSERT INTO pagamentos (pedido_id, valor, status, pago_em) VALUES
  (1, 1890.00, 'confirmado', '2026-10-14 12:00:00'),
  (3, 4120.00, 'confirmado', '2026-10-15 09:00:00'),
  (2, 230.50, 'estornado', '2026-10-14 11:00:00'),
  (4, 99.90, 'pendente', NULL);

INSERT INTO audit_log (acao) VALUES ('login'), ('logout');
INSERT INTO usuarios (login, senha_hash) VALUES ('admin', 'x');
