-- Fixture do leak fuzzer (TestLeakFuzz). Roda com search_path no schema
-- crivo_fz. Todo valor protegido carrega um token zq<k><nn>kw<k> (letras
-- fora do hexadecimal, para não colidir com a saída do hash) e nenhum valor
-- liberado contém esses tokens. Linhas escondidas pelo where têm ids 97001+,
-- 97101+ e valor 98765.xx, que só existem nelas; ficam no começo e no meio
-- do heap, para que um erro numa linha escondida apareça antes do das visíveis.

CREATE TABLE clientes (
    id        int PRIMARY KEY,
    nome      text,          -- mask hash
    cpf       text,          -- except (bloqueada)
    email     text,          -- mask partial
    telefone  text,          -- mask redact
    cidade    text,
    criado_em date
);
INSERT INTO clientes VALUES
 (1, 'Nome zqn01kwn', 'zqp01kwp', 'zqm01kwm.contato@fz.example', '+55 zqt01kwt', 'Recife', '2024-01-10'),
 (2, 'Nome zqn02kwn', 'zqp02kwp', 'zqm02kwm.vendas@fz.example',  '+55 zqt02kwt', 'Natal',  '2024-02-11'),
 (3, 'Nome zqn03kwn', 'zqp03kwp', 'zqm03kwm.compras@fz.example', '+55 zqt03kwt', 'Belem',  '2024-03-12'),
 (4, 'Nome zqn04kwn', 'zqp04kwp', 'zqm04kwm.fin@fz.example',     NULL,           'Recife', '2024-04-13'),
 (5, 'Nome zqn05kwn', 'zqp05kwp', 'zqm05kwm.adm@fz.example',     '+55 zqt05kwt', 'Olinda', '2024-05-14'),
 (6, 'Nome zqn06kwn', 'zqp06kwp', NULL,                          '+55 zqt06kwt', 'Natal',  '2024-06-15');

CREATE TABLE pedidos (
    id         int PRIMARY KEY,
    cliente_id int,
    status     text,
    total      numeric(10,2),
    observacao text
);
INSERT INTO pedidos VALUES
 (1, 1, 'aberto',    10.50, 'urgente'),
 (2, 2, 'pago',      21.00, NULL),
 (3, 3, 'enviado',   31.50, 'fragil'),
 (4, 1, 'cancelado', 42.00, NULL),
 (5, 5, 'pago',      52.50, 'presente'),
 (6, 6, 'aberto',    63.00, NULL);

CREATE TABLE itens (
    id         serial PRIMARY KEY,
    pedido_id  int,
    produto    text,
    quantidade int
);
INSERT INTO itens (pedido_id, produto, quantidade) VALUES
 (1, 'caneta', 2), (1, 'papel', 5), (2, 'grampo', 1), (3, 'pasta', 3), (5, 'cola', 4);

CREATE TABLE pagamentos (
    id        int PRIMARY KEY,
    pedido_id int,
    valor     numeric(10,2),
    status    text,
    ref       text
);
INSERT INTO pagamentos VALUES
 (97001, 1, 98765.43, 'estornado', 'zqr01kwr'),
 (1,    1, 20.10,    'pago',      'PG-001'),
 (2,    2, 20.20,    'pago',      'PG-002'),
 (3,    3, 20.30,    'pendente',  'PG-003'),
 (97002, 2, 98765.44, 'estornado', 'zqr02kwr'),
 (4,    5, 20.40,    'pago',      'PG-004'),
 (5,    6, 20.50,    'pendente',  NULL);

CREATE TABLE contatos (
    id         int PRIMARY KEY,
    cliente_id int,
    apelido    text,          -- mask hash
    documento  text,          -- except (bloqueada)
    telefone   text,          -- mask partial
    status     text,
    obs        text
);
INSERT INTO contatos VALUES
 (97101, 1, 'zqa91kwa', 'zqd91kwd', '+55 zqf91kwf', 'inativo', 'zqh01kwh'),
 (1,    1, 'zqa01kwa', 'zqd01kwd', '+55 zqf01kwf', 'ativo',   'contato um'),
 (2,    2, 'zqa02kwa', 'zqd02kwd', '+55 zqf02kwf', 'ativo',   'contato dois'),
 (97102, 2, 'zqa92kwa', 'zqd92kwd', '+55 zqf92kwf', 'INATIVO', 'zqh02kwh'),
 (3,    3, 'zqa03kwa', 'zqd03kwd', NULL,           'ativo',   NULL),
 (4,    5, 'zqa04kwa', 'zqd04kwd', '+55 zqf04kwf', 'Ativo',   'contato quatro');

CREATE TABLE audit_log (
    id      int PRIMARY KEY,
    actor   text,
    detalhe text
);
INSERT INTO audit_log VALUES (1, 'zqu01kwu', 'login zqu11kwu'), (2, 'zqu02kwu', 'export zqu12kwu');

CREATE TABLE notas (
    id    int PRIMARY KEY,
    texto text
);
INSERT INTO notas VALUES (1, 'zqx01kwx'), (2, 'zqx02kwx');
