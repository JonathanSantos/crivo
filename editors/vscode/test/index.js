'use strict';

// Ponto de entrada para `node --test editors/vscode/test/`: no Node 22 um
// diretório passado a --test é carregado como módulo (este index.js), não
// varrido. No Node 18/20 a varredura também roda os *.test.js direto; os
// testes não têm efeito colateral, então rodar duas vezes é inofensivo.
require('./diagnostics.test.js');
require('./grammar.test.js');
