-- Criação do banco de dados
CREATE DATABASE IF NOT EXISTS INVENTARIO;

-- Tabela USUARIO ---
CREATE TABLE IF NOT EXISTS USUARIO (
    IDUSUARIO INT NOT NULL AUTO_INCREMENT,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    SENHA VARCHAR(100) NOT NULL,
    EMAIL VARCHAR(60) NOT NULL, 
    DATACENTER VARCHAR(10) NOT NULL, 
    NIVEL_ACESSO VARCHAR(50) NOT NULL,
    DATACADASTRO DATE NOT NULL,
    PRIMEIRO_LOGIN TINYINT(1) DEFAULT 1,
    PRIMARY KEY (IDUSUARIO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela MATERIAL
CREATE TABLE IF NOT EXISTS MATERIAL (
    IDMATERIAL INT NOT NULL AUTO_INCREMENT,
    MATERIAL VARCHAR(50) NOT NULL,
    PRIMARY KEY (IDMATERIAL)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela CONECTOR
CREATE TABLE IF NOT EXISTS CONECTOR (
    IDCONECTOR INT NOT NULL AUTO_INCREMENT,
    CONECTOR VARCHAR(50) NOT NULL,
    PRIMARY KEY (IDCONECTOR)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela METRAGEM
CREATE TABLE IF NOT EXISTS METRAGEM (
    IDMETRAGEM INT NOT NULL AUTO_INCREMENT,
    METRAGEM VARCHAR(50) NOT NULL,
    PRIMARY KEY (IDMETRAGEM)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela MODELO
CREATE TABLE IF NOT EXISTS MODELO (
    IDMODELO INT NOT NULL AUTO_INCREMENT,
    MODELO VARCHAR(50) NOT NULL,
    PRIMARY KEY (IDMODELO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela FORNECEDOR
CREATE TABLE IF NOT EXISTS FORNECEDOR (
    IDFORNECEDOR INT NOT NULL AUTO_INCREMENT,
    FORNECEDOR VARCHAR(50) NOT NULL,
    PRIMARY KEY (IDFORNECEDOR)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela GRUPO
CREATE TABLE IF NOT EXISTS GRUPO (
    IDGRUPO INT NOT NULL AUTO_INCREMENT,
    GRUPO VARCHAR(50) NOT NULL,
    PRIMARY KEY (IDGRUPO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela LOCALIZACAO
CREATE TABLE IF NOT EXISTS LOCALIZACAO (
    IDLOCALIZACAO INT NOT NULL AUTO_INCREMENT,
    LOCALIZACAO VARCHAR(50) NOT NULL,
    PRIMARY KEY (IDLOCALIZACAO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela PRODUTO
CREATE TABLE IF NOT EXISTS PRODUTO (
    IDPRODUTO INT NOT NULL AUTO_INCREMENT,
    IDMATERIAL INT NOT NULL,
    IDCONECTOR INT NOT NULL,
    IDMETRAGEM INT NOT NULL,
    IDMODELO INT NOT NULL,
    IDFORNECEDOR INT NOT NULL,
    DATACADASTRO DATE NOT NULL,
    IDDATACENTER INT NOT NULL,
    IDGRUPO INT NOT NULL,
    IDLOCALIZACAO INT NOT NULL,
    PRIMARY KEY (IDPRODUTO),
    FOREIGN KEY (IDMATERIAL) REFERENCES MATERIAL (IDMATERIAL),
    FOREIGN KEY (IDCONECTOR) REFERENCES CONECTOR (IDCONECTOR),
    FOREIGN KEY (IDMETRAGEM) REFERENCES METRAGEM (IDMETRAGEM),
    FOREIGN KEY (IDMODELO) REFERENCES MODELO (IDMODELO),
    FOREIGN KEY (IDFORNECEDOR) REFERENCES FORNECEDOR (IDFORNECEDOR),
    FOREIGN KEY (IDGRUPO) REFERENCES GRUPO (IDGRUPO),
    FOREIGN KEY (IDLOCALIZACAO) REFERENCES LOCALIZACAO (IDLOCALIZACAO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela ESTOQUE
CREATE TABLE IF NOT EXISTS ESTOQUE (
    IDESTOQUE INT NOT NULL AUTO_INCREMENT,
    QUANTIDADE INT NOT NULL,
    RESERVADO_RESERVA INT DEFAULT 0,
    RESERVADO_TRANSFERENCIA INT DEFAULT 0,
    IDPRODUTO INT NOT NULL,
    PRIMARY KEY (IDESTOQUE),
    FOREIGN KEY (IDPRODUTO) REFERENCES PRODUTO (IDPRODUTO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela DATACENTER
CREATE TABLE IF NOT EXISTS DATACENTER (
    IDDATACENTER INT NOT NULL AUTO_INCREMENT,
    NOME VARCHAR(50) NOT NULL,
    PRIMARY KEY (IDDATACENTER)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabelas de movimentação de estoque

-- Tabela ACRESCIMO
CREATE TABLE IF NOT EXISTS ACRESCIMO (
    ID INT NOT NULL AUTO_INCREMENT,
    QUANTIDADE INT NOT NULL,
    DATAACRESCIMO DATE NOT NULL,
    OBSERVACAO VARCHAR(250) NOT NULL, 
    OPERACAO VARCHAR(50) NOT NULL,
    SITUACAO VARCHAR(50) NOT NULL,
    IDPRODUTO INT NOT NULL,
    IDUSUARIO INT NOT NULL,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    PRIMARY KEY (ID),
    FOREIGN KEY (IDPRODUTO) REFERENCES PRODUTO (IDPRODUTO),
    FOREIGN KEY (IDUSUARIO) REFERENCES USUARIO (IDUSUARIO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela SUBTRACAO
CREATE TABLE IF NOT EXISTS SUBTRACAO (
    ID INT NOT NULL AUTO_INCREMENT,
    NUMWO VARCHAR(50) NOT NULL,
    QUANTIDADE INT NOT NULL,
    DATASUBTRACAO DATE NOT NULL,
    OBSERVACAO VARCHAR(250) NOT NULL, 
    OPERACAO VARCHAR(50) NOT NULL,
    SITUACAO VARCHAR(50) NOT NULL,
    IDPRODUTO INT NOT NULL,
    IDUSUARIO INT NOT NULL,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    PRIMARY KEY (ID),
    FOREIGN KEY (IDPRODUTO) REFERENCES PRODUTO (IDPRODUTO),
    FOREIGN KEY (IDUSUARIO) REFERENCES USUARIO (IDUSUARIO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela SOBREPOR
CREATE TABLE IF NOT EXISTS SOBREPOR (
    ID INT NOT NULL AUTO_INCREMENT,
    QUANTIDADE INT NOT NULL,
    DATASOBREPOR DATE NOT NULL,
    OBSERVACAO VARCHAR(250) NOT NULL, 
    OPERACAO VARCHAR(50) NOT NULL,
    SITUACAO VARCHAR(50) NOT NULL,
    IDPRODUTO INT NOT NULL,
    IDUSUARIO INT NOT NULL,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    PRIMARY KEY (ID),
    FOREIGN KEY (IDPRODUTO) REFERENCES PRODUTO (IDPRODUTO),
    FOREIGN KEY (IDUSUARIO) REFERENCES USUARIO (IDUSUARIO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela RESERVA
CREATE TABLE IF NOT EXISTS RESERVA (
    ID INT NOT NULL AUTO_INCREMENT,
    NUMWO VARCHAR(50) NOT NULL,
    QUANTIDADE INT NOT NULL,
    DATARESERVA DATE NOT NULL,
    OBSERVACAO VARCHAR(50) NOT NULL,
    OPERACAO VARCHAR(50) NOT NULL,
    SITUACAO VARCHAR(50) NOT NULL,
    IDPRODUTO INT NOT NULL,
    IDUSUARIO INT NOT NULL,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    PRIMARY KEY (ID),
    FOREIGN KEY (IDPRODUTO) REFERENCES PRODUTO (IDPRODUTO),
    FOREIGN KEY (IDUSUARIO) REFERENCES USUARIO (IDUSUARIO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Tabela DEVOLVER
CREATE TABLE IF NOT EXISTS DEVOLVER (
    ID INT NOT NULL AUTO_INCREMENT,
    NUMWO VARCHAR(50) NOT NULL,
    QUANTIDADE INT NOT NULL,
    DATADEVOLUCAO DATE NOT NULL,
    OBSERVACAO VARCHAR(250) NOT NULL,
    OPERACAO VARCHAR(50) NOT NULL,
    SITUACAO VARCHAR(50) NOT NULL,
    IDPRODUTO INT NOT NULL,
    IDUSUARIO INT NOT NULL,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    PRIMARY KEY (ID),
    FOREIGN KEY (IDPRODUTO) REFERENCES PRODUTO (IDPRODUTO),
    FOREIGN KEY (IDUSUARIO) REFERENCES USUARIO (IDUSUARIO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


-- Tabela INUTILIZAR
CREATE TABLE IF NOT EXISTS INUTILIZAR (
    ID INT NOT NULL AUTO_INCREMENT,
    QUANTIDADE INT NOT NULL,
    DATAINUTILIZAR DATE NOT NULL,
    OBSERVACAO VARCHAR(250) NOT NULL, 
    OPERACAO VARCHAR(50) NOT NULL,
    SITUACAO VARCHAR(50) NOT NULL,
    IDPRODUTO INT NOT NULL,
    IDUSUARIO INT NOT NULL,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    PRIMARY KEY (ID),
    FOREIGN KEY (IDPRODUTO) REFERENCES PRODUTO (IDPRODUTO),
    FOREIGN KEY (IDUSUARIO) REFERENCES USUARIO (IDUSUARIO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE IF NOT EXISTS TRANSFERENCIA (
    ID INT NOT NULL AUTO_INCREMENT,
    NUMWO VARCHAR(50) NOT NULL,
    QUANTIDADE INT NOT NULL,
    DATA_TRANSFERENCIA DATE NOT NULL,
    IDDATACENTER INT NOT NULL,
    OBSERVACAO VARCHAR(250) NOT NULL,
    OPERACAO VARCHAR(50) NOT NULL,
    SITUACAO VARCHAR(50) NOT NULL,
    IDPRODUTO_ORIGEM INT NOT NULL,
    IDPRODUTO_DESTINO INT NOT NULL,
    IDUSUARIO INT NOT NULL,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    PRIMARY KEY(ID),
    FOREIGN KEY (IDDATACENTER) REFERENCES DATACENTER(IDDATACENTER),
    FOREIGN KEY (IDPRODUTO_ORIGEM) REFERENCES PRODUTO (IDPRODUTO),
    FOREIGN KEY (IDPRODUTO_DESTINO) REFERENCES PRODUTO (IDPRODUTO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE TRANSFERENCIA_LOG (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    IDTRANSFERENCIA INT NOT NULL,
    IDUSUARIO INT NOT NULL,
    NOME VARCHAR(100) NOT NULL,
    CODIGOP VARCHAR(50) NOT NULL,
    ACAO VARCHAR(10) NOT NULL,
    DATA TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    IDPRODUTO_ORIGEM INT NOT NULL,
    IDPRODUTO_DESTINO INT NOT NULL,
    FOREIGN KEY (IDTRANSFERENCIA) REFERENCES TRANSFERENCIA(ID),
    FOREIGN KEY (IDUSUARIO) REFERENCES USUARIO(IDUSUARIO),
    FOREIGN KEY (IDPRODUTO_ORIGEM) REFERENCES PRODUTO(IDPRODUTO),
    FOREIGN KEY (IDPRODUTO_DESTINO) REFERENCES PRODUTO(IDPRODUTO)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



-- Tabela NOTAFISCAL
CREATE TABLE IF NOT EXISTS NOTAFISCAL (
    ID INT NOT NULL AUTO_INCREMENT,
    NUMNOTAFISCAL VARCHAR(50) NOT NULL,
    VALORNOTAFISCAL VARCHAR(50) NOT NULL,
    MATERIAL VARCHAR(50) NOT NULL,
    CONECTOR VARCHAR(50) NOT NULL,
    METRAGEM VARCHAR(50) NOT NULL,
    MODELO VARCHAR(50) NOT NULL,
    GRUPO VARCHAR (50) NOT NULL,
    QUANTIDADE INT NOT NULL,
    FORNECEDOR VARCHAR(50) NOT NULL,
    DATARECEBIMENTO DATE NOT NULL,
    DATACADASTRO DATE NOT NULL,
    DATACENTER VARCHAR(10) NOT NULL,
    FILEPATH VARCHAR(255) NOT NULL,
    LOCALIZACAO VARCHAR(50) NOT NULL,
    IDPRODUTO INT NOT NULL,
    IDDATACENTER INT NOT NULL,
    PRIMARY KEY (ID),
    FOREIGN KEY (IDPRODUTO) REFERENCES PRODUTO (IDPRODUTO),
    FOREIGN KEY (IDDATACENTER) REFERENCES DATACENTER (IDDATACENTER)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



