<?php
// Iniciar sessão se necessário
session_start();
session_regenerate_id(true);

// Configurações de segurança da sessão
ini_set('session.cookie_secure', '1'); // Apenas HTTPS
ini_set('session.cookie_httponly', '1'); // Apenas HTTP
ini_set('session.use_strict_mode', '1'); // Modo restrito de sessão
ini_set('session.cookie_samesite', 'Strict'); // Protege contra CSRF
ini_set('session.cookie_lifetime', '0'); // Cookie expira com a sessão
ini_set('display_errors', '0'); // Desativar exibição de erros em produção

// Adiciona cabeçalhos de segurança para proteger a página contra ataques

header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';");
// 'Content-Security-Policy' (CSP) define uma política de segurança de conteúdo que ajuda a prevenir a execução de scripts maliciosos e a proteger contra ataques como Cross-Site Scripting (XSS).
// - 'default-src 'self'': Permite que recursos (scripts, estilos, etc.) sejam carregados apenas do mesmo domínio da página.
// - 'script-src 'self'': Permite apenas scripts provenientes do mesmo domínio.
// - 'style-src 'self'': Permite apenas estilos provenientes do mesmo domínio.
// - 'img-src 'self' data:': Permite imagens do mesmo domínio e também imagens embutidas em base64 (data URIs).
// - 'font-src 'self'': Permite fontes do mesmo domínio.
// - 'connect-src 'self'': Permite conexões de dados (como AJAX) apenas para o mesmo domínio.
// - 'frame-ancestors 'none'': Impede que a página seja exibida em frames ou iframes de outros sites, prevenindo ataques de clickjacking.

header("X-Content-Type-Options: nosniff");
// 'X-Content-Type-Options' impede que o navegador "adivinhe" o tipo MIME dos arquivos. Garante que o navegador interprete o tipo de conteúdo conforme declarado pelo servidor, prevenindo ataques baseados na interpretação incorreta de tipos MIME.

header("X-Frame-Options: DENY");
// 'X-Frame-Options' impede que a página seja exibida em frames ou iframes de outros sites, ajudando a prevenir ataques de clickjacking. O valor 'DENY' bloqueia totalmente a exibição da página em frames.

header("X-XSS-Protection: 1; mode=block");
// 'X-XSS-Protection' ativa a proteção contra ataques de Cross-Site Scripting (XSS). No modo 'block', o navegador bloqueia qualquer script que pareça ser um ataque XSS, em vez de tentar escapar o código.

header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
// 'Strict-Transport-Security' (HSTS) instrui o navegador a usar apenas conexões HTTPS para o site por um período especificado. 
// - 'max-age=31536000': Define o tempo que o navegador deve lembrar da política como um ano (31536000 segundos).
// - 'includeSubDomains': Aplica a política a todos os subdomínios do domínio principal.

header("Referrer-Policy: no-referrer");
// 'Referrer-Policy' controla o envio de informações de referência ao fazer solicitações para outros sites.
// - 'no-referrer': Impede o envio de informações de referência, aumentando a privacidade do usuário.

header("Feature-Policy: vibrate 'none'; camera 'none'; microphone 'none'; geolocation 'self';");
// 'Feature-Policy' permite controlar o acesso a APIs específicas e recursos do navegador.
// - 'vibrate 'none'': Desativa o acesso à API de vibração.
// - 'camera 'none'': Desativa o acesso à câmera.
// - 'microphone 'none'': Desativa o acesso ao microfone.
// - 'geolocation 'self'': Permite o acesso à localização apenas para o mesmo domínio.

header("X-Permitted-Cross-Domain-Policies: none");
// 'X-Permitted-Cross-Domain-Policies' controla o acesso a políticas de domínio cruzado. 
// - 'none': Impede que agentes externos leiam informações da página, protegendo contra ataques onde agentes externos tentam acessar dados restritos.

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
// 'Cache-Control' controla como e por quanto tempo a página deve ser armazenada em cache pelos navegadores.
// - 'no-store' e 'no-cache': Garantem que a página não seja armazenada em cache.
// - 'must-revalidate': Indica que o navegador deve revalidar a página com o servidor antes de usá-la.
// - 'max-age=0': Define o tempo máximo que a página pode ser armazenada como zero.

header("Expect-CT: max-age=86400, enforce");
// 'Expect-CT' protege contra certificados SSL inválidos ou expirados.
// - 'max-age=86400': Define o tempo de cache como 24 horas (86400 segundos).
// - 'enforce': Aplica a política de Expect-CT, exigindo que o certificado seja verificado conforme as regras.

header("Access-Control-Allow-Origin: https://example.com");
// 'Access-Control-Allow-Origin' controla quais domínios têm permissão para acessar os recursos do seu servidor.
// - 'https://example.com': Substitua pelo domínio específico que deve ter acesso. Isso ajuda a evitar o acesso não autorizado de outros domínios.



// Conexão e consulta ao banco de dados
require_once('../../ViewConnection/ConnectionInventario.php');

// Função para sanitizar entrada de dados
function sanitize($conn, $input) {
    return $conn->real_escape_string($input);
}

// Função para validar se as datas de recebimento e cadastro são válidas
function datasSaoValidas($datacadastro) {
    try {
        // Definir a zona de tempo para as datas recebidas e a data atual do servidor
        $timeZone = new DateTimeZone('America/Sao_Paulo'); // Substitua pela sua zona de tempo

        // Converter as datas para objetos DateTime com a zona de tempo definida
        $dataCadastroObj = DateTime::createFromFormat('Y-m-d', $datacadastro, $timeZone);
        $currentDateObj = new DateTime('now', $timeZone); // Data atual do servidor

        // Comparar apenas a parte da data (sem considerar horas, minutos, segundos)
        $dataCadastroFormatada = $dataCadastroObj->format('Y-m-d');
        $currentDate = $currentDateObj->format('Y-m-d');

        // Verificar se as datas recebidas são iguais à data atual do servidor
        if ($dataCadastroFormatada !== $currentDate) {
            return false;
        }

        return true;
    } catch (Exception $e) {
        // Tratar exceção de conversão de datas
        return false;
    }
}

// Função para obter ou inserir e obter o ID de uma tabela
function getIdOrInsert($conn, $table, $column, $idColumn, $value) {
    $value = strtoupper($value); // Convertendo para maiúsculas
    $checkSql = "SELECT $idColumn FROM $table WHERE UPPER($column) = UPPER('$value')";
    $result = mysqli_query($conn, $checkSql);

    if (mysqli_num_rows($result) > 0) {
        $row = mysqli_fetch_assoc($result);
        return $row[$idColumn];
    } else {
        $insertSql = "INSERT INTO $table ($column) VALUES ('$value')";
        if (mysqli_query($conn, $insertSql)) {
            return $conn->insert_id;
        } else {
            header("Location: ../ViewFail/FailCreateInserirDadosTabela.php?erro=" . urlencode("Não foi possível inserir dados nas tabelas do banco de dados. Informe o departamento de TI "));
            exit(); // Termina a execução do script após redirecionamento
        }
    }
}

// Verificar se o formulário foi submetido
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Obter os dados do formulário e sanitizar
    $material = strtoupper(sanitize($conn, $_POST['Material'] ?? ''));
    $conector = strtoupper(sanitize($conn, $_POST['Conector'] ?? ''));
    $metragem = strtoupper(sanitize($conn, $_POST['Metragem'] ?? ''));
    $modelo = strtoupper(sanitize($conn, $_POST['Modelo'] ?? ''));
    $quantidade = sanitize($conn, $_POST['Quantidade'] ?? '');
    $fornecedor = strtoupper(sanitize($conn, $_POST['Fornecedor'] ?? ''));
    $datacadastro = sanitize($conn, $_POST['DataCadastro'] ?? '');
    $datacenterNome = strtoupper(sanitize($conn, $_POST['DataCenter'] ?? ''));
    $grupo = strtoupper(sanitize($conn, $_POST['Grupo'] ?? ''));
    $localizacao = strtoupper(sanitize($conn, $_POST['Localizacao'] ?? ''));
    $tipo = strtoupper(sanitize($conn, $_POST['Tipo'] ?? ''));
    $observacao = strtoupper(sanitize($conn, $_POST['Observacao'] ?? ''));

    // Obter o ID do usuário a partir da sessão
    $idUsuario = $_SESSION['usuarioId'] ?? '';

    // Sanitizar o ID do usuário para evitar injeção de SQL
    $idUsuario = $conn->real_escape_string($idUsuario);

    // Consulta para obter o datacenter e o nível de acesso do usuário
    $consultaDatacenterNivelAcesso = "SELECT UPPER(DATACENTER), NIVEL_ACESSO FROM USUARIO WHERE IDUSUARIO = ?";
    if ($stmt = $conn->prepare($consultaDatacenterNivelAcesso)) {
        $stmt->bind_param("i", $idUsuario);
        $stmt->execute();
        $stmt->bind_result($datacenterUsuario, $nivelAcesso);
        $stmt->fetch();
        $stmt->close();
    }

    // Verificar se a quantidade é negativa
    if ($quantidade < 0) {
        // Redirecionar para a página de falha
        header("Location: ../ViewFail/FailCreateQuantidadeNegativa.php?erro=" . urlencode("Não é permitido o registro de valores negativos no campo de quantidade"));
        exit(); // Termina a execução do script após redirecionamento
    }

    // Verificar se a data de cadastro é válida
    if (!datasSaoValidas($datacadastro)) {
        // Redirecionar para a página de falha com mensagem de erro
        header("Location: ../ViewFail/FailCreateDataInvalida.php?erro=" . urlencode("A data está fora do intervalo permitido. A data deve ser igual a data atual"));
        exit(); // Termina a execução do script após redirecionamento
    }

    // Verificar se o datacenter do usuário é igual ao datacenter recebido pelo formulário, exceto se o nível de acesso for "GESTOR"
    if (strtoupper($nivelAcesso) !== 'GESTOR' && strtoupper($datacenterUsuario) !== strtoupper($datacenterNome)) {
        // Redirecionar para a página de falha
        header("Location: ../ViewFail/FailCreateProdutoDatacenterIncorreto.php?erro=" . urlencode("Você não pode cadastrar um produto que seja de outro datacenter"));
        exit(); // Termina a execução do script após redirecionamento
    }

    try {
        $conn->begin_transaction();

        $idMaterial = getIdOrInsert($conn, 'MATERIAL', 'MATERIAL', 'IDMATERIAL', $material);
        $idConector = getIdOrInsert($conn, 'CONECTOR', 'CONECTOR', 'IDCONECTOR', $conector);
        $idMetragem = getIdOrInsert($conn, 'METRAGEM', 'METRAGEM', 'IDMETRAGEM', $metragem);
        $idModelo = getIdOrInsert($conn, 'MODELO', 'MODELO', 'IDMODELO', $modelo);
        $idFornecedor = getIdOrInsert($conn, 'FORNECEDOR', 'FORNECEDOR', 'IDFORNECEDOR', $fornecedor);
        $idDataCenter = getIdOrInsert($conn, 'DATACENTER', 'NOME', 'IDDATACENTER', $datacenterNome);
        $idGrupo = getIdOrInsert($conn, 'GRUPO', 'GRUPO', 'IDGRUPO', $grupo);
        $idLocalizacao = getIdOrInsert($conn, 'LOCALIZACAO', 'LOCALIZACAO', 'IDLOCALIZACAO', $localizacao);

        // Verificar se um produto com os mesmos detalhes, exceto fornecedor e modelo, já existe no mesmo datacenter
        $check_sql = "SELECT p.* FROM PRODUTO p
                      WHERE p.IDMATERIAL = '$idMaterial'
                      AND p.IDCONECTOR = '$idConector'
                      AND p.IDMETRAGEM = '$idMetragem'
                      AND p.IDDATACENTER = '$idDataCenter'
                      AND p.IDGRUPO = '$idGrupo'
                      AND p.IDLOCALIZACAO = '$idLocalizacao'
                      AND p.IDFORNECEDOR = '$idFornecedor'
                      AND p.IDMODELO = '$idModelo'
                      AND p.TIPO = '$tipo'
                      AND p.OBSERVACAO = '$observacao'";
        $result = mysqli_query($conn, $check_sql);

        if (mysqli_num_rows($result) > 0) {
            // Se o produto já existe com os mesmos detalhes (inclusive fornecedor e modelo), redirecionar para a página de falha
            header("Location: ../ViewFail/FailCreateProdutoExistente.php?erro=" . urlencode("Não foi possível realizar o cadastro. Produto já cadastrado"));
            exit(); // Termina a execução do script após redirecionamento
        } else {
            // Inserir dados na tabela PRODUTO
            $sqlInsertProduto = "INSERT INTO PRODUTO (IDMATERIAL, IDCONECTOR, IDMETRAGEM, IDMODELO, IDFORNECEDOR, DATACADASTRO, IDDATACENTER, IDGRUPO, IDLOCALIZACAO, TIPO, OBSERVACAO) 
                                 VALUES ('$idMaterial', '$idConector', '$idMetragem', '$idModelo', '$idFornecedor', '$datacadastro', '$idDataCenter', '$idGrupo', '$idLocalizacao', '$tipo', '$observacao')";
            if (!mysqli_query($conn, $sqlInsertProduto)) {
                header("Location: ../ViewFail/FailCreateInserirDadosProduto.php?erro=" . urlencode("Não foi possível inserir os dados na tabela PRODUTO"));
                exit(); // Termina a execução do script após redirecionamento
            }

            // Obter o ID do produto inserido
            $idProduto = $conn->insert_id;

            // Inserir dados na tabela ESTOQUE
            $sqlInsertEstoque = "INSERT INTO ESTOQUE (IDPRODUTO, QUANTIDADE) 
                                 VALUES ('$idProduto', '$quantidade')";
            if (!mysqli_query($conn, $sqlInsertEstoque)) {
                header("Location: ../ViewFail/FailCreateInserirDadosEstoque.php?erro=" . urlencode("Não foi possível inserir os dados na tabela ESTOQUE"));
                exit(); // Termina a execução do script após redirecionamento
            }

            // Commit da transação se todas as operações foram bem-sucedidas
            $conn->commit();

            // Redirecionar para a página de sucesso
            header("Location: ../ViewSucess/SucessCreateProduto.php?sucesso=" . urlencode("O cadastro do produto foi realizado com sucesso"));
            exit(); // Termina a execução do script após redirecionamento
        }
    } catch (Exception $e) {
        // Em caso de erro, fazer rollback da transação
        $conn->rollback();

        // Exibir mensagem de erro
        echo "Erro: " . $e->getMessage();

        // Redirecionar para a página de falha
        header("Location: ../ViewFail/FailCreateProduto.php?erro=" . urlencode("Não foi possível realizar o cadastro do produto. Tente novamente"));
        exit(); // Termina a execução do script após redirecionamento
    }
}
?>
