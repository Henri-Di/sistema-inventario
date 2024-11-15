<?php
// Iniciar sessão
session_start();
session_regenerate_id(true); // Regenera o ID da sessão para aumentar a segurança

// Configurações de segurança da sessão
ini_set('session.cookie_secure', '1'); // Apenas HTTPS
ini_set('session.cookie_httponly', '1'); // Apenas HTTP
ini_set('session.use_strict_mode', '1'); // Modo restrito de sessão
ini_set('session.cookie_samesite', 'Strict'); // Protege contra CSRF
ini_set('session.cookie_lifetime', '0'); // Cookie expira com a sessão
ini_set('display_errors', '0'); // Desativar exibição de erros em produção

// Verifica se as variáveis de sessão relacionadas ao usuário estão definidas
if (!isset($_SESSION['usuarioId']) || !isset($_SESSION['usuarioNome']) || !isset($_SESSION['usuarioCodigoP'])) {
    // Se o usuário não estiver autenticado, redireciona para uma página de erro
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

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

// Inicializa variáveis com os dados do formulário
$idProdutoOrigem = filter_input(INPUT_POST, 'id', FILTER_SANITIZE_NUMBER_INT);
$quantidadeTransferencia = filter_input(INPUT_POST, 'QuantidadeTransferencia', FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
$dataTransferencia = filter_input(INPUT_POST, 'DataTransferencia', FILTER_SANITIZE_SPECIAL_CHARS);
$idDataCenterDestino = filter_input(INPUT_POST, 'DataCenter', FILTER_SANITIZE_SPECIAL_CHARS);
$observacao = mb_strtoupper(filter_input(INPUT_POST, 'Observacao', FILTER_SANITIZE_SPECIAL_CHARS), 'UTF-8'); // Convertendo para maiúsculas com suporte a UTF-8
$numWo = filter_input(INPUT_POST, 'NumWo', FILTER_SANITIZE_SPECIAL_CHARS); // Captura o valor de NUMWO

// Obter os dados do usuário da sessão
$idUsuario = $_SESSION['usuarioId'];
$nomeUsuario = $_SESSION['usuarioNome'];
$codigoPUsuario = $_SESSION['usuarioCodigoP'];

// Definir valores fixos
$operacao = "TRANSFERÊNCIA";
$situacao = "PENDENTE"; // A transferência começa como "Pendente"

// Verificar se o campo observação excede 35 caracteres
if (mb_strlen($observacao, 'UTF-8') > 35) {
    header("Location: ../ViewFail/FailCreateObservacaoInvalida.php?erro=" . urlencode("O campo observação excede o limite de 35 caracteres. Refaça a operação e tente novamente"));
    exit();
}

// Verifica se há campos vazios
if (empty($idProdutoOrigem) || empty($quantidadeTransferencia) || empty($dataTransferencia) || empty($idDataCenterDestino) || empty($observacao) || empty($numWo)) {
    header("Location: ../ViewFail/FailCreateTransferenciaErroDados.php?erro=" . urlencode("Existem campos vazios no formulário. Verifique e tente novamente"));
    exit();
}

// Verifica se a quantidade é válida
if (!is_numeric($quantidadeTransferencia) || $quantidadeTransferencia <= 0) {
    header("Location: ../ViewFail/FailCreateQuantidadeNegativa.php?erro=" . urlencode("Não é permitido o registro de valores negativos no campo de quantidade"));
    exit();
}

// Função para validar se as datas são válidas
function datasSaoValidas($dataTransferencia) {
    try {
        $timeZone = new DateTimeZone('America/Sao_Paulo');
        $dataCadastroObj = DateTime::createFromFormat('Y-m-d', $dataTransferencia, $timeZone);
        $currentDateObj = new DateTime('now', $timeZone);
        $dataCadastroFormatada = $dataCadastroObj->format('Y-m-d');
        $currentDate = $currentDateObj->format('Y-m-d');
        return $dataCadastroFormatada === $currentDate;
    } catch (Exception $e) {
        return false;
    }
}

$conn->begin_transaction();

try {
    // Obter informações do produto de origem
    $sqlProdutoOrigem = "SELECT IDMATERIAL, IDCONECTOR, IDMETRAGEM, IDMODELO, IDFORNECEDOR, e.QUANTIDADE, e.RESERVADO_TRANSFERENCIA, p.IDDATACENTER 
                         FROM PRODUTO p
                         INNER JOIN ESTOQUE e ON p.IDPRODUTO = e.IDPRODUTO
                         WHERE p.IDPRODUTO = ?";
    $stmtProdutoOrigem = $conn->prepare($sqlProdutoOrigem);
    $stmtProdutoOrigem->bind_param("i", $idProdutoOrigem);
    $stmtProdutoOrigem->execute();
    $stmtProdutoOrigem->bind_result($idMaterial, $idConector, $idMetragem, $idModelo, $idFornecedor, $quantidadeAtualOrigem, $reservadoAtual, $idDataCenterOrigem);
    $stmtProdutoOrigem->fetch();
    $stmtProdutoOrigem->close();

    if ($quantidadeAtualOrigem < $quantidadeTransferencia) {
        header("Location: ../ViewFail/FailCreateEstoqueInsuficiente.php?erro=" . urlencode("A transferência não pode ser realizada. O estoque do produto é insuficiente"));
        exit();
    }

    // Obter ID do data center de destino
    $sqlDatacenterDestino = "SELECT IDDATACENTER FROM DATACENTER WHERE NOME = ?";
    $stmtDatacenterDestino = $conn->prepare($sqlDatacenterDestino);
    $stmtDatacenterDestino->bind_param("s", $idDataCenterDestino);
    $stmtDatacenterDestino->execute();
    $stmtDatacenterDestino->bind_result($idDatacenterDestino);
    $stmtDatacenterDestino->fetch();
    $stmtDatacenterDestino->close();

    if (!$idDatacenterDestino) {
        header("Location: ../ViewFail/FailCreateDatacenterDestinoNãoEncontrado.php?erro=" . urlencode("O datacenter de destino não foi encontrado"));
        exit();
    }

    if ($idDataCenterOrigem == $idDatacenterDestino) {
        header("Location: ../ViewFail/FailCreateProdutoOrigemDestino.php?erro=" . urlencode("O produto de destino não pode ser igual ao produto de origem da transferência"));
        exit();
    }

    // Verificar se existe um produto de destino compatível no datacenter de destino
    $sqlProdutoDestino = "SELECT p.IDPRODUTO 
                          FROM PRODUTO p
                          INNER JOIN ESTOQUE e ON p.IDPRODUTO = e.IDPRODUTO
                          WHERE p.IDMATERIAL = ? AND p.IDCONECTOR = ? AND p.IDMETRAGEM = ? AND p.IDMODELO = ? AND p.IDFORNECEDOR = ? AND p.IDDATACENTER = ?";
    $stmtProdutoDestino = $conn->prepare($sqlProdutoDestino);
    $stmtProdutoDestino->bind_param("iiiiii", $idMaterial, $idConector, $idMetragem, $idModelo, $idFornecedor, $idDatacenterDestino);
    $stmtProdutoDestino->execute();
    $stmtProdutoDestino->store_result();
    $numRows = $stmtProdutoDestino->num_rows;
    $stmtProdutoDestino->close();

    if ($numRows == 0) {
        header("Location: ../ViewFail/FailCreateProdutoDestinoNaoEncontrado.php?erro=" . urlencode("O produto de destino não foi encontrado no datacenter destino"));
        exit();
    }

    // Obter ID do produto de destino
    $sqlIdProdutoDestino = "SELECT IDPRODUTO 
                            FROM PRODUTO 
                            WHERE IDMATERIAL = ? AND IDCONECTOR = ? AND IDMETRAGEM = ? AND IDMODELO = ? AND IDFORNECEDOR = ? AND IDDATACENTER = ?";
    $stmtIdProdutoDestino = $conn->prepare($sqlIdProdutoDestino);
    $stmtIdProdutoDestino->bind_param("iiiiii", $idMaterial, $idConector, $idMetragem, $idModelo, $idFornecedor, $idDatacenterDestino);
    $stmtIdProdutoDestino->execute();
    $stmtIdProdutoDestino->bind_result($idProdutoDestino);
    $stmtIdProdutoDestino->fetch();
    $stmtIdProdutoDestino->close();

    if (!$idProdutoDestino) {
        header("Location: ../ViewFail/FailCreateProdutoDestinoNaoEncontrado.php?erro=" . urlencode("O produto de destino não foi encontrado no datacenter destino"));
        exit();
    }

    // Inserir registro de transferência
    $sqlInsertTransferencia = "INSERT INTO TRANSFERENCIA (QUANTIDADE, DATA_TRANSFERENCIA, IDDATACENTER, OBSERVACAO, OPERACAO, SITUACAO, IDPRODUTO_ORIGEM, IDPRODUTO_DESTINO, IDUSUARIO, NOME, CODIGOP, NUMWO) 
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmtInsert = $conn->prepare($sqlInsertTransferencia);
    $stmtInsert->bind_param("isssssiiisss", $quantidadeTransferencia, $dataTransferencia, $idDatacenterDestino, $observacao, $operacao, $situacao, $idProdutoOrigem, $idProdutoDestino, $idUsuario, $nomeUsuario, $codigoPUsuario, $numWo);

    if (!$stmtInsert->execute()) {
        header("Location: ../ViewFail/FailCreateInserirDadosTransferencia.php?erro=" . urlencode("Não foi possível inserir os dados na tabela TRANSFERENCIA. Informe o departamento de TI"));
        exit();
    }

    // Atualizar o campo RESERVADO_TRANSFERENCIA no estoque do produto de origem
    $sqlTotalReservado = "SELECT SUM(QUANTIDADE) 
                          FROM TRANSFERENCIA 
                          WHERE IDPRODUTO_ORIGEM = ? AND SITUACAO = 'PENDENTE'";
    $stmtTotalReservado = $conn->prepare($sqlTotalReservado);
    $stmtTotalReservado->bind_param("i", $idProdutoOrigem);
    $stmtTotalReservado->execute();
    $stmtTotalReservado->bind_result($totalReservado);
    $stmtTotalReservado->fetch();
    $stmtTotalReservado->close();

    if (!$totalReservado) {
        $totalReservado = 0;
    }

    $reservadoAtual += $totalReservado;

    $sqlUpdateEstoque = "UPDATE ESTOQUE SET RESERVADO_TRANSFERENCIA = ? WHERE IDPRODUTO = ?";
    $stmtUpdateEstoque = $conn->prepare($sqlUpdateEstoque);
    $stmtUpdateEstoque->bind_param("ii", $reservadoAtual, $idProdutoOrigem);

    if (!$stmtUpdateEstoque->execute()) {
        header("Location: ../ViewFail/FailCreateAtualizarEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto de origem. Informe o departamento de TI"));
        exit();
    }

    $conn->commit();

    header("Location: ../ViewSucess/SucessCreateTransferencia.php?sucesso=" . urlencode(" A transferência foi realizada com sucesso. Aguarde a confirmação do datacenter de destino"));
    exit();
} catch (Exception $e) {
    $conn->rollback();
    header("Location: ../ViewFail/FailCreateTransferenciaErroGeral.php?erro=" . urlencode("Ocorreu um erro durante o processo de transferência. Informe o departamento de TI"));
    exit();
} finally {
    $stmtInsert->close();
    $stmtTotalReservado->close();
    $stmtUpdateEstoque->close();
    $conn->close();
}
?>