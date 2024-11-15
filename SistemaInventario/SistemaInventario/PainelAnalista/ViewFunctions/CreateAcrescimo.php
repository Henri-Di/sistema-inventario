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

// Verificar se o usuário está autenticado
if (!isset($_SESSION['usuarioId']) || !isset($_SESSION['usuarioNome']) || !isset($_SESSION['usuarioCodigoP'])) {
    // Se qualquer uma das variáveis de sessão obrigatórias não estiver definida, redireciona o usuário para a página de erro de autenticação
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Conexão ao banco de dados
require_once('../../ViewConnection/ConnectionInventario.php');

// Verificar a conexão com o banco de dados
if ($conn->connect_error) {
    header("Location: ../ViewFail/FailCreateConexaoBanco.php?erro=" . urlencode("Falha na conexão com o banco de dados. Tente novamente mais tarde."));
    exit();
}

// Função para validar a quantidade, garantindo que seja numérica e positiva
function validarQuantidade($quantidade) {
    return is_numeric($quantidade) && $quantidade > 0;
}

// Função para validar a data, garantindo que esteja no formato 'Y-m-d'
function validarData($data) {
    $format = 'Y-m-d';
    $d = DateTime::createFromFormat($format, $data);
    return $d && $d->format($format) === $data;
}

// Função para validar se a data é a data atual
function datasSaoValidas($dataAcrescimo) {
    try {
        $timeZone = new DateTimeZone('America/Sao_Paulo'); // Substitua pela sua zona de tempo
        $dataAcrescimoObj = DateTime::createFromFormat('Y-m-d', $dataAcrescimo, $timeZone);
        $currentDateObj = new DateTime('now', $timeZone); // Data atual do servidor
        $dataAcrescimoFormatada = $dataAcrescimoObj->format('Y-m-d');
        $currentDate = $currentDateObj->format('Y-m-d');
        return $dataAcrescimoFormatada === $currentDate;
    } catch (Exception $e) {
        return false;
    }
}

// Obter e validar os dados do formulário
$idProduto = filter_var($_POST['id'] ?? '', FILTER_SANITIZE_NUMBER_INT);
$quantidadeAcrescimo = filter_var($_POST['Acrescimo'] ?? '', FILTER_SANITIZE_NUMBER_INT);
$dataAcrescimo = filter_var($_POST['DataAcrescimo'] ?? '', FILTER_SANITIZE_SPECIAL_CHARS);
$observacao = mb_strtoupper(filter_var($_POST['Observacao'] ?? '', FILTER_SANITIZE_SPECIAL_CHARS), 'UTF-8');

// Verificar se o campo observação excede 35 caracteres
if (mb_strlen($observacao, 'UTF-8') > 35) {
    header("Location: ../ViewFail/FailCreateObservacaoInvalida.php?erro=" . urlencode("O campo observação excede o limite de 35 caracteres."));
    exit();
}

// Validar os dados do formulário
if (empty($idProduto) || !validarQuantidade($quantidadeAcrescimo) || !validarData($dataAcrescimo) || !datasSaoValidas($dataAcrescimo)) {
    header("Location: ../ViewFail/FailCreateDadosInvalidos.php?erro=" . urlencode("Os dados fornecidos são inválidos. Tente novamente"));
    exit();
}

// Obter os dados do usuário da sessão
$idUsuario = $_SESSION['usuarioId'];
$nomeUsuario = mb_strtoupper($_SESSION['usuarioNome'], 'UTF-8');
$codigoPUsuario = mb_strtoupper($_SESSION['usuarioCodigoP'], 'UTF-8');

// Definir valores fixos para a operação e situação
$operacao = "ACRÉSCIMO";
$situacao = "ACRESCENTADO";

// Iniciar transação para garantir a consistência dos dados
$conn->begin_transaction();

try {
    // Verificar se há reservas para o produto na tabela ESTOQUE
    $sqlVerificaReserva = "SELECT RESERVADO_TRANSFERENCIA FROM ESTOQUE WHERE IDPRODUTO = ?";
    $stmtVerificaReserva = $conn->prepare($sqlVerificaReserva);
    $stmtVerificaReserva->bind_param("i", $idProduto);
    $stmtVerificaReserva->execute();
    $stmtVerificaReserva->bind_result($reservado);
    $stmtVerificaReserva->fetch();
    $stmtVerificaReserva->close();

    // Determinar se o produto tem reservas pendentes
    $temReserva = $reservado > 0;

    // Inserir os dados na tabela ACRESCIMO usando prepared statement para evitar SQL injection
    $sqlInsertAcrescimo = "INSERT INTO ACRESCIMO (QUANTIDADE, DATAACRESCIMO, OBSERVACAO, OPERACAO, SITUACAO, IDPRODUTO, IDUSUARIO, NOME, CODIGOP) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmtInsert = $conn->prepare($sqlInsertAcrescimo);
    $stmtInsert->bind_param("issssisss", $quantidadeAcrescimo, $dataAcrescimo, $observacao, $operacao, $situacao, $idProduto, $idUsuario, $nomeUsuario, $codigoPUsuario);
    if (!$stmtInsert->execute()) {
        // Em caso de falha, redirecionar para a página de erro
        header("Location: ../ViewFail/FailCreateInserirDadosAcrescimo.php?erro=" . urlencode("Não foi possível inserir os dados na tabela ACRESCIMO. Informe o departamento de TI"));
        exit();
    }

    // Atualizar a tabela ESTOQUE acrescentando a quantidade
    $sqlUpdateEstoque = "UPDATE ESTOQUE SET QUANTIDADE = QUANTIDADE + ? WHERE IDPRODUTO = ?";
    $stmtUpdate = $conn->prepare($sqlUpdateEstoque);
    $stmtUpdate->bind_param("ii", $quantidadeAcrescimo, $idProduto);
    if (!$stmtUpdate->execute()) {
        // Em caso de falha, redirecionar para a página de erro
        header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto. Refaça a operação e tente novamente"));
        exit();
    }

    // Commit da transação se todas as operações foram bem-sucedidas
    $conn->commit();

    // Redirecionar para a página de sucesso com base na existência de reservas
    if ($temReserva) {
        header("Location: ../ViewSucess/SucessCreateAtualizaEstoqueComTransferencia.php?sucesso=" . urlencode("O estoque do produto será atualizado após a confirmação das transferências pendentes"));
    } else {
        header("Location: ../ViewSucess/SucessCreateAtualizaEstoque.php?sucesso=" . urlencode("O estoque do produto foi atualizado com sucesso"));
    }
    exit();
    
} catch (Exception $e) {
    // Em caso de erro, fazer rollback da transação
    $conn->rollback();
    error_log("Erro na atualização de estoque: " . $e->getMessage());
    header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode($e->getMessage()));
    exit();

} finally {
    // Fechar os statements e a conexão
    if (isset($stmtInsert)) {
        $stmtInsert->close();
    }
    if (isset($stmtUpdate)) {
        $stmtUpdate->close();
    }
    $conn->close();
}
?>
