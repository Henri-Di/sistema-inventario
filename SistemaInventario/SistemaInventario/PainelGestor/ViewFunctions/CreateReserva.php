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

// Verificar se o usuário está autenticado
if (!isset($_SESSION['usuarioId']) || !isset($_SESSION['usuarioNome']) || !isset($_SESSION['usuarioCodigoP'])) {
    // Redirecionar para a página de erro se o usuário não estiver autenticado
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Termina a execução do script após o redirecionamento
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


// Verificar novamente se os dados do usuário estão disponíveis na sessão (redundante, já foi feito acima)
if (!isset($_SESSION['usuarioId']) || !isset($_SESSION['usuarioNome']) || !isset($_SESSION['usuarioCodigoP'])) {
    // Redirecionar para a página de erro se o usuário não estiver autenticado
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Termina a execução do script após o redirecionamento
}

// Conectar ao banco de dados
require_once('../../ViewConnection/ConnectionInventario.php');

// Função para validar se a quantidade é um número positivo
function validarQuantidade($quantidade) {
    return is_numeric($quantidade) && $quantidade > 0; // Retorna verdadeiro se for um número e maior que zero
}

// Função para validar o formato da data
function validarData($data) {
    $format = 'Y-m-d'; // Define o formato da data
    $d = DateTime::createFromFormat($format, $data); // Cria um objeto DateTime a partir da string de data
    return $d && $d->format($format) === $data; // Retorna verdadeiro se o formato estiver correto
}

// Função para validar se a data fornecida é igual à data atual
function datasSaoValidas($datareserva) {
    try {
        $timeZone = new DateTimeZone('America/Sao_Paulo'); // Define o fuso horário
        $datareservaObj = DateTime::createFromFormat('Y-m-d', $datareserva, $timeZone); // Cria o objeto DateTime para a data de reserva
        $currentDateObj = new DateTime('now', $timeZone); // Cria o objeto DateTime para a data atual
        $datareservaFormatada = $datareservaObj->format('Y-m-d'); // Formata a data de reserva
        $currentDate = $currentDateObj->format('Y-m-d'); // Formata a data atual
        return $datareservaFormatada === $currentDate; // Retorna verdadeiro se a data de reserva for igual à data atual
    } catch (Exception $e) {
        return false; // Retorna falso em caso de exceção
    }
}

// Obter e validar os dados do formulário
$idProduto = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT); // Obtém e valida o ID do produto
$numwo = mb_strtoupper(filter_input(INPUT_POST, 'NumWo', FILTER_SANITIZE_SPECIAL_CHARS), 'UTF-8'); // Obtém e sanitiza o número do WO, convertendo para maiúsculas
$quantidadeReservar = filter_input(INPUT_POST, 'Reservar', FILTER_VALIDATE_INT); // Obtém e valida a quantidade a reservar
$datareserva = filter_input(INPUT_POST, 'DataReserva', FILTER_SANITIZE_SPECIAL_CHARS); // Obtém e sanitiza a data de reserva
$observacao = mb_strtoupper(filter_input(INPUT_POST, 'Observacao', FILTER_SANITIZE_SPECIAL_CHARS), 'UTF-8'); // Obtém e sanitiza a observação, convertendo para maiúsculas

// Verificar se o campo observação excede 35 caracteres
if (mb_strlen($observacao, 'UTF-8') > 35) {
    // Redirecionar para a página de erro se o campo observação for inválido
    header("Location: ../ViewFail/FailCreateObservacaoInvalida.php?erro=" . urlencode("O campo observação excede o limite de 35 caracteres. Refaça a operação e tente novamente"));
    exit(); // Termina a execução do script após o redirecionamento
}

// Validar se os campos obrigatórios foram preenchidos e se os dados são válidos
if (empty($idProduto) || empty($numwo) || !$quantidadeReservar || !validarQuantidade($quantidadeReservar) || !validarData($datareserva) || !datasSaoValidas($datareserva)) {
    // Redirecionar para a página de erro se algum dado estiver inválido
    header("Location: ../ViewFail/FailCreateDadosInvalidos.php?erro=" . urlencode("Os dados fornecidos são inválidos. Refaça a operação e tente novamente"));
    exit(); // Termina a execução do script após o redirecionamento
}

// Obter os dados do usuário da sessão
$idUsuario = $_SESSION['usuarioId']; // ID do usuário
$nomeUsuario = mb_strtoupper($_SESSION['usuarioNome'], 'UTF-8'); // Nome do usuário em maiúsculas
$codigoPUsuario = mb_strtoupper($_SESSION['usuarioCodigoP'], 'UTF-8'); // Código do usuário em maiúsculas

// Definir valores fixos
$operacao = "RESERVAR"; // Tipo de operação
$situacao = "PENDENTE"; // Situação da reserva

// Verificar a conexão com o banco de dados
if ($conn->connect_error) {
    die("Falha na conexão: " . $conn->connect_error); // Exibir mensagem de erro se a conexão falhar
}

// Iniciar transação para garantir consistência dos dados
$conn->begin_transaction();

try {
    // Verificar a quantidade total atual no estoque
    $sqlVerificaEstoque = "SELECT QUANTIDADE FROM ESTOQUE WHERE IDPRODUTO = ?";
    $stmtVerificaEstoque = $conn->prepare($sqlVerificaEstoque); // Prepara a consulta
    $stmtVerificaEstoque->bind_param("i", $idProduto); // Liga o ID do produto ao parâmetro
    $stmtVerificaEstoque->execute(); // Executa a consulta
    $stmtVerificaEstoque->bind_result($quantidadeTotal); // Liga o resultado ao variável
    $stmtVerificaEstoque->fetch(); // Obtém o resultado
    $stmtVerificaEstoque->close(); // Fecha o statement

    // Calcular a nova quantidade no estoque após a reserva
    $novaQuantidadeEstoque = $quantidadeTotal - $quantidadeReservar;

    // Atualizar a tabela ESTOQUE com a nova quantidade
    $sqlUpdateEstoque = "UPDATE ESTOQUE SET QUANTIDADE = ? WHERE IDPRODUTO = ?";
    $stmtUpdate = $conn->prepare($sqlUpdateEstoque); // Prepara a consulta de atualização
    $stmtUpdate->bind_param("ii", $novaQuantidadeEstoque, $idProduto); // Liga os parâmetros

    if (!$stmtUpdate->execute()) {
        // Se a atualização falhar, redirecionar para a página de erro
        header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto. Refaça a operação e tente novamente"));
        exit(); // Termina a execução do script após o redirecionamento
    }

    // Inserir dados na tabela RESERVA usando prepared statement
    $sqlInsertReserva = "INSERT INTO RESERVA (NUMWO, QUANTIDADE, DATARESERVA, OBSERVACAO, OPERACAO, SITUACAO, IDPRODUTO, IDUSUARIO, NOME, CODIGOP) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmtInsert = $conn->prepare($sqlInsertReserva); // Prepara a consulta de inserção
    $stmtInsert->bind_param("sissssiiss", $numwo, $quantidadeReservar, $datareserva, $observacao, $operacao, $situacao, $idProduto, $idUsuario, $nomeUsuario, $codigoPUsuario); // Liga os parâmetros

    if (!$stmtInsert->execute()) {
        // Se a inserção falhar, redirecionar para a página de erro
        header("Location: ../ViewFail/FailCreateInserirDadosReserva.php?erro=" . urlencode("Não foi possível inserir os dados na tabela RESERVA. Informe o departamento de TI"));
        exit(); // Termina a execução do script após o redirecionamento
    }

    // Commit da transação se todas as operações foram bem-sucedidas
    $conn->commit();

    // Redirecionar para a página de sucesso apropriada
    header("Location: ../ViewSucess/SucessCreateReserva.php?sucesso=" . urlencode("A reserva do produto foi realizada com sucesso"));
    exit(); // Termina a execução do script após o redirecionamento

} catch (Exception $e) {
    // Em caso de erro, fazer rollback da transação para manter a integridade dos dados
    $conn->rollback();

    // Registrar o erro no log do servidor
    error_log("Erro: " . $e->getMessage());

    // Redirecionar para a página de falha com uma mensagem de erro
    header("Location: ../ViewFail/FailCreateReserva.php?erro=" . urlencode("Não foi possível criar a reserva do produto. Refaça a operação e tente novamente"));
    exit(); // Termina a execução do script após o redirecionamento

} finally {
    // Fechar os statements e a conexão com o banco de dados
    if (isset($stmtInsert)) {
        $stmtInsert->close(); // Fecha o statement de inserção
    }
    if (isset($stmtUpdate)) {
        $stmtUpdate->close(); // Fecha o statement de atualização
    }
    $conn->close(); // Fecha a conexão com o banco de dados
}
?>