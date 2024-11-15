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
    // Redireciona o usuário para a página de erro de autenticação se não estiver autenticado
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

require_once('../../ViewConnection/ConnectionInventario.php'); // Inclui o arquivo de conexão com o banco de dados

// Verificar se os dados do usuário estão disponíveis na sessão
if (!isset($_SESSION['usuarioId']) || !isset($_SESSION['usuarioNome']) || !isset($_SESSION['usuarioCodigoP'])) {
    // Redireciona o usuário para a página de erro de autenticação se não estiver autenticado
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Função para sanitizar os dados
function sanitizeData($conn, $data) {
    // Remove espaços em branco no início e no fim
    $data = trim($data);
    // Remove barras invertidas adicionadas automaticamente
    $data = stripslashes($data);
    // Escapa caracteres especiais para evitar SQL Injection
    $data = $conn->real_escape_string($data);
    // Converte para maiúsculas
    $data = mb_strtoupper($data, 'UTF-8');
    return $data;
}

// Obter os dados do formulário e sanitizá-los
$idProduto = isset($_POST['id']) ? sanitizeData($conn, $_POST['id']) : '';
$quantidadeInutilizada = isset($_POST['Inutilizar']) ? sanitizeData($conn, $_POST['Inutilizar']) : '';
$dataInutilizar = isset($_POST['DataInutilizar']) ? sanitizeData($conn, $_POST['DataInutilizar']) : '';
$observacao = isset($_POST['Observacao']) ? sanitizeData($conn, $_POST['Observacao']) : '';

// Obter os dados do usuário da sessão e sanitizá-los
$idUsuario = sanitizeData($conn, $_SESSION['usuarioId']);
$nomeUsuario = sanitizeData($conn, $_SESSION['usuarioNome']);
$codigoPUsuario = sanitizeData($conn, $_SESSION['usuarioCodigoP']);

// Definir valores fixos
$operacao = "INUTILIZAR"; // Define o tipo de operação
$situacao = "INUTILIZADO"; // Define a situação da operação

// Verificar se o campo observação excede 35 caracteres
if (mb_strlen($observacao, 'UTF-8') > 35) {
    // Redirecionar para a página de falha se a observação exceder o limite de caracteres
    header("Location: ../ViewFail/FailCreateObservacaoInvalida.php?erro=" . urlencode("O campo observação excede o limite de 35 caracteres. Refaça a operação e tente novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Verificar a conexão com o banco de dados
if ($conn->connect_error) {
    die("Falha na conexão: " . $conn->connect_error); // Termina a execução do script se houver um erro na conexão
}

// Verificar se a quantidade é negativa
if ($quantidadeInutilizada <= 0) {
    // Redirecionar para a página de falha se a quantidade for negativa
    header("Location: ../ViewFail/FailCreateQuantidadeNegativa.php?erro=" . urlencode("Não é permitido o registro de valores negativos no campo de quantidade"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Função para validar se a data de inutilização é válida
function dataSaoValida($dataInutilizar) {
    try {
        // Define o fuso horário para São Paulo
        $timeZone = new DateTimeZone('America/Sao_Paulo');
        // Cria um objeto DateTime para a data de inutilização
        $dataInutilizarObj = DateTime::createFromFormat('Y-m-d', $dataInutilizar, $timeZone);
        // Cria um objeto DateTime para a data atual
        $currentDateObj = new DateTime('now', $timeZone);

        // Verifica se a data de inutilização é válida
        if ($dataInutilizarObj === false) {
            return false;
        }

        // Formata a data de inutilização e a data atual
        $dataInutilizarFormatada = $dataInutilizarObj->format('Y-m-d');
        $currentDate = $currentDateObj->format('Y-m-d');

        // Compara a data de inutilização com a data atual
        return $dataInutilizarFormatada === $currentDate;
    } catch (Exception $e) {
        return false;
    }
}

// Iniciar transação para garantir consistência
$conn->begin_transaction();

try {
    // Verificar se há reservas para o produto
    $sqlVerificaReserva = "SELECT RESERVADO_TRANSFERENCIA FROM ESTOQUE WHERE IDPRODUTO = ?";
    $stmtVerificaReserva = $conn->prepare($sqlVerificaReserva);
    $stmtVerificaReserva->bind_param("i", $idProduto);
    $stmtVerificaReserva->execute();
    $stmtVerificaReserva->bind_result($reservado);
    $stmtVerificaReserva->fetch();
    $stmtVerificaReserva->close();
    
    $temReserva = $reservado > 0; // Verifica se há reservas para o produto

    // Consulta para obter a quantidade atual no estoque
    $sqlSelectEstoque = "SELECT QUANTIDADE FROM ESTOQUE WHERE IDPRODUTO = ?";
    $stmtSelect = $conn->prepare($sqlSelectEstoque);
    $stmtSelect->bind_param("i", $idProduto);
    $stmtSelect->execute();
    $stmtSelect->bind_result($quantidadeAtual);
    $stmtSelect->fetch();
    $stmtSelect->close();

    // Verificar se a quantidade inutilizada é maior do que a quantidade atual no estoque
    if ($quantidadeInutilizada > $quantidadeAtual) {
        // Redirecionar para a página de falha se a quantidade inutilizada for maior que a quantidade atual
        header("Location: ../ViewFail/FailCreateQuantidadeExcedeEstoque.php?erro=" . urlencode("A quantidade inutilizada é superior à quantidade do estoque atual"));
        exit(); // Interrompe a execução do script após o redirecionamento
    }

    // Inserir dados na tabela INUTILIZAR usando prepared statement
    $sqlInsertInutilizar = "INSERT INTO INUTILIZAR (QUANTIDADE, DATAINUTILIZAR, OBSERVACAO, OPERACAO, SITUACAO, IDPRODUTO, IDUSUARIO, NOME, CODIGOP) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmtInsert = $conn->prepare($sqlInsertInutilizar);
    $stmtInsert->bind_param("issssiiss", $quantidadeInutilizada, $dataInutilizar, $observacao, $operacao, $situacao, $idProduto, $idUsuario, $nomeUsuario, $codigoPUsuario);

    // Executa a inserção e verifica se foi bem-sucedida
    if (!$stmtInsert->execute()) {
        // Redirecionar para a página de falha se a inserção falhar
        header("Location: ../ViewFail/FailCreateInserirDadosInutilizar.php?erro=" . urlencode("Não foi possível inserir os dados na tabela INUTILIZAR. Informe o departamento de TI"));
        exit(); // Interrompe a execução do script após o redirecionamento
    }

    // Atualizar a tabela ESTOQUE subtraindo a quantidade inutilizada
    $sqlUpdateEstoque = "UPDATE ESTOQUE SET QUANTIDADE = QUANTIDADE - ? WHERE IDPRODUTO = ?";
    $stmtUpdate = $conn->prepare($sqlUpdateEstoque);
    $stmtUpdate->bind_param("ii", $quantidadeInutilizada, $idProduto);

    // Executa a atualização do estoque e verifica se foi bem-sucedida
    if (!$stmtUpdate->execute()) {
        // Redirecionar para a página de falha se a atualização falhar
        header("Location: ../ViewFail/FailCreateAtualizarEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque. Informe o departamento de TI"));
        exit(); // Interrompe a execução do script após o redirecionamento
    }

    // Se houver reserva, atualizar a quantidade reservada
    if ($temReserva) {
        $sqlUpdateReserva = "UPDATE ESTOQUE SET RESERVADO_TRANSFERENCIA = RESERVADO_TRANSFERENCIA - ? WHERE IDPRODUTO = ?";
        $stmtUpdateReserva = $conn->prepare($sqlUpdateReserva);
        $stmtUpdateReserva->bind_param("ii", $quantidadeInutilizada, $idProduto);

        // Executa a atualização de reserva e verifica se foi bem-sucedida
        if (!$stmtUpdateReserva->execute()) {
            // Redirecionar para a página de falha se a atualização da reserva falhar
            header("Location: ../ViewFail/FailCreateAtualizarReserva.php?erro=" . urlencode("Não foi possível atualizar a reserva do estoque. Informe o departamento de TI"));
            exit(); // Interrompe a execução do script após o redirecionamento
        }
    }

    // Commit da transação se todas as operações forem bem-sucedidas
    $conn->commit();
    
    // Redireciona para a página de sucesso após a operação bem-sucedida
    header("Location: ../ViewSuccess/SuccessInutilizarProduto.php?sucesso=" . urlencode("O produto foi inutilizado com sucesso"));
    exit(); // Interrompe a execução do script após o redirecionamento

} catch (Exception $e) {
    // Rollback da transação em caso de erro
    $conn->rollback();
    
    // Redireciona para a página de falha se ocorrer uma exceção
    header("Location: ../ViewFail/FailCreateException.php?erro=" . urlencode("Erro na operação: " . $e->getMessage()));
    exit(); // Interrompe a execução do script após o redirecionamento
} finally {
    // Fecha a conexão com o banco de dados
    $conn->close();
}
?>
