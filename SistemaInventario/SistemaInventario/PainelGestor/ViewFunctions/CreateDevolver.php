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

// Conexão e consulta ao banco de dados
require_once('../../ViewConnection/ConnectionInventario.php'); // Inclui o arquivo que estabelece a conexão com o banco de dados

// Função para validar quantidade
function validarQuantidade($quantidade) {
    // Verifica se a quantidade é um número e maior que zero
    return is_numeric($quantidade) && $quantidade > 0;
}

// Função para validar data
function validarData($data) {
    // Verifica se a data está no formato correto (Y-m-d)
    $format = 'Y-m-d';
    $d = DateTime::createFromFormat($format, $data);
    return $d && $d->format($format) === $data;
}

// Função para validar se a data é a data atual
function datasSaoValidas($dataDevolucao) {
    try {
        // Define a zona de tempo
        $timeZone = new DateTimeZone('America/Sao_Paulo'); // Substitua pela sua zona de tempo
        // Cria objeto DateTime para a data de devolução e para a data atual
        $dataDevolucaoObj = DateTime::createFromFormat('Y-m-d', $dataDevolucao, $timeZone);
        $currentDateObj = new DateTime('now', $timeZone); // Data atual do servidor
        // Formata as datas para comparação
        $dataDevolucaoFormatada = $dataDevolucaoObj->format('Y-m-d');
        $currentDate = $currentDateObj->format('Y-m-d');
        // Verifica se as datas são iguais
        return $dataDevolucaoFormatada === $currentDate;
    } catch (Exception $e) {
        // Retorna false se houver uma exceção
        return false;
    }
}

// Obter e validar os dados do formulário
$idProduto = $_POST['id'] ?? ''; // Obtém o ID do produto do formulário
$numWO = mb_strtoupper($_POST['NumWo'] ?? '', 'UTF-8'); // Obtém e converte o número WO para maiúsculas
$quantidadeDevolucao = $_POST['Devolucao'] ?? ''; // Obtém a quantidade de devolução do formulário
$dataDevolucao = $_POST['DataDevolucao'] ?? ''; // Obtém a data de devolução do formulário
$observacao = mb_strtoupper($_POST['Observacao'] ?? '', 'UTF-8'); // Obtém e converte a observação para maiúsculas

// Verificar se o campo observação excede 250 caracteres
if (mb_strlen($observacao, 'UTF-8') > 250) {
    // Redireciona para a página de erro se a observação for muito longa
    header("Location: ../ViewFail/FailCreateObservacaoInvalida.php?erro=" . urlencode("O campo observação excede o limite de 250 caracteres."));
    exit();
}

// Validar os dados do formulário
if (empty($idProduto) || empty($numWO) || !validarQuantidade($quantidadeDevolucao) || !validarData($dataDevolucao) || !datasSaoValidas($dataDevolucao)) {
    // Redireciona para a página de erro se algum dado for inválido
    header("Location: ../ViewFail/FailCreateDadosInvalidos.php?erro=" . urlencode("Os dados fornecidos são inválidos. Tente novamente"));
    exit();
}

// Obter os dados do usuário da sessão
$idUsuario = $_SESSION['usuarioId']; // Obtém o ID do usuário da sessão
$nomeUsuario = mb_strtoupper($_SESSION['usuarioNome'], 'UTF-8'); // Obtém e converte o nome do usuário para maiúsculas
$codigoPUsuario = mb_strtoupper($_SESSION['usuarioCodigoP'], 'UTF-8'); // Obtém e converte o código P do usuário para maiúsculas

// Definir valores fixos
$operacao = "DEVOLUÇÃO"; // Define a operação como devolução
$situacao = "DEVOLVIDO"; // Define a situação como devolvido

// Verificar a conexão com o banco de dados
if ($conn->connect_error) {
    // Redireciona para a página de erro se a conexão falhar
    header("Location: ../ViewFail/FailCreateConexaoBanco.php?erro=" . urlencode("Falha na conexão com o banco de dados. Tente novamente mais tarde."));
    exit();
}

// Iniciar transação para garantir consistência
$conn->begin_transaction(); // Inicia uma transação

try {
    // Verificar se há reservas para o produto
    $sqlVerificaReserva = "SELECT RESERVADO_TRANSFERENCIA FROM ESTOQUE WHERE IDPRODUTO = ?";
    $stmtVerificaReserva = $conn->prepare($sqlVerificaReserva); // Prepara a consulta SQL
    $stmtVerificaReserva->bind_param("i", $idProduto); // Associa o ID do produto ao statement
    $stmtVerificaReserva->execute(); // Executa a consulta
    $stmtVerificaReserva->bind_result($reservado); // Associa o resultado da consulta à variável $reservado
    $stmtVerificaReserva->fetch(); // Obtém o resultado da consulta
    $stmtVerificaReserva->close(); // Fecha o statement

    $temReserva = $reservado > 0; // Verifica se há reservas

    // Inserir dados na tabela DEVOLVER usando prepared statement
    $sqlInsertDevolver = "INSERT INTO DEVOLVER (NUMWO, QUANTIDADE, DATADEVOLUCAO, OBSERVACAO, OPERACAO, SITUACAO, IDPRODUTO, IDUSUARIO, NOME, CODIGOP) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmtInsert = $conn->prepare($sqlInsertDevolver); // Prepara a consulta SQL para inserção
    $stmtInsert->bind_param("sissssiiss", $numWO, $quantidadeDevolucao, $dataDevolucao, $observacao, $operacao, $situacao, $idProduto, $idUsuario, $nomeUsuario, $codigoPUsuario); // Associa os parâmetros ao statement
    if (!$stmtInsert->execute()) {
        // Redireciona para a página de erro se a inserção falhar
        header("Location: ../ViewFail/FailCreateInserirDadosDevolver.php?erro=" . urlencode("Não foi possível inserir os dados na tabela DEVOLVER. Informe o departamento de TI"));
        exit();
    }

    // Atualizar a tabela ESTOQUE subtraindo a quantidade
    $sqlUpdateEstoque = "UPDATE ESTOQUE SET QUANTIDADE = QUANTIDADE - ? WHERE IDPRODUTO = ?";
    $stmtUpdate = $conn->prepare($sqlUpdateEstoque); // Prepara a consulta SQL para atualização
    $stmtUpdate->bind_param("ii", $quantidadeDevolucao, $idProduto); // Associa os parâmetros ao statement
    if (!$stmtUpdate->execute()) {
        // Redireciona para a página de erro se a atualização falhar
        header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto. Refaça a operação e tente novamente"));
        exit();
    }

    // Commit da transação se todas as operações foram bem-sucedidas
    $conn->commit(); // Confirma a transação

    // Redirecionar para a página apropriada com base na existência de reservas
    if ($temReserva) {
        header("Location: ../ViewSucess/SucessCreateAtualizaEstoqueComTransferencia.php?sucesso=" . urlencode("O estoque do produto será atualizado após a confirmação das transferências pendentes"));
    } else {
        header("Location: ../ViewSucess/SucessCreateAtualizaEstoque.php?sucesso=" . urlencode("O estoque do produto foi atualizado com sucesso"));
    }
    exit();

} catch (Exception $e) {
    // Em caso de erro, fazer rollback da transação
    $conn->rollback(); // Reverte a transação em caso de erro
    error_log("Erro na atualização de estoque: " . $e->getMessage()); // Registra o erro no log do servidor
    header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto. Refaça a operação e tente novamente"));
    exit();

} finally {
    // Fechar os statements e a conexão
    if (isset($stmtInsert)) {
        $stmtInsert->close(); // Fecha o statement de inserção
    }
    if (isset($stmtUpdate)) {
        $stmtUpdate->close(); // Fecha o statement de atualização
    }
    $conn->close(); // Fecha a conexão com o banco de dados
}
?>
