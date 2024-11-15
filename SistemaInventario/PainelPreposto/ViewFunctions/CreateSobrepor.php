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

// Verifica se as variáveis de sessão relacionadas ao usuário estão definidas
if (!isset($_SESSION['usuarioId']) || !isset($_SESSION['usuarioNome']) || !isset($_SESSION['usuarioCodigoP'])) {
    // Se não estiver autenticado, redireciona para uma página de erro
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Inclui o arquivo de conexão com o banco de dados
require_once('../../ViewConnection/ConnectionInventario.php');

// Função para validar se a quantidade é um número e não negativa
function validarQuantidade($quantidade) {
    return is_numeric($quantidade) && $quantidade >= 0;
}

// Função para validar se a data está no formato correto (Y-m-d)
function validarData($data) {
    $format = 'Y-m-d'; // Define o formato da data
    $d = DateTime::createFromFormat($format, $data); // Cria um objeto DateTime a partir da string de data
    return $d && $d->format($format) === $data; // Verifica se a data está no formato correto
}

// Função para validar se a data fornecida é igual à data atual
function datasSaoValidas($dataSobrepor) {
    try {
        $timeZone = new DateTimeZone('America/Sao_Paulo'); // Define o fuso horário
        $dataCadastroObj = DateTime::createFromFormat('Y-m-d', $dataSobrepor, $timeZone); // Cria o objeto DateTime para a data fornecida
        $currentDateObj = new DateTime('now', $timeZone); // Cria o objeto DateTime para a data atual
        $dataCadastroFormatada = $dataCadastroObj->format('Y-m-d'); // Formata a data fornecida
        $currentDate = $currentDateObj->format('Y-m-d'); // Formata a data atual
        return $dataCadastroFormatada === $currentDate; // Verifica se a data fornecida é igual à data atual
    } catch (Exception $e) {
        return false; // Retorna falso em caso de exceção
    }
}

// Obtém e valida os dados enviados pelo formulário
$idProduto = isset($_POST['id']) ? $_POST['id'] : ''; // Obtém o ID do produto
$quantidadeSobrepor = isset($_POST['Sobrepor']) ? $_POST['Sobrepor'] : ''; // Obtém a quantidade a sobrepor
$dataSobrepor = isset($_POST['DataSobrepor']) ? $_POST['DataSobrepor'] : ''; // Obtém a data para sobreposição
$observacao = isset($_POST['Observacao']) ? mb_strtoupper($_POST['Observacao'], 'UTF-8') : ''; // Obtém a observação e converte para maiúsculas

// Sanitiza e valida os dados recebidos do formulário
$idProduto = filter_var($idProduto, FILTER_VALIDATE_INT); // Valida o ID do produto como um inteiro
$quantidadeSobrepor = filter_var($quantidadeSobrepor, FILTER_VALIDATE_INT); // Valida a quantidade como um inteiro
$dataSobrepor = filter_var($dataSobrepor, FILTER_SANITIZE_SPECIAL_CHARS); // Sanitiza a data para evitar caracteres especiais

// Verifica se o campo observação excede 35 caracteres
if (mb_strlen($observacao, 'UTF-8') > 35) {
    // Redireciona para uma página de erro se o campo observação for inválido
    header("Location: ../ViewFail/FailCreateObservacaoInvalida.php?erro=" . urlencode("O campo observação excede o limite de 35 caracteres. Refaça a operação e tente novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Verifica se os dados fornecidos são válidos
if (empty($idProduto) || !validarQuantidade($quantidadeSobrepor) || !validarData($dataSobrepor) || !datasSaoValidas($dataSobrepor)) {
    // Redireciona para uma página de erro se algum dado for inválido
    header("Location: ../ViewFail/FailCreateDadosInvalidos.php?erro=" . urlencode("Os dados fornecidos são inválidos. Refaça a operação e tente novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Obtém os dados do usuário da sessão
$idUsuario = $_SESSION['usuarioId']; // ID do usuário
$nomeUsuario = mb_strtoupper($_SESSION['usuarioNome'], 'UTF-8'); // Nome do usuário em maiúsculas
$codigoPUsuario = mb_strtoupper($_SESSION['usuarioCodigoP'], 'UTF-8'); // Código do usuário em maiúsculas

// Define valores fixos para a operação
$operacao = "SOBREPOR"; // Tipo de operação
$situacao = "SOBREPOSIÇÃO"; // Situação da operação

// Verifica a conexão com o banco de dados
if ($conn->connect_error) {
    die("Falha na conexão: " . $conn->connect_error); // Exibe mensagem de erro se a conexão falhar
}

// Inicia uma transação para garantir a consistência dos dados
$conn->begin_transaction();

try {
    // Verifica se há reservas para o produto
    $sqlVerificaReserva = "SELECT RESERVADO_TRANSFERENCIA FROM ESTOQUE WHERE IDPRODUTO = ?"; // Consulta para verificar reservas
    $stmtVerificaReserva = $conn->prepare($sqlVerificaReserva); // Prepara a consulta
    $stmtVerificaReserva->bind_param("i", $idProduto); // Liga o ID do produto ao parâmetro
    $stmtVerificaReserva->execute(); // Executa a consulta
    $stmtVerificaReserva->bind_result($reservado); // Liga o resultado à variável
    $stmtVerificaReserva->fetch(); // Obtém o resultado
    $stmtVerificaReserva->close(); // Fecha o statement
    
    // Verifica se há reserva
    $temReserva = $reservado > 0;

    // Insere dados na tabela SOBREPOR
    $sqlInsertSobrepor = "INSERT INTO SOBREPOR (QUANTIDADE, DATASOBREPOR, OBSERVACAO, OPERACAO, SITUACAO, IDPRODUTO, IDUSUARIO, NOME, CODIGOP) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"; // Consulta para inserção
    $stmtInsert = $conn->prepare($sqlInsertSobrepor); // Prepara a consulta de inserção
    $stmtInsert->bind_param("isssssiis", $quantidadeSobrepor, $dataSobrepor, $observacao, strtoupper($operacao), strtoupper($situacao), $idProduto, $idUsuario, $nomeUsuario, $codigoPUsuario); // Liga os parâmetros

    if (!$stmtInsert->execute()) {
        // Se a inserção falhar, redireciona para uma página de erro
        header("Location: ../ViewFail/FailCreateInserirDadosSobrepor.php?erro=" . urlencode("Não foi possível inserir os dados na tabela SOBREPOR. Informe o departamento de TI"));
        exit(); // Interrompe a execução do script após o redirecionamento
    }

    // Atualiza a tabela ESTOQUE com a quantidade sobreposta
    $sqlUpdateEstoque = "UPDATE ESTOQUE SET QUANTIDADE = ? WHERE IDPRODUTO = ?"; // Consulta para atualizar o estoque
    $stmtUpdate = $conn->prepare($sqlUpdateEstoque); // Prepara a consulta de atualização
    $stmtUpdate->bind_param("ii", $quantidadeSobrepor, $idProduto); // Liga os parâmetros

    if (!$stmtUpdate->execute()) {
        // Se a atualização falhar, redireciona para uma página de erro
        header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto. Refaça a operação e tente novamente"));
        exit(); // Interrompe a execução do script após o redirecionamento
    }

    // Se todas as operações foram bem-sucedidas, faz o commit da transação
    $conn->commit();

    // Redireciona para a página de sucesso dependendo se há reserva ou não
    if ($temReserva) {
        header("Location: ../ViewSucess/SucessCreateAtualizaEstoqueComTransferencia.php?sucesso=" . urlencode("O estoque do produto será atualizado após a confirmação das transferências pendentes"));
    } else {
        header("Location: ../ViewSucess/SucessCreateAtualizaEstoque.php?sucesso=" . urlencode("O estoque do produto foi atualizado com sucesso"));
    }
    exit(); // Interrompe a execução do script após o redirecionamento
    
} catch (Exception $e) {
    // Em caso de erro, faz o rollback da transação para reverter as alterações
    $conn->rollback();

    // Registra o erro no log do servidor
    error_log("Erro: " . $e->getMessage());

    // Redireciona para a página de falha com uma mensagem de erro
    header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto. Refaça a operação e tente novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
} finally {
    // Fecha os statements e a conexão com o banco de dados
    if (isset($stmtInsert)) {
        $stmtInsert->close(); // Fecha o statement de inserção
    }
    if (isset($stmtUpdate)) {
        $stmtUpdate->close(); // Fecha o statement de atualização
    }
    $conn->close(); // Fecha a conexão com o banco de dados
}
?>
