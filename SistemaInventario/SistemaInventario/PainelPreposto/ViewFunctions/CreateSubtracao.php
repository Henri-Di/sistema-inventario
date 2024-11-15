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
    // Se o usuário não estiver autenticado, redireciona para uma página de erro
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Inclui o arquivo de conexão com o banco de dados
require_once('../../ViewConnection/ConnectionInventario.php');

// Função para sanitizar os dados recebidos do formulário
function sanitizeData($conn, $data) {
    // Remove espaços em branco no início e no fim da string
    $data = trim($data);
    // Remove barras invertidas adicionadas automaticamente pelo PHP
    $data = stripslashes($data);
    // Escapa caracteres especiais para evitar SQL Injection
    $data = $conn->real_escape_string($data);
    // Converte a string para maiúsculas
    $data = mb_strtoupper($data, 'UTF-8');
    return $data; // Retorna o dado sanitizado
}

// Obtém os dados enviados pelo formulário e sanitiza cada um
$idProduto = isset($_POST['id']) ? sanitizeData($conn, $_POST['id']) : '';
$numwo = isset($_POST['NumWo']) ? sanitizeData($conn, $_POST['NumWo']) : '';
$quantidadeSubtracao = isset($_POST['Subtracao']) ? sanitizeData($conn, $_POST['Subtracao']) : '';
$dataSubtracao = isset($_POST['DataSubtracao']) ? sanitizeData($conn, $_POST['DataSubtracao']) : '';
$observacao = isset($_POST['Observacao']) ? sanitizeData($conn, $_POST['Observacao']) : '';

// Obtém os dados do usuário da sessão e sanitiza
$idUsuario = sanitizeData($conn, $_SESSION['usuarioId']);
$nomeUsuario = sanitizeData($conn, $_SESSION['usuarioNome']);
$codigoPUsuario = sanitizeData($conn, $_SESSION['usuarioCodigoP']);

// Define valores fixos para a operação
$operacao = "SUBTRAÇÃO"; // Tipo de operação realizada
$situacao = "DIMINUIDO"; // Situação após a operação

// Verifica se o campo observação excede 35 caracteres
if (mb_strlen($observacao, 'UTF-8') > 35) {
    // Redireciona para uma página de erro se a observação for inválida
    header("Location: ../ViewFail/FailCreateObservacaoInvalida.php?erro=" . urlencode("O campo observação excede o limite de 35 caracteres. Refaça a operação e tente novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Verifica a conexão com o banco de dados
if ($conn->connect_error) {
    // Exibe uma mensagem de erro se a conexão falhar
    die("Falha na conexão: " . $conn->connect_error);
}

// Verifica se a quantidade a ser subtraída é positiva
if ($quantidadeSubtracao <= 0) {
    // Redireciona para uma página de erro se a quantidade for negativa ou zero
    header("Location: ../ViewFail/FailCreateQuantidadeNegativa.php?erro=" . urlencode("Não é permitido o registro de valores negativos no campo de quantidade"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Função para validar se a data de subtração é válida
function datasSaoValidas($dataSubtracao) {
    try {
        // Define o fuso horário para as datas
        $timeZone = new DateTimeZone('America/Sao_Paulo'); // Ajuste o fuso horário conforme necessário

        // Cria objetos DateTime para a data fornecida e a data atual
        $dataCadastroObj = DateTime::createFromFormat('Y-m-d', $dataSubtracao, $timeZone);
        $currentDateObj = new DateTime('now', $timeZone); // Data atual do servidor

        // Formata as datas para comparação
        $dataCadastroFormatada = $dataCadastroObj->format('Y-m-d');
        $currentDate = $currentDateObj->format('Y-m-d');

        // Verifica se a data fornecida é igual à data atual
        if ($dataCadastroFormatada !== $currentDate) {
            return false; // Retorna falso se as datas não coincidirem
        }

        return true; // Retorna verdadeiro se as datas coincidirem
    } catch (Exception $e) {
        // Trata exceções que possam ocorrer durante a validação das datas
        return false; // Retorna falso em caso de exceção
    }
}

// Inicia uma transação para garantir a consistência dos dados
$conn->begin_transaction();

try {
    // Verifica se há reservas para o produto
    $sqlVerificaReserva = "SELECT RESERVADO_TRANSFERENCIA FROM ESTOQUE WHERE IDPRODUTO = ?";
    $stmtVerificaReserva = $conn->prepare($sqlVerificaReserva); // Prepara a consulta
    $stmtVerificaReserva->bind_param("i", $idProduto); // Liga o ID do produto ao parâmetro
    $stmtVerificaReserva->execute(); // Executa a consulta
    $stmtVerificaReserva->bind_result($reservado); // Obtém o resultado da consulta
    $stmtVerificaReserva->fetch(); // Busca os dados
    $stmtVerificaReserva->close(); // Fecha o statement

    // Determina se há reserva para o produto
    $temReserva = $reservado > 0;

    // Insere os dados na tabela SUBTRACAO
    $sqlInsertSubtracao = "INSERT INTO SUBTRACAO (NUMWO, QUANTIDADE, DATASUBTRACAO, OBSERVACAO, OPERACAO, SITUACAO, IDPRODUTO, IDUSUARIO, NOME, CODIGOP) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    $stmtInsert = $conn->prepare($sqlInsertSubtracao); // Prepara a consulta de inserção
    $stmtInsert->bind_param("sisssssiss", $numwo, $quantidadeSubtracao, $dataSubtracao, $observacao, $operacao, $situacao, $idProduto, $idUsuario, $nomeUsuario, $codigoPUsuario); // Liga os parâmetros
    
    if (!$stmtInsert->execute()) {
        // Se a inserção falhar, redireciona para uma página de erro
        header("Location: ../ViewFail/FailCreateInserirDadosSubtracao.php?erro=" . urlencode("Não foi possível inserir os dados na tabela SUBTRACAO. Informe o departamento de TI"));
        exit(); // Interrompe a execução do script após o redirecionamento
    }

    // Atualiza a tabela ESTOQUE subtraindo a quantidade
    $sqlUpdateEstoque = "UPDATE ESTOQUE SET QUANTIDADE = QUANTIDADE - ? WHERE IDPRODUTO = ?";
    
    $stmtUpdate = $conn->prepare($sqlUpdateEstoque); // Prepara a consulta de atualização
    $stmtUpdate->bind_param("ii", $quantidadeSubtracao, $idProduto); // Liga os parâmetros
    
    if (!$stmtUpdate->execute()) {
        // Se a atualização falhar, redireciona para uma página de erro
        header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto. Refaça a operação e tente novamente"));
        exit(); // Interrompe a execução do script após o redirecionamento
    }

    // Verifica se a data de subtração é válida
    if (!datasSaoValidas($dataSubtracao)) {
        // Se a data não for válida, redireciona para uma página de erro
        header("Location: ../ViewFail/FailCreateDataInvalida.php?erro=" . urlencode("A data está fora do intervalo permitido. A data deve ser igual à data atual"));
        exit(); // Interrompe a execução do script após o redirecionamento
    }

    // Faz o commit da transação se todas as operações foram bem-sucedidas
    $conn->commit();

    // Redireciona para a página de sucesso apropriada com base na existência de reservas
    if ($temReserva) {
        header("Location: ../ViewSucess/SucessCreateAtualizaEstoqueComTransferencia.php?sucesso=" . urlencode("O estoque do produto será atualizado após a confirmação das transferências pendentes"));
    } else {
        header("Location: ../ViewSucess/SucessCreateAtualizaEstoque.php?sucesso=" . urlencode("O estoque do produto foi atualizado com sucesso"));
    }
    exit(); // Interrompe a execução do script após o redirecionamento

} catch (Exception $e) {
    // Em caso de erro, faz o rollback da transação para reverter as alterações
    $conn->rollback();

    // Exibe a mensagem de erro para depuração
    echo "Erro: " . $e->getMessage();

    // Redireciona para uma página de erro
    header("Location: ../ViewFail/FailCreateAtualizaEstoque.php?erro=" . urlencode("Não foi possível atualizar o estoque do produto. Refaça a operação e tente novamente "));
    exit(); // Interrompe a execução do script após o redirecionamento
    
} finally {
    // Fecha os statements e a conexão com o banco de dados, se existirem
    if (isset($stmtInsert)) {
        $stmtInsert->close(); // Fecha o statement de inserção
    }
    if (isset($stmtUpdate)) {
        $stmtUpdate->close(); // Fecha o statement de atualização
    }
    
    $conn->close(); // Fecha a conexão com o banco de dados
}
?>
