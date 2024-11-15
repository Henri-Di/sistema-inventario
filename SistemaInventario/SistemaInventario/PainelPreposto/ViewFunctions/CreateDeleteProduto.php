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
    // Se qualquer uma das variáveis de sessão obrigatórias não estiver definida, redireciona o usuário para a página de erro de autenticação
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}

// Conexão e consulta ao banco de dados
require_once('../../ViewConnection/ConnectionInventario.php'); // Inclui o arquivo que estabelece a conexão com o banco de dados

// Função para executar consultas SQL com prepared statements
function executeQuery($conn, $sql, $params = null) {
    // Prepara a consulta SQL
    $stmt = $conn->prepare($sql);

    // Se parâmetros forem fornecidos, faz o binding dos parâmetros ao prepared statement
    if ($params !== null) {
        $stmt->bind_param(...$params); // Descompacta o array de parâmetros e os associa ao statement
    }

    // Executa a consulta SQL
    $stmt->execute();
    // Obtém o resultado da consulta, se houver
    $result = $stmt->get_result();
    // Fecha o statement para liberar recursos
    $stmt->close();

    return $result; // Retorna o resultado da consulta
}

// Obter o ID do parâmetro GET e sanitizar para evitar injeção de SQL
$id = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_NUMBER_INT);

// Verificar se o ID não está vazio
if (!empty($id)) {
    // Iniciar uma transação para garantir a consistência das operações
    $conn->begin_transaction();

    try {
        // Construir as consultas SQL para exclusão nas tabelas relacionadas
        // A execução das consultas depende do ID do produto
        $sqlDeleteEstoque = "DELETE FROM ESTOQUE WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteEstoque, ['i', $id]);

        $sqlDeleteAcrescimo = "DELETE FROM ACRESCIMO WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteAcrescimo, ['i', $id]);

        $sqlDeleteSubtracao = "DELETE FROM SUBTRACAO WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteSubtracao, ['i', $id]);

        $sqlDeleteSobrepor = "DELETE FROM SOBREPOR WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteSobrepor, ['i', $id]);

        $sqlDeleteReserva = "DELETE FROM RESERVA WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteReserva, ['i', $id]);

        $sqlDeleteDevolver = "DELETE FROM DEVOLVER WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteDevolver, ['i', $id]);

        $sqlDeleteInutilizar = "DELETE FROM INUTILIZAR WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteInutilizar, ['i', $id]);

        $sqlDeleteNotaFiscal = "DELETE FROM NOTAFISCAL WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteNotaFiscal, ['i', $id]);

        // Construir a consulta SQL para exclusão do produto
        $sqlDeleteProduto = "DELETE FROM PRODUTO WHERE IDPRODUTO = ?";
        executeQuery($conn, $sqlDeleteProduto, ['i', $id]);

        // Commit da transação se todas as operações foram bem-sucedidas
        $conn->commit();

        // Redirecionar para a página de sucesso com uma mensagem informando que o produto foi removido com sucesso
        header("Location: ../ViewSucess/SucessCreateDeleteProduto.php?sucesso=" . urlencode("O produto foi removido com sucesso"));
        exit(); // Termina a execução do script após redirecionamento
    } catch (Exception $e) {
        // Em caso de erro específico do MySQL, faz rollback da transação
        $conn->rollback();
        
        // Redirecionar para a página de falha com uma mensagem de erro específica do MySQL
        header("Location: ../ViewFail/FailCreateDeleteProduto.php?erro=" . urlencode("Não foi possível remover o produto. Tente novamente " . $e->getMessage()));
        exit(); // Termina a execução do script após redirecionamento
    } catch (Exception $e) {
        // Em caso de erro genérico, faz rollback da transação
        $conn->rollback();

        // Redirecionar para a página de falha com uma mensagem de erro genérica
        header("Location: ../ViewFail/FailCreateDeleteProduto.php?erro=" . urlencode("Não foi possível remover o produto. Tente novamente" . $e->getMessage()));
        exit(); // Termina a execução do script após redirecionamento
    } finally {
        // Fechar a conexão com o banco de dados para liberar recursos
        $conn->close();
    }
} else {
    // Se o ID estiver vazio ou não for um número válido, redirecionar para a página de falha
    header("Location: ../ViewFail/FailCreateDeleteProduto.php?erro=" . urlencode("Não foi possível remover o produto. Tente novamente" . $e->getMessage()));
    exit(); // Termina a execução do script após redirecionamento
}
?>
