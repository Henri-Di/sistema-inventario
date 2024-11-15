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

// Verifica se o usuário está autenticado
if (!isset($_SESSION['usuarioId']) || !isset($_SESSION['usuarioNome']) || !isset($_SESSION['usuarioCodigoP'])) {
    // Se não estiver autenticado, redireciona para a página de erro
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Encerra a execução do script para garantir que o código abaixo não seja executado
}

// Inclui o arquivo de conexão com o banco de dados
require_once('../../ViewConnection/ConnectionInventario.php');

// Verifica se o formulário foi submetido via método POST e se todos os campos obrigatórios estão presentes
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['NomeUsuario'], $_POST['CodigoUsuario'], $_POST['SenhaUsuario'], $_POST['EmailUsuario'], $_POST['DataCenter'], $_POST['NiveldeAcesso'])) {

    // Recebe e sanitiza os dados do formulário, convertendo para maiúsculas onde necessário
    $nome = mb_strtoupper(filter_input(INPUT_POST, 'NomeUsuario', FILTER_SANITIZE_SPECIAL_CHARS), 'UTF-8'); // Nome do usuário convertido para maiúsculas e sanitizado
    $codigo = mb_strtoupper(filter_input(INPUT_POST, 'CodigoUsuario', FILTER_SANITIZE_SPECIAL_CHARS), 'UTF-8'); // Código do usuário convertido para maiúsculas e sanitizado
    $senha = password_hash($_POST['SenhaUsuario'], PASSWORD_DEFAULT); // Hasheia a senha do usuário para segurança
    $email = filter_input(INPUT_POST, 'EmailUsuario', FILTER_SANITIZE_EMAIL); // Sanitiza o email do usuário
    $datacenter = mb_strtoupper(filter_input(INPUT_POST, 'DataCenter', FILTER_SANITIZE_SPECIAL_CHARS), 'UTF-8'); // Nome do data center convertido para maiúsculas e sanitizado
    $nivel_acesso = mb_strtoupper(filter_input(INPUT_POST, 'NiveldeAcesso', FILTER_SANITIZE_SPECIAL_CHARS), 'UTF-8'); // Nível de acesso convertido para maiúsculas e sanitizado
    $datacadastro = date('Y-m-d'); // Data atual no formato 'YYYY-MM-DD'

    // Verifica se o usuário ou e-mail já existem no banco de dados
    $stmt = $conn->prepare("SELECT * FROM USUARIO WHERE CODIGOP = ? OR EMAIL = ?");
    if ($stmt) {
        $stmt->bind_param("ss", $codigo, $email); // Associa os parâmetros da consulta SQL
        $stmt->execute(); // Executa a consulta
        $result = $stmt->get_result(); // Obtém o resultado da consulta

        // Se encontrar algum resultado, significa que o usuário ou e-mail já existem
        if ($result->num_rows > 0) {
            // Define uma mensagem de erro e redireciona para a página de falha
            $_SESSION['message'] = "Usuário ou e-mail já existem.";
            header("Location: ../ViewFail/FailCreateUsuarioExistente.php?erro=". urlencode("Não foi possível realizar o cadastro do novo usuário. Informações de um usuário já existente estão sendo utilizadas"));
            exit(); // Encerra a execução do script
        } else {
            // Prepara e executa a inserção do novo usuário no banco de dados
            $stmt = $conn->prepare("INSERT INTO USUARIO (NOME, CODIGOP, SENHA, EMAIL, DATACENTER, NIVEL_ACESSO, DATACADASTRO, PRIMEIRO_LOGIN) VALUES (?, ?, ?, ?, ?, ?, ?, 1)");
            if ($stmt) {
                $stmt->bind_param("sssssss", $nome, $codigo, $senha, $email, $datacenter, $nivel_acesso, $datacadastro); // Associa os parâmetros da inserção
                if ($stmt->execute()) {
                    // Define uma mensagem de sucesso e redireciona para a página de sucesso
                    $_SESSION['message'] = "Usuário criado com sucesso.";
                    header("Location: ../ViewSucess/SucessCreateUsuario.php?sucesso=" . urlencode("O cadastro do usuário foi realizado com sucesso"));
                    exit(); // Encerra a execução do script
                } else {
                    // Define uma mensagem de erro e redireciona para a página de falha se a inserção falhar
                    $_SESSION['message'] = "Falha ao criar usuário.";
                    header("Location: ../ViewFail/FailCreateNovoUsuario.php?erro=" . urlencode("Não foi possível realizar o cadastro do usuário. Refaça a operação e tente novamente"));
                    exit(); // Encerra a execução do script
                }
            } else {
                // Define uma mensagem de erro e redireciona para a página de falha se a preparação da inserção falhar
                $_SESSION['message'] = "Erro na preparação da inserção de usuário.";
                header("Location: ../ViewFail/FailCreateInserirDadosUsuario.php?erro=" . urlencode("Não foi possível inserir os dados na tabela USUARIO. Informe o departamento de TI"));
                exit(); // Encerra a execução do script
            }
        }
    } else {
        // Define uma mensagem de erro e redireciona para a página de falha se a preparação da consulta falhar
        $_SESSION['message'] = "Erro na preparação da consulta.";
        header("Location: ../ViewFail/FailCreateNovoUsuario.php?erro=" . urlencode("Não foi possível realizar o cadastro do usuário. Refaça a operação e tente novamente"));
        exit(); // Encerra a execução do script
    }

    // Fecha a declaração e a conexão com o banco de dados
    $stmt->close();
    $conn->close();
}
?>
