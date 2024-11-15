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
    // Se as informações do usuário não estiverem disponíveis na sessão, redireciona para a página de erro de autenticação
    header("Location: ../ViewFail/FailCreateUsuarioNaoAutenticado.php?erro=" . urlencode("O usuário não está autenticado. Realize o login novamente"));
    exit(); // Interrompe a execução do script para evitar que o código subsequente seja executado
}

// Conexão e consulta ao banco de dados
require_once('../../ViewConnection/ConnectionInventario.php'); // Inclui o arquivo que estabelece a conexão com o banco de dados

// Verificar se os dados do formulário foram submetidos
if ($_SERVER["REQUEST_METHOD"] == "POST") { // Verifica se o método de requisição é POST
    // Sanitizar e validar os dados de entrada
    $id = filter_input(INPUT_POST, 'id', FILTER_SANITIZE_NUMBER_INT); // Sanitiza o ID do produto passado no formulário
    $materialId = filter_input(INPUT_POST, 'Material', FILTER_SANITIZE_NUMBER_INT); // Sanitiza o ID do material
    $conectorId = filter_input(INPUT_POST, 'Conector', FILTER_SANITIZE_NUMBER_INT); // Sanitiza o ID do conector
    $metragemId = filter_input(INPUT_POST, 'Metragem', FILTER_SANITIZE_NUMBER_INT); // Sanitiza o ID da metragem
    $modeloId = filter_input(INPUT_POST, 'Modelo', FILTER_SANITIZE_NUMBER_INT); // Sanitiza o ID do modelo
    $fornecedorId = filter_input(INPUT_POST, 'Fornecedor', FILTER_SANITIZE_NUMBER_INT); // Sanitiza o ID do fornecedor
    $datacenterNome = filter_input(INPUT_POST, 'DataCenter', FILTER_SANITIZE_SPECIAL_CHARS); // Sanitiza o nome do datacenter

    // Iniciar transação
    $conn->begin_transaction(); // Inicia uma transação no banco de dados

    try {
        // Verificar se o datacenter existe, se não, inserir
        $idDatacenter = null; // Inicializa a variável para o ID do datacenter
        if (!empty($datacenterNome)) {
            // Consulta para verificar se o datacenter já existe
            $sqlDatacenter = "SELECT IDDATACENTER FROM DATACENTER WHERE NOME = ?";
            $stmtDatacenter = $conn->prepare($sqlDatacenter); // Prepara a consulta SQL
            $stmtDatacenter->bind_param("s", $datacenterNome); // Associa o parâmetro do nome do datacenter
            $stmtDatacenter->execute(); // Executa a consulta
            $stmtDatacenter->store_result(); // Armazena o resultado da consulta para processamento posterior

            if ($stmtDatacenter->num_rows > 0) {
                // Se o datacenter já existe, obtém o ID
                $stmtDatacenter->bind_result($idDatacenter); // Associa o resultado da consulta à variável $idDatacenter
                $stmtDatacenter->fetch(); // Busca o resultado da consulta
            } else {
                // Se o datacenter não existe, insere um novo
                $sqlInsertDatacenter = "INSERT INTO DATACENTER (NOME) VALUES (?)";
                $stmtInsertDatacenter = $conn->prepare($sqlInsertDatacenter); // Prepara a consulta de inserção
                $stmtInsertDatacenter->bind_param("s", $datacenterNome); // Associa o parâmetro do nome do datacenter
                $stmtInsertDatacenter->execute(); // Executa a consulta de inserção
                $idDatacenter = $stmtInsertDatacenter->insert_id; // Obtém o ID do datacenter recém-inserido
                $stmtInsertDatacenter->close(); // Fecha o statement de inserção
            }

            $stmtDatacenter->close(); // Fecha o statement de verificação do datacenter
        }

        // Preparar a consulta SQL para atualização
        $sqlUpdate = "UPDATE PRODUTO SET "; // Inicia a consulta SQL de atualização
        $params = []; // Array para armazenar os parâmetros da consulta
        $types = ''; // String para armazenar os tipos dos parâmetros

        // Adicionar as colunas a serem atualizadas com base nos dados recebidos
        if (!empty($materialId)) {
            $sqlUpdate .= "IDMATERIAL = ?, "; // Adiciona a coluna de material à consulta SQL
            $params[] = $materialId; // Adiciona o valor do material ao array de parâmetros
            $types .= 'i'; // Adiciona o tipo 'i' (integer) ao string de tipos
        }
        if (!empty($conectorId)) {
            $sqlUpdate .= "IDCONECTOR = ?, "; // Adiciona a coluna de conector à consulta SQL
            $params[] = $conectorId; // Adiciona o valor do conector ao array de parâmetros
            $types .= 'i'; // Adiciona o tipo 'i' (integer) ao string de tipos
        }
        if (!empty($metragemId)) {
            $sqlUpdate .= "IDMETRAGEM = ?, "; // Adiciona a coluna de metragem à consulta SQL
            $params[] = $metragemId; // Adiciona o valor da metragem ao array de parâmetros
            $types .= 'i'; // Adiciona o tipo 'i' (integer) ao string de tipos
        }
        if (!empty($modeloId)) {
            $sqlUpdate .= "IDMODELO = ?, "; // Adiciona a coluna de modelo à consulta SQL
            $params[] = $modeloId; // Adiciona o valor do modelo ao array de parâmetros
            $types .= 'i'; // Adiciona o tipo 'i' (integer) ao string de tipos
        }
        if (!empty($fornecedorId)) {
            $sqlUpdate .= "IDFORNECEDOR = ?, "; // Adiciona a coluna de fornecedor à consulta SQL
            $params[] = $fornecedorId; // Adiciona o valor do fornecedor ao array de parâmetros
            $types .= 'i'; // Adiciona o tipo 'i' (integer) ao string de tipos
        }
        if (!empty($idDatacenter)) {
            $sqlUpdate .= "IDDATACENTER = ?, "; // Adiciona a coluna de datacenter à consulta SQL
            $params[] = $idDatacenter; // Adiciona o valor do datacenter ao array de parâmetros
            $types .= 'i'; // Adiciona o tipo 'i' (integer) ao string de tipos
        }

        // Remove a última vírgula e espaço do SQL de atualização
        $sqlUpdate = rtrim($sqlUpdate, ", "); // Remove a vírgula final da consulta SQL

        // Adicionar a cláusula WHERE para especificar o registro a ser atualizado
        $sqlUpdate .= " WHERE IDPRODUTO = ?";
        $params[] = $id; // Adiciona o ID do produto ao array de parâmetros
        $types .= 'i'; // Adiciona o tipo 'i' (integer) ao string de tipos

        // Inicializar o statement
        $stmtUpdate = $conn->prepare($sqlUpdate); // Prepara a consulta SQL de atualização

        // Verificar se o statement foi preparado com sucesso
        if (!$stmtUpdate) {
            // Se o statement não foi preparado, redireciona para a página de falha
            header("Location: ../ViewFail/FailCreateModificaProduto.php?erro=" . urlencode("Não foi possivel realizar a alteração no cadastro do produto. Refaça a operação e tente novamente"));
            exit(); // Interrompe a execução do script após o redirecionamento
        }

        // Bind dos parâmetros
        if (!empty($types) && count($params) > 0) {
            $stmtUpdate->bind_param($types, ...$params); // Associa os parâmetros ao statement
        } else {
            // Se não houver parâmetros, redireciona para a página de falha
            header("Location: ../ViewFail/FailCreateModificaProduto.php?erro=" . urlencode("Não foi possivel realizar a alteração no cadastro do produto. Refaça a operação e tente novamente"));
            exit(); // Interrompe a execução do script após o redirecionamento
        }

        // Executar o statement de atualização
        if ($stmtUpdate->execute()) {
            // Se a atualização for bem-sucedida, faz o commit da transação
            $conn->commit(); // Confirma as alterações no banco de dados
            // Redireciona para a página de sucesso
            header("Location: ../ViewSucess/SucessCreateModificaProduto.php?sucesso=" . urlencode("A alteração foi realizada com sucesso no cadastro do produto"));
            exit(); // Interrompe a execução do script após o redirecionamento
        } else {
            // Se a atualização falhar, redireciona para a página de falha
            header("Location: ../ViewFail/FailCreateModificaProduto.php?erro=" . urlencode("Não foi possivel realizar a alteração no cadastro do produto. Refaça a operação e tente novamente"));
            exit(); // Interrompe a execução do script após o redirecionamento
        }

        // Fechar o statement de atualização
        $stmtUpdate->close(); // Fecha o statement de atualização
    } catch (Exception $e) {
        // Se ocorrer uma exceção durante a execução, faz rollback da transação
        $conn->rollback(); // Reverte as alterações no banco de dados
        // Redireciona para a página de falha
        header("Location: ../ViewFail/FailCreateModificaProduto.php?erro=" . urlencode("Não foi possivel realizar a alteração no cadastro do produto. Refaça a operação e tente novamente"));
        exit(); // Interrompe a execução do script após o redirecionamento
    } finally {
        // Fechar a conexão
        $conn->close(); // Fecha a conexão com o banco de dados
    }
} else {
    // Redirecionar para a página de falha se o método de requisição não for POST
    header("Location: ../ViewFail/FailCreateModificaProduto.php?erro=" . urlencode("Não foi possivel realizar a alteração no cadastro do produto. Refaça a operação e tente novamente"));
    exit(); // Interrompe a execução do script após o redirecionamento
}
?>
