<?php
// Iniciar sessão
session_start();
session_regenerate_id(true);

header("Content-Security-Policy: default-src 'self'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

// Incluir o arquivo de conexão com o banco de dados
require_once("../ViewConnection/ConnectionInventario.php");

// Função para redirecionar com base no nível de acesso
function redirecionarPorNivelAcesso($nivelAcesso) {
    if ($nivelAcesso == 'GESTOR') {
        header("Location: ../PainelGestor/ViewForms/PainelAdministrativo.php");
        exit();
    } elseif ($nivelAcesso == 'PREPOSTO') {
        header("Location: ../PainelPreposto/ViewForms/PainelPresposto.php");
        exit();
    } elseif ($nivelAcesso == 'ANALISTA') {
        header("Location: ../PainelAnalista/ViewForms/PainelAnalista.php");
        exit();
    }elseif ($nivelAcesso == 'TÉCNICO') {
        header("Location: ../PainelTecnico/ViewForms/PainelTecnico.php");
        exit();
    }
    exit(); // Termina a execução do script após o redirecionamento
}

// Verificar se os campos CodigoP e Senha estão definidos e são válidos
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['CodigoP']) && isset($_POST['Senha'])) {
    // Sanitizar entradas usando filter_input
    $codigoP = filter_input(INPUT_POST, 'CodigoP', FILTER_SANITIZE_SPECIAL_CHARS);
    $senha = $_POST['Senha'];

    // Preparar a consulta SQL usando prepared statements para evitar SQL Injection
    $stmt = $conn->prepare("SELECT IDUSUARIO, NOME, CODIGOP, DATACENTER, NIVEL_ACESSO, SENHA, PRIMEIRO_LOGIN FROM USUARIO WHERE CODIGOP = ? LIMIT 1");
    if ($stmt) {
        $stmt->bind_param('s', $codigoP);
        $stmt->execute();
        $stmt->store_result();
        
        // Verificar se encontrou exatamente um usuário
        if ($stmt->num_rows == 1) {
            $stmt->bind_result($idUsuario, $nome, $codigoP, $datacenter, $nivelAcesso, $hashSenha, $primeiroLogin);
            $stmt->fetch();
            
            // Verificar se a senha está correta
            if (password_verify($senha, $hashSenha)) {
                // Armazenar dados na sessão, exceto a senha
                $_SESSION['usuarioId'] = $idUsuario;
                $_SESSION['usuarioNome'] = $nome;
                $_SESSION['usuarioCodigoP'] = $codigoP;
                $_SESSION['usuarioDatacenter'] = $datacenter;
                $_SESSION['usuarioNivelAcesso'] = $nivelAcesso;
                $_SESSION['usuarioPrimeiroLogin'] = $primeiroLogin;

                // Verificar se é o primeiro login
                if ($primeiroLogin == 1) {
                    header("Location: ../ViewTrocarSenha/TrocarSenhaUsuario.php");
                } else {
                    // Redirecionar com base no nível de acesso
                    redirecionarPorNivelAcesso($nivelAcesso);
                }
                exit(); // Termina a execução do script após o redirecionamento
            } else {
                // Senha incorreta
                $_SESSION['loginErro'] = "<p style='color:red;font-weight:bold;margin-left:0%;font-size:14px;'>Credenciais inválidas</p>";
                header("Location: ../Index.php");
                exit(); // Termina a execução do script após o redirecionamento
            }
        } else {
            // Usuário não encontrado
            $_SESSION['loginErro'] = "<p style='color:red;font-weight:bold;margin-left:0%;font-size:14px;'>Credenciais inválidas</p>";
            header("Location: ../Index.php");
            exit(); // Termina a execução do script após o redirecionamento
        }

        // Fechar a declaração
        $stmt->close();
    } else {
        // Mensagem de erro em caso de falha na preparação da consulta
        $_SESSION['loginErro'] = "<p style='color:red;font-weight:bold;margin-left:45%;font-size:14px;'>Erro no servidor. Tente novamente mais tarde.</p>";
        header("Location: ../Index.php");
        exit(); // Termina a execução do script após o redirecionamento
    }

    // Fechar a conexão
    $conn->close();
} else {
    // Verificar se o usuário está autenticado
    if (isset($_SESSION['usuarioId']) && isset($_SESSION['usuarioNivelAcesso'])) {
        // Redirecionar com base no nível de acesso
        redirecionarPorNivelAcesso($_SESSION['usuarioNivelAcesso']);
    } else {
        // Redirecionar para a página de login
        header("Location: ../Index.php");
        exit(); // Termina a execução do script após o redirecionamento
    }
}


?>