<?php
// Iniciar sessão
session_start();

// Verificar se o usuário está autenticado e é o primeiro login
if (!isset($_SESSION['usuarioId']) || $_SESSION['usuarioPrimeiroLogin'] != 1) {
    header("Location: ../Index.php");
    exit();
}

// Conexão e consulta ao banco de dados
require_once('../ViewConnection/ConnectionInventario.php');

// Função para redirecionar com base no nível de acesso
function redirecionarPorNivelAcesso($nivelAcesso) {
    if ($nivelAcesso == 'GESTOR') {
        header("Location: ../PainelGestor/ViewForms/PainelAdministrativo.php");
        exit();
    } elseif ($nivelAcesso == 'PREPOSTO') {
        header("Location: ../PainelPreposto/ViewForms/PainelPreposto.php");
        exit();
    }elseif ($nivelAcesso == 'ANALISTA') {
        header("Location: ../PainelAnalista/ViewForms/PainelAnalista.php");
        exit();
    }elseif ($nivelAcesso == 'TÉCNICO') {
        header("Location: ../PainelTecnico/ViewForms/PainelTecnico.php");
        exit();
    }
    exit(); // Termina a execução do script após o redirecionamento
}

// Verificar se o formulário foi enviado
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitizar a nova senha
    $novaSenha = filter_input(INPUT_POST, 'NovaSenha', FILTER_SANITIZE_SPECIAL_CHARS);
    $confirmarSenha = filter_input(INPUT_POST, 'ConfirmarSenha', FILTER_SANITIZE_SPECIAL_CHARS);

    if ($novaSenha === $confirmarSenha) {
        // Hashear a nova senha
        $hashNovaSenha = password_hash($novaSenha, PASSWORD_DEFAULT);

        // Atualizar a senha e definir primeiro login como 0
        $stmt = $conn->prepare("UPDATE USUARIO SET SENHA = ?, PRIMEIRO_LOGIN = 0 WHERE IDUSUARIO = ?");
        if ($stmt) {
            $stmt->bind_param('si', $hashNovaSenha, $_SESSION['usuarioId']);
            if ($stmt->execute()) {
                // Atualizar o status de primeiro login na sessão
                $_SESSION['usuarioPrimeiroLogin'] = 0;
                
                // Redirecionar para o painel adequado
                redirecionarPorNivelAcesso($_SESSION['usuarioNivelAcesso']);
            } else {
                $erro = "Erro ao atualizar a senha. Tente novamente mais tarde.";
            }
            $stmt->close();
        } else {
            $erro = "Erro na preparação da atualização da senha.";
        }
    } else {
        $erro = "As senhas não coincidem.";
    }

    // Fechar a conexão
    $conn->close();
}
?>
