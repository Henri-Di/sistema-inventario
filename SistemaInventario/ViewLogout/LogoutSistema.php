<!-- Start código PHP para destruir sessão do usuário -->
<?php
session_start();

// Limpar variáveis de sessão relacionadas ao usuário
unset($_SESSION['usuarioId']);
unset($_SESSION['usuarioNome']);
unset($_SESSION['usuarioCodigoP']);
unset($_SESSION['usuarioSenha']);

// Definir mensagem de deslogado
$_SESSION['logindeslogado'] = "<p style='color:red;font-weight:bold;margin-left:0%;font-size:14px;'>Sessão encerrada</p>";

// Redirecionar o usuário para a página de login
header("Location: ../Index.php");
exit(); // Termina a execução do script após o redirecionamento
?>
<!-- End código PHP para destruir sessão do usuário -->
