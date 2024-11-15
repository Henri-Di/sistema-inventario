<?php
// Definição das credenciais do banco de dados
define('DB_SERVER', '127.0.0.1');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'INVENTARIO');

// Criar a conexão com o banco de dados
$conn = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Verificar a conexão
if (!$conn) {
    die("Falha na conexão: " . mysqli_connect_error());
}

// Opcionalmente, você pode descomentar a linha abaixo para mostrar uma mensagem de sucesso
// echo "Conexão realizada com sucesso";
?>
