    <!--- Start PHP session usuário -->
    <?php 
    session_start();
    ?>
        
    <script>

    document.oncontextmenu = function(){return false;}
    
    </script> 

    <!-- Start document HTML/CSS/PHP/JAVASCRIPT -->
    <!DOCTYPE html>
    <html lang="PT-BR">

    <!-- Start top page-->
    <head>
    <!-- Charset page -->  
	<meta charset="UTF-8">

    <!-- Compatible IE-edge -->
	<meta http-equiv="X-UA-Compatible" content="IE=edge">

    <!-- Viewport responsive page -->
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
	<!-- jQuery library -->
	<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
	  
    <!-- Popper JS -->
	<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
	  
    <!-- Font-awesome library -->
	<script src="https://kit.fontawesome.com/yourcode.js" crossorigin="anonymous"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">

    <!-- Bootstrap library -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
	<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
	<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
    
    <!-- CSS document page -->
    <link rel="stylesheet" href="./CSS/BlueArt.css">

    <!-- Google fonts library -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sofia+Sans+Extra+Condensed:ital,wght@0,1..1000;1,1..1000&display=swap">

	<!-- Title page -->
    <title>Sistema de Inventário - Acesso Sistema</title>	
  
    </head>
    <!-- End top page-->

    <!-- Start body page -->
    <body  class="blue-body-index" style="font-family:'Sofia Sans Extra Condensed';">


    <!-- Start container -->
<div class="container-fluid" id="blue-container-login">
    <div class="login-wrapper">
        <!-- Start logo page -->
        <h2 id="logo-blue">Inventário de Material <i class="fa fa-cubes" id="blue-icon-logo"></i></h2><br>
    <!-- End logo page -->
        <img src="./Images/images.png" class="logo">
        <!-- Start formulario de login index -->
        <form class="needs-validation" name="AcessoRestrito" id="blue-form-login" method="POST" action="./ViewLogin/LoginUser.php" novalidate>
            <div class="form-group">
                <input type="text" name="CodigoP" id="blue-input-login" placeholder="Usuário" autocomplete="off" required>
                <div class="valid-feedback"></div>
                <div class="invalid-feedback"></div>
            </div>
            <br>
            <br>
            <div class="form-group">
                <input type="password" name="Senha" id="blue-input-login" placeholder="Senha" autocomplete="off" required>
                <div class="valid-feedback"></div>
                <div class="invalid-feedback"></div>
            </div>
            <br>
            <button type="submit" id="blue-btn-login">Acessar</button>
        </form>
        <!-- End formulario de login index -->
        <!-- Start código PHP verificação login -->
        <p id="blue-alert-login">
            <?php if (isset($_SESSION['loginErro'])) {
                echo $_SESSION['loginErro'];
                unset($_SESSION['loginErro']);
            } ?>
        </p>
        <p id="blue-alert-login">
            <?php if (isset($_SESSION['logindeslogado'])) {
                echo $_SESSION['logindeslogado'];
                unset($_SESSION['logindeslogado']);
            } ?>
        </p>
        <!-- End código PHP verificação login -->
    </div>
</div>
<!-- End container-fluid -->
    


    </body>
    <!-- End body page -->


    
    </html>
    <!-- End html page -->