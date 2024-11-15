<!-- Start PHP Session -->
<?php session_start(); ?>

<!-- Start Javascript loader page -->
<script>
var myVar;

function myFunction() {
    myVar = setTimeout(showPage, 500);
}

function showPage() {
    document.getElementById("loader").style.display = "none";
    document.getElementById("blue-animate").style.display = "block";
}
</script>
<!-- End Javascript loader page -->

<!-- Start Javascript loader body -->
<script>
document.oncontextmenu = function() { return false; }
</script>
<!-- End Javascript loader body -->

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
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>

    <!-- Popper JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>

    <!-- Font-awesome library -->
    <script src="https://kit.fontawesome.com/yourcode.js" crossorigin="anonymous"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">

    <!-- Bootstrap library -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

    <!-- CSS document page -->
    <link rel="stylesheet" href="../CSS/BlueArt.css">

    <!-- Google fonts library -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sofia+Sans+Extra+Condensed:ital,wght@0,1..1000;1,1..1000&display=swap">

    <!-- Title page -->
    <title>Sistema de Inventário - Remover Material</title>

    <!-- Start CSS container sidenav -->
    <style>
    /* Set height of the grid so .sidenav can be 100% (adjust as needed) */
    .row.content {
        height: 550px;
    }

    /* Set gray background color and 100% height */
    .sidenav {
        background-color: #ffffff;
        height: auto;
    }

    /* On small screens, set height to 'auto' for the grid */
    @media screen and (max-width: 767px) {
        .row.content {
            height: auto;
        }
    }
    </style>
    <!-- End CSS container sidenav -->
</head>
<!-- End top page-->

<!-- Start body page -->
<body oncontextmenu="return false" onload="myFunction()" style="margin:0;font-family:'Sofia Sans Extra Condensed';">

<!-- Start container-fluid -->
<div class="container-fluid">

    <!-- Start container row content -->
    <div class="row content" id="row-content">

        <!-- Start container col-sm-3 sidenav -->
        <div class="col-sm-3 sidenav hidden-xs" id="blue-sidenav-hidden-xs">
            <!-- Start logo page -->
            <h2 id="logo-blue">Inventário de Material<i class="fa fa-cubes" id="blue-icon-logo"></i></h2><br>
            <!-- End logo page -->

            <div class="logo-container">
                <img src="../../Images/images.png" class="logo">
            </div>

            <!-- Start menu-link page -->
            <nav>
            <ul class="nav nav-pills nav-stacked">
                <li id="list-blue"><a id="menu-blue" href="../ViewForms/PainelTecnico.php"><i class="fa fa-user " id="blue-icon-btn-painel" style="margin-left:1%;margin-right:1%;font-size:15px;"></i> Painel Administrativo</a></li><br>
                <li id="list-blue"><a id="menu-blue" href="../ViewRelatorio/RelatorioProduto.php"><i class="fa fa-cube " id="blue-icon-btn-painel" style="margin-left:1%;margin-right:1%;font-size:15px;"></i>Relatório Produto</a></li><br>
                <li id="list-blue"><a id="menu-blue" href="../ViewRelatorio/RelatorioNotaFiscal.php"><i class="fa fa-cart-plus " id="blue-icon-btn-painel" style="margin-left:1%;margin-right:1%;font-size:15px;"></i>Relatório Nota Fiscal</a></li><br>
            </ul>
            </nav>
            <!-- End menu-link page -->

            <br>
            <!-- End menu-link page -->

        </div>
        <!-- End container col-sm-3 sidenav -->

        <!-- Start container loader page -->
        <div id="loader"></div>
        <!-- End container loader page -->

        <!-- Start container animate-bottom -->
        <div style="display:none;" id="blue-animate" class="animate-bottom">

            <!-- Start container col-sm-9 -->
            <div class="col-sm-9" id="blue-col-sm-9">

                <!-- Start container well -->
                <div class="well" id="well-zero"><br>

                    <div class="container-fluid">
                        <!-- Botão de sair -->
                        <button id="blue-btn-sign-out" onclick="window.location.href='../../ViewLogout/LogoutSistema.php';"><i class="fa fa-sign-out"></i></button>
                        <!-- Nome do usuário -->
                        <p id="blue-text-session-user">TÉCNICO - <?php echo $_SESSION['usuarioNome']; ?></p>
                    </div>

                    <br>

                    <style>

                    .alerts {
                        padding: 5px;
                        background-color: transparent;
                        color: #f0f0f0;
                    }

                    .closebtns {
                        margin-left: 15px;
                        color: #ff6600;
                        font-weight: bold;
                        float: right;
                        font-size: 22px;
                        line-height: 20px;
                        cursor: pointer;
                        transition: 0.3s;
                    }

                    .closebtns:hover {
                        color: black;
                    }
                    </style>

                     <!-- Container para alertas de transferências pendentes -->
    <div class="alerts" style="display: none;" id="transferAlert">
        <?php
        // Conexão ao banco de dados
        require_once('../../ViewConnection/ConnectionInventario.php');

        $sql = "SELECT 
                    T.*, 
                    DC_DESTINO.NOME AS NOME_DATACENTER_DESTINO,
                    DC_ORIGEM.NOME AS NOME_DATACENTER_ORIGEM,
                    MAT_ORIGEM.MATERIAL AS NOME_MATERIAL_ORIGEM,
                    MET_ORIGEM.METRAGEM AS METRAGEM_PRODUTO_ORIGEM,
                    MAT_DESTINO.MATERIAL AS NOME_MATERIAL_DESTINO,
                    MET_DESTINO.METRAGEM AS METRAGEM_PRODUTO_DESTINO,
                    MO_ORIGEM.MODELO AS NOME_MODELO_ORIGEM,
                    MO_DESTINO.MODELO AS NOME_MODELO_DESTINO,
                    U.NOME AS NOME_USUARIO,
                    DATE_FORMAT(T.DATA_TRANSFERENCIA, '%d/%m/%Y') AS DATA_FORMATADA
                FROM 
                    TRANSFERENCIA T
                JOIN 
                    PRODUTO P_ORIGEM ON T.IDPRODUTO_ORIGEM = P_ORIGEM.IDPRODUTO
                JOIN 
                    PRODUTO P_DESTINO ON T.IDPRODUTO_DESTINO = P_DESTINO.IDPRODUTO
                JOIN 
                    MATERIAL MAT_ORIGEM ON P_ORIGEM.IDMATERIAL = MAT_ORIGEM.IDMATERIAL
                JOIN 
                    METRAGEM MET_ORIGEM ON P_ORIGEM.IDMETRAGEM = MET_ORIGEM.IDMETRAGEM
                JOIN 
                    MODELO MO_ORIGEM ON P_ORIGEM.IDMODELO = MO_ORIGEM.IDMODELO
                JOIN 
                    MATERIAL MAT_DESTINO ON P_DESTINO.IDMATERIAL = MAT_DESTINO.IDMATERIAL
                JOIN 
                    METRAGEM MET_DESTINO ON P_DESTINO.IDMETRAGEM = MET_DESTINO.IDMETRAGEM
                JOIN 
                    MODELO MO_DESTINO ON P_DESTINO.IDMODELO = MO_DESTINO.IDMODELO
                JOIN 
                    DATACENTER DC_DESTINO ON P_DESTINO.IDDATACENTER = DC_DESTINO.IDDATACENTER
                JOIN 
                    DATACENTER DC_ORIGEM ON P_ORIGEM.IDDATACENTER = DC_ORIGEM.IDDATACENTER
                JOIN 
                    USUARIO U ON T.IDUSUARIO = U.IDUSUARIO
                WHERE 
                    T.SITUACAO = 'Pendente'";

        $result = $conn->query($sql);

        if ($result === false) {
            echo "Erro na consulta: " . $conn->error;
        } else {
            if ($result->num_rows > 0) {
                echo "<script>document.getElementById('transferAlert').style.display = 'block';</script>";

                while ($row = $result->fetch_assoc()) {
                    // Conversão da data para formato brasileiro
                    $dateformated = $row['DATA_FORMATADA'];
                    
                    // Imprimir cada reserva pendente
                    echo <<<HTML

                    <!-- Botão para fechar alerta -->
                    <span class="closebtns" onclick="this.parentElement.style.display='none';">&times;</span>

                    <!-- Título do alerta de transferência pendente -->
                    <div id="blue-line-title-btn-painel-alert">
                        <p id="blue-title-btn-painel-alert">Transferência Pendente <i class="fa fa-retweet" id="blue-icon-btn-painel" style="font-size:12px;"></i></p>
                    </div>

                    <!-- Tabela com detalhes da transferência pendente -->
                    <table class="table table-bordered" id="blue-table-cadastro-auxiliar" style="margin-top:1%;">
                        <tr id="line-blue-table-alert">
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Código Saída</div>
                                <div id="blue-input-cdst-alert">{$row['ID']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">N° WO</div>
                                <div id="blue-input-cdst-alert">{$row['NUMWO']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Produto Destino</div>
                                <div id="blue-input-cdst-alert">{$row['NOME_MATERIAL_DESTINO']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Metragem</div>
                                <div id="blue-input-cdst-alert">{$row['METRAGEM_PRODUTO_DESTINO']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Modelo</div>
                                <div id="blue-input-cdst-alert">{$row['NOME_MODELO_ORIGEM']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Estoque Transferido</div>
                                <div id="blue-input-cdst-alert">{$row['QUANTIDADE']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Datacenter Origem</div>
                                <div id="blue-input-cdst-alert">{$row['NOME_DATACENTER_ORIGEM']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Datacenter Destino</div>
                                <div id="blue-input-cdst-alert">{$row['NOME_DATACENTER_DESTINO']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Data Transferência</div>
                                <div id="blue-input-cdst-alert">{$row['DATA_FORMATADA']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Observação</div>
                                <div id="blue-input-cdst-alert">{$row['OBSERVACAO']}</div>
                            </td>
                        </tr>
                    </table>
     HTML;
                }
            
            } else {
                echo "Nenhuma transferência pendente encontrada.";
            }
        }
        ?>
    </div>

    <!-- Container para alertas de reservas pendentes -->
    <div class="alerts" style="display: none;" id="transferAlerts">
        <?php
        // Conexão ao banco de dados
        require_once('../../ViewConnection/ConnectionInventario.php');

        // Nome do usuário da sessão atual
        $nomeUsuarioSessao = $_SESSION['usuarioNome'];

        $sql = "SELECT 
                    R.*, 
                    DC.NOME AS NOME_DATACENTER,
                    MAT.MATERIAL AS NOME_MATERIAL,
                    MET.METRAGEM AS METRAGEM_PRODUTO,
                    U.NOME AS NOME_USUARIO,
                    E.QUANTIDADE AS QUANTIDADE_TOTAL,
                    R.QUANTIDADE AS QUANTIDADE_RESERVADA,
                    R.OBSERVACAO,
                    DATE_FORMAT(R.DATARESERVA, '%d/%m/%Y') AS DATA_FORMATADA,
                    MO.MODELO AS NOME_MODELO
                FROM 
                    RESERVA R
                JOIN 
                    PRODUTO P ON R.IDPRODUTO = P.IDPRODUTO
                JOIN 
                    MATERIAL MAT ON P.IDMATERIAL = MAT.IDMATERIAL
                JOIN 
                    METRAGEM MET ON P.IDMETRAGEM = MET.IDMETRAGEM
                JOIN 
                    DATACENTER DC ON P.IDDATACENTER = DC.IDDATACENTER
                JOIN 
                    USUARIO U ON R.IDUSUARIO = U.IDUSUARIO
                JOIN 
                    ESTOQUE E ON P.IDPRODUTO = E.IDPRODUTO
                JOIN 
                    MODELO MO ON P.IDMODELO = MO.IDMODELO
                WHERE 
                    R.SITUACAO = 'Pendente'
                    AND U.NOME = '" . $conn->real_escape_string($nomeUsuarioSessao) . "'";

        // Executar consulta
        $result = $conn->query($sql);

        if ($result === false) {
            echo "Erro na consulta: " . $conn->error;
        } else {
            // Verificar se há resultados
            if ($result->num_rows > 0) {
                echo "<script>document.getElementById('transferAlerts').style.display = 'block';</script>";

                // Exibir os resultados
                while ($row = $result->fetch_assoc()) {
                    // Imprimir cada reserva pendente
                    echo <<<HTML
                    <!-- Botão para fechar alerta -->
                    <span class="closebtns" onclick="this.parentElement.style.display='none';">&times;</span>

                    <!-- Título do alerta de reserva pendente -->
                    <div id="blue-line-title-btn-painel-alert">
                        <p id="blue-title-btn-painel-alert">Reserva Pendente <i class="fa fa-star" id="blue-icon-btn-painel" style="font-size:12px;"></i></p>
                    </div>

                    <!-- Tabela com detalhes da reserva pendente -->
                    <table class="table table-bordered" id="blue-table-cadastro-auxiliar" style="margin-top:1%;">
                        <tr id="line-blue-table-alert">
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Código Reserva</div>
                                <div id="blue-input-cdst-alert">{$row['ID']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Nº WO</div>
                                <div id="blue-input-cdst-alert">{$row['NUMWO']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Produto</div>
                                <div id="blue-input-cdst-alert">{$row['NOME_MATERIAL']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Metragem</div>
                                <div id="blue-input-cdst-alert">{$row['METRAGEM_PRODUTO']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Modelo</div>
                                <div id="blue-input-cdst-alert">{$row['NOME_MODELO']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Estoque Reservado</div>
                                <div id="blue-input-cdst-alert">{$row['QUANTIDADE_RESERVADA']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Estoque Total</div>
                                <div id="blue-input-cdst-alert">{$row['QUANTIDADE_TOTAL']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">DataCenter</div>
                                <div id="blue-input-cdst-alert">{$row['NOME_DATACENTER']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Data Reserva</div>
                                <div id="blue-input-cdst-alert">{$row['DATA_FORMATADA']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Observação</div>
                                <div id="blue-input-cdst-alert">{$row['OBSERVACAO']}</div>
                            </td>
                            <td id="colun-blue-table-alert">
                                <div id="blue-title-listar-alert">Analista</div>
                                <div id="blue-input-cdst-alert">{$row['NOME_USUARIO']}</div>
                            </td>
                        </tr>
                    </table>
        HTML;
                }
            } else {
                echo "Nenhuma reserva pendente encontrada para este usuário.";
            }
        }
        ?>
    </div> 


    <div id="blue-line-title-btn-painel">
    <p id="blue-title-btn-painel">Remover Material <i class="fa fa-trash" id="blue-icon-btn-painel"></i></p>
</div>
<br>
<div class="container-fluid" style="margin-left:25%;">
    <table class="table table-bordered" style="width:60%;height:auto;">
        <form method="POST" class="example" action="">
            
            <!-- Início do código PHP para listagem dos materiais -->
            <?php 
                require_once('../../ViewConnection/ConnectionInventario.php'); 
                $id = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_NUMBER_INT);
                $consulta = "SELECT * FROM MATERIAL WHERE IDMATERIAL='$id'";
                $con = mysqli_query($conn, $consulta) or die(mysqli_error($conn, $consulta));
            ?> 
            <!-- Fim do código PHP para listagem dos materiais -->

            <!-- Início do código PHP para repetição de listagem -->
            <?php while($dado = $con->fetch_array()) { ?> 
                <tr id="line-blue-table">
                    <td id="colun-blue-table">   
                        <div id="blue-title-listar">Código</div>
                        <input type="text" id="blue-input-cdst" value="<?php echo $dado['IDMATERIAL']; ?>" name="id" disabled>
                        <input type="hidden" id="blue-input-cdst" value="<?php echo $dado['IDMATERIAL']; ?>" name="id">
                    </td>
            <?php } ?>
            <!-- Fim do código PHP para repetição de listagem -->

            <!-- Início do código PHP para listagem dos materiais -->
            <?php 
                require_once('../../ViewConnection/ConnectionInventario.php');
                $id = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_NUMBER_INT);
                $consulta = "SELECT * FROM MATERIAL WHERE IDMATERIAL='$id'";
                $con = mysqli_query($conn, $consulta) or die(mysqli_error($conn, $consulta));
            ?> 
            <!-- Fim do código PHP para listagem dos materiais -->

            <!-- Início do código PHP para repetição de listagem -->
            <?php while($dado = $con->fetch_array()) { ?> 
                    <td id="colun-blue-table">   
                        <div id="blue-title-listar">Material</div>
                        <input type="text" id="blue-input-cdst" value="<?php echo $dado['MATERIAL']; ?>" name="Material" disabled/>
                        <input type="hidden" id="blue-input-cdst" value="<?php echo $dado['MATERIAL']; ?>" name="Material"/>
                    </td>
                </tr>
            <?php } ?>
            <!-- Fim do código PHP para repetição de listagem -->
        
    </table>

    <button type="submit" id="blue-button-nova-senha" onclick="window.location.href='../ViewFunctions/CreateDeleteMaterial.php?id=<?php echo $dado['IDMATERIAL'];?>';">Remover Material <i class="fa fa-trash"></i></button>
    </form>
</div>

<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>

<!-- Início do container footer-page -->
<div class="container" id="footer-page">
    <!-- Início do container text footer-page -->
    <div id="group-text-footer">
        <p>Caixa Econômica Federal - Centralizadora de Suporte de Tecnologia da Informação CESTI <i class="fa fa-gears" id="group-icon-footer"></i></p>
    </div>
    <!-- Fim do container text footer-page -->    

    <div class="container-fluid" style="display: flex; justify-content: center; align-items: center; margin-top: -15px;">
        <svg xmlns="http://www.w3.org/2000/svg" width="50" height="50" viewBox="0 0 192.756 192.756" style="border:none;">
            <g fill-rule="evenodd" clip-rule="evenodd">
                <path fill="#fff" d="M0 0h192.756v192.756H0V0z"/>
                <path d="M64.466 90.115l-4.258 10.61h5.891L64.485 90.07l-.019.045zM41.91 114.469l17.467-35.957h13.202l7.366 35.957H68.35l-.852-4.791H56.25l-2.588 4.791H41.91zm43.522 0l5.06-35.957h11.682l-5.059 35.957H85.432zm77.691-24.399l-4.275 10.655h5.891l-1.616-10.655zm-22.574 24.399l17.467-35.957h13.201l7.365 35.957h-11.594l-.852-4.791h-11.248l-2.588 4.791h-11.751zM114.725 97.656h14.636l10.03 16.612h-14.639l-10.027-16.612z" fill="#0d6fab"/>
                <path fill="#db8135" d="M116.246 95.104h15.129l13.139-16.54h-15.129l-13.139 16.54zM101.117 114.369h15.129l13.139-16.744h-15.129l-13.139 16.744z"/>
                <path fill="#0d6fab" d="M106.572 78.362h14.121l9.674 16.742h-14.121l-9.674-16.742zM42.257 79.8l-1.124 10.575c-4.306-5.939-14.284-1.841-15.068 5.558-.996 9.392 8.608 11.583 13.835 6.052l-1.127 10.6c-1.56.768-3.085 1.361-4.59 1.764a18.783 18.783 0 0 1-4.487.648c-1.872.039-3.567-.158-5.096-.588a12.436 12.436 0 0 1-4.134-2.002c-2.36-1.725-4.066-3.918-5.118-6.588-1.05-2.678-1.397-5.699-1.038-9.076.288-2.713.973-5.188 2.062-7.432 1.08-2.244 2.576-4.281 4.481-6.129 1.801-1.763 3.762-3.092 5.885-3.996 2.113-.895 4.421-1.373 6.915-1.425a17.085 17.085 0 0 1 4.37.46c1.425.341 2.831.873 4.234 1.579z"/>
            </g>
        </svg>
    </div>
</div>
<!-- Fim do container footer-page -->

</div>
<!-- Fim do container well -->

</div>
<!-- Fim do container col-sm-9 -->

</div>
<!-- Fim do container animate-bottom -->

</div>
<!-- Fim do container row content -->

</div>
<!-- Fim do container-fluid -->

</body>
<!-- Fim do corpo da página -->

</html>
<!-- Fim do documento HTML -->