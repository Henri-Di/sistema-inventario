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
    <title>Sistema de Inventário - Modificar Nota</title>

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
<div id="container">
    <div id="blue-line-title-btn-painel">
        <p id="blue-title-btn-painel">Modificar Nota Fiscal <i class="fa fa-pencil" id="blue-icon-btn-painel"></i></p>
    </div>
    <br>

    <?php
    // Conexão e consulta ao banco de dados
    require_once('../../ViewConnection/ConnectionInventario.php'); 
    
    $id = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_NUMBER_INT);

    $consulta = "SELECT * FROM NOTAFISCAL WHERE ID='$id'";
    $con = mysqli_query($conn, $consulta) or die(mysqli_error($conn));
    $dado = $con->fetch_array();
    ?>

    <form method="POST" action="CreateModificaNotaFiscal.php">
        <input type="hidden" value="<?php echo $dado['ID']; ?>" name="id"/>

        <table class="table table-bordered" id="blue-table-cadastro-auxiliar">
            <tr id="line-blue-table">
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Nº Nota Fiscal</div>
                    <input type="text" id="blue-input-cdst" name="NumNotaFiscal" value="<?php echo $dado['NUMNOTAFISCAL'];?>" autocomplete="off"/>
                </td>
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Valor Nota Fiscal</div>
                    <input type="text" id="blue-input-cdst" name="ValorNotaFiscal" value="<?php echo $dado['VALORNOTAFISCAL'];?>" autocomplete="off"/>
                </td>
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Material</div>
                    <select id="select-form" name="Material">
                        <option value="<?php echo $dado['MATERIAL']; ?>"><?php echo $dado['MATERIAL']; ?></option>
                        <?php
                        $consultaMaterial = "SELECT MATERIAL FROM MATERIAL";
                        $conMaterial = mysqli_query($conn, $consultaMaterial) or die(mysqli_error($conn));
                        while($material = $conMaterial->fetch_array()) {
                            echo "<option value=\"{$material['MATERIAL']}\">{$material['MATERIAL']}</option>";
                        }
                        ?>
                    </select>
                </td>
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Conector</div>
                    <select id="select-form" name="Conector">
                        <option value="<?php echo $dado['CONECTOR']; ?>"><?php echo $dado['CONECTOR']; ?></option>
                        <?php
                        $consultaConector = "SELECT CONECTOR FROM CONECTOR";
                        $conConector = mysqli_query($conn, $consultaConector) or die(mysqli_error($conn));
                        while($conector = $conConector->fetch_array()) {
                            echo "<option value=\"{$conector['CONECTOR']}\">{$conector['CONECTOR']}</option>";
                        }
                        ?>
                    </select>
                </td>
            </tr>

            <tr id="line-blue-table">
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Metragem</div>
                    <select id="select-form" name="Metragem">
                        <option value="<?php echo $dado['METRAGEM']; ?>"><?php echo $dado['METRAGEM']; ?></option>
                        <?php
                        $consultaMetragem = "SELECT METRAGEM FROM METRAGEM";
                        $conMetragem = mysqli_query($conn, $consultaMetragem) or die(mysqli_error($conn));
                        while($metragem = $conMetragem->fetch_array()) {
                            echo "<option value=\"{$metragem['METRAGEM']}\">{$metragem['METRAGEM']}</option>";
                        }
                        ?>
                    </select>
                </td>
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Modelo</div>
                    <select id="select-form" name="Modelo">
                        <option value="<?php echo $dado['MODELO']; ?>"><?php echo $dado['MODELO']; ?></option>
                        <?php
                        $consultaModelo = "SELECT MODELO FROM MODELO";
                        $conModelo = mysqli_query($conn, $consultaModelo) or die(mysqli_error($conn));
                        while($modelo = $conModelo->fetch_array()) {
                            echo "<option value=\"{$modelo['MODELO']}\">{$modelo['MODELO']}</option>";
                        }
                        ?>
                    </select>
                </td>
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Quantidade</div>
                    <input type="number" id="blue-input-cdst" name="Quantidade" value="<?php echo $dado['QUANTIDADE'];?>" autocomplete="off"/>
                </td>
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Fornecedor</div>
                    <select id="select-form" name="Fornecedor">
                        <option value="<?php echo $dado['FORNECEDOR']; ?>"><?php echo $dado['FORNECEDOR']; ?></option>
                        <?php
                        $consultaFornecedor = "SELECT FORNECEDOR FROM FORNECEDOR";
                        $conFornecedor = mysqli_query($conn, $consultaFornecedor) or die(mysqli_error($conn));
                        while($fornecedor = $conFornecedor->fetch_array()) {
                            echo "<option value=\"{$fornecedor['FORNECEDOR']}\">{$fornecedor['FORNECEDOR']}</option>";
                        }
                        ?>
                    </select>
                </td>
            </tr>

            <tr id="line-blue-table">
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Data Recebimento</div>
                    <input type="date" id="blue-input-cdst" name="DataRecebimento" value="<?php echo $dado['DATARECEBIMENTO'];?>" autocomplete="off"/>
                </td>
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Data Cadastro</div>
                    <input type="date" id="blue-input-cdst" name="DataCadastro" value="<?php echo $dado['DATACADASTRO'];?>" autocomplete="off"/>
                </td>
                <td id="colun-blue-table">
                    <div id="blue-title-listar">Data Center</div>
                    <input type="text" id="blue-input-cdst" name="DataCenter" value="<?php echo $dado['DATACENTER'];?>" autocomplete="off"/>
                </td>
            </tr>
        </table>

        <button type="submit" id="blue-btn-table-cadastro-produto">Modificar Nota Fiscal <i class="fa fa-pencil"></i></button>
    </form>
    <br><br><br><br><br><br><br><br><br><br><br><br><br><br>
    <!-- Início do container do footer da página -->
    <div class="container" id="footer-page">
        <!-- Início do container de texto do footer -->
        <div id="group-text-footer">
            <p>Caixa Econômica Federal - Centralizadora de Suporte de Tecnologia da Informação CESTI <i class="fa fa-gears" id="group-icon-footer"></i></p>
        </div>
        <!-- Fim do container de texto do footer -->

        <div class="container-fluid" style="display: flex; justify-content: center; align-items: center; margin-top: -15px;">
            <svg xmlns="http://www.w3.org/2000/svg" width="50" height="50" viewBox="0 0 192.756 192.756" style="border:none;">
                <g fill-rule="evenodd" clip-rule="evenodd">
                    <path fill="#fff" d="M0 0h192.756v192.756H0V0z"/>
                    <path d="M64.466 90.115l-4.258 10.61h5.891L64.485 90.07l-.019.045zM41.91 114.469l17.467-35.957h13.202l7.366 35.957H68.35l-.852-4.791H56.25l-2.588 4.791H41.91zm43.522 0l5.06-35.957h11.682l-5.059 35.957H85.432zm77.691-24.399l-4.275 10.655h5.891l-1.616-10.655zm-22.574 24.399l17.467-35.957h13.201l7.365 35.957h-11.594l-.852-4.791h-11.248l-2.588 4.791h-11.751zm-34.7 0l5.06-35.957h11.682l-5.06 35.957h-11.682zm-34.941-10.828h8.697l-3.815-21.443-4.882 10.913zM139.68 104.07h8.697l-3.815-21.443-4.882 10.913z" fill="#010101"/>
                </g>
            </svg>
        </div>
        <!-- Fim do container de ícone do footer -->
    </div>
    <!-- Fim do container do footer da página -->
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
