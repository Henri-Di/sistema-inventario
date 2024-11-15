<?php
// Iniciar sessão
session_start();
session_regenerate_id(true); // Regenera o ID da sessão para aumentar a segurança 
?>

<!-- Início do documento HTML -->
<!DOCTYPE html>
<html lang="pt-br">

<!-- Cabeçalho da página -->
<head>
    <!-- Charset da página -->
    <meta charset="UTF-8">
    <!-- Compatibilidade com IE -->
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <!-- Viewport para responsividade -->
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Biblioteca jQuery -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
    <!-- Biblioteca Popper JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
    <!-- Biblioteca Font Awesome -->
    <script src="https://kit.fontawesome.com/yourcode.js" crossorigin="anonymous"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <!-- Biblioteca Bootstrap -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <!-- Estilo CSS da página -->
    <link rel="stylesheet" href="../CSS/BlueArt.css">
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sofia+Sans+Extra+Condensed:ital,wght@0,1..1000;1,1..1000&display=swap">
    <!-- Título da página -->
    <title>Sistema de Inventário - Impressão Documento de Saída</title>
    <style>
        .blue-body-transferencia{
            padding: 0;
            margin: 0;    
        }

        main {
            width: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
            flex-direction: column;
            margin-top: 20px;
        }
        
        .row{
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .col{
            float:left;
            width: 100%;
            height: auto;
            margin: 0px 50px 0px;
            justify-content: center;
            align-items: center;
            background-color: transparent;
        }

        #title-print{
            width: 100%;
            height: auto;
        }

        #title-document{
            width: 100%;
            height: auto;
            padding: 0.5vh;
            font-weight: bold;
            font-size: 16px;
            color: #000000;
            text-align: center;
            border:1px solid #000000
        }

         @media print {
            /* Ocultar o botão de impressão */
            button {
                display: none;
            }
            /* Ocultar elementos desnecessários */
            header, footer {
                display: none;
            }
        }
    </style>
</head>
<body class="blue-body-transferencia">
    <!-- Container fluid principal -->
    <div class="container-fluid" class="print-only">
        <!-- Conteúdo principal -->
        <main>
        <div class="container">
            <div class="row">
                <div class="col">
                    <span>
                        <img src="../../Images/BancoBrasil.png" style="width: 50%; height: auto; padding: 0px;" />
                    </span>
                </div> 
                <div class="col">
                    <span>
                        <img src="../../Images/GBT.jpg" style="width: 60%; height: auto; padding: 0px;" />
                    </span>
                </div>
                <div class="col">
                    <svg xmlns="http://www.w3.org/2000/svg" width="150" height="150" viewBox="0 0 192.756 192.756" style="border:none;">
            <g fill-rule="evenodd" clip-rule="evenodd">
                <path fill="#fff" d="M0 0h192.756v192.756H0V0z"/>
                <path d="M64.466 90.115l-4.258 10.61h5.891L64.485 90.07l-.019.045zM41.91 114.469l17.467-35.957h13.202l7.366 35.957H68.35l-.852-4.791H56.25l-2.588 4.791H41.91zm43.522 0l5.06-35.957h11.682l-5.059 35.957H85.432zm77.691-24.399l-4.275 10.655h5.891l-1.616-10.655zm-22.574 24.399l17.467-35.957h13.201l7.365 35.957h-11.594l-.852-4.791h-11.248l-2.588 4.791h-11.751zM114.725 97.656h14.636l10.03 16.612h-14.639l-10.027-16.612z" fill="#0d6fab"/>
                <path fill="#db8135" d="M116.246 95.104h15.129l13.139-16.54h-15.129l-13.139 16.54zM101.117 114.369h15.129l13.139-16.744h-15.129l-13.139 16.744z"/>
                <path fill="#0d6fab" d="M106.572 78.362h14.121l9.674 16.742h-14.121l-9.674-16.742zM42.257 79.8l-1.124 10.575c-4.306-5.939-14.284-1.841-15.068 5.558-.996 9.392 8.608 11.583 13.835 6.052l-1.127 10.6c-1.56.768-3.085 1.361-4.59 1.764a18.783 18.783 0 0 1-4.487.648c-1.872.039-3.567-.158-5.096-.588a12.436 12.436 0 0 1-4.134-2.002c-2.36-1.725-4.066-3.918-5.118-6.588-1.05-2.678-1.397-5.699-1.038-9.076.288-2.713.973-5.188 2.062-7.432 1.08-2.244 2.576-4.281 4.481-6.129 1.801-1.763 3.762-3.092 5.885-3.996 2.113-.895 4.421-1.373 6.915-1.425a17.085 17.085 0 0 1 4.37.46c1.425.341 2.831.873 4.234 1.579z"/>
            </g>
        </svg>
    </div>   
            </div>
        </div>

        <!-- Container fluid secundário -->
        <div class="container" class="title-print">
                <p id="title-document">GESTÃO DATACENTER</p>
                <p id="title-document">CONTROLE DE MOVIMENTAÇÃO DE MÓVEIS E EQUIPAMENTOS</p>
                <p id="title-document">AUTORIZAÇÃO DE SAÍDA DE MATERIAIS E EQUIPAMENTOS</p>
        </div>

    <div class="container">
    <!-- PHP para conexão e consulta ao banco de dados -->
    <?php
                require_once('../../ViewConnection/ConnectionInventario.php');

                // Verifica a conexão com o banco de dados
                if ($conn->connect_error) {
                    die("Falha na conexão: " . $conn->connect_error);
                }

                // Obtém o ID da transferência a partir da requisição
                $id = $_GET['id_transferencia'] ?? '';

                // Prepara a consulta SQL usando prepared statements
                $sql = "SELECT 
                            T.*, 
                            DC_DESTINO.NOME AS NOME_DATACENTER_DESTINO,
                            DC_ORIGEM.NOME AS NOME_DATACENTER_ORIGEM,
                            MAT_ORIGEM.MATERIAL AS NOME_MATERIAL_ORIGEM,
                            MET_ORIGEM.METRAGEM AS METRAGEM_PRODUTO_ORIGEM,
                            MAT_DESTINO.MATERIAL AS NOME_MATERIAL_DESTINO,
                            MET_DESTINO.METRAGEM AS METRAGEM_PRODUTO_DESTINO,
                            MO.MODELO AS MODELO_PRODUTO_ORIGEM,
                            FO.FORNECEDOR AS FORNECEDOR_PRODUTO_ORIGEM,
                            G.GRUPO AS NOME_GRUPO_ORIGEM,
                            L.LOCALIZACAO AS NOME_LOCALIZACAO_ORIGEM,
                            T.QUANTIDADE,
                            T.SITUACAO,
                            T.NUMWO
                        FROM 
                            TRANSFERENCIA T
                        JOIN 
                            PRODUTO P_ORIGEM ON T.IDPRODUTO_ORIGEM = P_ORIGEM.IDPRODUTO
                        JOIN 
                            PRODUTO P_DESTINO ON T.IDPRODUTO_DESTINO = P_DESTINO.IDPRODUTO
                        JOIN 
                            MATERIAL MAT_ORIGEM ON P_ORIGEM.IDMATERIAL = MAT_ORIGEM.IDMATERIAL
                        JOIN 
                            MATERIAL MAT_DESTINO ON P_DESTINO.IDMATERIAL = MAT_DESTINO.IDMATERIAL
                        JOIN 
                            METRAGEM MET_ORIGEM ON P_ORIGEM.IDMETRAGEM = MET_ORIGEM.IDMETRAGEM
                        JOIN 
                            METRAGEM MET_DESTINO ON P_DESTINO.IDMETRAGEM = MET_DESTINO.IDMETRAGEM
                        JOIN 
                            DATACENTER DC_DESTINO ON P_DESTINO.IDDATACENTER = DC_DESTINO.IDDATACENTER
                        JOIN 
                            DATACENTER DC_ORIGEM ON P_ORIGEM.IDDATACENTER = DC_ORIGEM.IDDATACENTER
                        JOIN 
                            MODELO MO ON P_ORIGEM.IDMODELO = MO.IDMODELO
                        JOIN 
                            FORNECEDOR FO ON P_ORIGEM.IDFORNECEDOR = FO.IDFORNECEDOR
                        JOIN 
                            GRUPO G ON P_ORIGEM.IDGRUPO = G.IDGRUPO
                        JOIN 
                            LOCALIZACAO L ON P_ORIGEM.IDLOCALIZACAO = L.IDLOCALIZACAO
                        WHERE 
                            T.ID = ?";

                if ($stmt = $conn->prepare($sql)) {
                    // Vincula os parâmetros
                    $stmt->bind_param("i", $id);
                    
                    // Executa a consulta
                    $stmt->execute();

                    // Obtém os resultados
                    $result = $stmt->get_result();

                    // Verifica se houve resultados e processa-os
                    if ($result->num_rows > 0) {
                        while ($row = $result->fetch_assoc()) {
                            // Formata a data
                            $date = strtotime($row['DATA_TRANSFERENCIA']);
                            $dateformated = date("d/m/Y", $date);
    ?>
                            <!-- Tabela de exibição dos dados -->
                            <table class="table" id="blue-table-cadastro-auxiliar-print">
                                <tr id="line-blue-table-print">
                                <td id="colun-blue-table">
                                        <div id="blue-title-listar-print">WO</div>
                                        <input type="text" id="blue-input-cdst-print" value="<?php echo $row['NUMWO']; ?>" disabled />
                                    </td>
                                    <td id="colun-blue-table">
                                        <div id="blue-title-listar-print">Material</div>
                                        <input type="text" id="blue-input-cdst-print" value="<?php echo $row['NOME_MATERIAL_ORIGEM']; ?>" disabled />
                                    </td>
                                    <td id="colun-blue-table">
                                        <div id="blue-title-listar-print">Metragem</div>
                                        <input type="text" id="blue-input-cdst-print" value="<?php echo $row['METRAGEM_PRODUTO_DESTINO']; ?>" disabled />
                                    </td>
                                    <td id="colun-blue-table">
                                        <div id="blue-title-listar-print">Modelo</div>
                                        <input type="text" id="blue-input-cdst-print" value="<?php echo $row['MODELO_PRODUTO_ORIGEM']; ?>" disabled />
                                    </td>
                                    <td id="colun-blue-table">
                                        <div id="blue-title-listar-print">Quantidade</div>
                                        <input type="text" id="blue-input-cdst-print" value="<?php echo $row['QUANTIDADE']; ?>" disabled />
                                    </td>
                                    <td id="colun-blue-table">
                                        <div id="blue-title-listar-print">Data de Emissão</div>
                                        <input type="text" id="blue-input-cdst-print" value="<?php echo $dateformated; ?>" disabled/>
                                    </td>
                                </tr>
                        </table>
                    <!-- Fim da tabela de exibição dos dados -->
    </div>

    <div class="container">
                        <!-- Tabela de exibição dos dados -->
                            <table class="table table-bordered" id="blue-table-cadastro-auxiliar-print">
                                <tr id="line-blue-table-print">
                                <td id="colun-blue-table">
                                    <div id="blue-title-listar-print">REGISTRO DE MOVIMENTAÇÃO</div>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">
                                    ORIGEM: 
                                    <span style="margin-left: 120px;">BANCO DO BRASIL</span> 
                                        (<span style="padding: 0 10px;"></span>) 
                                    <span style="margin-left: 120px;">CAIXA</span> 
                                        (<span style="padding: 0 10px;"></span>) 
                                    <span style="margin-left: 120px;">GBT</span> 
                                        (<span style="padding: 0 10px;"></span>)
                                    </p>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">LOCAL DE ORIGEM: DATACENTER - GRANJA DO TORTO</p>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">LOCAL DE DESTINO: DATACENTER - CTC</p>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">TRANSPORTADO POR:</p>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">DATA PREVISTA DE SAÍDA: <span style="padding:0 40px;">/</span>   <span style="padding:0 20px;">/</span></p>
                                    </td>
                                    </tr>
                                </tr>
                            </table>
                            <!-- Fim da tabela de exibição dos dados -->
    </div>

    <div class="container">
         <!-- Tabela de exibição dos dados -->
         <table class="table table-bordered" id="blue-table-cadastro-auxiliar-print">
                                <tr id="line-blue-table-print">
                                <td id="colun-blue-table">
                                    <div id="blue-title-listar-print">IDENTIFICAÇÃO DO RESPONSÁVEL PELA AUTORIZAÇÃO</div>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">
                                    NOME LEGIVEL: 
                                    <span style="margin-left: 400px;">MATRICULA:</span> 
                                    </p>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">LOCAL DE TRABALHO: CAIXA - CETAD</p>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">ASSINATURA: </p>
                                    </td>
                                    </tr>
                            </table>
                            <!-- Fim da tabela de exibição dos dados -->

                                <!-- Tabela de exibição dos dados -->
                                <table class="table table-bordered" id="blue-table-cadastro-auxiliar-print">
                                <tr id="line-blue-table-print">
                                <td id="colun-blue-table">
                                    <div id="blue-title-listar-print">CONFERÊNCIA PELO SERVIÇO DE VIGILÂNCIA (EFETIVAÇÃO DA SAÍDA)</div>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">
                                    CONFERIDO POR:</p>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">DATA: <span style="padding:0 40px;">/</span>   <span style="padding:0 20px;">/</span>
                                    <span style="margin-left: 315px;">HORA:    <span style="padding:0 30px;">:</span></span> 
                                    </p>
                                    </td>
                                    </tr>
                                    <tr id="line-blue-table-print">
                                    <td id="colun-blue-table">
                                    <p style="color: #000000;font-weight:bold;">ASSINATURA: </p>
                                    </td>
                                    </tr>
                            </table>
                            <!-- Botão para impressão -->
                            <div style="margin-left:5%;margin-top:5%;">
                                <button  id="blue-btn-print" onclick="window.print()"><i class="fa fa-print"></i> Imprimir</button>
                            </div>
                            <br><br><br>
                            <!-- Fim do botão para impressão -->   
                <?php
                        }
                    } else {
                        echo "Nenhum resultado encontrado.";
                    }

                    // Fecha a declaração
                    $stmt->close();
                } else {
                    echo "Erro ao preparar a declaração SQL: " . $conn->error;
                }

                // Fecha a conexão com o banco de dados
                $conn->close();
                ?>
                <!-- Fim do PHP para conexão e consulta ao banco de dados -->
                </div>

            </div>
            <!-- Fim do container fluid secundário -->
        </main>
        <!-- Fim do conteúdo principal -->
    </div>
    <!-- Fim do container fluid principal -->
        </main>
    </div>
</body>
</hmtl>