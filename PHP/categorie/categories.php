<?php

/**
 * Page des catégories par famille - Tableau avec bordures noires
 */

// Vérifier si le paramètre famille est présent
if (!isset($_GET['famille'])) {
    header('Location: index.php');
    exit;
}

$famille = $_GET['famille'];

session_start();

// Récupérer l'année analysée depuis la session
$annee_analysee = isset($_SESSION['current_log']['annee']) ? $_SESSION['current_log']['annee'] : '2024'; // Valeur par défaut si non définie

// Chemin du fichier CSV
$csv_file = '10produits_avec_familles.csv';
// Si le chemin spécifique est disponible, utilisez-le
$specific_path = '../Python/produit/' . $annee_analysee . '/1-3-produits_avec_familles_nbr_vulnprod.csv';

if (file_exists($specific_path)) {
    $csv_file = $specific_path;
}

$categories_data = [];

if (($handle = fopen($csv_file, "r")) !== FALSE) {
    $header = fgetcsv($handle, 0, ",", "\"", "\\");

    $famille_index = array_search('Family', $header);
    $category_index = array_search('Category', $header);
    $vendor_index = array_search('Vendor', $header);
    $product_index = array_search('Product Name', $header);

    if ($famille_index === false || $category_index === false) {
        die("Structure du CSV incorrecte: colonnes manquantes");
    }

    while (($data = fgetcsv($handle, 0, ",", "\"", "\\")) !== FALSE) {
        if ($data[$famille_index] === $famille) {
            $category = $data[$category_index];
            $vendor = $data[$vendor_index];
            $product = isset($data[$product_index]) ? $data[$product_index] : '';

            if (!isset($categories_data[$category])) {
                $categories_data[$category] = [
                    'name' => $category,
                    'count' => 0,
                    'vendors' => [],
                    'vendor_products' => []
                ];
            }

            $categories_data[$category]['count']++;

            if (!isset($categories_data[$category]['vendor_products'][$vendor])) {
                $categories_data[$category]['vendor_products'][$vendor] = [];
                $categories_data[$category]['vendors'][] = $vendor;
            }

            if (!empty($product)) {
                $categories_data[$category]['vendor_products'][$vendor][] = $product;
            }
        }
    }
    fclose($handle);

    // Tri alphabétique des catégories
    ksort($categories_data);

    // Pour chaque catégorie, trier les vendeurs par nombre de produits
    foreach ($categories_data as $category => $data) {
        $vendor_counts = [];
        foreach ($data['vendor_products'] as $vendor => $products) {
            $vendor_counts[$vendor] = count($products);
        }
        arsort($vendor_counts);

        // Recréer la liste de vendeurs dans l'ordre de nombre de produits
        $sorted_vendors = [];
        foreach (array_keys($vendor_counts) as $vendor) {
            $sorted_vendors[] = $vendor;
        }

        $categories_data[$category]['vendors'] = $sorted_vendors;
        $categories_data[$category]['vendor_counts'] = $vendor_counts;
    }
} else {
    die("Impossible d'ouvrir le fichier CSV: " . $csv_file);
}

// Modifier la fonction generateProductsUrl pour rediriger vers 4-liste_produit_catg_fam.php
function generateProductsUrl($category)
{
    global $famille;
    return "4-liste_produit_catg_fam.php?categorie=" . urlencode($category) . "&famille=" . urlencode($famille);
}
?>
<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Catégories - <?php echo htmlspecialchars($famille); ?></title>

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">

    <style>
        body {
            background-color: #f8f9fa;
            padding: 20px;
        }

        .main-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0;
        }

        .header-section {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            background-color: white;
            padding: 15px 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .page-title {
            font-size: 24px;
            margin: 0;
            color: #343a40;
        }

        .search-box {
            background-color: white;
            padding: 15px 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .category-table {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            padding: 0;
            overflow: hidden;
        }

        .table {
            margin-bottom: 0;
            border-collapse: collapse;
        }

        .table th,
        .table td {
            border: 1px solid #000;
            /* Bordures noires */
        }

        .table th {
            background-color: #f0f0f0;
            color: #495057;
            font-weight: 600;
            padding: 12px 15px;
            vertical-align: middle;
        }

        .table td {
            padding: 12px 15px;
            vertical-align: middle;
        }

        .category-name {
            font-weight: 500;
            color: #212529;
        }

        .product-count {
            font-weight: 600;
            color: #0056b3;
            text-align: center;
            font-size: 16px;
        }

        .vendors-list {
            list-style: none;
            padding: 0;
            margin: 0;
            border: 1px solid #000;
            /* Bordure noire */
            border-radius: 4px;
            overflow: hidden;
        }

        .vendors-list li {
            padding: 6px 10px;
            border-bottom: 1px solid #000;
            /* Bordure noire */
            display: flex;
            justify-content: space-between;
            align-items: center;
            background-color: #fff;
        }

        .vendors-list li:last-child {
            border-bottom: none;
        }

        .vendors-list .vendor-name {
            font-weight: 500;
        }

        .vendors-list .vendor-count {
            background-color: #e7f5ff;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 14px;
            color: #0056b3;
            min-width: 35px;
            text-align: center;
            border: 1px solid #000;
            /* Bordure noire */
        }

        .more-vendors {
            text-align: center;
            color: #6c757d;
            font-style: italic;
            padding: 5px;
            background-color: #f8f9fa;
            border-bottom-left-radius: 4px;
            border-bottom-right-radius: 4px;
            border: 1px solid #000;
            /* Bordure noire */
            border-top: none;
            font-size: 14px;
        }

        .btn-consult {
            padding: 8px 16px;
            font-weight: 500;
        }

        .search-input-group {
            max-width: 400px;
        }

        .category-stats {
            font-size: 14px;
            color: #6c757d;
        }

        .action-column {
            text-align: center;
            width: 120px;
        }

        .row-id {
            text-align: center;
            font-weight: 600;
            color: #6c757d;
        }

        /* Supprimer les bordures arrondies par défaut de Bootstrap sur le tableau */
        .table-bordered {
            border-radius: 0;
        }

        .table-bordered th,
        .table-bordered td {
            border: 1px solid #000;
            /* Bordures noires */
        }
    </style>
</head>

<body>
    <div class="main-container">
        <div class="header-section">
            <h1 class="page-title">Famille: <?php echo htmlspecialchars($famille); ?></h1>
            <a href="1-accueille_categorie.php" class="btn btn-outline-secondary">
                <i class="fas fa-arrow-left"></i> Retour
            </a>
        </div>

        <div class="search-box">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <div class="input-group search-input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fas fa-search"></i></span>
                        </div>
                        <input type="text" id="searchInput" class="form-control" placeholder="Rechercher une catégorie...">
                    </div>
                </div>
                <div class="col-md-6 text-md-right mt-3 mt-md-0">
                    <div class="category-stats">
                        <strong><?php echo count($categories_data); ?></strong> catégories trouvées |
                        <strong><?php echo array_sum(array_column($categories_data, 'count')); ?></strong> produits au total
                    </div>
                </div>
            </div>
        </div>

        <div class="category-table">
            <?php if (empty($categories_data)): ?>
                <div class="alert alert-info m-3">
                    Aucune catégorie trouvée pour cette famille.
                </div>
            <?php else: ?>
                <table class="table table-bordered" id="categoriesTable">
                    <thead>
                        <tr>
                            <th style="width: 5%">#</th>
                            <th style="width: 25%">Catégorie</th>
                            <th style="width: 10%">Produits</th>
                            <th style="width: 50%">Vendeurs</th>
                            <th class="action-column">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php $counter = 1; ?>
                        <?php foreach ($categories_data as $category): ?>
                            <tr>
                                <td class="row-id"><?php echo $counter++; ?></td>
                                <td class="category-name"><?php echo htmlspecialchars($category['name']); ?></td>
                                <td class="product-count"><?php echo $category['count']; ?></td>
                                <td>
                                    <ul class="vendors-list">
                                        <?php
                                        $top_vendors = array_slice($category['vendor_counts'], 0, 5, true);
                                        foreach ($top_vendors as $vendor => $count):
                                        ?>
                                            <li>
                                                <span class="vendor-name"><?php echo htmlspecialchars($vendor); ?></span>
                                                <span class="vendor-count"><?php echo $count; ?></span>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>

                                    <?php if (count($category['vendors']) > 5): ?>
                                        <div class="more-vendors">
                                            + <?php echo count($category['vendors']) - 5; ?> autres vendeurs
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td class="action-column">
                                    <a href="<?php echo generateProductsUrl($category['name']); ?>" class="btn btn-primary btn-consult">
                                        Consulter
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script>
        $(document).ready(function() {
            $("#searchInput").on("keyup", function() {
                var value = $(this).val().toLowerCase();
                $("#categoriesTable tbody tr").filter(function() {
                    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
                });
            });
        });
    </script>
</body>

</html>