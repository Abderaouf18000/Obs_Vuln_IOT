<?php

session_start();

// Récupérer l'année analysée depuis la session
$annee_analysee = isset($_SESSION['current_log']['annee']) ? $_SESSION['current_log']['annee'] : '2024'; // Valeur par défaut si non définie

// Utiliser l'année dans le chemin du fichier
$csv_file = '../../Python/produit/' . $annee_analysee . '/1-3-produits_avec_familles_nbr_vulnprod.csv';

$display_limit = 30; // Nombre de lignes à afficher par page
$page = isset($_GET['page']) ? intval($_GET['page']) : 1;
$search = isset($_GET['search']) ? $_GET['search'] : '';
$search_field = isset($_GET['search_field']) ? $_GET['search_field'] : 'all'; // Champ de recherche
$sort_by = isset($_GET['sort']) ? $_GET['sort'] : 'Nombre_Vulnerabilites';
$sort_dir = isset($_GET['dir']) ? $_GET['dir'] : 'desc';

// Récupérer les paramètres de famille et catégorie depuis l'URL
$categorie = isset($_GET['categorie']) ? $_GET['categorie'] : "Industrial Controller";
$family = isset($_GET['famille']) ? $_GET['famille'] : "Industriel et Automatisation";

// Fonction pour formater les nombres
function formatNumber($number)
{
    return number_format($number, 0, ',', ' ');
}

// Lecture du fichier CSV
$data = [];
$header = [];
$total_rows = 0;

if (file_exists($csv_file) && ($handle = fopen($csv_file, "r")) !== FALSE) {
    // Lire l'en-tête
    $header = fgetcsv($handle, 1000, ",", "\"", "\\");

    // Lire les données
    while (($row = fgetcsv($handle, 1000, ",", "\"", "\\")) !== FALSE) {
        $row_data = array_combine($header, $row);

        // Appliquer les filtres de catégorie et famille
        if ($row_data['Category'] !== $categorie || $row_data['Family'] !== $family) {
            continue; // Ignorer les lignes qui ne correspondent pas aux filtres
        }

        // Appliquer le filtre de recherche si spécifié
        if (!empty($search)) {
            $match = false;

            if ($search_field == 'all') {
                // Rechercher dans tous les champs
                foreach ($row as $cell) {
                    if (stripos($cell, $search) !== false) {
                        $match = true;
                        break;
                    }
                }
            } else {
                // Rechercher dans un champ spécifique
                $index = array_search($search_field, $header);
                if ($index !== false && isset($row[$index]) && stripos($row[$index], $search) !== false) {
                    $match = true;
                }
            }

            if (!$match) continue;
        }

        $data[] = $row_data;
        $total_rows++;
    }
    fclose($handle);

    // Tri des données
    usort($data, function ($a, $b) use ($sort_by, $sort_dir) {
        if ($sort_by === 'Nombre_Vulnerabilites') {
            $valA = intval($a[$sort_by]);
            $valB = intval($b[$sort_by]);
        } else {
            $valA = $a[$sort_by];
            $valB = $b[$sort_by];
        }

        if ($sort_dir === 'asc') {
            return $valA <=> $valB;
        } else {
            return $valB <=> $valA;
        }
    });
}

// Pagination
$total_pages = ceil($total_rows / $display_limit);
if ($page < 1) $page = 1;
if ($page > $total_pages && $total_pages > 0) $page = $total_pages;

$start = ($page - 1) * $display_limit;
$displayed_data = array_slice($data, $start, $display_limit);

// Calculer les statistiques
$total_vulnerabilities = 0;
$vulnerabilities_by_vendor = [];
$vulnerabilities_by_product = []; // Statistique pour les produits

foreach ($data as $row) {
    $total_vulnerabilities += intval($row['Nombre_Vulnerabilites']);

    $vendor = $row['Vendor'];
    if (!isset($vulnerabilities_by_vendor[$vendor])) {
        $vulnerabilities_by_vendor[$vendor] = 0;
    }
    $vulnerabilities_by_vendor[$vendor] += intval($row['Nombre_Vulnerabilites']);

    // Déterminer si la colonne s'appelle "Product Name" ou "Product"
    $product_column = null;
    if (in_array('Product Name', $header)) {
        $product_column = 'Product Name';
    } elseif (in_array('Product', $header)) {
        $product_column = 'Product';
    } else {
        // Si aucune des deux n'est trouvée, afficher un message d'erreur
        echo "<div class='alert alert-danger'>Erreur: Ni 'Product Name' ni 'Product' n'ont été trouvés dans le fichier CSV.</div>";
        // Utiliser la première colonne comme solution de repli
        $product_column = $header[0];
    }

    // Ajout des statistiques par produit
    $product = $row[$product_column];
    if (!isset($vulnerabilities_by_product[$product])) {
        $vulnerabilities_by_product[$product] = 0;
    }
    $vulnerabilities_by_product[$product] += intval($row['Nombre_Vulnerabilites']);
}

// Trier les statistiques
arsort($vulnerabilities_by_vendor);
arsort($vulnerabilities_by_product); // Trier les produits par nombre de vulnérabilités

// Fonction pour préserver les paramètres de famille et catégorie dans les liens de pagination et tri
function buildUrl($params = [])
{
    global $categorie, $family;
    $baseParams = [
        'categorie' => $categorie,
        'famille' => $family
    ];
    $allParams = array_merge($baseParams, $params);
    return '?' . http_build_query($allParams);
}

?>
<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analyse des vulnérabilités - <?= htmlspecialchars($categorie) ?></title>

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">

    <style>
        body {
            padding: 20px 0;
            background-color: #f8f9fa;
        }

        .card {
            margin-bottom: 20px;
            border: 1px solid rgba(0, 0, 0, .125);
            border-radius: 0.25rem;
        }

        .card-header {
            background-color: #f8f9fa;
            border-bottom: 1px solid rgba(0, 0, 0, .125);
            padding: 0.75rem 1.25rem;
            font-weight: 500;
        }

        /* Styles améliorés pour le tableau */
        .table {
            color: #333333;
            background-color: #ffffff;
            border: 1px solid #dee2e6;
        }

        /* Style pour les en-têtes de tableau en noir */
        .table-dark {
            background-color: #000 !important;
            color: #fff;
        }

        .table-dark th {
            border: 1px solid #333 !important;
        }

        .table-dark th a {
            color: #fff !important;
            text-decoration: none;
        }

        .table-dark th a:hover {
            color: #f8f9fa !important;
        }

        /* Style pour les bordures noires du tableau */
        .table-bordered {
            border: 2px solid #000 !important;
        }

        .table-bordered th,
        .table-bordered td {
            border: 1px solid #000 !important;
        }

        .table tbody tr {
            border-bottom: 1px solid #000 !important;
        }

        .table th {
            font-weight: 600;
            padding: 12px;
            position: relative;
        }

        .table td {
            padding: 12px;
            background-color: #ffffff;
            border: 1px solid #000 !important;
        }

        .table-hover tbody tr:hover {
            background-color: #f5f5f5 !important;
            color: #212529;
        }

        .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(0, 0, 0, 0.05);
        }

        .table-striped tbody tr:nth-of-type(even) {
            background-color: #ffffff;
        }

        .table th a {
            display: block;
            padding-right: 20px;
        }

        .sort-icon {
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
        }

        /* Renforcer les couleurs des indicateurs de vulnérabilités */
        .high-vulnerabilities {
            color: #dc3545;
            font-weight: bold;
        }

        .medium-vulnerabilities {
            color: #fd7e14;
            font-weight: bold;
        }

        .low-vulnerabilities {
            color: #0d6efd;
            font-weight: bold;
        }

        .chart-bar {
            height: 20px;
            margin-bottom: 8px;
            background-color: #0d6efd;
            border-radius: 2px;
        }

        /* Réduction de la taille de base et des marges */
        body {
            font-size: 0.875rem;
            /* 14px au lieu de 16px */
            padding: 10px 0;
        }

        /* Réduction de la taille des titres */
        h1 {
            font-size: 1.5rem;
            margin-bottom: 0.75rem;
        }

        /* Réduction des marges et paddings */
        .card {
            margin-bottom: 10px;
        }

        .card-body {
            padding: 0.75rem;
        }

        .card-header {
            padding: 0.5rem 0.75rem;
        }

        /* Réduction des espacements dans les tableaux */
        .table th,
        .table td {
            padding: 0.4rem 0.5rem;
        }

        /* Rendre les boutons plus petits */
        .btn-sm {
            padding: 0.2rem 0.5rem;
            font-size: 0.75rem;
        }

        /* Style pour les liens des produits */
        .product-link {
            color: #0d6efd;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
        }

        .product-link:hover {
            text-decoration: underline;
            color: #0a58ca;
        }

        .product-link .bi-search {
            opacity: 0.7;
            transition: opacity 0.2s;
        }

        .product-link:hover .bi-search {
            opacity: 1;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1>
                Analyse des vulnérabilités - <?= htmlspecialchars($categorie) ?>
                <small class="text-muted">(<?= htmlspecialchars($family) ?>)</small>
            </h1>
            <div>
                <a href="categories.php?famille=<?= urlencode($family) ?>" class="btn btn-outline-secondary me-2">
                    <i class="bi bi-arrow-left me-1"></i> Retour
                </a>
                <a href="1-accueille_categorie.php" class="btn btn-primary">
                    <i class="bi bi-house-door me-1"></i> Accueil
                </a>
            </div>
        </div>

        <!-- Statistiques générales -->
        <div class="card mb-4">
            <div class="card-header">
                <i class="bi bi-bar-chart"></i> Statistiques générales
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <h3 class="text-primary"><?= formatNumber($total_rows) ?></h3>
                                <div class="text-muted">Produits analysés</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <h3 class="text-success"><?= formatNumber(count($vulnerabilities_by_vendor)) ?></h3>
                                <div class="text-muted">Vendeurs</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <h3 class="text-danger"><?= formatNumber($total_vulnerabilities) ?></h3>
                                <div class="text-muted">Vulnérabilités totales</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Barre de recherche -->
        <div class="card">
            <div class="card-header">
                <i class="bi bi-search"></i> Recherche
            </div>
            <div class="card-body">
                <form action="" method="GET" class="row g-3">
                    <!-- Champs cachés pour préserver les paramètres de famille et catégorie -->
                    <input type="hidden" name="categorie" value="<?= htmlspecialchars($categorie) ?>">
                    <input type="hidden" name="famille" value="<?= htmlspecialchars($family) ?>">

                    <div class="col-md-4">
                        <input type="text" name="search" class="form-control" placeholder="Terme de recherche..." value="<?= htmlspecialchars($search) ?>">
                    </div>
                    <div class="col-md-3">
                        <select name="search_field" class="form-select">
                            <option value="all" <?= ($search_field == 'all') ? 'selected' : '' ?>>Tous les champs</option>
                            <option value="Product" <?= ($search_field == 'Product') ? 'selected' : '' ?>>Produit</option>
                            <option value="Vendor" <?= ($search_field == 'Vendor') ? 'selected' : '' ?>>Vendeur</option>
                        </select>
                    </div>
                    <div class="col-md-5">
                        <button class="btn btn-primary" type="submit">
                            <i class="bi bi-search"></i> Rechercher
                        </button>
                        <?php if (!empty($search)): ?>
                            <a href="<?= buildUrl(['page' => 1]) ?>" class="btn btn-outline-secondary ms-2">
                                <i class="bi bi-x-circle"></i> Réinitialiser
                            </a>
                        <?php endif; ?>
                    </div>
                </form>
            </div>
        </div>

        <!-- Tableau principal - STRUCTURE FILTRÉE -->
        <div class="card mt-4">
            <div class="card-header d-flex justify-content-between align-items-center">
                <div>
                    <i class="bi bi-table"></i> Liste des produits <?= htmlspecialchars($categorie) ?>
                    <span class="badge bg-secondary ms-2"><?= formatNumber($total_rows) ?> produits<?= !empty($search) ? ' filtrés' : '' ?></span>
                </div>
                <div>
                    <small class="text-muted"><?= $display_limit ?> éléments par page</small>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-hover table-bordered">
                        <thead class="table-dark">
                            <tr>
                                <th>
                                    <a href="<?= buildUrl(['sort' => 'Product', 'dir' => ($sort_by == 'Product' && $sort_dir == 'asc') ? 'desc' : 'asc', 'search' => $search, 'search_field' => $search_field, 'page' => $page]) ?>">
                                        Produit
                                        <?php if ($sort_by == 'Product'): ?>
                                            <span class="sort-icon"><i class="bi bi-arrow-<?= $sort_dir == 'asc' ? 'up' : 'down' ?>"></i></span>
                                        <?php endif; ?>
                                    </a>
                                </th>
                                <th>
                                    <a href="<?= buildUrl(['sort' => 'Vendor', 'dir' => ($sort_by == 'Vendor' && $sort_dir == 'asc') ? 'desc' : 'asc', 'search' => $search, 'search_field' => $search_field, 'page' => $page]) ?>">
                                        Vendeur
                                        <?php if ($sort_by == 'Vendor'): ?>
                                            <span class="sort-icon"><i class="bi bi-arrow-<?= $sort_dir == 'asc' ? 'up' : 'down' ?>"></i></span>
                                        <?php endif; ?>
                                    </a>
                                </th>
                                <th class="text-center">
                                    <a href="<?= buildUrl(['sort' => 'Nombre_Vulnerabilites', 'dir' => ($sort_by == 'Nombre_Vulnerabilites' && $sort_dir == 'asc') ? 'desc' : 'asc', 'search' => $search, 'search_field' => $search_field, 'page' => $page]) ?>">
                                        Vulnérabilités
                                        <?php if ($sort_by == 'Nombre_Vulnerabilites'): ?>
                                            <span class="sort-icon"><i class="bi bi-arrow-<?= $sort_dir == 'asc' ? 'up' : 'down' ?>"></i></span>
                                        <?php endif; ?>
                                    </a>
                                </th>
                                <th class="text-center">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($displayed_data)): ?>
                                <tr>
                                    <td colspan="4" class="text-center py-3">
                                        <i class="bi bi-exclamation-circle text-muted"></i> Aucune donnée trouvée
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($displayed_data as $row): ?>
                                    <tr>
                                        <td>
                                            <a href="https://www.google.com/search?q=<?= urlencode($row['Product'] . ' ' . $row['Vendor'] . ' ' . $categorie . ' description') ?>"
                                                target="_blank"
                                                class="product-link"
                                                title="Rechercher ce produit sur Google">
                                                <?= htmlspecialchars($row['Product']) ?>
                                                <i class="bi bi-search text-primary ms-1" style="font-size: 0.8rem;"></i>
                                            </a>
                                        </td>
                                        <td><?= htmlspecialchars($row['Vendor']) ?></td>
                                        <td class="text-center 
                                            <?php
                                            $vulnerabilities = intval($row['Nombre_Vulnerabilites']);
                                            if ($vulnerabilities > 10) echo 'high-vulnerabilities';
                                            elseif ($vulnerabilities > 5) echo 'medium-vulnerabilities';
                                            elseif ($vulnerabilities > 0) echo 'low-vulnerabilities';
                                            ?>">
                                            <?= formatNumber($vulnerabilities) ?>
                                        </td>
                                        <td class="text-center">
                                            <a href="8-detail_produit.php?produit=<?= urlencode(htmlspecialchars($row['Product'])) ?>" class="btn btn-sm btn-primary">
                                                <i class="bi bi-info-circle me-1"></i> Détails
                                            </a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Légende des couleurs -->
                <div class="mt-2 small text-muted">
                    <span class="high-vulnerabilities me-3">■</span> Élevé (>10)
                    <span class="medium-vulnerabilities ms-3 me-3">■</span> Moyen (6-10)
                    <span class="low-vulnerabilities ms-3">■</span> Faible (1-5)
                </div>

                <!-- Pagination avec préservation des paramètres de famille et catégorie -->
                <?php if ($total_pages > 1): ?>
                    <nav aria-label="Pagination" class="mt-3">
                        <ul class="pagination justify-content-center">
                            <li class="page-item <?= ($page <= 1) ? 'disabled' : '' ?>">
                                <a class="page-link" href="<?= buildUrl(['page' => $page - 1, 'sort' => $sort_by, 'dir' => $sort_dir, 'search' => $search, 'search_field' => $search_field]) ?>" aria-label="Précédent">
                                    <span aria-hidden="true">&laquo;</span>
                                </a>
                            </li>

                            <?php
                            $start_page = max(1, $page - 2);
                            $end_page = min($total_pages, $start_page + 4);
                            if ($end_page - $start_page < 4) {
                                $start_page = max(1, $end_page - 4);
                            }

                            // Première page
                            if ($start_page > 1): ?>
                                <li class="page-item">
                                    <a class="page-link" href="<?= buildUrl(['page' => 1, 'sort' => $sort_by, 'dir' => $sort_dir, 'search' => $search, 'search_field' => $search_field]) ?>">1</a>
                                </li>
                                <?php if ($start_page > 2): ?>
                                    <li class="page-item disabled">
                                        <span class="page-link">...</span>
                                    </li>
                                <?php endif; ?>
                            <?php endif; ?>

                            <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                                <li class="page-item <?= ($i == $page) ? 'active' : '' ?>">
                                    <a class="page-link" href="<?= buildUrl(['page' => $i, 'sort' => $sort_by, 'dir' => $sort_dir, 'search' => $search, 'search_field' => $search_field]) ?>">
                                        <?= $i ?>
                                    </a>
                                </li>
                            <?php endfor; ?>

                            <?php
                            // Dernière page
                            if ($end_page < $total_pages): ?>
                                <?php if ($end_page < $total_pages - 1): ?>
                                    <li class="page-item disabled">
                                        <span class="page-link">...</span>
                                    </li>
                                <?php endif; ?>
                                <li class="page-item">
                                    <a class="page-link" href="<?= buildUrl(['page' => $total_pages, 'sort' => $sort_by, 'dir' => $sort_dir, 'search' => $search, 'search_field' => $search_field]) ?>">
                                        <?= $total_pages ?>
                                    </a>
                                </li>
                            <?php endif; ?>

                            <li class="page-item <?= ($page >= $total_pages) ? 'disabled' : '' ?>">
                                <a class="page-link" href="<?= buildUrl(['page' => $page + 1, 'sort' => $sort_by, 'dir' => $sort_dir, 'search' => $search, 'search_field' => $search_field]) ?>" aria-label="Suivant">
                                    <span aria-hidden="true">&raquo;</span>
                                </a>
                            </li>
                        </ul>
                    </nav>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Graphiques de statistiques -->
    <div class="container">
        <!-- Top produits par vulnérabilités - Section modifiée -->
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0"><i class="bi bi-pie-chart me-2"></i> Top produits <?= htmlspecialchars($categorie) ?> par vulnérabilités</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-lg-7">
                        <!-- Tableau des détails -->
                        <div class="table-responsive mb-3 mb-lg-0">
                            <table class="table table-bordered table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th class="text-center" style="width: 50px;">#</th>
                                        <th>Produit</th>
                                        <th>Vendeur</th>
                                        <th class="text-end" style="width: 150px;">Vulnérabilités</th>
                                        <th class="text-end" style="width: 120px;">Pourcentage</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    $top_products = array_slice($vulnerabilities_by_product, 0, 10, true);
                                    $product_total = array_sum($top_products);
                                    $counter = 0;
                                    $colors = [
                                        '#FF6384',
                                        '#36A2EB',
                                        '#FFCE56',
                                        '#4BC0C0',
                                        '#9966FF',
                                        '#FF9F40',
                                        '#8AC249',
                                        '#EA526F',
                                        '#49ADF5',
                                        '#C8B8DB'
                                    ];

                                    foreach ($top_products as $product => $count):
                                        $percentage = round(($count / $product_total) * 100, 1);
                                        $counter++;

                                        // Trouver le vendeur correspondant à ce produit
                                        $vendor = "";
                                        foreach ($data as $row) {
                                            if ($row['Product'] === $product) {
                                                $vendor = $row['Vendor'];
                                                break;
                                            }
                                        }
                                    ?>
                                        <tr>
                                            <td class="text-center">
                                                <span class="badge rounded-pill" style="background-color: <?= $colors[$counter - 1] ?>;">
                                                    <?= $counter ?>
                                                </span>
                                            </td>
                                            <td>
                                                <strong>
                                                    <a href="https://www.google.com/search?q=<?= urlencode($product . ' ' . $vendor . ' ' . $categorie . ' description') ?>"
                                                        target="_blank"
                                                        class="product-link"
                                                        title="Rechercher ce produit sur Google">
                                                        <?= htmlspecialchars($product) ?>
                                                        <i class="bi bi-search text-primary ms-1" style="font-size: 0.8rem;"></i>
                                                    </a>
                                                </strong>
                                            </td>
                                            <td><?= htmlspecialchars($vendor) ?></td>
                                            <td class="text-end"><?= formatNumber($count) ?></td>
                                            <td class="text-end">
                                                <div class="progress" style="height: 20px;">
                                                    <div class="progress-bar" role="progressbar"
                                                        style="width: <?= $percentage ?>%; background-color: <?= $colors[$counter - 1] ?>;"
                                                        aria-valuenow="<?= $percentage ?>" aria-valuemin="0" aria-valuemax="100">
                                                        <?= $percentage ?>%
                                                    </div>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                                <tfoot class="table-light">
                                    <tr>
                                        <td colspan="3" class="text-end"><strong>Total</strong></td>
                                        <td class="text-end"><strong><?= formatNumber($product_total) ?></strong></td>
                                        <td class="text-end"><strong>100%</strong></td>
                                    </tr>
                                </tfoot>
                            </table>
                        </div>
                    </div>
                    <div class="col-lg-5">
                        <!-- Diagramme circulaire -->
                        <div class="card h-100">
                            <div class="card-body">
                                <div style="height: 400px;">
                                    <canvas id="productPieChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row mt-3">
                    <div class="col-md-12">
                        <div class="alert alert-info">
                            <i class="bi bi-info-circle me-2"></i>
                            Ce graphique montre les produits <?= htmlspecialchars($categorie) ?> de la famille <?= htmlspecialchars($family) ?> ayant le plus grand nombre de vulnérabilités identifiées.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Script pour le diagramme circulaire -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Données pour le graphique
            const productData = {
                labels: [
                    <?php
                    $counter = 0;
                    foreach ($top_products as $product => $count):
                        echo ($counter > 0 ? ', ' : '') . "'" . addslashes($product) . "'";
                        $counter++;
                    endforeach;
                    ?>
                ],
                datasets: [{
                    data: [
                        <?php
                        $counter = 0;
                        foreach ($top_products as $product => $count):
                            echo ($counter > 0 ? ', ' : '') . $count;
                            $counter++;
                        endforeach;
                        ?>
                    ],
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                        '#FF9F40', '#8AC249', '#EA526F', '#49ADF5', '#C8B8DB'
                    ],
                    hoverBackgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                        '#FF9F40', '#8AC249', '#EA526F', '#49ADF5', '#C8B8DB'
                    ],
                    borderWidth: 1
                }]
            };

            // Options du graphique
            const options = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            boxWidth: 12,
                            font: {
                                size: 10
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            };

            // Créer le graphique
            const ctx = document.getElementById('productPieChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: productData,
                options: options
            });
        });
    </script>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>