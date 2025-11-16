<?php
ini_set('max_execution_time', 300); // 5 minutes
ini_set('memory_limit', '512M'); // 512 Mo
// Charger la classe contenant la fonction
require_once '2-vstatistique.php';

// Vérifiez si le paramètre 'vendor' existe dans l'URL
if (isset($_GET['vendor']) && !empty($_GET['vendor'])) {
    // Récupérer et sécuriser le vendeur depuis l'URL
    $vendeurRechercher = htmlspecialchars($_GET['vendor'], ENT_QUOTES, 'UTF-8');

    $produitsCveObj = new vstatistique(); // Créer une instance de la classe
    $resultats = $produitsCveObj->lireProduitsEtCveAvecScoresEtTypes($vendeurRechercher);
    $nbrvuln   = $produitsCveObj->countUniqueVulnerabilitiesByVendor($vendeurRechercher);
    $statistics = $produitsCveObj->countVulnerabilitiesBySeverity($vendeurRechercher);
    $statistics_2 = $produitsCveObj->getVendorCorrectionTimes($vendeurRechercher);
    
    $total_viln = $statistics['total'];
    $stat_critical = $statistics['critical'];
    $stat_high = $statistics['high'];
    $stat_medium = $statistics['medium'];
    $stat_low = $statistics['low'];

    $stat_score_critical = $statistics_2['critical'];
    $stat_score_high = $statistics_2['high'];
    $stat_score_medium = $statistics_2['medium'];
    $stat_score_low = $statistics_2['low'];

    $type = $produitsCveObj->getTypeVulnerabilityByVendor($vendeurRechercher);
    $scoresMoyens = $produitsCveObj->getVendorAverageScore($vendeurRechercher);
    $avg_fix_time = $produitsCveObj->getVendorAverageFixTime($vendeurRechercher);
    
} else {
    // Si aucun vendeur n'est envoyé, redirigez ou affichez un message
    header('Location: vendeur.php'); // Redirige vers la page des vendeurs
    exit;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Résultats - <?= htmlspecialchars($vendeurRechercher, ENT_QUOTES, 'UTF-8') ?></title>

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css">
    <!-- Font Awesome pour les icônes -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">

    <style>
        /* Général */
        body {
            background-color: #f4f6f9;
            font-family: 'Arial', sans-serif;
        }
        h1 {
            color: #212529;
        }

        /* Tableau */
        .table-container {
            background: #fff;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }

        .table {
            border: 2px solid #000;
            margin-bottom: 0 !important;
            table-layout: fixed;
            width: 100%;
        }

        .table th,
        .table td {
            border: 1px solid #000;
            vertical-align: middle;
            word-wrap: break-word;
        }

        /* Définir les largeurs des colonnes */
        .table th:nth-child(1), .table td:nth-child(1) { 
            width: 18%; 
        }
        .table th:nth-child(2), .table td:nth-child(2) { 
            width: 10%; 
            text-align: center;
        }
        .table th:nth-child(3), .table td:nth-child(3) { 
            width: 15%; 
        }
        .table th:nth-child(4), .table td:nth-child(4) { 
            width: 10%; 
            text-align: center;
        }
        .table th:nth-child(5), .table td:nth-child(5) { 
            width: 12%; 
            text-align: center;
        }
        .table th:nth-child(6), .table td:nth-child(6) { 
            width: 35%; 
            text-align: center; /* Centrer le texte pour cette colonne */
        }

        /* Rangées alternées */
        .table-striped tbody tr:nth-of-type(odd) {
            background-color: #f8f9fc;
        }

        /* Effet au survol */
        .table-hover tbody tr:hover {
            background-color: #e2e6ea;
        }

        /* Score moyen centré */
        .score-cell {
            text-align: center;
            font-weight: bold;
        }
        
        /* Style minimaliste et structuré pour les statistiques */
        .stats-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            background-color: white;
            border: 1px solid #dee2e6;
        }
        
        .stats-table th {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            color: #495057;
        }
        
        .stats-table td {
            border: 1px solid #dee2e6;
            padding: 12px 15px;
            vertical-align: middle;
        }
        
        .stats-table .value-cell {
            font-weight: 600;
            font-size: 18px;
            text-align: center;
        }
        
        .stats-label {
            font-size: 14px;
            color: #6c757d;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        .stats-header {
            font-size: 16px;
            font-weight: 600;
            color: #495057;
            margin-bottom: 5px;
        }
        
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #0d6efd; }
        .low { color: #198754; }
        
        .large-value {
            font-size: 24px;
            font-weight: 700;
            line-height: 1.2;
        }
        
        .border-critical { border-left: 4px solid #dc3545; }
        .border-high { border-left: 4px solid #fd7e14; }
        .border-medium { border-left: 4px solid #0d6efd; }
        .border-low { border-left: 4px solid #198754; }
        .border-neutral { border-left: 4px solid #6c757d; }
        
        /* Style pour la recherche avancée */
        .search-container {
            margin-bottom: 15px;
        }
        
        .search-input {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .search-options {
            display: flex;
            margin-top: 10px;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .search-option {
            display: flex;
            align-items: center;
            margin-right: 15px;
        }
        
        .search-label {
            margin-left: 5px;
            font-size: 14px;
        }
        
        .highlighted {
            background-color: #ffeb3b;
            font-weight: bold;
        }
        
        /* Style pour la pagination */
        .pagination-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 15px;
            margin-bottom: 15px;
        }
        
        .pagination {
            margin-bottom: 0;
        }
        
        .page-item.active .page-link {
            background-color: #0d6efd;
            border-color: #0d6efd;
        }
        
        .page-link {
            color: #0d6efd;
            cursor: pointer;
        }
        
        .entries-info {
            color: #6c757d;
            font-size: 14px;
        }
        
        .page-size-selector {
            padding: 6px 10px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            margin-left: 10px;
        }
        
        /* Style pour les colonnes triables */
        .sortable {
            cursor: pointer;
            position: relative;
        }
        
        .sortable:after {
            content: '↕';
            position: absolute;
            right: 8px;
            opacity: 0.5;
        }
        
        .sorting-asc:after {
            content: '↑';
            opacity: 1;
        }
        
        .sorting-desc:after {
            content: '↓';
            opacity: 1;
        }

        .cve-cell a {
            color: #0d6efd;
            text-decoration: none;
            transition: color 0.2s;
        }

        .cve-cell a:hover {
            color: #0a58ca;
            text-decoration: underline;
        }

        .cve-cell a strong {
            font-weight: bold;
        }

        .cve-cell a .highlighted {
            background-color: #ffeb3b;
            font-weight: bold;
        }

        /* CSS optimisé pour dézoomer la page de statistiques vendeur */

/* Ajustement de base */
body {
    font-size: 0.85rem; /* Réduction de la taille de base du texte */
    padding: 8px; /* Réduction du padding général */
    background-color: #f4f6f9;
    font-family: 'Arial', sans-serif;
}

h1 {
    font-size: 1.5rem; /* Réduction de la taille du titre principal */
    margin-bottom: 0.5rem;
}

.container {
    padding: 0 10px; /* Réduction des marges latérales */
    max-width: 1200px; /* Limite la largeur sur grands écrans */
}

.my-4 {
    margin-top: 0.75rem !important;
    margin-bottom: 0.75rem !important;
}

.mb-3 {
    margin-bottom: 0.5rem !important;
}

/* Statistiques et tableaux */
.stats-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 10px; /* Réduction de l'espacement */
    background-color: white;
    border: 1px solid #dee2e6;
}

.stats-table th {
    background-color: #f8f9fa;
    border: 1px solid #dee2e6;
    padding: 6px 8px; /* Réduction du padding */
    text-align: left;
    font-weight: 600;
    color: #495057;
    font-size: 13px;
}

.stats-table td {
    border: 1px solid #dee2e6;
    padding: 6px 8px; /* Réduction du padding */
    vertical-align: middle;
}

.stats-table .value-cell {
    font-weight: 600;
    font-size: 16px; /* Réduction de la taille */
    text-align: center;
}

.stats-label {
    font-size: 12px; /* Réduction de la taille */
    color: #6c757d;
    margin-bottom: 2px; /* Réduction de la marge */
    font-weight: bold;
}

.large-value {
    font-size: 18px; /* Réduction de la taille */
    font-weight: 700;
    line-height: 1.2;
}

/* Tableau principal */
.table-container {
    background: #fff;
    border-radius: 6px;
    padding: 10px; /* Réduction du padding */
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);
    margin-bottom: 10px;
}

.table {
    border: 1px solid #000;
    margin-bottom: 0 !important;
    table-layout: fixed;
    width: 100%;
    font-size: 0.85rem;
}

.table th,
.table td {
    border: 1px solid #000;
    vertical-align: middle;
    word-wrap: break-word;
    padding: 6px 8px; /* Réduction du padding */
}

.table th {
    font-size: 12px; /* Réduction de la taille */
}

/* Recherche et pagination */
.search-container {
    margin-bottom: 8px; /* Réduction de la marge */
}

.search-input {
    width: 100%;
    padding: 6px 8px; /* Réduction du padding */
    border: 1px solid #ced4da;
    border-radius: 4px;
    font-size: 13px; /* Réduction de la taille */
}

.search-options {
    display: flex;
    margin-top: 5px; /* Réduction de la marge */
    flex-wrap: wrap;
    gap: 8px; /* Réduction de l'écart */
}

.search-option {
    display: flex;
    align-items: center;
    margin-right: 10px; /* Réduction de la marge */
}

.search-label {
    margin-left: 3px; /* Réduction de la marge */
    font-size: 12px; /* Réduction de la taille */
}

.pagination-container {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 8px; /* Réduction de la marge */
    margin-bottom: 8px; /* Réduction de la marge */
}

.pagination {
    margin-bottom: 0;
}

.page-link {
    padding: 0.25rem 0.5rem; /* Réduction du padding */
    font-size: 0.8rem; /* Réduction de la taille */
}

.entries-info {
    color: #6c757d;
    font-size: 12px; /* Réduction de la taille */
}

.page-size-selector {
    padding: 2px 5px; /* Réduction du padding */
    border: 1px solid #ced4da;
    border-radius: 4px;
    margin-left: 5px; /* Réduction de la marge */
    font-size: 12px; /* Réduction de la taille */
}

/* Boutons */
.btn-sm {
    padding: 0.15rem 0.4rem; /* Réduction du padding */
    font-size: 0.75rem; /* Réduction de la taille */
}

/* Modal */
.modal-dialog {
    max-width: 90%; /* Plus large pour utiliser plus d'espace */
}

.modal-body {
    padding: 0.75rem; /* Réduction du padding */
}

.modal-footer {
    padding: 0.5rem; /* Réduction du padding */
}

/* Viewport scale pour le dézoom global */
@viewport {
    zoom: 0.9;
    width: device-width;
}
    </style>
</head>
<body>
<div class="container my-4">
<div class="mb-3 d-flex justify-content-between align-items-center">
    <h1>Résultats pour le vendeur : <?= htmlspecialchars($vendeurRechercher, ENT_QUOTES, 'UTF-8') ?></h1>
    <div>
        <button id="export-excel" class="btn btn-success btn-sm me-2">
            <i class="fas fa-file-excel"></i> Exporter en Excel
        </button>
        <a href="1-vendeur.php" class="btn btn-secondary btn-sm">Retour à la liste des vendeurs</a>
    </div>
</div>

    <!-- Messages d'erreur et affichage -->
    <?php if (is_string($resultats)): ?>
        <div class="alert alert-danger">
            <?= htmlspecialchars($resultats, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php elseif (empty($resultats)): ?>
        <div class="alert alert-info">
            Aucune vulnérabilité trouvée pour ce vendeur.
        </div>
    <?php else: ?>
        <!-- Structure de tableau pour les statistiques principales -->
        <!-- Structure de tableau pour les statistiques principales -->
<table class="stats-table">
    <tr>
        <th width="25%">Score CVSS Moyen</th>
        <th width="25%">Total des Vulnérabilités</th>
        <th width="25%">Temps de Correction</th>
        <th width="25%">Type le Plus Courant</th>
    </tr>
    <tr>
        <?php
        // Déterminer la classe de couleur selon le score
        $scoreClass = '';
        if ($scoresMoyens >= 9.0) {
            $scoreClass = 'critical';
        } elseif ($scoresMoyens >= 7.0) {
            $scoreClass = 'high';
        } elseif ($scoresMoyens >= 4.0) {
            $scoreClass = 'medium';
        } else {
            $scoreClass = 'low';
        }
        ?>
        <td class="value-cell">
            <div class="large-value <?= $scoreClass ?>"><?= number_format($scoresMoyens, 2) ?></div>
            <div class="stats-label">Sur une échelle de 10</div>
        </td>
        <td class="value-cell">
            <div class="large-value"><?= $total_viln ?></div>
            <div class="stats-label">Vulnérabilités identifiées</div>
        </td>
        <td class="value-cell">
            <div class="large-value"><?= $avg_fix_time ?></div>
            <div class="stats-label">Jours en moyenne</div>
        </td>
        <td class="value-cell">
            <div style="font-size: 14px; line-height: 1.4; font-weight: 600; text-align: left;">
                <?= htmlspecialchars($type, ENT_QUOTES, 'UTF-8') ?>
            </div>
        </td>
    </tr>
</table>
        
        <!-- Structure de tableau pour la répartition par niveau de risque -->
<table class="stats-table">
    <tr>
        <th colspan="4">Répartition par Niveau de Risque</th>
    </tr>
    <tr>
        <td width="25%" class="border-critical">
            <div class="stats-label">Critique</div>
            <div class="value-cell critical"><?= $stat_critical ?></div>
            <div class="stats-label text-center">
                <?= $total_viln > 0 ? number_format(($stat_critical / $total_viln) * 100, 1) : '0.0' ?>%
            </div>
        </td>
        <td width="25%" class="border-high">
            <div class="stats-label">Élevé</div>
            <div class="value-cell high"><?= $stat_high ?></div>
            <div class="stats-label text-center">
                <?= $total_viln > 0 ? number_format(($stat_high / $total_viln) * 100, 1) : '0.0' ?>%
            </div>
        </td>
        <td width="25%" class="border-medium">
            <div class="stats-label">Moyen</div>
            <div class="value-cell medium"><?= $stat_medium ?></div>
            <div class="stats-label text-center">
                <?= $total_viln > 0 ? number_format(($stat_medium / $total_viln) * 100, 1) : '0.0' ?>%
            </div>
        </td>
        <td width="25%" class="border-low">
            <div class="stats-label">Faible</div>
            <div class="value-cell low"><?= $stat_low ?></div>
            <div class="stats-label text-center">
                <?= $total_viln > 0 ? number_format(($stat_low / $total_viln) * 100, 1) : '0.0' ?>%
            </div>
        </td>
    </tr>
</table>

<!-- Tableau séparé pour les temps moyens de correction -->
<table class="stats-table">
    <tr>
        <th colspan="4">Temps Moyen de Correction par Niveau</th>
    </tr>
    <tr>
        <td width="25%" class="border-critical">
            <div class="stats-label">Critique</div>
            <div class="value-cell critical"><?= $stat_score_critical ?? 'N/A' ?></div>
            <div class="stats-label text-center">jours</div>
        </td>
        <td width="25%" class="border-high">
            <div class="stats-label">Élevé</div>
            <div class="value-cell high"><?= $stat_score_high ?? 'N/A' ?></div>
            <div class="stats-label text-center">jours</div>
        </td>
        <td width="25%" class="border-medium">
            <div class="stats-label">Moyen</div>
            <div class="value-cell medium"><?= $stat_score_medium ?? 'N/A' ?></div>
            <div class="stats-label text-center">jours</div>
        </td>
        <td width="25%" class="border-low">
            <div class="stats-label">Faible</div>
            <div class="value-cell low"><?= $stat_score_low ?? 'N/A' ?></div>
            <div class="stats-label text-center">jours</div>
        </td>
    </tr>
</table>

        <!-- Barre de recherche avancée -->
        <div class="search-container">
            <input type="text" id="advanced-search" class="search-input" placeholder="Rechercher dans le tableau...">
            <div class="search-options">
                <div class="search-option">
                    <input type="checkbox" id="search-produit" checked>
                    <label for="search-produit" class="search-label">Produit</label>
                </div>
                <div class="search-option">
                    <input type="checkbox" id="search-cve" checked>
                    <label for="search-cve" class="search-label">CVE ID</label>
                </div>
                <div class="search-option">
                    <input type="checkbox" id="search-type" checked>
                    <label for="search-type" class="search-label">Type de Vulnérabilité</label>
                </div>
                <div class="search-option">
                    <input type="checkbox" id="search-score">
                    <label for="search-score" class="search-label">Scores</label>
                </div>
                <div class="search-option">
                    <input type="checkbox" id="search-exact">
                    <label for="search-exact" class="search-label">Correspondance exacte</label>
                </div>
                <button class="btn btn-sm btn-outline-secondary ms-auto search-reset">Réinitialiser</button>
            </div>
        </div>

        <!-- Sélecteur d'entrées par page -->
        <div class="d-flex align-items-center mb-3">
            <label for="page-size" class="me-2">Afficher</label>
            <select id="page-size" class="page-size-selector">
                <option value="10">10</option>
                <option value="25" selected>25</option>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="all">Tout</option>
            </select>
            <span class="ms-2">entrées</span>
        </div>

        <!-- Tableau des résultats avec rowspan comme dans l'original -->
        <div class="table-container">
            <table id="resultats-table" class="table table-hover table-striped">
                <thead class="table-primary">
                <tr>
                    <th class="sortable" data-sort="produit">Produit</th>
                    <th class="text-center sortable" data-sort="scoreMoyen">Score Moyen</th>
                    <th class="sortable" data-sort="cveId">CVE ID</th>
                    <th class="text-center sortable" data-sort="cvssScore">Score CVSSv3</th>
                    <th class="text-center sortable" data-sort="severity">Gravité</th>
                    <th class="text-center sortable" data-sort="cweType">Type de Vulnérabilité</th>
                </tr>
                </thead>
                <tbody id="table-body">
                <!-- Le contenu du tableau sera généré par JavaScript -->
                </tbody>
            </table>
        </div>
        
        <!-- Pagination -->
        <div class="pagination-container">
            <div class="entries-info">Affichage de <span id="showing-start">1</span> à <span id="showing-end">0</span> sur <span id="total-entries">0</span> entrées</div>
            <nav aria-label="Pagination des résultats">
                <ul class="pagination" id="pagination">
                    <!-- Pagination générée par JavaScript -->
                </ul>
            </nav>
        </div>
        
        <!-- Préparer les données pour JavaScript -->
        <script>
            var tableData = [];
            
            <?php
            $index = 0;
            
            // Construction d'un tableau de données structuré pour JavaScript
            foreach ($resultats as $produit => $cveData):
                $rowspan = count($cveData); // Nombre de lignes pour ce produit
                $isFirstRow = true;
                
                // Calculer le score moyen pour ce produit spécifique
                $totalScoreProduit = 0;
                $countProduit = 0;
                
                foreach ($cveData as $cvItem) {
                    if (isset($cvItem['CVSSv3_Score']) && is_numeric($cvItem['CVSSv3_Score'])) {
                        $totalScoreProduit += $cvItem['CVSSv3_Score'];
                        $countProduit++;
                    }
                }
                
                // Calculer la moyenne pour ce produit
                $scoreMoyenProduit = $countProduit > 0 ? $totalScoreProduit / $countProduit : 0;
                
                // Déterminer la classe de couleur pour ce produit
                $scoreClassProduit = '';
                if ($scoreMoyenProduit >= 9.0) {
                    $scoreClassProduit = 'critical';
                } elseif ($scoreMoyenProduit >= 7.0) {
                    $scoreClassProduit = 'high';
                } elseif ($scoreMoyenProduit >= 4.0) {
                    $scoreClassProduit = 'medium';
                } else {
                    $scoreClassProduit = 'low';
                }

                foreach ($cveData as $cveId => $cveDetails):
                    $severity = isset($cveDetails['Severity']) ? $cveDetails['Severity'] : 'N/A';
                    $cweType = isset($cveDetails['CWE_Type']) ? $cveDetails['CWE_Type'] : 'Type non spécifié';
                    ?>
                    
                    tableData.push({
                        produit: <?= json_encode($produit) ?>,
                        scoreMoyen: <?= json_encode(number_format($scoreMoyenProduit, 2)) ?>,
                        scoreClass: <?= json_encode($scoreClassProduit) ?>,
                        cveId: <?= json_encode($cveId) ?>,
                        cvssScore: <?= json_encode($cveDetails['CVSSv3_Score']) ?>,
                        severity: <?= json_encode($severity) ?>,
                        cweType: <?= json_encode($cweType) ?>,
                        rowId: 'row-<?= $index ?>',
                        isFirstInGroup: <?= $isFirstRow ? 'true' : 'false' ?>,
                        rowspan: <?= $isFirstRow ? $rowspan : 0 ?>
                    });
                    
                    <?php
                    $isFirstRow = false;
                    $index++;
                endforeach;
            endforeach;
            ?>
        </script>
    <?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>

<script>
    $(document).ready(function () {
        // Variables pour la pagination et le tri
        var currentPage = 1;
        var pageSize = 25;
        var totalPages = 1;
        var filteredData = [...tableData]; // Copie des données
        var sortField = '';
        var sortDirection = 'asc';
        
        // Initialisation
        calculateTotalPages();
        renderTable();
        updatePagination();
        
        // Fonction pour calculer le nombre total de pages
        function calculateTotalPages() {
            if (pageSize === 'all') {
                totalPages = 1;
                return;
            }
            
            // Calculer le nombre de pages en tenant compte des groupes
            var totalGroups = 0;
            var currentProduct = '';
            
            // Compter les groupes uniques
            filteredData.forEach(function(item) {
                if (item.isFirstInGroup) {
                    totalGroups++;
                }
            });
            
            totalPages = Math.ceil(totalGroups / Math.floor(pageSize / 2));
            
            if (currentPage > totalPages) {
                currentPage = 1;
            }
        }
        
        // Fonction pour obtenir les données de la page actuelle
        function getCurrentPageData() {
            if (pageSize === 'all') {
                return filteredData;
            }
            
            // Logique spéciale pour la pagination avec rowspan
            var result = [];
            var groupedByProduct = {};
            
            // Grouper par produit
            filteredData.forEach(function(item) {
                if (!groupedByProduct[item.produit]) {
                    groupedByProduct[item.produit] = [];
                }
                groupedByProduct[item.produit].push(item);
            });
            
            // Convertir en array de groupes
            var groups = Object.values(groupedByProduct);
            
            // Calculer l'index de départ pour la pagination
            var startGroupIndex = (currentPage - 1) * Math.floor(pageSize / 2);
            var groupCount = 0;
            var itemCount = 0;
            
            // Parcourir les groupes jusqu'à remplir la page
            for (var i = startGroupIndex; i < groups.length && itemCount < pageSize; i++) {
                var group = groups[i];
                result = result.concat(group);
                itemCount += group.length;
                groupCount++;
            }
            
            return result;
        }
        
        // Fonction pour générer le tableau avec rowspan
        function renderTable() {
            var data = getCurrentPageData();
            var tbody = $('#table-body');
            tbody.empty();
            
            // Réinitialiser les groupes pour la page courante
            var groupedByProduct = {};
            var groupSizes = {};
            
            // Grouper par produit
            data.forEach(function(item) {
                if (!groupedByProduct[item.produit]) {
                    groupedByProduct[item.produit] = [];
                }
                groupedByProduct[item.produit].push(item);
            });
            
            // Calculer les tailles de groupe
            Object.keys(groupedByProduct).forEach(function(produit) {
                groupSizes[produit] = groupedByProduct[produit].length;
            });
            
            // Générer les lignes du tableau
            data.forEach(function(item, index) {
                var isFirst = index === 0 || data[index - 1].produit !== item.produit;
                var row = $('<tr>').attr('id', item.rowId).addClass('data-row');
                
                // Si c'est le premier élément d'un groupe, ajouter les cellules avec rowspan
                if (isFirst) {
                    var rowspan = groupSizes[item.produit];
                    row.append(
                        $('<td>')
                            .attr('rowspan', rowspan)
                            .addClass('produit-cell')
                            .html('<strong>' + item.produit + '</strong>')
                    );
                    
                    row.append(
                        $('<td>')
                            .attr('rowspan', rowspan)
                            .addClass('text-center score-moyen-cell')
                            .html('<strong class="' + item.scoreClass + '">' + item.scoreMoyen + '</strong>')
                    );
                }
                
                // Ajouter les autres cellules
var cveLink = '<a href="#" class="cve-modal-link" data-cve-id="' + item.cveId + '">' +
'<strong>' + item.cveId + '</strong></a>';
                row.append($('<td>').addClass('cve-cell').html(cveLink));
                row.append($('<td>').addClass('text-center cvss-score-cell').html('<strong>' + item.cvssScore + '</strong>'));
                row.append($('<td>').addClass('text-center severity-cell').html('<strong>' + item.severity + '</strong>'));
                row.append($('<td>').addClass('text-center cwe-type-cell').html('<strong>' + item.cweType + '</strong>'));
                
                tbody.append(row);
            });
            
            // Mettre à jour les informations de pagination
            var startEntry = filteredData.length > 0 ? (currentPage - 1) * pageSize + 1 : 0;
            var endEntry = pageSize === 'all' ? filteredData.length : Math.min(startEntry + data.length - 1, filteredData.length);
            
            $('#showing-start').text(startEntry);
            $('#showing-end').text(endEntry);
            $('#total-entries').text(filteredData.length);
        }
        
        // Fonction pour mettre à jour la pagination
        function updatePagination() {
            var pagination = $('#pagination');
            pagination.empty();
            
            // Si tout est affiché ou il n'y a qu'une page, pas besoin de pagination
            if (pageSize === 'all' || totalPages <= 1) {
                return;
            }
            
            // Bouton précédent
            pagination.append(
                $('<li>').addClass('page-item ' + (currentPage === 1 ? 'disabled' : ''))
                    .append($('<a>').addClass('page-link').attr('data-page', 'prev').html('&laquo;'))
            );
            
            // Pages numériques
            var startPage = Math.max(1, currentPage - 2);
            var endPage = Math.min(totalPages, startPage + 4);
            
            if (endPage - startPage < 4) {
                startPage = Math.max(1, endPage - 4);
            }
            
            for (var i = startPage; i <= endPage; i++) {
                pagination.append(
                    $('<li>').addClass('page-item ' + (i === currentPage ? 'active' : ''))
                        .append($('<a>').addClass('page-link').attr('data-page', i).text(i))
                );
            }
            
            // Bouton suivant
            pagination.append(
                $('<li>').addClass('page-item ' + (currentPage === totalPages ? 'disabled' : ''))
                    .append($('<a>').addClass('page-link').attr('data-page', 'next').html('&raquo;'))
            );
        }
        
        // Fonction pour trier les données
        function sortData(field, direction) {
            filteredData.sort(function(a, b) {
                var aValue = a[field];
                var bValue = b[field];
                
                // Comparer numériquement si ce sont des nombres
                if (!isNaN(parseFloat(aValue)) && !isNaN(parseFloat(bValue))) {
                    return direction === 'asc' ? 
                        parseFloat(aValue) - parseFloat(bValue) : 
                        parseFloat(bValue) - parseFloat(aValue);
                }
                
                // Sinon comparer comme des chaînes
                return direction === 'asc' ? 
                    String(aValue).localeCompare(String(bValue)) : 
                    String(bValue).localeCompare(String(aValue));
            });
            
            // Mettre à jour les marqueurs isFirstInGroup
            var currentProduct = '';
            filteredData.forEach(function(item, index) {
                item.isFirstInGroup = (index === 0 || filteredData[index - 1].produit !== item.produit);
            });
            
            // Recalculer les rowspans
            var groupSizes = {};
            filteredData.forEach(function(item) {
                if (!groupSizes[item.produit]) {
                    groupSizes[item.produit] = 0;
                }
                groupSizes[item.produit]++;
            });
            
            filteredData.forEach(function(item) {
                if (item.isFirstInGroup) {
                    item.rowspan = groupSizes[item.produit];
                } else {
                    item.rowspan = 0;
                }
            });
        }
        
        // Fonction pour filtrer les données
        function filterData(searchText) {
            if (!searchText) {
                filteredData = [...tableData];
                return;
            }
            
            searchText = searchText.toLowerCase();
            
            // Options de recherche
            var searchProduit = $('#search-produit').is(':checked');
            var searchCve = $('#search-cve').is(':checked');
            var searchType = $('#search-type').is(':checked');
            var searchScore = $('#search-score').is(':checked');
            var exact = $('#search-exact').is(':checked');
            
            // Fonction de test
            function testValue(value, test) {
                if (typeof value !== 'string') {
                    value = String(value);
                }
                value = value.toLowerCase();
                return exact ? value === test : value.includes(test);
            }
            
            // Filtrer les données
            filteredData = tableData.filter(function(item) {
                if (searchProduit && testValue(item.produit, searchText)) {
                    return true;
                }
                if (searchCve && testValue(item.cveId, searchText)) {
                    return true;
                }
                if (searchType && testValue(item.cweType, searchText)) {
                    return true;
                }
                if (searchScore && (
                    testValue(item.scoreMoyen, searchText) ||
                    testValue(item.cvssScore, searchText)
                )) {
                    return true;
                }
                return false;
            });
            
            // Si le tri était actif, ré-appliquer
            if (sortField) {
                sortData(sortField, sortDirection);
            }
        }
        
        // Fonction pour surligner les correspondances
        function highlightMatches(text, searchText) {
            if (!searchText) return text;
            
            var exact = $('#search-exact').is(':checked');
            var pattern = exact ? 
                new RegExp('\\b(' + escapeRegExp(searchText) + ')\\b', 'gi') : 
                new RegExp('(' + escapeRegExp(searchText) + ')', 'gi');
                
            return text.replace(pattern, '<span class="highlighted">$1</span>');
        }
        
        // Fonction pour échapper les caractères spéciaux RegExp
        function escapeRegExp(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }
        
        // Gestionnaires d'événements
        
        // Changement de page
        $(document).on('click', '.page-link', function(e) {
            e.preventDefault();
            
            var page = $(this).data('page');
            
            if (page === 'prev') {
                if (currentPage > 1) {
                    currentPage--;
                }
            } else if (page === 'next') {
                if (currentPage < totalPages) {
                    currentPage++;
                }
            } else {
                currentPage = parseInt(page);
            }
            
            renderTable();
            updatePagination();
        });
        
        // Changement de taille de page
        $('#page-size').change(function() {
            pageSize = $(this).val();
            currentPage = 1;
            calculateTotalPages();
            renderTable();
            updatePagination();
        });
        
        // Tri des colonnes
        $('.sortable').click(function() {
            var field = $(this).data('sort');
            
            // Si on clique sur la même colonne, inverser la direction
            if (sortField === field) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortField = field;
                sortDirection = 'asc';
            }
            
            // Visuel pour indiquer le tri
            $('.sortable').removeClass('sorting-asc sorting-desc');
            $(this).addClass('sorting-' + sortDirection);
            
            // Trier les données
            sortData(sortField, sortDirection);
            
            // Réinitialiser la pagination à la première page
            currentPage = 1;
            calculateTotalPages();
            renderTable();
            updatePagination();
        });
        
        // Recherche avancée
        $('#advanced-search').on('input', function() {
            var searchText = $(this).val().toLowerCase();
            
            // Filtrer les données
            filterData(searchText);
            
            // Réinitialiser la pagination
            currentPage = 1;
            calculateTotalPages();
            renderTable();
            updatePagination();
            
            // Surligner les correspondances si la recherche n'est pas vide
            if (searchText) {
                var searchProduit = $('#search-produit').is(':checked');
                var searchCve = $('#search-cve').is(':checked');
                var searchType = $('#search-type').is(':checked');
                var searchScore = $('#search-score').is(':checked');
                
                if (searchProduit) {
                    $('.produit-cell strong').each(function() {
                        $(this).html(highlightMatches($(this).text(), searchText));
                    });
                }
                
                if (searchCve) {
                    $('.cve-cell a strong').each(function() {
    var originalText = $(this).text();
    var highlightedText = highlightMatches(originalText, searchText);
    $(this).html(highlightedText);
});
                }
                
                if (searchType) {
                    $('.cwe-type-cell strong').each(function() {
                        $(this).html(highlightMatches($(this).text(), searchText));
                    });
                }
                
                if (searchScore) {
                    $('.score-moyen-cell strong, .cvss-score-cell strong').each(function() {
                        $(this).html(highlightMatches($(this).text(), searchText));
                    });
                }
            }
        });
        
        // Options de recherche
        $('.search-option input').change(function() {
            // Refaire la recherche avec les nouvelles options
            $('#advanced-search').trigger('input');
        });
        
        // Réinitialisation de la recherche
        $('.search-reset').click(function() {
            $('#advanced-search').val('');
            $('.search-option input[type="checkbox"]').prop('checked', function() {
                return this.id === 'search-produit' || this.id === 'search-cve' || this.id === 'search-type';
            });
            
            // Réinitialiser les données
            filteredData = [...tableData];
            sortField = '';
            sortDirection = 'asc';
            $('.sortable').removeClass('sorting-asc sorting-desc');
            
            // Réinitialiser la pagination
            currentPage = 1;
            calculateTotalPages();
            renderTable();
            updatePagination();
        });
    });

    // Gestionnaire pour les liens CVE - ouvre la modal et charge les détails
$(document).on('click', '.cve-modal-link', function(e) {
    e.preventDefault();
    var cveId = $(this).data('cve-id');
    
    // Mettre à jour le titre de la modal avec l'ID CVE
    $('#cveDetailModalLabel').text('Détails de ' + cveId);
    
    // Réinitialiser le contenu de la modal avec l'indicateur de chargement
    $('#cveDetailContent').html('<div class="text-center"><div class="spinner-border text-primary" role="status">' +
        '<span class="visually-hidden">Chargement...</span></div>' +
        '<p>Chargement des détails de la vulnérabilité...</p></div>');
    
    // Mettre à jour le lien "Voir en plein écran"
    $('#openCveDetails').attr('href', '6-detail_cve.php?cve_id=' + cveId);
    
    // Ouvrir la modal
    var cveModal = new bootstrap.Modal(document.getElementById('cveDetailModal'));
    cveModal.show();
    
    // Charger les détails via AJAX
    $.ajax({
        url: '6-detail_cve.php',
        type: 'GET',
        data: { cve_id: cveId, format: 'ajax' },
        success: function(data) {
            $('#cveDetailContent').html(data);
        },
        error: function() {
            $('#cveDetailContent').html('<div class="alert alert-danger">' +
                'Erreur lors du chargement des données. Veuillez réessayer ou ' +
                '<a href="6-detail_cve.php?cve_id=' + cveId + '" target="_blank">ouvrir dans un nouvel onglet</a>.' +
                '</div>');
        }
    });
});
</script>

<!-- Modal pour afficher les détails CVE -->
<div class="modal fade" id="cveDetailModal" tabindex="-1" aria-labelledby="cveDetailModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="cveDetailModalLabel">Détails de la vulnérabilité</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Fermer"></button>
      </div>
      <div class="modal-body">
        <div id="cveDetailContent">
          <div class="text-center">
            <div class="spinner-border text-primary" role="status">
              <span class="visually-hidden">Chargement...</span>
            </div>
            <p>Chargement des détails de la vulnérabilité...</p>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Fermer</button>
        <a id="openCveDetails" href="#" class="btn btn-primary" target="_blank">Voir en plein écran</a>
      </div>
    </div>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>

<script>
$(document).ready(function() {
    $('#export-excel').click(function() {
        // Créer un nouveau classeur
        var wb = XLSX.utils.book_new();
        
        // Préparer les données pour l'export
        var headerRow = ["Produit", "Score Moyen", "CVE ID", "Score CVSSv3", "Gravité", "Type de Vulnérabilité"];
        var rows = [headerRow];
        
        // Obtenir les données à exporter (soit toutes, soit filtrées)
        var dataToExport = window.filteredData || tableData;
        if (!dataToExport || dataToExport.length === 0) {
            dataToExport = tableData;
        }
        
        // Ajouter les données au tableau
        dataToExport.forEach(function(item) {
            rows.push([
                item.produit,
                item.scoreMoyen,
                item.cveId,
                item.cvssScore,
                item.severity,
                item.cweType
            ]);
        });
        
        // Créer la feuille de calcul avec les données
        var ws = XLSX.utils.aoa_to_sheet(rows);
        
        // Configurer les largeurs de colonnes
        ws['!cols'] = [
            {width: 25},  // Produit
            {width: 15},  // Score Moyen
            {width: 20},  // CVE ID
            {width: 15},  // Score CVSSv3
            {width: 15},  // Gravité
            {width: 40}   // Type de Vulnérabilité
        ];
        
        // Créer une chaîne XML pour les styles
        var xmlStyles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
            '<fonts count="2">' +
            '<font><sz val="11"/><name val="Calibri"/></font>' +
            '<font><b/><sz val="11"/><name val="Calibri"/></font>' +
            '</fonts>' +
            '<fills count="2">' +
            '<fill><patternFill patternType="none"/></fill>' +
            '<fill><patternFill patternType="solid"><fgColor rgb="FFFFFF00"/></patternFill></fill>' +
            '</fills>' +
            '<borders count="2">' +
            '<border><left/><right/><top/><bottom/></border>' +
            '<border>' +
            '<left style="thin"><color rgb="FF000000"/></left>' +
            '<right style="thin"><color rgb="FF000000"/></right>' +
            '<top style="thin"><color rgb="FF000000"/></top>' +
            '<bottom style="thin"><color rgb="FF000000"/></bottom>' +
            '</border>' +
            '</borders>' +
            '<cellXfs count="3">' +
            '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" applyBorder="1"/>' +
            '<xf numFmtId="0" fontId="1" fillId="1" borderId="1" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1">' +
            '<alignment horizontal="center"/></xf>' +
            '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" applyBorder="1" applyAlignment="1">' +
            '<alignment horizontal="center"/></xf>' +
            '</cellXfs>' +
            '</styleSheet>';
        
        // Ajouter une mise en forme conditionnelle pour les en-têtes
        ws['!conditionalFormatting'] = {
            '0:0': { // La première ligne (en-têtes)
                type: 'cellIs',
                operator: 'greaterThan',
                formula: '-1',
                style: {
                    fill: {fgColor: {rgb: 'FFFF00'}}, // Jaune
                    font: {bold: true},
                    border: {
                        top: {style: 'thin', color: {rgb: '000000'}},
                        bottom: {style: 'thin', color: {rgb: '000000'}},
                        left: {style: 'thin', color: {rgb: '000000'}},
                        right: {style: 'thin', color: {rgb: '000000'}}
                    }
                }
            }
        };
        
        // Ajouter des informations de feuille supplémentaires pour la mise en forme
        if (!ws['!props']) ws['!props'] = {};
        ws['!props'].Styles = xmlStyles;
        
        // Ajouter la feuille au classeur
        wb.SheetNames.push("Vulnerabilités");
        wb.Sheets["Vulnerabilités"] = ws;
        
        // Créer une feuille d'informations
        var infoSheet = XLSX.utils.aoa_to_sheet([
            ["Rapport de Vulnérabilité"],
            [""],
            ["Vendeur:", "<?= htmlspecialchars($vendeurRechercher, ENT_QUOTES, 'UTF-8') ?>"],
            ["Date d'export:", new Date().toLocaleDateString()],
            ["Nombre de vulnérabilités:", dataToExport.length.toString()],
            ["Score CVSS Moyen:", "<?= number_format($scoresMoyens, 2) ?>"]
        ]);
        
        // Ajouter la feuille d'informations
        wb.SheetNames.push("Informations");
        wb.Sheets["Informations"] = infoSheet;
        
        // Générer le fichier Excel avec option de formatage maximal
        var opts = {
            bookType: 'xlsx',
            bookSST: true,
            type: 'binary',
            cellStyles: true
        };
        
        // Créer le fichier Excel
        var wbout = XLSX.write(wb, opts);
        
        // Convertir le binaire en Blob
        function s2ab(s) {
            var buf = new ArrayBuffer(s.length);
            var view = new Uint8Array(buf);
            for (var i=0; i<s.length; i++) view[i] = s.charCodeAt(i) & 0xFF;
            return buf;
        }
        
        // Créer un objet Blob
        var blob = new Blob([s2ab(wbout)], {type: 'application/octet-stream'});
        
        // Générer le nom de fichier
        var fileName = "vulnerabilites_<?= htmlspecialchars($vendeurRechercher, ENT_QUOTES, 'UTF-8') ?>_" + 
                      new Date().toISOString().slice(0,10) + ".xlsx";
        
        // Créer un lien de téléchargement et le déclencher
        var link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = fileName;
        link.click();
        
        // Message de confirmation
        setTimeout(function() {
            alert("Export Excel terminé avec succès !");
        }, 100);
    });
});
</script>

<!-- Solution alternative utilisant TableExport.js -->
<script>
// Méthode alternative avec TableExport (décommentez si vous voulez utiliser cette méthode)
/*
$(document).ready(function() {
    // Charger TableExport.js dynamiquement si nécessaire
    function loadTableExport() {
        if (typeof TableExport === 'undefined') {
            // Charger les scripts nécessaires
            $.getScript('https://cdn.jsdelivr.net/npm/tableexport@5.2.0/dist/js/tableexport.min.js', function() {
                $.getScript('https://cdn.jsdelivr.net/npm/xlsx@0.16.9/dist/xlsx.full.min.js', function() {
                    exportTableWithBorders();
                });
            });
        } else {
            exportTableWithBorders();
        }
    }
    
    // Fonction pour créer une table temporaire et l'exporter
    function exportTableWithBorders() {
        // Créer une table temporaire avec toutes les données
        var $tempTable = $('<table class="temp-export-table" style="display:none;"></table>');
        var $thead = $('<thead></thead>');
        var $tbody = $('<tbody></tbody>');
        
        // Ajouter l'en-tête
        var $headerRow = $('<tr></tr>');
        ["Produit", "Score Moyen", "CVE ID", "Score CVSSv3", "Gravité", "Type de Vulnérabilité"].forEach(function(header) {
            $headerRow.append('<th style="background-color: yellow; font-weight: bold;">' + header + '</th>');
        });
        $thead.append($headerRow);
        $tempTable.append($thead);
        
        // Obtenir les données à exporter
        var dataToExport = window.filteredData || tableData;
        if (!dataToExport || dataToExport.length === 0) {
            dataToExport = tableData;
        }
        
        // Ajouter les données
        dataToExport.forEach(function(item) {
            var $row = $('<tr></tr>');
            [item.produit, item.scoreMoyen, item.cveId, item.cvssScore, item.severity, item.cweType].forEach(function(cell) {
                $row.append('<td style="border: 1px solid #000;">' + cell + '</td>');
            });
            $tbody.append($row);
        });
        $tempTable.append($tbody);
        
        // Ajouter la table au document temporairement
        $('body').append($tempTable);
        
        // Configurer l'export
        var exportOptions = {
            fileName: "vulnerabilites_<?= htmlspecialchars($vendeurRechercher, ENT_QUOTES, 'UTF-8') ?>",
            sheets: {
                name: 'Vulnerabilités'
            },
            exportButtons: false,
            position: 'bottom',
            formats: ['xlsx']
        };
        
        // Exporter la table
        var $exportContainer = TableExport($tempTable, exportOptions);
        var exportData = $exportContainer.getExportData()['temp-export-table']['xlsx'];
        
        // Déclencher le téléchargement
        $exportContainer.export2file(
            exportData.data,
            exportData.mimeType,
            exportData.filename,
            exportData.fileExtension
        );
        
        // Supprimer la table temporaire
        $tempTable.remove();
        
        // Message de confirmation
        setTimeout(function() {
            alert("Export Excel terminé avec succès !");
        }, 100);
    }
    
    // Remplacer la fonction du bouton d'export
    $('#export-excel').off('click').on('click', loadTableExport);
});
*/
</script>

<!-- Méthode utilisant l'export HTML spécialement formaté pour Excel -->
<script>
// Méthode HTML pour Excel (décommentez si vous préférez cette approche)
/*
$(document).ready(function() {
    $('#export-excel').off('click').on('click', function() {
        // Préparer les données
        var dataToExport = window.filteredData || tableData;
        if (!dataToExport || dataToExport.length === 0) {
            dataToExport = tableData;
        }
        
        // Créer le HTML spécial pour Excel
        var excelHTML = '<!DOCTYPE html>' +
            '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">' +
            '<head>' +
            '<!--[if gte mso 9]>' +
            '<xml>' +
            '<x:ExcelWorkbook>' +
            '<x:ExcelWorksheets>' +
            '<x:ExcelWorksheet>' +
            '<x:Name>Vulnerabilités</x:Name>' +
            '<x:WorksheetOptions>' +
            '<x:DisplayGridlines/>' +
            '</x:WorksheetOptions>' +
            '</x:ExcelWorksheet>' +
            '</x:ExcelWorksheets>' +
            '</x:ExcelWorkbook>' +
            '</xml>' +
            '<![endif]-->' +
            '<style>' +
            'table, th, td {border: 1px solid black; border-collapse: collapse;}' +
            'th {background-color: #FFFF00; font-weight: bold; text-align: center;}' +
            '.header {font-size: 16pt; font-weight: bold; margin-bottom: 10px;}' +
            '.subheader {font-size: 12pt; margin-bottom: 20px;}' +
            '</style>' +
            '</head>' +
            '<body>' +
            '<div class="header">Rapport de Vulnérabilité</div>' +
            '<div class="subheader">Vendeur: <?= htmlspecialchars($vendeurRechercher, ENT_QUOTES, 'UTF-8') ?></div>' +
            '<div class="subheader">Date d\'export: ' + new Date().toLocaleDateString() + '</div>' +
            '<table>' +
            '<tr>' +
            '<th>Produit</th>' +
            '<th>Score Moyen</th>' +
            '<th>CVE ID</th>' +
            '<th>Score CVSSv3</th>' +
            '<th>Gravité</th>' +
            '<th>Type de Vulnérabilité</th>' +
            '</tr>';
            
        // Ajouter les données
        dataToExport.forEach(function(item) {
            excelHTML += '<tr>' +
                '<td>' + item.produit + '</td>' +
                '<td style="text-align: center;">' + item.scoreMoyen + '</td>' +
                '<td>' + item.cveId + '</td>' +
                '<td style="text-align: center;">' + item.cvssScore + '</td>' +
                '<td style="text-align: center;">' + item.severity + '</td>' +
                '<td>' + item.cweType + '</td>' +
                '</tr>';
        });
        
        excelHTML += '</table></body></html>';
        
        // Créer le blob et préparer le téléchargement
        var blob = new Blob([excelHTML], {type: 'application/vnd.ms-excel'});
        var link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = "vulnerabilites_<?= htmlspecialchars($vendeurRechercher, ENT_QUOTES, 'UTF-8') ?>_" + 
                       new Date().toISOString().slice(0,10) + ".xls";
        
        // Déclencher le téléchargement
        link.click();
        
        setTimeout(function() {
            alert("Export Excel terminé avec succès ! Ouvrez le fichier avec Excel.");
        }, 100);
    });
});
*/
</script>

</body>
</html>