<?php
// prediction_iot.php - Page d'affichage des prédictions de vulnérabilités IoT par vendeur

// Définition du chemin vers le fichier CSV
$filepath = '2-Prédiction_vendeurs_2024.csv';

// Fonction pour lire et parser le CSV
function readCSVFile($file) {
    $data = [];
    
    // Vérifie si le fichier existe
    if (!file_exists($file)) {
        return ['error' => 'Le fichier CSV n\'existe pas.'];
    }
    
    // Ouvre le fichier en lecture
    if (($handle = fopen($file, "r")) !== FALSE) {
        // Lit la première ligne pour obtenir les en-têtes
        $headers = fgetcsv($handle, 0, ",", '"', "\\");
        
        // Vérifie que les en-têtes sont valides
        if (!is_array($headers)) {
            return ['error' => 'Format CSV invalide: impossible de lire les en-têtes.'];
        }
        
        // Normalise les en-têtes
        $headers = array_map('trim', $headers);
        
        // Lit les données ligne par ligne
        while (($row = fgetcsv($handle, 0, ",", '"', "\\")) !== FALSE) {
            if (is_array($row) && count($headers) === count($row)) {
                $data[] = array_combine($headers, $row);
            }
        }
        
        fclose($handle);
    }
    
    return $data;
}

// Fonction pour grouper les données par vendeur
function groupByVendor($data) {
    $grouped = [];
    
    foreach ($data as $item) {
        $vendeur = $item['Vendeur'];
        if (!isset($grouped[$vendeur])) {
            $grouped[$vendeur] = [];
        }
        $grouped[$vendeur][] = $item;
    }
    
    // Tri des vendeurs par ordre alphabétique
    ksort($grouped);
    
    return $grouped;
}

// Fonction pour filtrer les données par vendeur
function filterByVendor($data, $vendor = null) {
    if ($vendor === null || $vendor === 'all') {
        return $data;
    }
    
    return array_filter($data, function($item) use ($vendor) {
        return $item['Vendeur'] === $vendor;
    });
}

// Obtient tous les vendeurs uniques
function getUniqueVendors($data) {
    // Vérifie que $data est un tableau avant de traiter
    if (!is_array($data)) {
        return [];
    }
    
    // Vérifie s'il y a une erreur dans les données
    if (isset($data['error'])) {
        return [];
    }
    
    $vendors = array_column($data, 'Vendeur');
    return array_unique($vendors);
}

// Fonction pour formater le score de confiance
function formatConfidenceScore($score) {
    // Nettoie le score en supprimant les caractères non numériques
    $score = preg_replace('/[^0-9.]/', '', $score);
    return floatval($score);
}

// Fonction pour déterminer la classe CSS basée sur le score
function getScoreClass($score) {
    $score = formatConfidenceScore($score);
    
    if ($score >= 80) {
        return 'table-danger';
    } elseif ($score >= 70) {
        return 'table-warning';
    } else {
        return 'table-success';
    }
}

// Lit les données du CSV
$vulnerabilityData = readCSVFile($filepath);

// Vérifie s'il y a une erreur
if (isset($vulnerabilityData['error'])) {
    $error = $vulnerabilityData['error'];
    // Si erreur, initialise $vulnerabilityData comme un tableau vide pour éviter d'autres erreurs
    $vulnerabilityData = [];
}

// Vérifie que $vulnerabilityData est bien un tableau
if (!is_array($vulnerabilityData)) {
    $error = "Erreur: les données de vulnérabilité ne sont pas au format attendu.";
    $vulnerabilityData = [];
}

// Gestion des filtres
$selectedVendor = isset($_GET['vendor']) ? $_GET['vendor'] : 'all';
$uniqueVendors = getUniqueVendors($vulnerabilityData);

// Applique le filtre par vendeur
$filteredData = filterByVendor($vulnerabilityData, $selectedVendor);

// Tri des données
$sortBy = isset($_GET['sort']) ? $_GET['sort'] : 'score';
$sortDirection = isset($_GET['direction']) && $_GET['direction'] === 'asc' ? SORT_ASC : SORT_DESC;

// Tri par score de confiance (par défaut)
if ($sortBy === 'score') {
    $confidenceScores = array_map(function($item) {
        return formatConfidenceScore($item['Score de Confiance (★%)']);
    }, $filteredData);
    array_multisort($confidenceScores, $sortDirection, $filteredData);
}
// Tri par date
elseif ($sortBy === 'date') {
    $dates = array_map(function($item) {
        // Convertit la date au format MM/YYYY en timestamp
        $date = str_replace('/', '-', $item['Date Prédite (MM/AAAA)']);
        return strtotime('01-' . $date);
    }, $filteredData);
    array_multisort($dates, $sortDirection, $filteredData);
}
// Tri par vendeur
elseif ($sortBy === 'vendor') {
    $vendors = array_column($filteredData, 'Vendeur');
    array_multisort($vendors, $sortDirection, $filteredData);
}

// Groupe les données par vendeur
$groupedData = groupByVendor($filteredData);

// Calcule les statistiques
$totalVulnerabilities = count($filteredData);
$totalVendors = count($uniqueVendors);
$highRiskCount = 0;
foreach ($vulnerabilityData as $vuln) {
    if (formatConfidenceScore($vuln['Score de Confiance (★%)']) >= 80) {
        $highRiskCount++;
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prédictions de Vulnérabilités IoT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background-color: #f8f9fa;
            font-family: Arial, sans-serif;
            color: #333;
            line-height: 1.6;
        }
        
        .page-title {
            font-size: 22px;
            margin: 0;
            font-weight: 600;
        }
        
        .breadcrumb {
            background-color: transparent !important;
            margin-bottom: 0;
            padding: 0;
        }
        
        .breadcrumb-item {
            font-size: 14px;
        }
        
        .stat-card {
            border: none;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        .stat-card .card-header {
            background-color: #004085;
            color: white;
            font-weight: bold;
        }
        
        .stat-card .card-body {
            font-size: 24px;
            font-weight: bold;
            padding: 15px;
            text-align: center;
        }
        
        .filter-section {
            margin-bottom: 20px;
        }
        
        .table-fixed {
            table-layout: fixed;
        }
        
        .vendor-section {
            margin-bottom: 30px;
        }
        
        .vendor-title {
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 10px;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .vendor-title h3 {
            margin: 0;
        }
        
        .vulnerability-count {
            background-color: #004085;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .details-section {
            background-color: #f8f9fa;
            padding: 15px;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            margin-top: 10px;
        }
        
        .detail-title {
            font-weight: bold;
            margin-bottom: 5px;
            color: #004085;
        }
        
        .attack-scenario {
            background-color: #fff3cd;
            padding: 10px;
            border-left: 4px solid #ffc107;
            margin-top: 5px;
        }
        
        .related-cve {
            background-color: #d1ecf1;
            padding: 10px;
            border-left: 4px solid #17a2b8;
            margin-top: 5px;
        }
        
        .badge-score {
            font-size: 85%;
            padding: 5px 8px;
            border-radius: 4px;
        }
        
        .badge-high {
            background-color: #dc3545;
            color: white;
        }
        
        .badge-medium {
            background-color: #fd7e14;
            color: white;
        }
        
        .badge-low {
            background-color: #28a745;
            color: white;
        }
        
        .action-button {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            color: #004085;
            padding: 4px 8px;
            font-size: 14px;
            cursor: pointer;
            border-radius: 4px;
        }
        
        .action-button:hover {
            background-color: #004085;
            color: white;
            border-color: #004085;
        }
        
        .clickable-row {
            cursor: pointer;
        }
        
        .clickable-row:hover {
            background-color: #f2f2f2;
        }
        
        .table-container {
            border: 1px solid #dee2e6;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 20px;
        }
        
        .footer {
            background-color: #f8f9fa;
            border-top: 1px solid #dee2e6;
            padding: 20px 0;
            margin-top: 40px;
            text-align: center;
            color: #6c757d;
        }
        
        @media (max-width: 768px) {
            .vendor-title {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .vulnerability-count {
                margin-top: 5px;
            }
        }
    </style>
</head>
<body>
<!-- Header --> 
<div class="container mt-4 mb-4">
    <div class="card">
        <div class="card-header bg-primary text-white">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <h1 class="page-title">Prédictions de Vulnérabilités IoT</h1>
                </div>
                <div class="col-md-6 text-md-end">
                    <div class="d-flex justify-content-end align-items-center">
                        <nav aria-label="breadcrumb" class="me-3">
                            <ol class="breadcrumb justify-content-md-end mb-0">
                                <li class="breadcrumb-item active text-white-50">Page D'accueil</li>
                            </ol>
                        </nav>
                        <a href="0-Accuille.php" class="btn btn-sm btn-outline-light">
                            <i class="fas fa-arrow-left"></i> Retour
                        </a>
                    </div>
                </div>
            </div>
        </div>
        <div class="card-body bg-light">
            <p class="mb-0">
                <i class="fas fa-info-circle text-primary me-2"></i>
                Cette page présente des prédictions de vulnérabilités potentielles qui pourraient affecter les appareils IoT de différents fabricants.
                Ces analyses sont basées sur l'étude des tendances historiques, des composants matériels/logiciels et des vulnérabilités similaires déjà découvertes.
                Les scores de confiance indiquent la probabilité que ces vulnérabilités existent réellement.
            </p>
            
            <div class="mt-4 p-3 border rounded bg-white">
                <div class="d-flex justify-content-between align-items-center" role="button" data-bs-toggle="collapse" href="#collapseScoreInfo" aria-expanded="false" aria-controls="collapseScoreInfo" style="cursor: pointer;">
                    <h5 class="text-primary mb-0"><i class="fas fa-balance-scale me-2"></i>Score de Confiance et Précision : Comprendre le principe</h5>
                    <button class="btn btn-sm btn-outline-primary">
                        <i class="fas fa-chevron-down" id="toggleIcon"></i>
                    </button>
                </div>
                
                <div class="collapse mt-3" id="collapseScoreInfo">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <h6 class="text-primary"><i class="fas fa-chart-line me-2"></i>Score de Confiance (★%)</h6>
                                <p class="mb-2"><strong>C'est quoi ?</strong> Une estimation théorique de la probabilité qu'une vulnérabilité existe.</p>
                                <p class="mb-2"><strong>Sur quoi ça se base ?</strong></p>
                                <ul>
                                    <li>Similarité avec des failles connues (CVE)</li>
                                    <li>Ancienneté des composants (logiciels obsolètes = risque ↑)</li>
                                    <li>Historique du vendeur (nombre de failles récentes)</li>
                                    <li>Existence d'un PoC (Preuve d'exploitation)</li>
                                </ul>
                                <p class="mb-0"><strong>À quoi ça sert ?</strong></p>
                                <ul>
                                    <li>Identifier les risques <em>potentiels</em>.</li>
                                    <li>Prioriser les analyses techniques.</li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <div class="mb-3">
                                <h6 class="text-primary"><i class="fas fa-check-circle me-2"></i>Précision (%)</h6>
                                <p class="mb-2"><strong>C'est quoi ?</strong> La fiabilité <em>réelle</em> de la prédiction, ajustée selon la qualité des sources.</p>
                                <p class="mb-2"><strong>Sur quoi ça se base ?</strong></p>
                                <p><strong>Score de Confiance</strong> × <strong>Fiabilité de la Source</strong> :</p>
                                <ul>
                                    <li>NVD/CVE officielle : 90%</li>
                                    <li>ExploitDB (PoC vérifié) : 85%</li>
                                    <li>GitHub (non vérifié) : 60%</li>
                                </ul>
                                <p class="mb-0"><strong>À quoi ça sert ?</strong></p>
                                <ul>
                                    <li>Éviter les faux positifs.</li>
                                    <li>Savoir <em>à quel point</em> on peut faire confiance à l'alerte.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-3 pt-2 border-top">
                        <div class="row">
                            <div class="col-12">
                                <h6 class="text-primary"><i class="fas fa-question-circle me-2"></i>Pourquoi les Deux Métriques ?</h6>
                                <div class="row mt-2">
                                    <div class="col-md-4 mb-2 mb-md-0">
                                        <div class="card h-100 border-primary">
                                            <div class="card-header bg-primary text-white py-1 px-2">
                                                <strong>1. Équilibre</strong>
                                            </div>
                                            <div class="card-body py-2 px-2">
                                                Le Score de Confiance donne une <em>hypothèse</em>, la Précision la <em>corrige</em> avec des faits.
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-4 mb-2 mb-md-0">
                                        <div class="card h-100 border-primary">
                                            <div class="card-header bg-primary text-white py-1 px-2">
                                                <strong>2. Décision</strong>
                                            </div>
                                            <div class="card-body py-2 px-2">
                                                Une précision >70% justifie un correctif ; en dessous, on approfondit.
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="card h-100 border-primary">
                                            <div class="card-header bg-primary text-white py-1 px-2">
                                                <strong>3. Transparence</strong>
                                            </div>
                                            <div class="card-body py-2 px-2">
                                                Montre clairement la marge d'erreur.
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

    <!-- Main Content -->
    <div class="container">
        <!-- Back Button -->
        <div class="mb-4">

        </div>
        
        <?php if (isset($error)): ?>
            <!-- Error Message -->
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-exclamation-circle"></i> <?php echo $error; ?>
            </div>
        <?php else: ?>
            <!-- Statistics Row -->
            <div class="row mb-4">
                <div class="col-md-4 mb-3">
                    <div class="card stat-card">
                        <div class="card-header text-center">
                            Vulnérabilités prédites
                        </div>
                        <div class="card-body">
                            <?php echo $totalVulnerabilities; ?>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card stat-card">
                        <div class="card-header text-center">
                            Vendeurs affectés
                        </div>
                        <div class="card-body">
                            <?php echo $totalVendors; ?>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card stat-card">
                        <div class="card-header text-center">
                            Risques élevés (≥80%)
                        </div>
                        <div class="card-body">
                            <?php echo $highRiskCount; ?>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Filters Section -->
            <div class="card filter-section">
                <div class="card-header bg-light">
                    <h5 class="mb-0">Filtrer les résultats</h5>
                </div>
                <div class="card-body">
                    <form action="" method="get" class="row g-3">
                        <div class="col-md-4">
                            <label for="vendor" class="form-label">Vendeur:</label>
                            <select name="vendor" id="vendor" class="form-select">
                                <option value="all" <?php echo $selectedVendor === 'all' ? 'selected' : ''; ?>>Tous les vendeurs</option>
                                <?php foreach ($uniqueVendors as $vendor): ?>
                                    <option value="<?php echo htmlspecialchars($vendor); ?>" <?php echo $selectedVendor === $vendor ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($vendor); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label for="sort" class="form-label">Trier par:</label>
                            <select name="sort" id="sort" class="form-select">
                                <option value="score" <?php echo $sortBy === 'score' ? 'selected' : ''; ?>>Score de confiance</option>
                                <option value="date" <?php echo $sortBy === 'date' ? 'selected' : ''; ?>>Date prédite</option>
                                <option value="vendor" <?php echo $sortBy === 'vendor' ? 'selected' : ''; ?>>Vendeur</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label for="direction" class="form-label">Ordre:</label>
                            <select name="direction" id="direction" class="form-select">
                                <option value="desc" <?php echo $sortDirection === SORT_DESC ? 'selected' : ''; ?>>Décroissant</option>
                                <option value="asc" <?php echo $sortDirection === SORT_ASC ? 'selected' : ''; ?>>Croissant</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label class="form-label" style="visibility: hidden;">Appliquer</label>
                            <button type="submit" class="btn btn-primary w-100">Filtrer</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Vulnerability Data -->
            <?php if (empty($groupedData)): ?>
                <!-- No Results -->
                <div class="alert alert-info mt-4" role="alert">
                    <i class="fas fa-info-circle"></i> Aucune vulnérabilité trouvée pour les critères sélectionnés.
                </div>
            <?php else: ?>
                <!-- Table View by Vendor -->
                <?php foreach ($groupedData as $vendeur => $vulnerabilities): ?>
                    <div class="vendor-section mt-4">
                        <div class="vendor-title">
                            <h3><i class="fas fa-building text-primary"></i> <?php echo htmlspecialchars($vendeur); ?></h3>
                            <span class="vulnerability-count">
                                <?php echo count($vulnerabilities); ?> vulnérabilité<?php echo count($vulnerabilities) > 1 ? 's' : ''; ?>
                            </span>
                        </div>
                        
                        <div class="table-container">
                            <table class="table table-striped table-hover mb-0 table-fixed">
                                <thead class="table-light">
                                    <tr>
                                        <th style="width: 25%">Produit & Version</th>
                                        <th style="width: 20%">Type de vulnérabilité</th>
                                        <th style="width: 15%">Date prédite</th>
                                        <th style="width: 15%">Score de confiance</th>
                                        <th style="width: 10%">Précision</th>
                                        <th style="width: 15%">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php $rowCounter = 0; ?>
                                    <?php foreach ($vulnerabilities as $vulnerability): ?>
                                        <?php 
                                        $rowId = str_replace(' ', '_', $vendeur) . '-' . $rowCounter; 
                                        $scoreClass = getScoreClass($vulnerability['Score de Confiance (★%)']);
                                        $score = formatConfidenceScore($vulnerability['Score de Confiance (★%)']);
                                        $badgeClass = 'badge-low';
                                        if ($score >= 80) {
                                            $badgeClass = 'badge-high';
                                        } elseif ($score >= 70) {
                                            $badgeClass = 'badge-medium';
                                        }
                                        ?>
                                        <tr class="clickable-row" data-id="<?php echo $rowId; ?>">
                                            <td>
                                                <strong><?php echo htmlspecialchars($vulnerability['Produit Vulnérable']); ?></strong><br>
                                                <small class="text-muted"><?php echo htmlspecialchars($vulnerability['Version Firmware']); ?></small>
                                            </td>
                                            <td><?php echo htmlspecialchars($vulnerability['Type Vulnérabilité']); ?></td>
                                            <td><?php echo htmlspecialchars($vulnerability['Date Prédite (MM/AAAA)']); ?></td>
                                            <td>
                                                <span class="badge-score <?php echo $badgeClass; ?>">
                                                    <?php echo htmlspecialchars($vulnerability['Score de Confiance (★%)']); ?>
                                                </span>
                                            </td>
                                            <td><?php echo htmlspecialchars($vulnerability['Précision']); ?></td>
                                            <td>
                                                <button class="btn btn-sm btn-outline-primary" id="btn-<?php echo $rowId; ?>" onclick="toggleDetails('<?php echo $rowId; ?>')">
                                                    <i class="fas fa-info-circle"></i> Détails
                                                </button>
                                            </td>
                                        </tr>
                                        <tr id="details-row-<?php echo $rowId; ?>" class="d-none">
                                            <td colspan="6">
                                                <div class="details-section">
                                                    <div class="mb-3">
                                                        <div class="detail-title"><i class="fas fa-file-alt"></i> Description technique:</div>
                                                        <div><?php echo htmlspecialchars($vulnerability['Description Technique']); ?></div>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <div class="detail-title"><i class="fas fa-user-ninja"></i> Scénario d'attaque:</div>
                                                        <div class="attack-scenario">
                                                            <?php echo htmlspecialchars($vulnerability['Scénario d\'Attaque']); ?>
                                                        </div>
                                                    </div>
                                                    
                                                    <div>
                                                        <div class="detail-title"><i class="fas fa-shield-alt"></i> CVE Similaire:</div>
                                                        <div class="related-cve">
                                                            <?php echo htmlspecialchars($vulnerability['CVE Similaire']); ?>
                                                        </div>
                                                    </div>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php $rowCounter++; ?>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        <?php endif; ?>
    </div>
    
    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <p class="mb-0">© <?php echo date('Y'); ?> - Prédictions de Vulnérabilités IoT - Tous droits réservés</p>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function toggleDetails(rowId) {
            const detailsRow = document.getElementById('details-row-' + rowId);
            const button = document.getElementById('btn-' + rowId);
            
            if (detailsRow.classList.contains('d-none')) {
                detailsRow.classList.remove('d-none');
                button.innerHTML = '<i class="fas fa-times-circle"></i> Fermer';
            } else {
                detailsRow.classList.add('d-none');
                button.innerHTML = '<i class="fas fa-info-circle"></i> Détails';
            }
        }
        
        // Rendre les lignes cliquables
        document.addEventListener('DOMContentLoaded', function() {
            const clickableRows = document.querySelectorAll('.clickable-row');
            
            clickableRows.forEach(row => {
                row.addEventListener('click', function(e) {
                    // Éviter de déclencher si on clique sur le bouton
                    if (e.target.tagName !== 'BUTTON' && !e.target.closest('button')) {
                        const rowId = this.getAttribute('data-id');
                        toggleDetails(rowId);
                    }
                });
            });
        });

        // Ajouter ce script à la fin de la page, juste avant la fermeture du tag body
document.addEventListener('DOMContentLoaded', function() {
    // Récupération des éléments
    const toggleBtn = document.querySelector('[data-bs-toggle="collapse"]');
    const toggleIcon = document.getElementById('toggleIcon');
    const collapseElement = document.getElementById('collapseScoreInfo');
    
    // Fonction pour changer l'icône
    function updateIcon(isExpanded) {
        if (isExpanded) {
            toggleIcon.classList.remove('fa-chevron-down');
            toggleIcon.classList.add('fa-chevron-up');
        } else {
            toggleIcon.classList.remove('fa-chevron-up');
            toggleIcon.classList.add('fa-chevron-down');
        }
    }
    
    // Écouter l'événement de clic
    toggleBtn.addEventListener('click', function() {
        const isExpanded = toggleBtn.getAttribute('aria-expanded') === 'true';
        updateIcon(!isExpanded);
    });
    
    // Écouter les événements Bootstrap collapse
    collapseElement.addEventListener('shown.bs.collapse', function() {
        updateIcon(true);
    });
    
    collapseElement.addEventListener('hidden.bs.collapse', function() {
        updateIcon(false);
    });
});
    </script>
</body>
</html>