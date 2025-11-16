<?php

session_start();
ini_set('memory_limit', '1024M');
require 'vendor/autoload.php';

// Fonction pour formater les nombres avec séparateur de milliers
function formatNumber($number) {
    return number_format($number, is_int($number) ? 0 : 1, ',', ' ');
}

// Rediriger vers la page de recherche si le formulaire n'a pas été soumis
if ($_SERVER['REQUEST_METHOD'] !== 'POST' && !isset($_SESSION['search_filters']) && empty($_GET['filtre_valeur']) && empty($_GET['page'])) {
    header('Location: 9-recherche_avanc.php');
    exit;
}

// Récupérer les filtres depuis la session, le POST ou le GET
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $filters = [
        'product' => isset($_POST['product']) ? trim($_POST['product']) : '',
        'vendor' => isset($_POST['vendor']) ? $_POST['vendor'] : [],
        'family' => isset($_POST['family']) ? $_POST['family'] : [],
        'category' => isset($_POST['category']) ? $_POST['category'] : [],
        'cve_id' => isset($_POST['cve_id']) ? trim($_POST['cve_id']) : '',
        'severity' => isset($_POST['severity']) ? $_POST['severity'] : '',
        'fix_time_min' => isset($_POST['fix_time_min']) ? $_POST['fix_time_min'] : '',
        'fix_time_max' => isset($_POST['fix_time_max']) ? $_POST['fix_time_max'] : '',
        'cvss_score_min' => isset($_POST['cvss_score_min']) ? $_POST['cvss_score_min'] : '',
        'cvss_score_max' => isset($_POST['cvss_score_max']) ? $_POST['cvss_score_max'] : '',
        'cwe_category' => isset($_POST['cwe_category']) ? $_POST['cwe_category'] : []
    ];
    // Sauvegarder les filtres dans la session pour la pagination
    $_SESSION['search_filters'] = $filters;
} elseif (isset($_GET['filtre_type']) && isset($_GET['filtre_valeur'])) {
    // Traiter les filtres de la barre de recherche au-dessus du tableau
    $filtre_type = $_GET['filtre_type'];
    $filtre_valeur = trim($_GET['filtre_valeur']);
    
    // Si on a déjà des filtres dans la session, on les récupère
    if (isset($_SESSION['search_filters'])) {
        $filters = $_SESSION['search_filters'];
    } else {
        // Sinon on initialise un tableau vide
        $filters = [
            'product' => '',
            'vendor' => [],
            'family' => [],
            'category' => [],
            'cve_id' => '',
            'severity' => '',
            'fix_time_min' => '',
            'fix_time_max' => '',
            'cvss_score_min' => '',
            'cvss_score_max' => '',
            'cwe_category' => []
        ];
    }
    
    // On met à jour le filtre correspondant
    switch ($filtre_type) {
        case 'produit':
            $filters['product'] = $filtre_valeur;
            break;
        case 'vendor':
            $filters['vendor'] = [$filtre_valeur]; // on met dans un tableau car vendor est attendu comme un tableau
            break;
        case 'cve':
            $filters['cve_id'] = $filtre_valeur;
            break;
        case 'categorie':
            $filters['cwe_category'] = [$filtre_valeur]; // on met dans un tableau car cwe_category est attendu comme un tableau
            break;
    }
    
    // On met à jour la session
    $_SESSION['search_filters'] = $filters;
} else {
    // Si on vient de la pagination, on récupère les filtres de la session
    $filters = isset($_SESSION['search_filters']) ? $_SESSION['search_filters'] : [
        'product' => '',
        'vendor' => [],
        'family' => [],
        'category' => [],
        'cve_id' => '',
        'severity' => '',
        'fix_time_min' => '',
        'fix_time_max' => '',
        'cvss_score_min' => '',
        'cvss_score_max' => '',
        'cwe_category' => []
    ];
}

// Configuration de la pagination
$results_per_page = 25; // Nombre de résultats par page
$current_page = isset($_GET['page']) ? intval($_GET['page']) : 1;

// Récupérer l'année analysée depuis la session
$annee_analysee = isset($_SESSION['current_log']['annee']) ? $_SESSION['current_log']['annee'] : '2024'; // Valeur par défaut si non définie

// Utiliser l'année dans le chemin du fichier
$csv_file = '/Users/abderaoufbouhali/PycharmProjects/Mémoire/produit/' . $annee_analysee . '/7-catégorie_cwe_name.csv';
// Chemin vers le fichier CSV

/**
 * Fonction principale pour rechercher les vulnérabilités dans le fichier CSV
 */
function searchVulnerabilities($file, $filters) {
    $results = [];
    $total_count = 0;
    
    if (file_exists($file) && ($handle = fopen($file, "r")) !== FALSE) {
        $header = fgetcsv($handle, 0, ",", "\"", "\\");
        $column_indices = array_flip($header);
        
        while (($data = fgetcsv($handle, 0, ",", "\"", "\\")) !== FALSE) {
            $total_count++;
            $match = true;
            
            // Application des filtres
            if (!empty($filters['product']) && stripos($data[$column_indices['Product']], $filters['product']) === false) {
                $match = false;
            }
            
            if (!empty($filters['vendor']) && !in_array($data[$column_indices['Vendor']], $filters['vendor'])) {
                $match = false;
            }
            
            if (!empty($filters['family']) && !in_array($data[$column_indices['Family']], $filters['family'])) {
                $match = false;
            }
            
            if (!empty($filters['category']) && !in_array($data[$column_indices['Category']], $filters['category'])) {
                $match = false;
            }
            
            if (!empty($filters['cve_id']) && stripos($data[$column_indices['CVE_ID']], $filters['cve_id']) === false) {
                $match = false;
            }
            
            if (!empty($filters['severity']) && $data[$column_indices['Severity']] !== $filters['severity']) {
                $match = false;
            }
            
            $fix_time = floatval($data[$column_indices['Temps_de_correction']]);
            if (!empty($filters['fix_time_min']) && $fix_time < floatval($filters['fix_time_min'])) {
                $match = false;
            }
            if (!empty($filters['fix_time_max']) && $fix_time > floatval($filters['fix_time_max'])) {
                $match = false;
            }
            
            $cvss_score = floatval($data[$column_indices['CVSSv3_Score']]);
            if (!empty($filters['cvss_score_min']) && $cvss_score < floatval($filters['cvss_score_min'])) {
                $match = false;
            }
            if (!empty($filters['cvss_score_max']) && $cvss_score > floatval($filters['cvss_score_max'])) {
                $match = false;
            }
            
            if (!empty($filters['cwe_category']) && !in_array($data[$column_indices['Categorie_CWE']], $filters['cwe_category'])) {
                $match = false;
            }
            
            if ($match) {
                $results[] = array_combine($header, $data);
            }
        }
        fclose($handle);
    }
    
    return [
        'results' => $results,
        'total_count' => $total_count,
        'filtered_count' => count($results)
    ];
}

// Gestion de l'exportation Excel
if (isset($_GET['export']) && $_GET['export'] === 'excel') {
    // Vérifier si PhpSpreadsheet est installé
    if (!class_exists('PhpOffice\PhpSpreadsheet\Spreadsheet')) {
        // Si PhpSpreadsheet n'est pas installé, afficher un message d'erreur
        echo "La bibliothèque PhpSpreadsheet n'est pas installée. Veuillez l'installer avec Composer.";
        exit;
    }
    
    // Récupérer les données filtrées
    $export_results = searchVulnerabilities($csv_file, $filters);
    $export_data = $export_results['results'];
    
    // Créer un nouveau fichier Excel
    $spreadsheet = new \PhpOffice\PhpSpreadsheet\Spreadsheet();
    $sheet = $spreadsheet->getActiveSheet();
    $sheet->setTitle('Vulnérabilités');
    
    // Définir les en-têtes
    $headers = ['Produit', 'Vendeur', 'CVE ID', 'Sévérité', 'Score CVSS', 'Temps de correction (jours)', 'Catégorie CWE'];
    $sheet->fromArray($headers, NULL, 'A1');
    
    // Mettre en forme les en-têtes
    $headerStyle = [
        'font' => [
            'bold' => true,
            'color' => ['rgb' => 'FFFFFF'],
        ],
        'fill' => [
            'fillType' => \PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID,
            'startColor' => ['rgb' => '000000'],
        ],
        'alignment' => [
            'horizontal' => \PhpOffice\PhpSpreadsheet\Style\Alignment::HORIZONTAL_CENTER,
        ],
    ];
    $sheet->getStyle('A1:G1')->applyFromArray($headerStyle);
    
    // Ajouter les données
    $row = 2; // Commencer à la ligne 2 (après les en-têtes)
    foreach ($export_data as $vuln) {
        $sheet->setCellValue('A' . $row, isset($vuln['Product']) ? $vuln['Product'] : '');
        $sheet->setCellValue('B' . $row, isset($vuln['Vendor']) ? $vuln['Vendor'] : '');
        $sheet->setCellValue('C' . $row, isset($vuln['CVE_ID']) ? $vuln['CVE_ID'] : '');
        $sheet->setCellValue('D' . $row, isset($vuln['Severity']) ? $vuln['Severity'] : '');
        $sheet->setCellValue('E' . $row, isset($vuln['CVSSv3_Score']) ? $vuln['CVSSv3_Score'] : '');
        $sheet->setCellValue('F' . $row, isset($vuln['Temps_de_correction']) ? $vuln['Temps_de_correction'] : '');
        $sheet->setCellValue('G' . $row, isset($vuln['Categorie_CWE']) && !empty($vuln['Categorie_CWE']) ? $vuln['Categorie_CWE'] : 'Pas disponible');
        
        // Appliquer des styles conditionnels selon la sévérité
        if (isset($vuln['Severity'])) {
            $severity = strtolower($vuln['Severity']);
            $colorCell = '';
            
            if ($severity == 'critical' || $severity == 'critique') {
                $colorCell = 'FF9999'; // Rouge clair
            } else if ($severity == 'high' || $severity == 'haute' || $severity == 'élevée') {
                $colorCell = 'FFCC99'; // Orange clair
            } else if ($severity == 'medium' || $severity == 'moyenne') {
                $colorCell = '99CCFF'; // Bleu clair
            } else if ($severity == 'low' || $severity == 'basse' || $severity == 'faible') {
                $colorCell = '99CC99'; // Vert clair
            }
            
            if (!empty($colorCell)) {
                $sheet->getStyle('D' . $row)->applyFromArray([
                    'fill' => [
                        'fillType' => \PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID,
                        'startColor' => ['rgb' => $colorCell],
                    ],
                    'font' => [
                        'bold' => true,
                    ],
                ]);
            }
        }
        
        $row++;
    }
    
    // Ajuster automatiquement la largeur des colonnes
    foreach(range('A', 'G') as $col) {
        $sheet->getColumnDimension($col)->setAutoSize(true);
    }
    
    // Créer un objet Writer pour sauvegarder le fichier
    $writer = new \PhpOffice\PhpSpreadsheet\Writer\Xlsx($spreadsheet);
    
    // Définir les en-têtes pour le téléchargement
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="vulnerabilites_export_' . date('Y-m-d') . '.xlsx"');
    header('Cache-Control: max-age=0');
    
    // Envoyer le fichier au navigateur
    $writer->save('php://output');
    exit;
}

// Récupérer les données filtrées en utilisant la fonction searchVulnerabilities
$search_results = searchVulnerabilities($csv_file, $filters);
$product_details = $search_results['results'];
$total_items = count($product_details);

// Initialiser les statistiques
$stats = [
    'total_vulnerabilities' => $total_items,
    'avg_cvss_score' => 0,
    'avg_correction_time' => 0,
    'severity_count' => [
        'Critical' => 0,
        'High' => 0,
        'Medium' => 0,
        'Low' => 0
    ],
    'categories' => [] // Pour stocker les catégories de CWE
];

// Calculer des statistiques si des données sont trouvées
if (!empty($product_details)) {
    // Score CVSS moyen
    $total_score = 0;
    $score_count = 0;
    
    // Temps moyen de correction
    $total_correction_time = 0;
    $correction_time_count = 0;
    
    // Tableaux pour stocker les catégories
    $categories = [];
    
    foreach ($product_details as $vuln) {
        // Additionner les scores CVSS
        if (isset($vuln['CVSSv3_Score']) && is_numeric($vuln['CVSSv3_Score'])) {
            $total_score += floatval($vuln['CVSSv3_Score']);
            $score_count++;
        }
        
        // Additionner les temps de correction
        if (isset($vuln['Temps_de_correction']) && is_numeric($vuln['Temps_de_correction'])) {
            $total_correction_time += floatval($vuln['Temps_de_correction']);
            $correction_time_count++;
        }
        
        // Compter par sévérité en normalisant la casse
        if (isset($vuln['Severity'])) {
            $severity = strtolower($vuln['Severity']);
            
            if ($severity == 'critical' || $severity == 'critique') {
                $stats['severity_count']['Critical']++;
            } 
            else if ($severity == 'high' || $severity == 'haute' || $severity == 'élevée') {
                $stats['severity_count']['High']++;
            }
            else if ($severity == 'medium' || $severity == 'moyenne') {
                $stats['severity_count']['Medium']++;
            }
            else if ($severity == 'low' || $severity == 'basse' || $severity == 'faible') {
                $stats['severity_count']['Low']++;
            }
        }
        
        // Compter les catégories CWE
        if (isset($vuln['Categorie_CWE']) && !empty($vuln['Categorie_CWE'])) {
            $categorie = $vuln['Categorie_CWE'];
            if (!isset($categories[$categorie])) {
                $categories[$categorie] = 0;
            }
            $categories[$categorie]++;
        }
    }
    
    // Calculer le score CVSS moyen si des scores sont disponibles
    $stats['avg_cvss_score'] = $score_count > 0 ? 
        round($total_score / $score_count, 2) : 'N/A';
        
    // Calculer le temps moyen de correction (déjà en jours dans le fichier CSV)
    $stats['avg_correction_time'] = $correction_time_count > 0 ? 
        round($total_correction_time / $correction_time_count, 0) : 'N/A';
    
    // Trier et assigner les catégories (top 5)
    arsort($categories);
    $stats['categories'] = array_slice($categories, 0, 5, true);
}

// Pagination
$total_pages = ceil($total_items / $results_per_page);
if ($current_page < 1) $current_page = 1;
if ($current_page > $total_pages && $total_pages > 0) $current_page = $total_pages;

$start_index = ($current_page - 1) * $results_per_page;
$paginated_details = !empty($product_details) ? array_slice($product_details, $start_index, $results_per_page) : [];

// Récupérer le produit, le vendeur, etc. pour l'affichage
$nom_produit = !empty($filters['product']) ? $filters['product'] : '';
$vendor = !empty($filters['vendor']) ? implode(', ', $filters['vendor']) : '';
$severity = !empty($filters['severity']) ? $filters['severity'] : '';
$category = !empty($filters['category']) ? implode(', ', $filters['category']) : '';
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analyse de Vulnérabilités<?php echo !empty($nom_produit) ? ' - ' . htmlspecialchars($nom_produit) : ''; ?></title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 10px;
            color: #333;
            background-color: #f9f9fa;
            font-size: 14px;
        }
        h1, h2, h3 {
            color: #333;
        }
        .container {
            max-width: 1140px;
            margin: 0 auto;
            background-color: #fff;
            padding: 15px;
            box-shadow: 0 0 10px rgba(0,0,0,0.05);
            border-radius: 6px;
        }
        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid #eee;
        }
        .page-header h1 {
            font-size: 18px;
            margin: 0;
        }
        .back-btn {
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            color: #666;
            transition: color 0.2s;
        }
        .back-btn:hover {
            color: #0d6efd;
        }
        .back-btn i {
            margin-right: 5px;
        }
        .stats-cards {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 15px;
        }
        .stats-card {
            flex: 1;
            min-width: 160px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            text-align: center;
            background-color: #f9f9f9;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .stats-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        .stats-card-title {
            font-weight: bold;
            color: #555;
            margin-bottom: 5px;
            font-size: 12px;
            text-transform: uppercase;
        }
        .stats-card-value {
            font-size: 20px;
            font-weight: bold;
            color: #333;
        }
        .vulnerabilities-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
            background-color: white;
            border-radius: 5px;
            overflow: hidden;
            box-shadow: 0 0 5px rgba(0,0,0,0.05);
            border: 1px solid #000;
        }
        .vulnerabilities-table th {
            background-color: #000;
            color: #fff;
            text-align: left;
            padding: 8px;
            border: 1px solid #000;
            font-size: 13px;
            font-weight: 600;
        }
        .vulnerabilities-table td {
            padding: 6px 8px;
            border: 1px solid #000;
            font-size: 13px;
        }
        .vulnerabilities-table tr:hover {
            background-color: #f8f9fa;
        }
        .severity-critical { color: #d9534f; font-weight: bold; }
        .severity-high { color: #f0ad4e; font-weight: bold; }
        .severity-medium { color: #5bc0de; font-weight: bold; }
        .severity-low { color: #5cb85c; font-weight: bold; }
        .severity-blocks {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 15px;
        }
        .severity-block {
            flex: 1;
            min-width: 100px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            text-align: center;
            transition: transform 0.2s;
        }
        .severity-block:hover {
            transform: translateY(-3px);
        }
        .severity-block-critical {
            border-top: 3px solid #d9534f;
            background-color: rgba(217, 83, 79, 0.05);
        }
        .severity-block-high {
            border-top: 3px solid #f0ad4e;
            background-color: rgba(240, 173, 78, 0.05);
        }
        .severity-block-medium {
            border-top: 3px solid #5bc0de;
            background-color: rgba(91, 192, 222, 0.05);
        }
        .severity-block-low {
            border-top: 3px solid #5cb85c;
            background-color: rgba(92, 184, 92, 0.05);
        }
        .severity-count {
            font-size: 18px;
            font-weight: bold;
            margin: 5px 0;
        }
        .severity-label {
            font-weight: bold;
            margin-bottom: 3px;
            font-size: 12px;
            text-transform: uppercase;
        }
        .severity-subtext {
            font-size: 11px;
            color: #777;
        }
        .alert {
            padding: 10px;
            border: 1px solid transparent;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border-color: #f5c6cb;
        }
        h2 {
            background-color: #f8f8f8;
            padding: 8px 10px;
            border-left: 4px solid #0d6efd;
            margin-top: 15px;
            font-size: 16px;
            margin-bottom: 10px;
            border-radius: 0 4px 4px 0;
        }
        .pagination {
            margin-top: 15px;
            display: flex;
            justify-content: center;
        }
        .pagination .page-item .page-link {
            color: #333;
            padding: 4px 12px;
            font-size: 13px;
        }
        .pagination .page-item.active .page-link {
            background-color: #0d6efd;
            border-color: #0d6efd;
            color: white;
        }
        .result-info {
            margin-bottom: 10px;
            font-size: 13px;
            color: #666;
        }
        .no-results {
            text-align: center;
            padding: 30px;
            background-color: #f9f9f9;
            border-radius: 6px;
            color: #666;
            font-size: 16px;
        }
        .no-results i {
            font-size: 40px;
            display: block;
            margin-bottom: 15px;
            color: #ccc;
        }
        footer {
            margin-top: 20px !important;
            padding-top: 10px !important;
        }
        
        /* Style pour les nouveaux graphiques */
        .chart-container {
            width: 100%;
            height: 300px;
            margin-bottom: 20px;
        }
        .category-card {
            flex: 1;
            min-width: 180px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            background-color: #f8f9fa;
        }
        .category-title {
            font-weight: bold;
            font-size: 14px;
            margin-bottom: 5px;
            color: #333;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .category-value {
            font-size: 18px;
            font-weight: bold;
            color: #0d6efd;
        }
        .chart-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            font-size: 12px;
        }
        .legend-color {
            width: 12px;
            height: 12px;
            margin-right: 5px;
            border-radius: 2px;
        }
        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }
        
        /* Formulaire de recherche */
        .search-form {
            margin-bottom: 20px;
            padding: 15px;
            background-color: #f8f8f8;
            border-radius: 5px;
            border: 1px solid #ddd;
        }
        .search-form .form-group {
            margin-bottom: 0;
        }
        
        /* Style pour la barre de recherche au-dessus du tableau */
        .table-search {
            margin-bottom: 15px;
            padding: 10px;
            background-color: #f8f8f8;
            border-radius: 5px;
            border: 1px solid #ddd;
        }
        
        /* Style pour le bouton détails */
        .btn-details {
            padding: 2px 5px;
            font-size: 12px;
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
            margin-left: 3px;
            font-size: 0.8rem;
        }

        .product-link:hover .bi-search {
            opacity: 1;
        }
    </style>
</head>
<body>

    <div class="container">
        <!-- En-tête de page avec navigation -->
        <div class="page-header">
            <h1><i class="bi bi-shield-lock me-2"></i> Analyse des Vulnérabilités</h1>
            <a href="9-recherche_avanc.php" class="back-btn">
                <i class="bi bi-arrow-left"></i> Accueil
            </a>
        </div>
        <?php
// Affichage des filtres actifs s'il y en a
if (!empty(array_filter($filters))) {
    echo '<div class="filters-summary" style="background:#fdfdfd;border:1px solid #e0e0e0;padding:10px 15px;border-radius:8px;margin-bottom:20px;font-family:sans-serif;">';
    echo '<h4 style="font-size:15px;color:#444;margin-bottom:10px;border-left:4px solid #999;padding-left:8px;">Filtres appliqués</h4>';
    echo '<ul style="list-style:none;padding-left:0;margin:0;">';

    foreach ($filters as $key => $value) {
        if (!empty($value)) {
            echo '<li style="margin-bottom:6px;display:flex;align-items:center;">';
            echo '<span style="flex-shrink:0;width:120px;font-weight:600;color:#333;">' . ucfirst(str_replace('_', ' ', $key)) . ' :</span>';
            echo '<span style="color:#666;font-size:14px;">';
            if (is_array($value)) {
                echo implode(', ', array_filter($value));
            } else {
                echo htmlspecialchars($value);
            }
            echo '</span>';
            echo '</li>';
        }
    }

    echo '</ul>';
    echo '</div>';
}
?>
        <?php if (isset($product_details['error'])): ?>
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <p><?php echo $product_details['error']; ?></p>
            </div>
        <?php elseif (!empty($product_details)): ?>
            <?php if (!empty($nom_produit)): ?>
                <h1 class="mb-4">Détails du Produit: <?php echo htmlspecialchars($nom_produit); ?></h1>
            <?php endif; ?>
            
            <!-- Statistiques générales -->
            <h2><i class="bi bi-bar-chart me-2"></i> Statistiques Générales</h2>
            <div class="stats-cards">
                <div class="stats-card">
                    <div class="stats-card-title">Nombre total de vulnérabilités</div>
                    <div class="stats-card-value"><?php echo $stats['total_vulnerabilities']; ?></div>
                </div>
                
                <div class="stats-card">
                    <div class="stats-card-title">Score CVSS moyen</div>
                    <div class="stats-card-value"><?php echo $stats['avg_cvss_score']; ?></div>
                </div>
                
                <div class="stats-card">
                    <div class="stats-card-title">Temps moyen de correction (jours)</div>
                    <div class="stats-card-value"><?php echo $stats['avg_correction_time']; ?></div>
                </div>
            </div>
            
            <!-- Répartition par Sévérité -->
            <h2><i class="bi bi-pie-chart me-2"></i> Répartition par Sévérité</h2>
            <div class="severity-blocks">
                <div class="severity-block severity-block-critical">
                    <div class="severity-label severity-critical">Critique</div>
                    <div class="severity-count"><?php echo $stats['severity_count']['Critical']; ?></div>
                    <div class="severity-subtext">vulnérabilités</div>
                </div>
                
                <div class="severity-block severity-block-high">
                    <div class="severity-label severity-high">Élevée</div>
                    <div class="severity-count"><?php echo $stats['severity_count']['High']; ?></div>
                    <div class="severity-subtext">vulnérabilités</div>
                </div>
                
                <div class="severity-block severity-block-medium">
                    <div class="severity-label severity-medium">Moyenne</div>
                    <div class="severity-count"><?php echo $stats['severity_count']['Medium']; ?></div>
                    <div class="severity-subtext">vulnérabilités</div>
                </div>
                
                <div class="severity-block severity-block-low">
                    <div class="severity-label severity-low">Faible</div>
                    <div class="severity-count"><?php echo $stats['severity_count']['Low']; ?></div>
                    <div class="severity-subtext">vulnérabilités</div>
                </div>
            </div>
            
            <!-- Top Catégories CWE -->
            <?php if (!empty($stats['categories'])): ?>
            <h2><i class="bi bi-tag me-2"></i> Top Vuln Catégories CWE</h2>
            <div class="category-grid">
                <?php foreach($stats['categories'] as $category => $count): ?>
                <div class="category-card">
                    <div class="category-title" title="<?php echo htmlspecialchars($category); ?>">
                        <?php echo htmlspecialchars($category); ?>
                    </div>
                    <div class="category-value"><?php echo $count; ?></div>
                    <div class="severity-subtext">vulnérabilités</div>
                </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
            
            <!-- Liste des Vulnérabilités -->
            <h2><i class="bi bi-list-ul me-2"></i> Liste des Vulnérabilités</h2>
            <?php if ($stats['total_vulnerabilities'] > 0): ?>
                <!-- Information sur les résultats -->
                <div class="result-info d-flex justify-content-between align-items-center">
                    <div>
                        <?php
                        $showing_from = $start_index + 1;
                        $showing_to = min($start_index + $results_per_page, $total_items);
                        ?>
                        <span class="badge bg-secondary"><?php echo $total_items; ?> vulnérabilités</span>
                        <span class="text-muted ms-2">Affichage de <?php echo $showing_from; ?> à <?php echo $showing_to; ?> sur <?php echo $total_items; ?></span>
                    </div>
                    <button id="exportExcelBtn" class="btn btn-sm btn-success" title="Exporter les résultats en Excel">
                        <i class="bi bi-file-earmark-excel me-1"></i> Exporter Excel
                    </button>
                </div>
                
                <!-- Formulaire de recherche simplifié au-dessus du tableau -->
                <div class="table-search">
                    <form method="GET" action="" class="row g-2 align-items-center">
                        <div class="col-md-3">
                            <label for="filtre_type" class="form-label mb-0">Filtrer par:</label>
                            <select class="form-select form-select-sm" name="filtre_type" id="filtre_type">
                                <option value="produit">Produit</option>
                                <option value="vendor">Vendeur</option>
                                <option value="cve">CVE ID</option>
                                <option value="categorie">Catégorie CWE</option>
                            </select>
                        </div>
                        <div class="col-md-7">
                            <label for="filtre_valeur" class="form-label mb-0">Valeur:</label>
                            <input type="text" class="form-control form-control-sm" id="filtre_valeur" name="filtre_valeur" placeholder="Rechercher...">
                        </div>
                        <div class="col-md-2">
                            <label class="form-label mb-0">&nbsp;</label>
                            <button type="submit" class="btn btn-sm btn-primary w-100">Rechercher</button>
                        </div>
                    </form>
                </div>
                
                <!-- Modification du tableau pour ajouter des liens Google uniquement aux produits -->
<table class="vulnerabilities-table">
    <thead>
        <tr>
            <th>Produit</th>
            <th>Vendeur</th>
            <th>CVE ID</th>
            <th>Sévérité</th>
            <th>Score CVSS</th>
            <th>Temps de correction</th>
            <th>Catégorie CWE</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach($paginated_details as $vuln): ?>
        <tr>
            <td>
                <?php if (isset($vuln['Product']) && !empty($vuln['Product'])): ?>
                    <a href="https://www.google.com/search?q=<?= urlencode($vuln['Product'] . ' ' . $vuln['Vendor'] . ' vulnerabilities description') ?>" 
                       target="_blank" 
                       class="product-link"
                       title="Rechercher ce produit sur Google">
                        <?= htmlspecialchars($vuln['Product']) ?>
                        <i class="bi bi-search text-primary"></i>
                    </a>
                <?php else: ?>
                    Non spécifié
                <?php endif; ?>
            </td>
            <td><?php echo isset($vuln['Vendor']) ? htmlspecialchars($vuln['Vendor']) : ''; ?></td>
            <td><?php echo isset($vuln['CVE_ID']) ? htmlspecialchars($vuln['CVE_ID']) : ''; ?></td>
            <td class="severity-<?php echo isset($vuln['Severity']) ? strtolower($vuln['Severity']) : ''; ?>">
                <?php echo isset($vuln['Severity']) ? htmlspecialchars($vuln['Severity']) : ''; ?>
            </td>
            <td><?php echo isset($vuln['CVSSv3_Score']) ? htmlspecialchars($vuln['CVSSv3_Score']) : ''; ?></td>
            <td><?php echo isset($vuln['Temps_de_correction']) ? htmlspecialchars($vuln['Temps_de_correction']) : ''; ?></td>
            <td><?php echo (isset($vuln['Categorie_CWE']) && !empty($vuln['Categorie_CWE'])) ? htmlspecialchars($vuln['Categorie_CWE']) : 'Pas disponible'; ?></td>
            <td>
                <?php if (isset($vuln['CVE_ID']) && !empty($vuln['CVE_ID'])): ?>
                    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=<?php echo urlencode($vuln['CVE_ID']); ?>" 
                       class="btn btn-sm btn-primary btn-details" 
                       target="_blank" 
                       title="Voir les détails sur le site MITRE CVE">
                        <i class="bi bi-info-circle"></i> Détails
                    </a>
                <?php endif; ?>
            </td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>
                
                <!-- Pagination -->
                <?php if ($total_pages > 1): ?>
                <nav aria-label="Pagination">
                    <ul class="pagination">
                        <li class="page-item <?php echo ($current_page <= 1) ? 'disabled' : ''; ?>">
                            <a class="page-link" href="?page=<?php echo $current_page - 1; ?><?php echo !empty($_GET['filtre_type']) && !empty($_GET['filtre_valeur']) ? '&filtre_type=' . urlencode($_GET['filtre_type']) . '&filtre_valeur=' . urlencode($_GET['filtre_valeur']) : ''; ?>" aria-label="Précédent">
                                <span aria-hidden="true">&laquo;</span>
                            </a>
                        </li>
                        
                        <?php
                        $start_page = max(1, $current_page - 2);
                        $end_page = min($total_pages, $start_page + 4);
                        if ($end_page - $start_page < 4) {
                            $start_page = max(1, $end_page - 4);
                        }
                        
                        // Première page
                        if ($start_page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=1<?php echo !empty($_GET['filtre_type']) && !empty($_GET['filtre_valeur']) ? '&filtre_type=' . urlencode($_GET['filtre_type']) . '&filtre_valeur=' . urlencode($_GET['filtre_valeur']) : ''; ?>">1</a>
                            </li>
                            <?php if ($start_page > 2): ?>
                                <li class="page-item disabled">
                                    <span class="page-link">...</span>
                                </li>
                            <?php endif; ?>
                        <?php endif; ?>
                        
                        <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                            <li class="page-item <?php echo ($i == $current_page) ? 'active' : ''; ?>">
                                <a class="page-link" href="?page=<?php echo $i; ?><?php echo !empty($_GET['filtre_type']) && !empty($_GET['filtre_valeur']) ? '&filtre_type=' . urlencode($_GET['filtre_type']) . '&filtre_valeur=' . urlencode($_GET['filtre_valeur']) : ''; ?>">
                                    <?php echo $i; ?>
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
                                <a class="page-link" href="?page=<?php echo $total_pages; ?><?php echo !empty($_GET['filtre_type']) && !empty($_GET['filtre_valeur']) ? '&filtre_type=' . urlencode($_GET['filtre_type']) . '&filtre_valeur=' . urlencode($_GET['filtre_valeur']) : ''; ?>">
                                    <?php echo $total_pages; ?>
                                </a>
                            </li>
                        <?php endif; ?>
                        
                        <li class="page-item <?php echo ($current_page >= $total_pages) ? 'disabled' : ''; ?>">
                            <a class="page-link" href="?page=<?php echo $current_page + 1; ?><?php echo !empty($_GET['filtre_type']) && !empty($_GET['filtre_valeur']) ? '&filtre_type=' . urlencode($_GET['filtre_type']) . '&filtre_valeur=' . urlencode($_GET['filtre_valeur']) : ''; ?>" aria-label="Suivant">
                                <span aria-hidden="true">&raquo;</span>
                            </a>
                        </li>
                    </ul>
                </nav>
                <?php endif; ?>
                
            <?php else: ?>
                <!-- Affichage quand aucune vulnérabilité n'est trouvée -->
                <div class="no-results">
                    <i class="bi bi-search"></i>
                    <p>Aucune vulnérabilité trouvée pour les critères spécifiés.</p>
                </div>
            <?php endif; ?>
            
        <?php elseif (!empty($nom_produit) || !empty($vendor) || !empty($severity) || !empty($category)): ?>
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <p>Aucune donnée trouvée pour les critères spécifiés. Veuillez modifier vos filtres et réessayer.</p>
            </div>
        <?php else: ?>
            <div class="alert alert-info">
                <i class="bi bi-info-circle-fill me-2"></i>
                <p>Veuillez utiliser les filtres ci-dessus pour rechercher des vulnérabilités. Vous pouvez filtrer par produit, vendeur, sévérité ou catégorie.</p>
            </div>
        <?php endif; ?>
        
        <!-- Footer -->
        <footer class="mt-5 pt-4 border-top text-center text-muted">
            <small>
                <i class="bi bi-shield me-1"></i> Rapport de vulnérabilités - <?php echo date('Y'); ?>
                <?php if (!empty($nom_produit)): ?>
                    <span class="mx-2">|</span> Produit: <?php echo htmlspecialchars($nom_produit); ?>
                <?php endif; ?>
            </small>
        </footer>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Script pour l'exportation -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Bouton d'exportation Excel
            const exportExcelBtn = document.getElementById('exportExcelBtn');
            if (exportExcelBtn) {
                exportExcelBtn.addEventListener('click', function() {
                    // Créer l'URL d'exportation en incluant tous les filtres actuels
                    let exportUrl = window.location.pathname + '?export=excel';
                    
                    // Ajouter les paramètres de filtre existants
                    const urlParams = new URLSearchParams(window.location.search);
                    if (urlParams.has('filtre_type') && urlParams.has('filtre_valeur')) {
                        exportUrl += '&filtre_type=' + encodeURIComponent(urlParams.get('filtre_type'));
                        exportUrl += '&filtre_valeur=' + encodeURIComponent(urlParams.get('filtre_valeur'));
                    }
                    
                    // Rediriger vers l'URL d'exportation
                    window.location.href = exportUrl;
                });
            }
        });
    </script>
</body>
</html>