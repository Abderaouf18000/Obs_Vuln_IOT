<?php if (!empty($nom_produit)): ?>
    <span class="mx-2">|</span> Produit: <?php echo htmlspecialchars($nom_produit); ?>
<?php endif; ?>
</small>
</footer>
</div>

<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html><?php
        session_start();

        // Récupérer l'année analysée depuis la session
        $annee_analysee = isset($_SESSION['current_log']['annee']) ? $_SESSION['current_log']['annee'] : '2024';
        $annee_analysee = isset($_SESSION['current_log']['annee']) ? $_SESSION['current_log']['annee'] : '2024'; // Valeur par défaut si non définie

        // Définir la variable nom_produit (peut être obtenue via GET ou définie manuellement)
        $nom_produit = isset($_GET['produit']) ? $_GET['produit'] : '';
        // Vérifier si nous sommes en mode modal ou page complète
        $is_modal = isset($_GET['modal']) && $_GET['modal'] == '1';

        // Configuration de la pagination
        $results_per_page = 25; // Nombre de résultats par page
        $current_page = isset($_GET['page']) ? intval($_GET['page']) : 1;

        // Chemin vers le fichier CSV - MISE À JOUR avec le nouveau chemin et le nouveau fichier
        $csv_file = '../Python/produit/' . $annee_analysee . '/5-produits_avec_familles_et_cve_severity_tmpc_score_cwe.csv';

        // Fonction pour lire le CSV et extraire les données du produit spécifié
        function getProductDetails($csv_file, $product_name)
        {
            $product_data = [];

            // Vérifier si le fichier existe
            if (!file_exists($csv_file)) {
                return ['error' => 'Le fichier CSV n\'existe pas.'];
            }

            // Ouvrir le fichier en lecture
            if (($handle = fopen($csv_file, "r")) !== FALSE) {
                // Lire l'en-tête
                $header = fgetcsv($handle, 1000, ",", '"', "\\");

                // Trouver l'index de la colonne "Product"
                $product_index = -1;
                foreach ($header as $index => $column_name) {
                    if (strcasecmp($column_name, 'Product') === 0) {
                        $product_index = $index;
                        break;
                    }
                }

                // Si la colonne "Product" n'est pas trouvée, utiliser l'index 1 par défaut
                if ($product_index === -1) {
                    $product_index = 1;
                }

                // Parcourir chaque ligne
                while (($data = fgetcsv($handle, 1000, ",", '"', "\\")) !== FALSE) {
                    // Si le produit correspond à la recherche
                    if (isset($data[$product_index]) && strcasecmp($data[$product_index], $product_name) === 0) {
                        $row = [];
                        for ($i = 0; $i < count($header) && $i < count($data); $i++) {
                            $row[$header[$i]] = $data[$i];
                        }
                        $product_data[] = $row;
                    }
                }
                fclose($handle);
            }

            return $product_data;
        }

        // Récupérer les données du produit
        $product_details = [];
        if (!empty($nom_produit)) {
            $product_details = getProductDetails($csv_file, $nom_produit);
        }

        // Initialiser les statistiques
        $stats = [
            'total_vulnerabilities' => 0,
            'avg_cvss_score' => 0,
            'avg_correction_time' => 0,
            'severity_count' => [
                'Critical' => 0,
                'High' => 0,
                'Medium' => 0,
                'Low' => 0
            ]
        ];

        // Calculer des statistiques si des données sont trouvées
        if (!empty($product_details) && !isset($product_details['error'])) {
            // Nombre total de vulnérabilités
            $stats['total_vulnerabilities'] = count($product_details);

            // Score CVSS moyen - Maintenant nous avons la colonne CVSSv3_Score
            $total_score = 0;
            $score_count = 0;

            // Temps moyen de correction
            $total_correction_time = 0;
            $correction_time_count = 0;

            // Compteurs pour chaque niveau de sévérité
            $critical_count = 0;
            $high_count = 0;
            $medium_count = 0;
            $low_count = 0;

            foreach ($product_details as $vuln) {
                // Additionner les scores CVSS qui sont maintenant directement disponibles
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
                        $critical_count++;
                    } else if ($severity == 'high' || $severity == 'haute' || $severity == 'élevée') {
                        $high_count++;
                    } else if ($severity == 'medium' || $severity == 'moyenne') {
                        $medium_count++;
                    } else if ($severity == 'low' || $severity == 'basse' || $severity == 'faible') {
                        $low_count++;
                    }
                }
            }

            // Calculer le score CVSS moyen si des scores sont disponibles
            $stats['avg_cvss_score'] = $score_count > 0 ?
                round($total_score / $score_count, 2) : 'N/A';

            // Calculer le temps moyen de correction (déjà en jours dans le fichier CSV)
            $stats['avg_correction_time'] = $correction_time_count > 0 ?
                round($total_correction_time / $correction_time_count, 0) : 'N/A';

            // Assigner les compteurs de sévérité
            $stats['severity_count']['Critical'] = $critical_count;
            $stats['severity_count']['High'] = $high_count;
            $stats['severity_count']['Medium'] = $medium_count;
            $stats['severity_count']['Low'] = $low_count;
        }

        // Pagination
        $total_items = count($product_details);
        $total_pages = ceil($total_items / $results_per_page);
        if ($current_page < 1) $current_page = 1;
        if ($current_page > $total_pages && $total_pages > 0) $current_page = $total_pages;

        $start_index = ($current_page - 1) * $results_per_page;
        $paginated_details = !empty($product_details) ? array_slice($product_details, $start_index, $results_per_page) : [];

        // Si nous sommes en mode modal, renvoyer seulement le contenu
        if ($is_modal) {
        ?>
    <div>
        <h1>Analyse des Vulnérabilités pour le Produit: <?php echo htmlspecialchars($nom_produit); ?></h1>

        <?php if (!empty($nom_produit) && !empty($product_details) && !isset($product_details['error'])): ?>
            <h2>Statistiques Générales</h2>
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

            <h2>Répartition par Sévérité</h2>
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

            <h2>Liste des Vulnérabilités (<?php echo $stats['total_vulnerabilities']; ?>)</h2>
            <?php if ($stats['total_vulnerabilities'] > 0): ?>
                <table class="vulnerabilities-table">
                    <tr>
                        <th>Vendeur</th>
                        <th>CVE ID</th>
                        <th>Sévérité</th>
                        <th>Score CVSS</th>
                        <th>Temps de correction</th>
                        <th>Type (CWE)</th>
                    </tr>
                    <?php
                    // Limiter à 10 entrées pour la modal
                    $display_details = array_slice($product_details, 0, 10);
                    foreach ($display_details as $vuln): ?>
                        <tr>
                            <td><?php echo isset($vuln['Vendor']) ? htmlspecialchars($vuln['Vendor']) : ''; ?></td>
                            <td><?php echo isset($vuln['CVE_ID']) ? htmlspecialchars($vuln['CVE_ID']) : ''; ?></td>
                            <td class="severity-<?php echo isset($vuln['Severity']) ? strtolower($vuln['Severity']) : ''; ?>">
                                <?php echo isset($vuln['Severity']) ? htmlspecialchars($vuln['Severity']) : ''; ?>
                            </td>
                            <td><?php echo isset($vuln['CVSSv3_Score']) ? htmlspecialchars($vuln['CVSSv3_Score']) : ''; ?></td>
                            <td><?php echo isset($vuln['Temps_de_correction']) ? htmlspecialchars($vuln['Temps_de_correction']) : ''; ?></td>
                            <td><?php echo isset($vuln['cwe_name']) ? htmlspecialchars($vuln['cwe_name']) : ''; ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>

                <?php if (count($product_details) > 10): ?>
                    <div style="margin-top: 15px; text-align: center;">
                        <a href="2-detail_produit.php?produit=<?php echo urlencode($nom_produit); ?>" class="btn btn-primary btn-sm" target="_blank">
                            Voir toutes les vulnérabilités (<?php echo $stats['total_vulnerabilities']; ?>)
                        </a>
                    </div>
                <?php endif; ?>
            <?php else: ?>
                <p>Aucune vulnérabilité trouvée pour ce produit.</p>
            <?php endif; ?>

        <?php elseif (isset($product_details['error'])): ?>
            <div class="alert alert-danger">
                <p><?php echo $product_details['error']; ?></p>
            </div>
        <?php elseif (!empty($nom_produit)): ?>
            <div class="alert alert-danger">
                <p>Aucune donnée trouvée pour le produit "<?php echo htmlspecialchars($nom_produit); ?>". Veuillez vérifier l'orthographe et réessayer.</p>
            </div>
        <?php else: ?>
            <div class="alert alert-danger">
                <p>Veuillez ajouter le paramètre "produit" à l'URL pour voir les détails (exemple: ?produit=Windows).</p>
            </div>
        <?php endif; ?>
    </div>
<?php
            exit; // Terminer le script ici pour le mode modal
        }

        // Si nous ne sommes pas en mode modal, continuer avec la page HTML complète
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Détails du Produit: <?php echo htmlspecialchars($nom_produit); ?></title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f9f9fa;
        }

        h1,
        h2,
        h3 {
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 25px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.05);
            border-radius: 8px;
        }

        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }

        .page-header h1 {
            font-size: 22px;
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
            gap: 15px;
            margin-bottom: 20px;
        }

        .stats-card {
            flex: 1;
            min-width: 180px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 6px;
            text-align: center;
            background-color: #f9f9f9;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stats-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
        }

        .stats-card-title {
            font-weight: bold;
            color: #555;
            margin-bottom: 8px;
            font-size: 13px;
            text-transform: uppercase;
        }

        .stats-card-value {
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }

        .vulnerabilities-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            background-color: white;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 0 5px rgba(0, 0, 0, 0.05);
        }

        .vulnerabilities-table th {
            background-color: #f2f2f2;
            text-align: left;
            padding: 12px;
            border: 1px solid #ddd;
            font-size: 14px;
            font-weight: 600;
        }

        .vulnerabilities-table td {
            padding: 12px;
            border: 1px solid #ddd;
            font-size: 14px;
        }

        .vulnerabilities-table tr:hover {
            background-color: #f8f9fa;
        }

        .severity-critical {
            color: #d9534f;
            font-weight: bold;
        }

        .severity-high {
            color: #f0ad4e;
            font-weight: bold;
        }

        .severity-medium {
            color: #5bc0de;
            font-weight: bold;
        }

        .severity-low {
            color: #5cb85c;
            font-weight: bold;
        }

        .severity-blocks {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 25px;
        }

        .severity-block {
            flex: 1;
            min-width: 120px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 6px;
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
            font-size: 22px;
            font-weight: bold;
            margin: 10px 0;
        }

        .severity-label {
            font-weight: bold;
            margin-bottom: 5px;
            font-size: 13px;
            text-transform: uppercase;
        }

        .severity-subtext {
            font-size: 12px;
            color: #777;
        }

        .alert {
            padding: 15px;
            border: 1px solid transparent;
            border-radius: 6px;
            margin-bottom: 20px;
        }

        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border-color: #f5c6cb;
        }

        h2 {
            background-color: #f8f8f8;
            padding: 10px 15px;
            border-left: 4px solid #0d6efd;
            margin-top: 25px;
            font-size: 18px;
            margin-bottom: 15px;
            border-radius: 0 6px 6px 0;
        }

        .pagination {
            margin-top: 20px;
            display: flex;
            justify-content: center;
        }

        .pagination .page-item .page-link {
            color: #333;
            padding: 8px 16px;
        }

        .pagination .page-item.active .page-link {
            background-color: #0d6efd;
            border-color: #0d6efd;
            color: white;
        }

        .result-info {
            margin-bottom: 15px;
            font-size: 14px;
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

        /* CSS optimisé pour dézoomer la page de détails produit */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 10px;
            /* Réduit de 20px à 10px */
            color: #333;
            background-color: #f9f9fa;
            font-size: 14px;
            /* Taille de police réduite */
        }

        h1,
        h2,
        h3 {
            color: #333;
        }

        .container {
            max-width: 1140px;
            /* Légèrement plus petit que 1200px */
            margin: 0 auto;
            background-color: #fff;
            padding: 15px;
            /* Réduit de 25px à 15px */
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.05);
            border-radius: 6px;
            /* Légèrement réduit */
        }

        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            /* Réduit de 20px à 15px */
            padding-bottom: 8px;
            /* Réduit de 10px à 8px */
            border-bottom: 1px solid #eee;
        }

        .page-header h1 {
            font-size: 18px;
            /* Réduit de 22px à 18px */
            margin: 0;
        }

        /* Statistiques plus compactes */
        .stats-cards {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            /* Réduit de 15px à 10px */
            margin-bottom: 15px;
            /* Réduit de 20px à 15px */
        }

        .stats-card {
            flex: 1;
            min-width: 160px;
            /* Réduit de 180px à 160px */
            padding: 10px;
            /* Réduit de 15px à 10px */
            border: 1px solid #ddd;
            border-radius: 5px;
            text-align: center;
            background-color: #f9f9f9;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stats-card-title {
            font-weight: bold;
            color: #555;
            margin-bottom: 5px;
            /* Réduit de 8px à 5px */
            font-size: 12px;
            /* Réduit de 13px à 12px */
            text-transform: uppercase;
        }

        .stats-card-value {
            font-size: 20px;
            /* Réduit de 24px à 20px */
            font-weight: bold;
            color: #333;
        }

        /* Réduction de la taille des blocs de gravité */
        .severity-blocks {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            /* Réduit de 15px à 10px */
            margin-bottom: 15px;
            /* Réduit de 25px à 15px */
        }

        .severity-block {
            flex: 1;
            min-width: 100px;
            /* Réduit de 120px à 100px */
            padding: 10px;
            /* Réduit de 15px à 10px */
            border: 1px solid #ddd;
            border-radius: 5px;
            text-align: center;
            transition: transform 0.2s;
        }

        .severity-count {
            font-size: 18px;
            /* Réduit de 22px à 18px */
            font-weight: bold;
            margin: 5px 0;
            /* Réduit de 10px à 5px */
        }

        .severity-label {
            font-weight: bold;
            margin-bottom: 3px;
            /* Réduit de 5px à 3px */
            font-size: 12px;
            /* Réduit de 13px à 12px */
            text-transform: uppercase;
        }

        .severity-subtext {
            font-size: 11px;
            /* Réduit de 12px à 11px */
            color: #777;
        }

        /* Tableau des vulnérabilités plus compact */
        .vulnerabilities-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
            /* Réduit de 20px à 15px */
            background-color: white;
            border-radius: 5px;
            overflow: hidden;
            box-shadow: 0 0 5px rgba(0, 0, 0, 0.05);
            border: 1px solid #000;
            /* Bordure noire comme demandé précédemment */
        }

        .vulnerabilities-table th {
            background-color: #000;
            /* Noir comme demandé précédemment */
            color: #fff;
            text-align: left;
            padding: 8px;
            /* Réduit de 12px à 8px */
            border: 1px solid #000;
            /* Bordure noire */
            font-size: 13px;
            /* Réduit de 14px à 13px */
            font-weight: 600;
        }

        .vulnerabilities-table td {
            padding: 6px 8px;
            /* Réduit de 12px à 6px-8px */
            border: 1px solid #000;
            /* Bordure noire */
            font-size: 13px;
            /* Réduit de 14px à 13px */
        }

        /* Titres de section plus compacts */
        h2 {
            background-color: #f8f8f8;
            padding: 8px 10px;
            /* Réduit de 10px 15px à 8px 10px */
            border-left: 4px solid #0d6efd;
            margin-top: 15px;
            /* Réduit de 25px à 15px */
            font-size: 16px;
            /* Réduit de 18px à 16px */
            margin-bottom: 10px;
            /* Réduit de 15px à 10px */
            border-radius: 0 4px 4px 0;
        }

        /* Pagination plus compacte */
        .pagination {
            margin-top: 15px;
            /* Réduit de 20px à 15px */
        }

        .pagination .page-item .page-link {
            padding: 4px 12px;
            /* Réduit de 8px 16px à 4px 12px */
            font-size: 13px;
        }

        /* Information sur les résultats plus compacte */
        .result-info {
            margin-bottom: 10px;
            /* Réduit de 15px à 10px */
            font-size: 13px;
            /* Réduit de 14px à 13px */
        }

        /* Footer plus compact */
        footer {
            margin-top: 20px !important;
            /* Réduit de mt-5 (3rem) à 20px */
            padding-top: 10px !important;
            /* Réduit de pt-4 (1.5rem) à 10px */
        }

        /* Alerte plus compacte */
        .alert {
            padding: 10px;
            /* Réduit de 15px à 10px */
            margin-bottom: 15px;
            /* Réduit de 20px à 15px */
        }
    </style>
</head>

<body>
    <div class="container">
        <!-- En-tête de page avec navigation -->
        <!-- 1. Ajouter le bouton d'export dans l'en-tête de la page -->
        <div class="page-header">
            <h1><i class="bi bi-shield-lock me-2"></i> Détails du Produit: <?php echo htmlspecialchars($nom_produit); ?></h1>
            <div>
                <button id="export-excel" class="btn btn-success btn-sm me-2">
                    <i class="bi bi-file-excel"></i> Exporter en Excel
                </button>
                <a href="7-liste_produit.php" class="back-btn">
                    <i class="bi bi-arrow-left"></i> Retour à la liste
                </a>
            </div>
        </div>

        <?php if (!empty($nom_produit) && !empty($product_details) && !isset($product_details['error'])): ?>
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

            <!-- Liste des Vulnérabilités -->
            <h2><i class="bi bi-list-ul me-2"></i> Liste des Vulnérabilités</h2>
            <?php if ($stats['total_vulnerabilities'] > 0): ?>
                <!-- Information sur les résultats -->
                <div class="result-info">
                    <?php
                    $showing_from = $start_index + 1;
                    $showing_to = min($start_index + $results_per_page, $total_items);
                    ?>
                    <span class="badge bg-secondary"><?php echo $total_items; ?> vulnérabilités</span>
                    <span class="text-muted ms-2">Affichage de <?php echo $showing_from; ?> à <?php echo $showing_to; ?> sur <?php echo $total_items; ?></span>
                </div>

                <table class="vulnerabilities-table">
                    <thead>
                        <tr>
                            <th>Vendeur</th>
                            <th>CVE ID</th>
                            <th>Sévérité</th>
                            <th>Score CVSS</th>
                            <th>Temps de correction</th>
                            <th>Type (CWE)</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($paginated_details as $vuln): ?>
                            <tr>
                                <td><?php echo isset($vuln['Vendor']) ? htmlspecialchars($vuln['Vendor']) : ''; ?></td>
                                <td><?php echo isset($vuln['CVE_ID']) ? htmlspecialchars($vuln['CVE_ID']) : ''; ?></td>
                                <td class="severity-<?php echo isset($vuln['Severity']) ? strtolower($vuln['Severity']) : ''; ?>">
                                    <?php echo isset($vuln['Severity']) ? htmlspecialchars($vuln['Severity']) : ''; ?>
                                </td>
                                <td><?php echo isset($vuln['CVSSv3_Score']) ? htmlspecialchars($vuln['CVSSv3_Score']) : ''; ?></td>
                                <td><?php echo isset($vuln['Temps_de_correction']) ? htmlspecialchars($vuln['Temps_de_correction']) : ''; ?></td>
                                <td><?php echo isset($vuln['cwe_name']) ? htmlspecialchars($vuln['cwe_name']) : ''; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <!-- Pagination -->
                <?php if ($total_pages > 1): ?>
                    <nav aria-label="Pagination">
                        <ul class="pagination">
                            <li class="page-item <?php echo ($current_page <= 1) ? 'disabled' : ''; ?>">
                                <a class="page-link" href="?produit=<?php echo urlencode($nom_produit); ?>&page=<?php echo $current_page - 1; ?>" aria-label="Précédent">
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
                                    <a class="page-link" href="?produit=<?php echo urlencode($nom_produit); ?>&page=1">1</a>
                                </li>
                                <?php if ($start_page > 2): ?>
                                    <li class="page-item disabled">
                                        <span class="page-link">...</span>
                                    </li>
                                <?php endif; ?>
                            <?php endif; ?>

                            <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                                <li class="page-item <?php echo ($i == $current_page) ? 'active' : ''; ?>">
                                    <a class="page-link" href="?produit=<?php echo urlencode($nom_produit); ?>&page=<?php echo $i; ?>">
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
                                    <a class="page-link" href="?produit=<?php echo urlencode($nom_produit); ?>&page=<?php echo $total_pages; ?>">
                                        <?php echo $total_pages; ?>
                                    </a>
                                </li>
                            <?php endif; ?>

                            <li class="page-item <?php echo ($current_page >= $total_pages) ? 'disabled' : ''; ?>">
                                <a class="page-link" href="?produit=<?php echo urlencode($nom_produit); ?>&page=<?php echo $current_page + 1; ?>" aria-label="Suivant">
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
                    <p>Aucune vulnérabilité trouvée pour ce produit.</p>
                </div>
            <?php endif; ?>

        <?php elseif (isset($product_details['error'])): ?>
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <p><?php echo $product_details['error']; ?></p>
            </div>
        <?php elseif (!empty($nom_produit)): ?>
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <p>Aucune donnée trouvée pour le produit "<?php echo htmlspecialchars($nom_produit); ?>". Veuillez vérifier l'orthographe et réessayer.</p>
            </div>
        <?php else: ?>
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <p>Veuillez ajouter le paramètre "produit" à l'URL pour voir les détails (exemple: ?produit=Windows).</p>
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
    <!-- Ce script doit être placé avant la fermeture de la balise </body> -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Vérifier si le bouton existe déjà
            var existingButton = document.getElementById('export-excel');

            if (existingButton) {
                // Si le bouton existe, simplement remplacer son gestionnaire d'événement
                existingButton.removeEventListener('click', exportExcel);
                existingButton.addEventListener('click', exportExcel);
            } else {
                // Si le bouton n'existe pas, créer un nouveau bouton
                var exportButton = document.createElement('button');
                exportButton.id = 'export-excel';
                exportButton.className = 'btn btn-success btn-sm me-2';
                exportButton.innerHTML = '<i class="bi bi-file-excel"></i> Exporter en Excel';
                exportButton.addEventListener('click', exportExcel);

                // Ajouter le bouton à un emplacement approprié (en-tête, au-dessus du tableau, etc.)
                var targetLocation = document.querySelector('.page-header div');
                if (targetLocation) {
                    targetLocation.prepend(exportButton);
                } else {
                    // Alternative: ajouter juste au-dessus du tableau
                    var tableContainer = document.querySelector('.vulnerabilities-table');
                    if (tableContainer) {
                        tableContainer.parentNode.insertBefore(exportButton, tableContainer);
                    }
                }
            }

            // Fonction pour exporter le tableau en Excel
            function exportExcel() {
                // Créer un nouveau classeur
                var wb = XLSX.utils.book_new();

                // Obtenir le tableau des vulnérabilités
                var table = document.querySelector('.vulnerabilities-table');
                if (!table) {
                    alert("Tableau de vulnérabilités non trouvé!");
                    return;
                }

                // Préparer les données pour Excel
                var data = [];

                // Ajouter l'en-tête
                var headers = [];
                var headerCells = table.querySelectorAll('th');
                headerCells.forEach(function(cell) {
                    headers.push(cell.textContent.trim());
                });
                data.push(headers);

                // Ajouter toutes les lignes visibles du tableau
                var rows = table.querySelectorAll('tbody tr');
                rows.forEach(function(row) {
                    var rowData = [];
                    var cells = row.querySelectorAll('td');
                    cells.forEach(function(cell) {
                        rowData.push(cell.textContent.trim());
                    });
                    data.push(rowData);
                });

                // Créer une feuille avec les données
                var ws = XLSX.utils.aoa_to_sheet(data);

                // Configurer les largeurs de colonnes pour une meilleure lisibilité
                ws['!cols'] = [{
                        width: 20
                    }, // Vendeur
                    {
                        width: 15
                    }, // CVE ID
                    {
                        width: 12
                    }, // Sévérité
                    {
                        width: 12
                    }, // Score CVSS
                    {
                        width: 20
                    }, // Temps de correction
                    {
                        width: 40
                    } // Type (CWE)
                ];

                // Ajouter une feuille pour les données affichées
                XLSX.utils.book_append_sheet(wb, ws, "Vulnérabilités");

                // Si nous voulons exporter toutes les données (pas seulement ce qui est affiché)
                // Créer une seconde feuille contenant toutes les données
                var allData = [
                    ["Vendeur", "CVE ID", "Sévérité", "Score CVSS", "Temps de correction", "Type (CWE)"]
                ];

                <?php if (!empty($product_details) && !isset($product_details['error'])): ?>
                    <?php foreach ($product_details as $vuln): ?>
                        allData.push([
                            "<?php echo isset($vuln['Vendor']) ? addslashes(htmlspecialchars($vuln['Vendor'])) : ''; ?>",
                            "<?php echo isset($vuln['CVE_ID']) ? addslashes(htmlspecialchars($vuln['CVE_ID'])) : ''; ?>",
                            "<?php echo isset($vuln['Severity']) ? addslashes(htmlspecialchars($vuln['Severity'])) : ''; ?>",
                            "<?php echo isset($vuln['CVSSv3_Score']) ? addslashes(htmlspecialchars($vuln['CVSSv3_Score'])) : ''; ?>",
                            "<?php echo isset($vuln['Temps_de_correction']) ? addslashes(htmlspecialchars($vuln['Temps_de_correction'])) : ''; ?>",
                            "<?php echo isset($vuln['cwe_name']) ? addslashes(htmlspecialchars($vuln['cwe_name'])) : ''; ?>"
                        ]);
                    <?php endforeach; ?>
                <?php endif; ?>

                var allDataSheet = XLSX.utils.aoa_to_sheet(allData);

                // Configurer les largeurs de colonnes pour la feuille complète
                allDataSheet['!cols'] = ws['!cols'];

                // Ajouter cette feuille au classeur
                XLSX.utils.book_append_sheet(wb, allDataSheet, "Toutes vulnérabilités");

                // Ajouter une feuille d'informations
                var infoData = [
                    ["Rapport de vulnérabilités pour le produit: <?php echo addslashes(htmlspecialchars($nom_produit)); ?>"],
                    ["Date d'export:", new Date().toLocaleDateString()],
                    ["Nombre total de vulnérabilités:", "<?php echo $stats['total_vulnerabilities']; ?>"],
                    ["Score CVSS moyen:", "<?php echo $stats['avg_cvss_score']; ?>"],
                    ["Temps moyen de correction (jours):", "<?php echo $stats['avg_correction_time']; ?>"]
                ];

                var infoSheet = XLSX.utils.aoa_to_sheet(infoData);
                XLSX.utils.book_append_sheet(wb, infoSheet, "Informations");

                // Générer le nom du fichier
                var fileName = "vulnerabilites_<?php echo preg_replace('/[^a-zA-Z0-9]/', '_', $nom_produit); ?>_" +
                    new Date().toISOString().slice(0, 10) + ".xlsx";

                // Déclencher le téléchargement
                XLSX.writeFile(wb, fileName);

                // Message de confirmation
                alert("Export Excel terminé avec succès!");
            }
        });
    </script>

</body>

</html>