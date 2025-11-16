<?php
/**
 * Script PHP optimisé pour afficher rapidement les détails d'une vulnérabilité (CVE)
 * Support ajouté pour les requêtes AJAX
 * 
 * Utilisation: 
 * - Normal: cve_details.php?cve_id=CVE-XXXX-XXXX
 * - AJAX: cve_details.php?cve_id=CVE-XXXX-XXXX&format=ajax
 */

// Configuration
$csv_file = '/Users/abderaoufbouhali/PycharmProjects/Mémoire/results/30-details_cves_fusion_29-19.csv'; // Chemin vers le fichier CSV
$default_cve = 'CVE-2019-0020'; // CVE par défaut à afficher si aucun paramètre n'est fourni
$cache_file = 'cve_cache.php'; // Fichier de cache (optionnel)


// Vérifier si la demande est en AJAX
$is_ajax = isset($_GET['format']) && $_GET['format'] === 'ajax';

// Fonction pour charger et rechercher les données dans le CSV de façon optimisée
function getCVEDetails($cve_id, $csv_file, $use_cache = true, $cache_file = 'cve_cache.php') {
    // Le reste de votre fonction reste inchangé
    $results = [];
    $cve_id = strtoupper($cve_id); // Normaliser l'ID pour la recherche
    
    // Utiliser le cache si disponible et activé
    if ($use_cache && file_exists($cache_file)) {
        include($cache_file);
        if (isset($cve_cache[$cve_id])) {
            return $cve_cache[$cve_id];
        }
    }
    
    // Vérifier que le fichier existe
    if (!file_exists($csv_file)) {
        return ['error' => 'Le fichier CSV n\'a pas été trouvé.'];
    }
    
    // Ouvrir le fichier en lecture
    if (($handle = fopen($csv_file, "r")) !== FALSE) {
        // Lire la première ligne pour obtenir les en-têtes
        $headers = fgetcsv($handle, 0, ",", '"', "\\");
        
        if (!$headers) {
            fclose($handle);
            return ['error' => 'Impossible de lire les en-têtes du CSV.'];
        }
        
        // Convertir les en-têtes en minuscules pour la recherche insensible à la casse
        $headers_lower = array_map('strtolower', $headers);
        
        // Trouver l'index de la colonne CVE_ID
        $cve_id_index = array_search('cve_id', $headers_lower);
        if ($cve_id_index === false) {
            $cve_id_index = array_search('cve-id', $headers_lower);
        }
        
        if ($cve_id_index === false) {
            fclose($handle);
            return ['error' => 'Le format du CSV est incorrect, colonne CVE_ID introuvable.'];
        }
        
        // Option d'optimisation 1: Utiliser un index si le fichier est très grand (> 10 MB)
        $filesize = filesize($csv_file);
        if ($filesize > 10 * 1024 * 1024) { // Plus de 10 MB
            // Créer ou utiliser un index existant
            $index_file = $csv_file . '.index.php';
            
            if (file_exists($index_file) && filemtime($index_file) >= filemtime($csv_file)) {
                // Utiliser un index existant si le fichier CSV n'a pas été modifié depuis
                include($index_file);
                if (isset($cve_index[$cve_id])) {
                    // Position dans le fichier
                    $positions = $cve_index[$cve_id];
                    foreach ($positions as $position) {
                        fseek($handle, $position);
                        $data = fgetcsv($handle, 0, ",", '"', "\\");
                        if ($data) {
                            $result = [];
                            foreach ($headers as $i => $header) {
                                $result[$header] = isset($data[$i]) ? $data[$i] : '';
                            }
                            $results[] = $result;
                        }
                    }
                    fclose($handle);
                    return $results;
                }
            }
        }
        
        // Si pas d'index ou CVE non trouvé dans l'index, parcourir le fichier ligne par ligne
        // Revenir au début du fichier (après les en-têtes)
        fseek($handle, 0);
        $headers = fgetcsv($handle, 0, ",", '"', "\\"); // Ignorer la ligne d'en-tête
        
        // Lire chaque ligne du CSV
        while (($data = fgetcsv($handle, 0, ",", '"', "\\")) !== FALSE) {
            // Optimisation 2: Vérification rapide avant traitement complet
            if (isset($data[$cve_id_index]) && strtoupper($data[$cve_id_index]) === $cve_id) {
                // Créer un tableau associatif avec les données
                $result = [];
                foreach ($headers as $i => $header) {
                    $result[$header] = isset($data[$i]) ? $data[$i] : '';
                }
                $results[] = $result;
            }
        }
        fclose($handle);
    } else {
        return ['error' => 'Impossible d\'ouvrir le fichier CSV.'];
    }
    
    // Mettre en cache le résultat si activé
    if ($use_cache && !empty($results)) {
        if (file_exists($cache_file)) {
            include($cache_file);
        } else {
            $cve_cache = [];
        }
        $cve_cache[$cve_id] = $results;
        file_put_contents($cache_file, '<?php $cve_cache = ' . var_export($cve_cache, true) . '; ?>');
    }
    
    return $results;
}

// Fonction pour obtenir la couleur en fonction de la sévérité
function getSeverityColor($severity) {
    $severity = strtoupper($severity);
    switch ($severity) {
        case 'CRITICAL':
            return '#e74c3c'; // Rouge
        case 'HIGH':
            return '#e67e22'; // Orange
        case 'MEDIUM':
            return '#f1c40f'; // Jaune
        case 'LOW':
            return '#3498db'; // Bleu
        default:
            return '#95a5a6'; // Gris
    }
}

// Fonction pour générer les liens externes vers les bases de données de vulnérabilités
function getCVELinks($cve_id) {
    $links = [];
    
    // Lien vers la base de données NVD
    $links['nvd'] = [
        'url' => 'https://nvd.nist.gov/vuln/detail/' . urlencode($cve_id),
        'name' => 'NVD (National Vulnerability Database)'
    ];
    
    // Lien vers MITRE CVE
    $links['mitre'] = [
        'url' => 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' . urlencode($cve_id),
        'name' => 'MITRE CVE'
    ];
    
    // Lien vers CVE Details
    $links['cvedetails'] = [
        'url' => 'https://www.cvedetails.com/cve/' . urlencode($cve_id),
        'name' => 'CVE Details'
    ];
    
    return $links;
}

// Récupérer le CVE_ID depuis l'URL
$cve_id = isset($_GET['cve_id']) ? htmlspecialchars($_GET['cve_id']) : $default_cve;

// Mesurer le temps d'exécution
$start_time = microtime(true);

// Rechercher les détails du CVE
$details = getCVEDetails($cve_id, $csv_file, true, $cache_file);

// Obtenir les liens externes
$external_links = getCVELinks($cve_id);

$execution_time = microtime(true) - $start_time;

// Si c'est une requête AJAX, afficher juste le contenu principal sans les en-têtes HTML
if ($is_ajax) {
    // Afficher directement le contenu pour l'inclusion dans la modal
    if (empty($details)) {
        echo '<div class="alert alert-info">Aucune information trouvée pour ' . htmlspecialchars($cve_id) . '</div>';
    } elseif (isset($details['error'])) {
        echo '<div class="alert alert-danger">' . $details['error'] . '</div>';
    } else {
        // Récupérer les styles de la page principale pour les couleurs de sévérité
        echo '<style>
            .severity {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 3px;
                color: white;
                font-weight: bold;
            }
            .data-row {
                margin-bottom: 10px;
                padding-bottom: 10px;
                border-bottom: 1px solid #eee;
            }
            .label {
                font-weight: bold;
                color: #7f8c8d;
            }
            .value {
                font-weight: normal;
            }
            .cwe-details {
                background-color: #f9f9f9;
                padding: 15px;
                border-radius: 5px;
                margin-top: 10px;
                border-left: 4px solid #3498db;
            }
            .details-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
                margin-bottom: 20px;
            }
            .external-links {
                margin-top: 20px;
                padding: 15px;
                background-color: #f8f9fa;
                border-left: 4px solid #2ecc71;
                border-radius: 5px;
            }
            .external-links h5 {
                margin-top: 0;
                color: #27ae60;
                font-weight: bold;
            }
            .external-links a {
                display: inline-block;
                margin-right: 10px;
                margin-bottom: 10px;
                padding: 6px 12px;
                background-color: #2ecc71;
                color: white;
                text-decoration: none;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
        </style>';
        
        // Afficher le contenu pour chaque détail trouvé
        foreach ($details as $index => $cve) {
            if ($index > 0) {
                echo '<hr style="margin: 20px 0;">';
            }
            
            echo '<div class="details-grid">
                <div>
                    <div class="data-row">
                        <span class="label">Sévérité : </span>';
            if (!empty($cve['Severity'])) {
                echo '<span class="severity" style="background-color: ' . getSeverityColor($cve['Severity']) . ';">' .
                    htmlspecialchars($cve['Severity']) . '</span>';
            } else {
                echo '<span>Non spécifiée</span>';
            }
            echo '</div>
                    
                    <div class="data-row">
                        <span class="label">Score CVSS v3 : </span>
                        <span class="value">' . (!empty($cve['CVSSv3_Score']) ? htmlspecialchars($cve['CVSSv3_Score']) : 'Non disponible') . '</span>
                    </div>
                    
                    <div class="data-row">
                        <span class="label">Date de publication : </span>
                        <span class="value">' . (!empty($cve['Date_Publication']) ? htmlspecialchars($cve['Date_Publication']) : 'Non disponible') . '</span>
                    </div>
                    
                    <div class="data-row">
                        <span class="label">Dernière modification : </span>
                        <span class="value">' . (!empty($cve['Date_Modification']) ? htmlspecialchars($cve['Date_Modification']) : 'Non disponible') . '</span>
                    </div>
                    
                    <div class="data-row">
                        <span class="label">Temps de correction : </span>
                        <span class="value">';
            if (!empty($cve['Temps_de_correction'])) {
                echo htmlspecialchars($cve['Temps_de_correction']) . ' jours';
            } else {
                echo 'Non disponible';
            }
            echo '</span>
                    </div>
                </div>
                
                <div class="cwe-details">
                    <h5>Type de faiblesse (CWE)</h5>';
            if (!empty($cve['cwe_id']) && !empty($cve['cwe_name'])) {
                echo '<div class="data-row">
                        <span class="label">CWE-ID : </span>
                        <span class="value">CWE-' . htmlspecialchars($cve['cwe_id']) . '</span>
                    </div>
                    <div class="data-row">
                        <span class="label">Type Vuln. : </span>
                        <span class="value">' . htmlspecialchars($cve['cwe_name']) . '</span>
                    </div>';
            } else {
                echo '<p>Aucune information CWE disponible pour cette vulnérabilité.</p>';
            }
            echo '</div>
            </div>
            
            <div>
                <h5>Description</h5>
                <p>' . (!empty($cve['Description']) ? nl2br(htmlspecialchars($cve['Description'])) : 'Aucune description disponible.') . '</p>
            </div>';
        }
        
        // Liens externes en version compacte
        echo '<div class="external-links">
            <h5>Plus de détails</h5>';
        foreach ($external_links as $link) {
            echo '<a href="' . $link['url'] . '" target="_blank" rel="noopener noreferrer">' . $link['name'] . '</a> ';
        }
        echo '</div>';
    }
    
    exit; // Terminer le script après avoir envoyé le contenu AJAX
}

// Si ce n'est pas une requête AJAX, continuer avec le HTML complet
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Détails de <?php echo htmlspecialchars($cve_id); ?></title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .severity {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }
        .details-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .data-row {
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        .label {
            font-weight: bold;
            color: #7f8c8d;
        }
        .value {
            font-weight: normal;
        }
        .cwe-details {
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 4px solid #3498db;
        }
        .error {
            color: #e74c3c;
            padding: 15px;
            background-color: #fadbd8;
            border-radius: 4px;
        }
        .not-found {
            color: #7f8c8d;
            text-align: center;
            padding: 40px 0;
        }
        .execution-time {
            font-size: 12px;
            color: #7f8c8d;
            text-align: right;
            margin-top: 20px;
        }
        .external-links {
            margin-top: 30px;
            padding: 15px;
            background-color: #f8f9fa;
            border-left: 4px solid #2ecc71;
            border-radius: 5px;
        }
        .external-links h3 {
            margin-top: 0;
            color: #27ae60;
        }
        .external-links a {
            display: inline-block;
            margin-right: 15px;
            margin-bottom: 10px;
            padding: 8px 15px;
            background-color: #2ecc71;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            transition: background-color 0.2s;
        }
        .external-links a:hover {
            background-color: #27ae60;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Détails des Vulnérabilités (CVE)</h1>
        
        <?php if (empty($details)): ?>
            <div class="not-found">
                <h2>Aucune information trouvée pour <?php echo htmlspecialchars($cve_id); ?></h2>
                <p>Veuillez vérifier l'identifiant CVE.</p>
            </div>
        <?php elseif (isset($details['error'])): ?>
            <div class="error">
                <?php echo $details['error']; ?>
            </div>
        <?php else: ?>
            <h2>Vulnérabilité : <?php echo htmlspecialchars($cve_id); ?></h2>
            
            <?php foreach ($details as $index => $cve): ?>
                <?php if ($index > 0): ?>
                    <hr style="margin: 30px 0;">
                <?php endif; ?>
                
                <div class="details-grid">
                    <div>
                        <div class="data-row">
                            <span class="label">Sévérité : </span>
                            <?php if (!empty($cve['Severity'])): ?>
                                <span class="severity" style="background-color: <?php echo getSeverityColor($cve['Severity']); ?>">
                                    <?php echo htmlspecialchars($cve['Severity']); ?>
                                </span>
                            <?php else: ?>
                                <span>Non spécifiée</span>
                            <?php endif; ?>
                        </div>
                        
                        <div class="data-row">
                            <span class="label">Score CVSS v3 : </span>
                            <span class="value"><?php echo !empty($cve['CVSSv3_Score']) ? htmlspecialchars($cve['CVSSv3_Score']) : 'Non disponible'; ?></span>
                        </div>
                        
                        <div class="data-row">
                            <span class="label">Date de publication : </span>
                            <span class="value"><?php echo !empty($cve['Date_Publication']) ? htmlspecialchars($cve['Date_Publication']) : 'Non disponible'; ?></span>
                        </div>
                        
                        <div class="data-row">
                            <span class="label">Dernière modification : </span>
                            <span class="value"><?php echo !empty($cve['Date_Modification']) ? htmlspecialchars($cve['Date_Modification']) : 'Non disponible'; ?></span>
                        </div>
                        
                        <div class="data-row">
                            <span class="label">Temps de correction : </span>
                            <span class="value">
                                <?php 
                                if (!empty($cve['Temps_de_correction'])) {
                                    echo htmlspecialchars($cve['Temps_de_correction']) . ' jours';
                                } else {
                                    echo 'Non disponible';
                                }
                                ?>
                            </span>
                        </div>
                    </div>
                    
                    <div class="cwe-details">
                        <h3>Type de faiblesse (CWE)</h3>
                        <?php if (!empty($cve['cwe_id']) && !empty($cve['cwe_name'])): ?>
                            <div class="data-row">
                                <span class="label">CWE-ID : </span>
                                <span class="value">CWE-<?php echo htmlspecialchars($cve['cwe_id']); ?></span>
                            </div>
                            <div class="data-row">
                                <span class="label">Type Vuln. : </span>
                                <span class="value"><?php echo htmlspecialchars($cve['cwe_name']); ?></span>
                            </div>
                        <?php else: ?>
                            <p>Aucune information CWE disponible pour cette vulnérabilité.</p>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div>
                    <h3>Description</h3>
                    <p><?php echo !empty($cve['Description']) ? nl2br(htmlspecialchars($cve['Description'])) : 'Aucune description disponible.'; ?></p>
                </div>
            <?php endforeach; ?>
            
            <!-- Section des liens externes -->
            <div class="external-links">
                <h3>Plus de détails</h3>
                <p>Consultez cette vulnérabilité sur les bases de données officielles:</p>
                <?php foreach ($external_links as $link): ?>
                    <a href="<?php echo $link['url']; ?>" target="_blank" rel="noopener noreferrer">
                        <?php echo $link['name']; ?>
                    </a>
                <?php endforeach; ?>
            </div>
            
            <div class="execution-time">
                Temps de réponse : <?php echo round($execution_time * 1000, 2); ?> ms
            </div>
        <?php endif; ?>
    </div>
</body>
</html>