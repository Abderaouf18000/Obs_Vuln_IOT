<?php

class vstatistique
{
    public $vendor;
    public $nbrvuln;
    public $score;
    public $most_commun_typre;
    public $average_score;

    public function __construct() {}

    function lireProduitsEtCveAvecScoresEtTypes($vendeurRechercher)
    {
        $produitsCsvFile = '../Python/results/6-liste_vendeurs_h-nist.csv';
        $scoresCsvFile = '../Python/results/2-liste_cve_scores-nist-mitre.csv';
        $typesCsvFile = '../Python/results/19-associer_cwe18_type1000.csv';

        // Vérifier si les fichiers existent et sont lisibles
        if (!file_exists($produitsCsvFile) || !is_readable($produitsCsvFile)) {
            return "Le fichier des produits ($produitsCsvFile) n'existe pas ou n'est pas lisible.";
        }
        if (!file_exists($scoresCsvFile) || !is_readable($scoresCsvFile)) {
            return "Le fichier des scores CVSS ($scoresCsvFile) n'existe pas ou n'est pas lisible.";
        }
        if (!file_exists($typesCsvFile) || !is_readable($typesCsvFile)) {
            return "Le fichier des types CWE ($typesCsvFile) n'existe pas ou n'est pas lisible.";
        }

        $produitsParVendeur = []; // Stocker les produits et leurs CVE_ID liés au vendeur
        $scoresCve = []; // Indexer les CVE_ID avec leurs scores et sévérité
        $typesCve = []; // Indexer les CVE_ID avec leurs types de vulnérabilité (CWE)

        // Lire les types de vulnérabilité (CWE) du fichier 19associer_cwe18_type1000.csv
        if (($handleTypes = fopen($typesCsvFile, 'r')) !== false) {
            $headerTypes = fgetcsv($handleTypes, 1000, ",", '"', "\\");

            // Valider que les colonnes nécessaires sont présentes
            if (!$headerTypes || !in_array('cve_id', $headerTypes) || !in_array('cwe_name', $headerTypes)) {
                fclose($handleTypes);
                return "Le fichier des types CWE ne contient pas une structure valide avec 'cve_id' et 'cwe_name'.";
            }

            // Lire chaque ligne et construire un index des types pour chaque CVE_ID
            while (($ligne = fgetcsv($handleTypes, 1000, ",", '"', "\\")) !== false) {
                $ligneAssoc = array_combine($headerTypes, $ligne);

                if (!$ligneAssoc || empty($ligneAssoc['cve_id'])) {
                    continue;
                }

                // Stocker les types avec l'ID du CVE comme index
                $typesCve[$ligneAssoc['cve_id']] = $ligneAssoc['cwe_name'] ?? 'Type non spécifié';
            }

            fclose($handleTypes);
        } else {
            return "Impossible de lire le fichier des types CWE.";
        }

        // Lire les scores CVSS du fichier 2-liste_cve_scores-nist.csv
        if (($handleScores = fopen($scoresCsvFile, 'r')) !== false) {
            $headerScores = fgetcsv($handleScores, 1000, ",", '"', "\\");

            // Valider que les colonnes nécessaires sont présentes
            if (!$headerScores || !in_array('CVE_ID', $headerScores) || !in_array('CVSSv3_Score', $headerScores) || !in_array('Severity', $headerScores)) {
                fclose($handleScores);
                return "Le fichier des scores ne contient pas une structure valide avec 'CVE_ID', 'CVSSv3_Score' et 'Severity'.";
            }

            // Lire chaque ligne et construire un index des scores pour chaque CVE_ID
            while (($ligne = fgetcsv($handleScores, 1000, ",", '"', "\\")) !== false) {
                $ligneAssoc = array_combine($headerScores, $ligne);

                if (!$ligneAssoc || empty($ligneAssoc['CVE_ID'])) {
                    continue;
                }

                // Stocker les scores avec l'ID du CVE comme index
                $scoresCve[$ligneAssoc['CVE_ID']] = [
                    'CVSSv3_Score' => $ligneAssoc['CVSSv3_Score'] ?? 'N/A',
                    'Severity' => $ligneAssoc['Severity'] ?? 'N/A',
                ];
            }

            fclose($handleScores);
        } else {
            return "Impossible de lire le fichier des scores.";
        }

        // Lire les produits et CVE_ID du fichier 6-liste_vendeurs_h_cve-nist.csv
        if (($handleProduits = fopen($produitsCsvFile, 'r')) !== false) {
            $headerProduits = fgetcsv($handleProduits, 1000, ",", '"', "\\");

            // Valider que les colonnes nécessaires sont présentes
            if (!$headerProduits || !in_array('Vendor', $headerProduits) || !in_array('Product', $headerProduits) || !in_array('CVE_ID', $headerProduits)) {
                fclose($handleProduits);
                return "Le fichier des produits ne contient pas une structure valide avec 'Vendor', 'Product', 'CVE_ID'.";
            }

            // Lire chaque ligne et collecter les données par vendeur
            while (($ligne = fgetcsv($handleProduits, 1000, ",", '"', "\\")) !== false) {
                // Vérifier que la ligne a le même nombre d'éléments que l'en-tête
                if (count($ligne) !== count($headerProduits)) {
                    // Log du problème pour débogage
                    error_log("Erreur: ligne avec " . count($ligne) . " éléments, en-tête avec " . count($headerProduits) . " éléments");
                    // Soit ignorer cette ligne
                    continue;
                    // Soit ajuster la taille des tableaux
                    // $ligne = array_pad($ligne, count($headerProduits), "");
                }

                $ligneAssoc = array_combine($headerProduits, $ligne);
                if (!$ligneAssoc) {
                    continue; // Passer les lignes invalides
                }

                // Si le vendeur correspond, ajouter le produit et ses informations
                if (strcasecmp($ligneAssoc['Vendor'], $vendeurRechercher) === 0) {
                    $produit = $ligneAssoc['Product'];
                    $cveId = $ligneAssoc['CVE_ID'];
                    // Ajouter un produit et son CVE_ID
                    if (!isset($produitsParVendeur[$produit])) {
                        $produitsParVendeur[$produit] = [];
                    }
                    // Ajouter les informations du CVE (score, sévérité et type CWE)
                    $produitsParVendeur[$produit][$cveId] = [
                        'CVSSv3_Score' => $scoresCve[$cveId]['CVSSv3_Score'] ?? 'N/A',
                        'Severity' => $scoresCve[$cveId]['Severity'] ?? 'N/A',
                        'CWE_Type' => $typesCve[$cveId] ?? 'Type non spécifié'
                    ];
                }
            }

            fclose($handleProduits); // Fermer le fichier après lecture
        } else {
            return "Impossible de lire le fichier des produits.";
        }

        // Vérifier si des résultats ont été trouvés
        if (empty($produitsParVendeur)) {
            return "Aucun produit ou CVE trouvé pour le vendeur : $vendeurRechercher.";
        }

        return $produitsParVendeur;
    }

    function countUniqueVulnerabilitiesByVendor($vendorName)
    {
        $filename = '../Python/results/6-liste_vendeurs_h_cve-nist.csv';
        // Vérifier que le fichier existe
        if (!file_exists($filename)) {
            return 0;
        }

        // Ouvrir le fichier
        $file = fopen($filename, 'r');
        if (!$file) {
            return 0;
        }

        // Initialiser le tableau pour stocker les CVE_ID uniques
        $uniqueCveIds = [];

        // Lire et ignorer l'en-tête (si présent)
        $header = fgetcsv($file, 0, ",", "\"", "\\");

        // Lire chaque ligne du fichier
        while (($data = fgetcsv($file, 0, ",", "\"", "\\")) !== FALSE) {
            // Vérifier que la ligne a au moins 3 colonnes
            if (count($data) >= 3) {
                $vendor = $data[0]; // Colonne du vendeur (index 0)
                $cveId = $data[2];  // Colonne du CVE_ID (index 2)

                // Si le vendeur correspond à celui recherché (insensible à la casse)
                if (strtolower($vendor) === strtolower($vendorName)) {
                    // Ajouter le CVE_ID au tableau des identifiants uniques
                    $uniqueCveIds[$cveId] = true;
                }
            }
        }

        // Fermer le fichier
        fclose($file);

        $this->nbrvuln = count($uniqueCveIds);
    }

    function countVulnerabilitiesBySeverity($vendorName)
    {
        $filename = '../Python/results/20-fusion_2fin_6-objscore.csv';

        // Vérifier que le fichier existe
        if (!file_exists($filename)) {
            return [
                'error' => 'Le fichier ' . $filename . ' n\'existe pas.'
            ];
        }

        // Ouvrir le fichier
        $file = fopen($filename, 'r');
        if (!$file) {
            return [
                'error' => 'Impossible d\'ouvrir le fichier ' . $filename
            ];
        }

        // Initialiser les compteurs (en minuscules)
        $severityCounts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'none' => 0,
            'unknown' => 0
        ];

        $totalCount = 0;

        // Lire l'en-tête
        $header = fgetcsv($file, 0, ",", "\"", "\\");

        // Vérifier que les colonnes nécessaires sont présentes
        if (!in_array('Vendor', $header) || !in_array('Severity', $header)) {
            fclose($file);
            return [
                'error' => 'Le fichier ne contient pas les colonnes requises (Vendor, Severity)'
            ];
        }

        // Trouver les index des colonnes
        $vendorIdx = array_search('Vendor', $header);
        $severityIdx = array_search('Severity', $header);

        // Normaliser le nom du vendeur recherché
        $searchVendor = strtolower(trim($vendorName));

        // Lire chaque ligne du fichier
        while (($data = fgetcsv($file, 0, ",", "\"", "\\")) !== FALSE) {
            // Vérifier que la ligne a les colonnes nécessaires
            if (count($data) > max($vendorIdx, $severityIdx)) {
                $vendor = $data[$vendorIdx];
                $severity = $data[$severityIdx];

                // Normaliser le nom du vendeur
                $normalizedVendor = strtolower(trim($vendor));

                // Comparaison exacte pour le vendeur
                if ($normalizedVendor === $searchVendor) {
                    $totalCount++;

                    // Convertir la sévérité en minuscules et supprimer les espaces
                    $normalizedSeverity = strtolower(trim($severity));

                    // Vérifier si cette sévérité existe dans notre liste de compteurs
                    if (isset($severityCounts[$normalizedSeverity])) {
                        $severityCounts[$normalizedSeverity]++;
                    } else {
                        $severityCounts['unknown']++;
                    }
                }
            }
        }

        // Fermer le fichier
        fclose($file);

        // Préparer le résultat
        $result = [
            'vendor' => $vendorName,
            'total' => $totalCount,
        ];

        // Ajouter les compteurs par sévérité
        foreach ($severityCounts as $severity => $count) {
            $result[$severity] = $count;
        }

        // Calculer les pourcentages
        if ($totalCount > 0) {
            foreach ($severityCounts as $severity => $count) {
                $result[$severity . '_percent'] = round(($count / $totalCount) * 100, 2);
            }
        }

        return $result;
    }

    function getTypeVulnerabilityByVendor($vendorName)
    {
        $csvFile = '../Python/results/22-typepop_vendor-21.csv';

        // Vérifier si le fichier existe
        if (!file_exists($csvFile)) {
            return ['error' => 'Le fichier CSV n\'existe pas'];
        }

        // Ouvrir le fichier CSV
        $handle = fopen($csvFile, 'r');
        if (!$handle) {
            return ['error' => 'Impossible d\'ouvrir le fichier CSV'];
        }

        $result = null;
        $header = true;

        // Parcourir le fichier CSV
        // Ajout du paramètre d'échappement pour éviter l'avertissement de dépréciation
        while (($data = fgetcsv($handle, 1000, ',', '"', '\\')) !== FALSE) {
            // Ignorer l'en-tête
            if ($header) {
                $header = false;
                continue;
            }

            // Vérifier si les données sont valides
            if (count($data) >= 2) {
                $vendor = trim($data[0]);
                $vulnerability = trim($data[1]);

                // Recherche insensible à la casse du vendeur
                if (strcasecmp($vendor, $vendorName) === 0) {
                    $result = $vulnerability;
                    break; // Sortir de la boucle dès qu'on a trouvé le vendeur
                }
            }
        }

        fclose($handle);

        // Vérifier si un résultat a été trouvé
        if ($result === null) {
            return "Type not yet assigned";
        }

        return $result;
    }

    function getVendorAverageScore($vendorName, $csvFilePath = '../Python/results/23-score_moy_vendor.csv', $precision = 2)
    {
        // Vérifier si le fichier existe
        if (!file_exists($csvFilePath)) {
            error_log("Erreur: Le fichier CSV '$csvFilePath' n'existe pas");
            return null;
        }

        // Ouvrir le fichier CSV
        $file = fopen($csvFilePath, 'r');
        if (!$file) {
            error_log("Erreur: Impossible d'ouvrir le fichier CSV '$csvFilePath'");
            return null;
        }

        // Lire l'en-tête pour déterminer l'index de la colonne du score
        // Ajouté tous les paramètres requis pour éviter l'avertissement de dépréciation
        $header = fgetcsv($file, 0, ",", "\"", "\\");
        $vendorIndex = array_search('Vendor', $header);
        $scoreIndex = array_search('Average_CVSS_Score', $header);

        // Vérifier si les colonnes requises existent
        if ($vendorIndex === false || $scoreIndex === false) {
            error_log("Erreur: Les colonnes nécessaires ne sont pas présentes dans le fichier CSV");
            fclose($file);
            return null;
        }

        // Variable pour stocker le score moyen du vendeur
        $averageScore = null;

        // Parcourir le fichier pour trouver le vendeur
        while (($row = fgetcsv($file, 0, ",", "\"", "\\")) !== false) {
            if (strcasecmp($row[$vendorIndex], $vendorName) === 0) {
                $averageScore = (float) $row[$scoreIndex];
                break;
            }
        }

        // Fermer le fichier
        fclose($file);

        // Arrondir le score si un vendeur a été trouvé
        if ($averageScore !== null) {
            $averageScore = round($averageScore, $precision);
        }

        return $averageScore !== null ? $averageScore : 0.0;
    }

    function getVendorAverageFixTime($vendorName)
    {
        $csvFilePath = '../Python/results/14-temp_moy_vendeur-mitre.csv';
        // Vérifier si le fichier existe
        if (!file_exists($csvFilePath)) {
            error_log("Erreur: Le fichier CSV '$csvFilePath' n'existe pas");
            return null;
        }

        // Ouvrir le fichier CSV
        $file = fopen($csvFilePath, 'r');
        if (!$file) {
            error_log("Erreur: Impossible d'ouvrir le fichier CSV '$csvFilePath'");
            return null;
        }

        // Lire l'en-tête pour déterminer l'index de la colonne du temps moyen
        $header = fgetcsv($file, 0, ",", "\"", "\\");
        $vendorIndex = array_search('Vendor', $header);
        $fixTimeIndex = array_search('Avg_Fix_Time', $header);

        // Vérifier si les colonnes requises existent
        if ($vendorIndex === false || $fixTimeIndex === false) {
            error_log("Erreur: Les colonnes nécessaires ne sont pas présentes dans le fichier CSV");
            fclose($file);
            return null;
        }

        // Variable pour stocker le temps moyen de correction
        $avgFixTime = null;

        // Parcourir le fichier pour trouver le vendeur
        while (($row = fgetcsv($file, 0, ",", "\"", "\\")) !== false) {
            // Comparaison insensible à la casse
            if (strcasecmp($row[$vendorIndex], $vendorName) === 0) {
                $avgFixTime = (int) $row[$fixTimeIndex];
                break;
            }
        }

        // Fermer le fichier
        fclose($file);

        return $avgFixTime;
    }

    function getVendorCorrectionTimes($vendorName)
    {
        $csvFile = '../Python/results/27-traitment_26.csv';

        // Vérifier si le fichier existe
        if (!file_exists($csvFile)) {
            return ['error' => 'Le fichier CSV n\'existe pas'];
        }

        // Ouvrir le fichier CSV
        if (($handle = fopen($csvFile, "r")) !== FALSE) {
            // Lire la première ligne pour obtenir les en-têtes
            $headers = fgetcsv($handle, 1000, ",", "\"", "\\");

            // Trouver les index des colonnes
            $vendorIndex = array_search('Vendor', $headers);
            $criticalAvgIndex = array_search('CRITICAL_avg', $headers);
            $highAvgIndex = array_search('HIGH_avg', $headers);
            $mediumAvgIndex = array_search('MEDIUM_avg', $headers);
            $lowAvgIndex = array_search('LOW_avg', $headers);

            // Vérifier si la colonne Vendor existe
            if ($vendorIndex === false) {
                fclose($handle);
                return ['error' => 'Format de CSV invalide, colonne Vendor non trouvée'];
            }

            // Lire les données
            while (($data = fgetcsv($handle, 1000, ",", "\"", "\\")) !== FALSE) {
                if (isset($data[$vendorIndex]) && $data[$vendorIndex] == $vendorName) {
                    // Récupérer les valeurs moyennes et les arrondir à des entiers
                    $result = [
                        'vendor' => $vendorName,
                        'critical' => ($criticalAvgIndex !== false && isset($data[$criticalAvgIndex]) && $data[$criticalAvgIndex] !== '') ?
                            intval(round(floatval($data[$criticalAvgIndex]))) : null,
                        'high' => ($highAvgIndex !== false && isset($data[$highAvgIndex]) && $data[$highAvgIndex] !== '') ?
                            intval(round(floatval($data[$highAvgIndex]))) : null,
                        'medium' => ($mediumAvgIndex !== false && isset($data[$mediumAvgIndex]) && $data[$mediumAvgIndex] !== '') ?
                            intval(round(floatval($data[$mediumAvgIndex]))) : null,
                        'low' => ($lowAvgIndex !== false && isset($data[$lowAvgIndex]) && $data[$lowAvgIndex] !== '') ?
                            intval(round(floatval($data[$lowAvgIndex]))) : null
                    ];

                    fclose($handle);
                    return $result;
                }
            }
            fclose($handle);
            return ['error' => 'Vendeur non trouvé'];
        }

        return ['error' => 'Impossible d\'ouvrir le fichier CSV'];
    }

    function  msg_hello($vendeur)
    {
        echo $vendeur;
    }
}
