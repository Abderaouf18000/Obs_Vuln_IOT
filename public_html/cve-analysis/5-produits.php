<?php
// Définir le fichier à lire
$fichier_csv = "../../Python/produit/results/25-produit_liste_h-nist.csv";
$donnees = [];
$message = "";

// Si un fichier a été téléchargé
if ($fichier_csv) {
    // Fonction pour lire le fichier CSV avec des tabulations comme séparateur
    function lireFichierCSV($fichier, $separateur = "\t")
    {
        $donnees = [];

        // Vérifier si le fichier existe
        if (!file_exists($fichier)) {
            return ["erreur" => "Le fichier n'existe pas."];
        }

        // Ouvrir le fichier en lecture
        $handle = fopen($fichier, 'r');
        if ($handle === false) {
            return ["erreur" => "Impossible d'ouvrir le fichier."];
        }

        // Lire l'en-tête
        $entetes = fgetcsv($handle, 0, $separateur);

        // Lire les données ligne par ligne
        while (($ligne = fgetcsv($handle, 0, $separateur)) !== false) {
            if (count($ligne) === count($entetes)) {
                $donnees[] = array_combine($entetes, $ligne);
            }
        }

        // Fermer le fichier
        fclose($handle);

        return $donnees;
    }

    // Lire les données du fichier CSV
    $donnees = lireFichierCSV($fichier_csv);

    // Vérifier s'il y a eu une erreur
    if (isset($donnees['erreur'])) {
        $message = '<div class="erreur">' . $donnees['erreur'] . '</div>';
        $donnees = [];
    } else {
        $message = '<div class="succes">Fichier chargé avec succès!</div>';
    }
}
?>
<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Données de vulnérabilités</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
        }

        h1,
        h2 {
            color: #333;
            text-align: center;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
        }

        th,
        td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        th {
            background-color: #4CAF50;
            color: white;
            position: sticky;
            top: 0;
        }

        tr:hover {
            background-color: #f5f5f5;
        }

        .cve-list {
            max-height: 150px;
            overflow-y: auto;
            background-color: #f9f9f9;
            padding: 8px;
            border-radius: 4px;
            border: 1px solid #ddd;
        }

        .badge {
            background-color: #e74c3c;
            color: white;
            padding: 3px 8px;
            border-radius: 10px;
            font-size: 0.8em;
        }

        .upload-form {
            max-width: 500px;
            margin: 0 auto;
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }

        .upload-form input[type="file"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
        }

        .upload-form button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px 15px;
            cursor: pointer;
            border-radius: 4px;
            width: 100%;
        }

        .upload-form button:hover {
            background-color: #45a049;
        }

        .erreur {
            background-color: #ffebee;
            color: #c62828;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            text-align: center;
        }

        .succes {
            background-color: #e8f5e9;
            color: #2e7d32;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            text-align: center;
        }
    </style>
</head>

<body>
    <h1>Analyse des vulnérabilités par produit</h1>

    <div class="upload-form">
        <h2>Téléchargez votre fichier CSV</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="fichier_csv" accept=".csv,.txt" required>
            <button type="submit">Analyser le fichier</button>
        </form>
        <?php echo $message; ?>
    </div>

    <?php if (empty($donnees)): ?>
        <?php if (empty($message)): ?>
            <p style="text-align: center; margin-top: 20px;">Veuillez télécharger un fichier CSV pour afficher les données.</p>
        <?php endif; ?>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>Vendeur</th>
                    <th>Produit</th>
                    <th>Nombre de vulnérabilités</th>
                    <th>Liste des CVE</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($donnees as $ligne): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($ligne['vendeur']); ?></td>
                        <td><?php echo htmlspecialchars($ligne['produit']); ?></td>
                        <td>
                            <span class="badge"><?php echo htmlspecialchars($ligne['nombre_vulnerabilites']); ?></span>
                        </td>
                        <td>
                            <div class="cve-list">
                                <?php
                                $cve_ids = explode(', ', $ligne['cve_ids']);
                                foreach ($cve_ids as $cve) {
                                    echo '<div>' . htmlspecialchars($cve) . '</div>';
                                }
                                ?>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</body>

</html>