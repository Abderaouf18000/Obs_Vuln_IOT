<?php
// exporter.php - Fichier de contrôle pour l'exportation

// Inclure les dépendances
require_once '2-vstatistique.php';

// Vérifier les paramètres
if (!isset($_GET['vendor']) || empty($_GET['vendor'])) {
    header('Location: 1-vendeur.php');
    exit;
}

// Récupérer et sécuriser le vendeur
$vendeur = htmlspecialchars($_GET['vendor'], ENT_QUOTES, 'UTF-8');

// Vérifier le format demandé
$format = isset($_GET['format']) ? $_GET['format'] : 'csv';

// Formats autorisés
$formatsAutorises = ['csv', 'excel', 'pdf'];

if (!in_array($format, $formatsAutorises)) {
    die('Format d\'exportation non valide.');
}

// Créer l'objet et lancer l'exportation
$produitsCveObj = new vstatistique();
$produitsCveObj->exportProduitsEtCve($vendeur, $format);

// Cette ligne ne devrait jamais être atteinte car les méthodes d'exportation quittent le script
header('Location: 3-resultats.php?vendor=' . urlencode($vendeur));
exit;