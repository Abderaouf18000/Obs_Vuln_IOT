import os
import shutil
import glob


def deplacer_fichiers_json(dossier_source, dossier_destination):
    """
    Déplace tous les fichiers JSON des sous-dossiers vers un dossier unique.

    Args:
        dossier_source (str): Chemin du dossier principal contenant les sous-dossiers
        dossier_destination (str): Chemin du dossier de destination pour tous les fichiers JSON
    """
    # Créer le dossier de destination s'il n'existe pas
    if not os.path.exists(dossier_destination):
        os.makedirs(dossier_destination)
        print(f"Dossier créé: {dossier_destination}")

    # Compteurs pour le rapport
    fichiers_deplaces = 0
    fichiers_ignores = 0

    # Parcourir récursivement tous les sous-dossiers
    for racine, dossiers, fichiers in os.walk(dossier_source):
        # Ignorer le dossier de destination s'il est un sous-dossier du dossier source
        if os.path.abspath(racine) == os.path.abspath(dossier_destination):
            continue

        # Traiter tous les fichiers JSON dans le dossier actuel
        for fichier in fichiers:
            if fichier.lower().endswith('.json'):
                chemin_source = os.path.join(racine, fichier)

                # Gérer les doublons potentiels
                chemin_destination = os.path.join(dossier_destination, fichier)
                if os.path.exists(chemin_destination):
                    # Créer un nom unique si le fichier existe déjà
                    nom_base, extension = os.path.splitext(fichier)
                    sous_dossier_nom = os.path.basename(racine)
                    nouveau_nom = f"{nom_base}_{sous_dossier_nom}{extension}"
                    chemin_destination = os.path.join(dossier_destination, nouveau_nom)

                try:
                    shutil.move(chemin_source, chemin_destination)
                    print(f"Déplacé: {chemin_source} → {chemin_destination}")
                    fichiers_deplaces += 1
                except Exception as e:
                    print(f"Erreur lors du déplacement de {chemin_source}: {e}")
                    fichiers_ignores += 1

    # Afficher le rapport final
    print(f"\nRapport:")
    print(f"- {fichiers_deplaces} fichiers JSON déplacés avec succès")
    print(f"- {fichiers_ignores} fichiers JSON non déplacés en raison d'erreurs")


# Exemple d'utilisation
if __name__ == "__main__":
    # Demander les chemins à l'utilisateur
    annee = "2019"
    dossier_source = f"cves/{annee}"
    dossier_destination = f"cvelist_mitre_{annee}"

    # Exécuter la fonction
    deplacer_fichiers_json(dossier_source, dossier_destination)