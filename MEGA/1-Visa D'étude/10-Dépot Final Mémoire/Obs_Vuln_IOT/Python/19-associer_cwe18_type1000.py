import pandas as pd
import os


def fusionner_cwe_avec_noms(fichier_cwe_cve, fichier_cwe_reference, fichier_sortie):
    """
    Fusionne les CWE IDs avec leurs noms depuis un fichier de référence.

    Args:
        fichier_cwe_cve (str): Chemin vers le fichier CSV contenant les associations CVE-CWE
        fichier_cwe_reference (str): Chemin vers le fichier CSV de référence des CWE
        fichier_sortie (str): Chemin pour enregistrer le fichier CSV fusionné
    """
    # Vérifier si les fichiers existent
    if not os.path.exists(fichier_cwe_cve):
        print(f"Erreur: Le fichier {fichier_cwe_cve} n'existe pas.")
        return False

    if not os.path.exists(fichier_cwe_reference):
        print(f"Erreur: Le fichier {fichier_cwe_reference} n'existe pas.")
        return False

    # Charger les données
    print(f"Chargement du fichier {fichier_cwe_cve}...")
    try:
        df_cve_cwe = pd.read_csv(fichier_cwe_cve)
        print(f"Fichier chargé avec succès: {len(df_cve_cwe)} lignes")
    except Exception as e:
        print(f"Erreur lors du chargement de {fichier_cwe_cve}: {e}")
        return False

    print(f"Chargement du fichier {fichier_cwe_reference}...")
    try:
        df_cwe_ref = pd.read_csv(fichier_cwe_reference)
        print(f"Fichier chargé avec succès: {len(df_cwe_ref)} lignes")
    except Exception as e:
        print(f"Erreur lors du chargement de {fichier_cwe_reference}: {e}")
        return False

    # Vérifier les colonnes
    if 'cwe_id' not in df_cve_cwe.columns:
        print(f"Erreur: La colonne 'cwe_id' n'existe pas dans {fichier_cwe_cve}")
        print(f"Colonnes disponibles: {df_cve_cwe.columns.tolist()}")
        return False

    # Vérifier si 'CWE-ID' existe dans le fichier de référence
    cwe_id_col = None
    if 'CWE-ID' in df_cwe_ref.columns:
        cwe_id_col = 'CWE-ID'
    elif 'CWE_ID' in df_cwe_ref.columns:
        cwe_id_col = 'CWE_ID'
    elif 'cwe_id' in df_cwe_ref.columns:
        cwe_id_col = 'cwe_id'
    else:
        print(f"Erreur: Aucune colonne d'ID CWE trouvée dans {fichier_cwe_reference}")
        print(f"Colonnes disponibles: {df_cwe_ref.columns.tolist()}")
        return False

    # Vérifier si la colonne 'Name' existe
    name_col = None
    if 'Name' in df_cwe_ref.columns:
        name_col = 'Name'
    elif 'name' in df_cwe_ref.columns:
        name_col = 'name'
    else:
        print(f"Erreur: Aucune colonne de nom trouvée dans {fichier_cwe_reference}")
        print(f"Colonnes disponibles: {df_cwe_ref.columns.tolist()}")
        return False

    # Créer un dictionnaire pour une recherche plus rapide
    print("Création du dictionnaire de référence CWE...")
    cwe_dict = df_cwe_ref.set_index(cwe_id_col)[name_col].to_dict()

    # Ajouter une colonne avec le nom du CWE
    print("Association des noms CWE...")
    df_cve_cwe['cwe_name'] = df_cve_cwe['cwe_id'].map(lambda x: cwe_dict.get(x, "Inconnu"))

    # Compter combien de CWE ont été trouvés/non trouvés
    found_cwe = (df_cve_cwe['cwe_name'] != "Inconnu").sum()
    not_found_cwe = (df_cve_cwe['cwe_name'] == "Inconnu").sum()

    print(f"Résultats de l'association:")
    print(f"- CWE avec noms trouvés: {found_cwe}")
    print(f"- CWE sans noms correspondants: {not_found_cwe}")

    # Création du dossier de sortie si nécessaire
    os.makedirs(os.path.dirname(fichier_sortie), exist_ok=True)

    # Enregistrer le résultat
    print(f"Enregistrement du fichier fusionné dans {fichier_sortie}...")
    df_cve_cwe.to_csv(fichier_sortie, index=False)
    print("Fusion terminée avec succès!")

    return True


# Exécution du script si lancé directement
if __name__ == "__main__":
    # Chemins des fichiers
    fichier_cwe_cve = "results/18-traitement_cve_type-nist-mitre.csv"
    fichier_cwe_reference = "results/cwe.csv"
    fichier_sortie = "results/19-associer_cwe18_type1000.csv"

    # Exécuter la fusion
    fusionner_cwe_avec_noms(fichier_cwe_cve, fichier_cwe_reference, fichier_sortie)