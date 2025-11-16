import pandas as pd
import os


def fusionner_csv(fichier1, fichier2, fichier_sortie=None):
    """
    Fusionne deux fichiers CSV en un seul fichier CSV plus complet.

    Args:
        fichier1 (str): Chemin vers le premier fichier CSV (contenant CVE_ID, Description, dates...)
        fichier2 (str): Chemin vers le deuxième fichier CSV (contenant CVE_ID, score CVSS, sévérité...)
        fichier_sortie (str, optional): Chemin pour le fichier CSV fusionné.
                                       Si non spécifié, un nom par défaut sera généré.

    Returns:
        str: Chemin du fichier CSV créé
    """
    # Déterminer le chemin de sortie si non spécifié
    if fichier_sortie is None:
        base_name1 = os.path.splitext(os.path.basename(fichier1))[0]
        base_name2 = os.path.splitext(os.path.basename(fichier2))[0]
        fichier_sortie = f"fusion_{base_name1}_{base_name2}.csv"

    try:
        # Lire les deux fichiers CSV
        print(f"Lecture du fichier {fichier1}...")
        df1 = pd.read_csv(fichier1)

        print(f"Lecture du fichier {fichier2}...")
        df2 = pd.read_csv(fichier2)

        # Vérifier que les deux DataFrame contiennent la colonne 'CVE_ID'
        if 'CVE_ID' not in df1.columns or 'CVE_ID' not in df2.columns:
            print("Erreur: Les deux fichiers doivent contenir une colonne 'CVE_ID'")
            return None

        # Fusionner les deux DataFrames en utilisant la colonne 'CVE_ID' comme clé
        print("Fusion des données...")
        df_fusionne = pd.merge(df1, df2, on='CVE_ID', how='outer')

        # Afficher quelques statistiques sur la fusion
        print(f"Nombre de lignes dans le fichier 1: {len(df1)}")
        print(f"Nombre de lignes dans le fichier 2: {len(df2)}")
        print(f"Nombre de lignes dans le fichier fusionné: {len(df_fusionne)}")
        print(f"Nombre de CVE communes: {len(df1[df1['CVE_ID'].isin(df2['CVE_ID'])])}")

        # Écrire le DataFrame fusionné dans un nouveau fichier CSV
        df_fusionne.to_csv(fichier_sortie, index=False)
        print(f"Fusion terminée. Fichier CSV créé: {fichier_sortie}")

        return fichier_sortie

    except Exception as e:
        print(f"Erreur lors de la fusion des fichiers: {str(e)}")
        return None


# Exemple d'utilisation
if __name__ == "__main__":
    fichier1 = "results/28-details_cves.csv"  # Contient CVE_ID, Description, Date_Publication, Date_Modification
    fichier2 = "results/25-fusion_2_24-tmcpv.csv"  # Contient CVE_ID, CVSSv3_Score, Severity, Temps_de_correction
    fichier_sortie = "results/29-details_cves_fusion_25-28.csv"

    fusionner_csv(fichier1, fichier2, fichier_sortie)