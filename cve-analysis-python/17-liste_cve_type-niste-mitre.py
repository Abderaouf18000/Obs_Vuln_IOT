import pandas as pd


def fusionner_fichiers_csv(file1, file2, output_file):
    """
    Fusionne deux fichiers CSV sur la colonne commune 'CVE-ID' et enregistre le résultat en sortie.

    Parameters:
    file1 (str): Chemin vers le premier fichier CSV.
    file2 (str): Chemin vers le deuxième fichier CSV.
    output_file (str): Chemin pour enregistrer le fichier CSV fusionné.

    Returns:
    None
    """
    try:
        # Charger les deux fichiers CSV
        df1 = pd.read_csv(file1)
        df2 = pd.read_csv(file2)

        # Renommer les colonnes pour les aligner sur une clé commune ('CVE-ID')
        df1.rename(columns={'CVE-ID': 'CVE_ID'}, inplace=True)

        # Fusionner les fichiers sur la colonne 'CVE_ID'
        merged_df = pd.merge(df1, df2, on="CVE_ID", how="outer")

        # Enregistrer le résultat dans un fichier CSV
        merged_df.to_csv(output_file, index=False)

        print(f"Fichier fusionné créé : {output_file}")
    except Exception as e:
        print(f"Erreur lors de la fusion des fichiers : {e}")


# Exemple d'utilisation
if __name__ == "__main__":
    # Chemins des fichiers CSV à fusionner
    file1 = "results/15-liste_cve_type-mitres.csv"  # Premier fichier
    file2 = "results/16-liste_cve_type-nist.csv"  # Deuxième fichier
    output_file = "results/17-liste_cve_type-mitre-nist.csv"  # Fichier de sortie

    # Appeler la fonction pour fusionner les fichiers
    fusionner_fichiers_csv(file1, file2, output_file)
