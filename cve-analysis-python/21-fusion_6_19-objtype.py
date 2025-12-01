import pandas as pd
import os


def fusionner_csv(fichier_vendeurs, fichier_cwe, fichier_sortie):
    """
    Fusionne deux fichiers CSV en conservant la structure du fichier vendeurs
    et en ajoutant les informations CWE correspondantes, tout en ignorant les 'Nom non trouvé'.

    Args:
        fichier_vendeurs (str): Chemin du fichier CSV contenant les informations des vendeurs
        fichier_cwe (str): Chemin du fichier CSV contenant les associations CWE
        fichier_sortie (str): Chemin du fichier CSV de sortie après fusion
    """
    # Charger les fichiers CSV
    print(f"Chargement du fichier {fichier_vendeurs}...")
    df_vendeurs = pd.read_csv(fichier_vendeurs)
    print(f"Chargement du fichier {fichier_cwe}...")
    df_cwe = pd.read_csv(fichier_cwe)

    # Afficher les premières lignes de chaque DataFrame
    print("\nAperçu du premier DataFrame (informations vendeurs):")
    print(df_vendeurs.head())
    print(f"Nombre total de lignes: {len(df_vendeurs)}")

    print("\nAperçu du deuxième DataFrame (associations CWE):")
    print(df_cwe.head())
    print(f"Nombre total de lignes: {len(df_cwe)}")

    # Filtrer les entrées "Nom non trouvé" du fichier CWE
    df_cwe_filtered = df_cwe[df_cwe["cwe_name"] != "Nom non trouvé"].copy()
    print(f"Nombre d'entrées après filtrage des 'Nom non trouvé': {len(df_cwe_filtered)}")
    print(f"Entrées supprimées: {len(df_cwe) - len(df_cwe_filtered)}")

    # Normaliser les noms de colonnes (cve_id vs CVE_ID)
    df_vendeurs.rename(columns={"CVE_ID": "cve_id"}, inplace=True)

    # Fusionner les deux DataFrames sur la colonne commune cve_id
    # Utiliser left join pour conserver uniquement la structure du fichier vendeurs
    print("\nFusion des DataFrames en cours (en conservant la structure du fichier vendeurs)...")
    df_fusionne = pd.merge(df_vendeurs, df_cwe_filtered, on="cve_id", how="left")

    # Afficher les premières lignes du DataFrame fusionné
    print("\nAperçu du DataFrame fusionné:")
    print(df_fusionne.head())
    print(f"Nombre total de lignes après fusion: {len(df_fusionne)}")

    # Créer le dossier de sortie s'il n'existe pas
    os.makedirs(os.path.dirname(fichier_sortie), exist_ok=True)

    # Enregistrer le DataFrame fusionné dans un nouveau fichier CSV
    df_fusionne.to_csv(fichier_sortie, index=False)
    print(f"\nLe fichier fusionné a été enregistré sous '{fichier_sortie}'")

    # Afficher quelques statistiques
    print("\nStatistiques sur les données fusionnées:")
    lignes_avec_cwe = len(df_fusionne[~df_fusionne["cwe_name"].isna()])
    lignes_sans_cwe = len(df_fusionne[df_fusionne["cwe_name"].isna()])

    print(f"Entrées de vendeurs avec correspondance CWE: {lignes_avec_cwe}")
    print(f"Entrées de vendeurs sans correspondance CWE: {lignes_sans_cwe}")
    if len(df_fusionne) > 0:
        print(f"Pourcentage d'entrées avec correspondance CWE: {lignes_avec_cwe / len(df_fusionne) * 100:.2f}%")
    else:
        print("Aucune entrée dans le fichier fusionné.")


# Utilisation de la fonction
if __name__ == "__main__":
    fichier_vendeurs = "results/6-liste_vendeurs_h-nist.csv"
    fichier_cwe = "results/19-associer_cwe18_type1000.csv"
    fichier_resultat = "results/21-fusion_6_19-objtype.csv"

    fusionner_csv(fichier_vendeurs, fichier_cwe, fichier_resultat)