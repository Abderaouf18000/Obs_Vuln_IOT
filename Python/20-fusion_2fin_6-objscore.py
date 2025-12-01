import pandas as pd


def merge_cve_data(vendors_file, scores_file, output_file):
    """
    Fusionne deux fichiers CSV et garde seulement les colonnes Vendor et Severity
    en supprimant les redondances où un même CVE_ID apparaît plusieurs fois

    Parameters:
    - vendors_file (str): Chemin vers le fichier CSV contenant les données vendeurs
    - scores_file (str): Chemin vers le fichier CSV contenant les scores CVSS
    - output_file (str): Nom du fichier de sortie
    """
    # Charger les fichiers CSV
    print(f"Chargement du fichier {vendors_file}...")
    vendors_df = pd.read_csv(vendors_file)
    print(f"Chargement terminé: {len(vendors_df)} lignes")

    print(f"Chargement du fichier {scores_file}...")
    scores_df = pd.read_csv(scores_file)
    print(f"Chargement terminé: {len(scores_df)} lignes")

    # Vérifier les colonnes dans chaque DataFrame
    print(f"Colonnes du fichier vendors: {vendors_df.columns.tolist()}")
    print(f"Colonnes du fichier scores: {scores_df.columns.tolist()}")

    # Fusionner les DataFrames sur la colonne CVE_ID
    print("Fusion des données en cours...")
    merged_df = pd.merge(vendors_df, scores_df, on='CVE_ID', how='left')
    print(f"Fusion terminée: {len(merged_df)} lignes")

    # Garder les colonnes nécessaires: Vendor, CVE_ID et Severity
    temp_df = merged_df[['Vendor', 'CVE_ID', 'Severity']].copy()

    # Supprimer les lignes avec des valeurs manquantes
    temp_df = temp_df.dropna()
    print(f"Données après suppression des valeurs manquantes: {len(temp_df)} lignes")

    # Supprimer les doublons basés sur la combinaison Vendor et CVE_ID
    # Cela élimine les cas où le même CVE_ID apparaît plusieurs fois pour le même vendeur
    dedup_df = temp_df.drop_duplicates(subset=['Vendor', 'CVE_ID'])
    print(f"Données après suppression des doublons: {len(dedup_df)} lignes")

    # Garder seulement les colonnes Vendor et Severity pour le fichier final
    vendor_severity_df = dedup_df[['Vendor', 'Severity']]

    # Afficher les premières lignes pour vérification
    print("\nAperçu des données (seulement Vendor et Severity):")
    print(vendor_severity_df.head(10))

    # Sauvegarder le résultat
    vendor_severity_df.to_csv(output_file, index=False)
    print(f"\nDonnées sauvegardées dans: {output_file}")

    return vendor_severity_df


if __name__ == "__main__":
    # Chemins des fichiers
    vendors_file = "results/6-liste_vendeurs_h-nist.csv"
    scores_file = "results/2-liste_cve_scores-nist-mitre.csv"
    output_file = "results/20-fusion_2fin_6-objscore.csv"

    # Exécuter la fusion
    vendor_severity_data = merge_cve_data(vendors_file, scores_file, output_file)

    # Statistiques sur les données
    print("\nStatistiques sur les données:")
    print(f"Nombre total de lignes: {len(vendor_severity_data)}")
    print(f"Nombre de vendeurs uniques: {vendor_severity_data['Vendor'].nunique()}")

    # Distributions des sévérités par vendeur
    severity_counts = vendor_severity_data.groupby(['Vendor', 'Severity']).size().reset_index(name='count')

    # Top 10 des vendeurs avec le plus de vulnérabilités
    top_vendors = vendor_severity_data['Vendor'].value_counts().head(10)
    print("\nTop 10 des vendeurs avec le plus de vulnérabilités:")
    print(top_vendors)

    # Distribution des sévérités
    severity_distribution = vendor_severity_data['Severity'].value_counts()
    print("\nDistribution des niveaux de sévérité:")
    print(severity_distribution)