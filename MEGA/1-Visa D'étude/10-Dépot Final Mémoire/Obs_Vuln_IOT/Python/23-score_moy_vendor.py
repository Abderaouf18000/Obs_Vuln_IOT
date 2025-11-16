import pandas as pd


def calculate_vendor_average_scores(vendors_file, scores_file, output_file='vendor_average_scores.csv'):
    """
    Fusionne deux fichiers CSV, calcule le score CVSS moyen par vendeur,
    et sauvegarde ces moyennes dans un fichier CSV.

    Parameters:
    - vendors_file (str): Chemin vers le fichier CSV contenant les données vendeurs
    - scores_file (str): Chemin vers le fichier CSV contenant les scores CVSS
    - output_file (str): Nom du fichier de sortie pour les scores moyens par vendeur
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

    # Supposons que le score CVSS est dans une colonne nommée 'CVSSv3_Score' ou 'Score'
    # Vérifier quelle colonne de score est présente
    score_column = None
    if 'CVSSv3_Score' in merged_df.columns:
        score_column = 'CVSSv3_Score'
    elif 'Score' in merged_df.columns:
        score_column = 'Score'
    else:
        # Si aucune colonne de score n'est trouvée, chercher des colonnes qui pourraient contenir le score
        possible_score_columns = [col for col in merged_df.columns if 'score' in col.lower() or 'cvss' in col.lower()]
        if possible_score_columns:
            score_column = possible_score_columns[0]
        else:
            print("ERREUR: Aucune colonne de score CVSS trouvée dans les données!")
            return None

    # S'assurer que le score est numérique
    merged_df[score_column] = pd.to_numeric(merged_df[score_column], errors='coerce')

    # Garder seulement les colonnes nécessaires
    reduced_df = merged_df[['Vendor', score_column]].copy()

    # Supprimer les lignes avec des valeurs manquantes
    reduced_df = reduced_df.dropna()
    print(f"Données après suppression des valeurs manquantes: {len(reduced_df)} lignes")

    # Calculer le score moyen par vendeur
    print("Calcul des scores moyens par vendeur...")
    avg_score_by_vendor = reduced_df.groupby('Vendor')[score_column].mean().reset_index()
    avg_score_by_vendor = avg_score_by_vendor.rename(columns={score_column: 'Average_CVSS_Score'})

    # Arrondir les scores moyens à 2 décimales
    avg_score_by_vendor['Average_CVSS_Score'] = avg_score_by_vendor['Average_CVSS_Score'].round(2)

    # Trier par score moyen décroissant
    avg_score_by_vendor = avg_score_by_vendor.sort_values('Average_CVSS_Score', ascending=False)

    # Afficher un aperçu
    print("\nAperçu des scores moyens par vendeur (top 10):")
    print(avg_score_by_vendor.head(10))

    # Sauvegarder le résultat
    avg_score_by_vendor.to_csv(output_file, index=False)
    print(f"\nScores moyens par vendeur sauvegardés dans: {output_file}")

    # Statistiques sur les données
    print("\nStatistiques sur les scores moyens:")
    print(f"Nombre de vendeurs: {len(avg_score_by_vendor)}")
    print(f"Score moyen minimum: {avg_score_by_vendor['Average_CVSS_Score'].min()}")
    print(f"Score moyen maximum: {avg_score_by_vendor['Average_CVSS_Score'].max()}")
    print(f"Score moyen global: {avg_score_by_vendor['Average_CVSS_Score'].mean().round(2)}")

    return avg_score_by_vendor


if __name__ == "__main__":
    # Chemins des fichiers
    vendors_file = "results/6-liste_vendeurs_h-nist.csv"
    scores_file = "results/2-liste_cve_scores-nist-mitre.csv"
    output_file = "results/23-score_moy_vendor.csv"

    # Exécuter le calcul et la sauvegarde des scores moyens par vendeur
    vendor_scores = calculate_vendor_average_scores(vendors_file, scores_file, output_file)