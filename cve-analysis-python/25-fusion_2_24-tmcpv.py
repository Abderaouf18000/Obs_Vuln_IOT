import pandas as pd
import csv


def combine_cve_data(scores_file, correction_time_file, output_file):
    """
    Combine les données de scores CVSS et de temps de correction pour chaque CVE_ID.

    Args:
        scores_file (str): Chemin vers le fichier CSV contenant les scores CVSS
        correction_time_file (str): Chemin vers le fichier CSV contenant les temps de correction
        output_file (str): Chemin vers le fichier CSV de sortie

    Returns:
        DataFrame: DataFrame combiné contenant les données fusionnées
    """
    try:
        # Charger les fichiers CSV
        scores_df = pd.read_csv(scores_file)
        correction_df = pd.read_csv(correction_time_file)

        print(f"Fichier des scores: {len(scores_df)} lignes")
        print(f"Fichier des temps de correction: {len(correction_df)} lignes")

        # Fusionner les DataFrames sur la colonne CVE_ID
        combined_df = pd.merge(scores_df, correction_df, on='CVE_ID', how='inner')

        print(f"Après fusion: {len(combined_df)} CVEs avec score et temps de correction")

        # Enregistrer le résultat dans un nouveau fichier CSV
        combined_df.to_csv(output_file, index=False)
        print(f"Données combinées enregistrées dans {output_file}")

        # Afficher quelques statistiques
        if not combined_df.empty:
            avg_time = combined_df['Temps_de_correction'].mean()
            avg_score = combined_df['CVSSv3_Score'].mean()

            print(f"Temps de correction moyen: {avg_time:.2f} jours")
            print(f"Score CVSS moyen: {avg_score:.2f}")

            # Analyse par niveau de sévérité
            if 'Severity' in combined_df.columns:
                print("\nTemps de correction moyen par niveau de sévérité:")
                severity_stats = combined_df.groupby('Severity')['Temps_de_correction'].agg(['mean', 'count'])
                for severity, stats in severity_stats.iterrows():
                    print(f"  {severity}: {stats['mean']:.2f} jours ({stats['count']} CVEs)")

        return combined_df

    except Exception as e:
        print(f"Erreur lors de la combinaison des données: {str(e)}")
        return None


# Exemple d'utilisation
if __name__ == "__main__":
    scores_file = "results/2-liste_cve_scores-nist-mitre.csv"
    correction_time_file = "results/24-calculate_cve_resolution_time-mitre.csv"
    output_file = "results/25-fusion_2_24-tmcpv.csv"

    combined_data = combine_cve_data(scores_file, correction_time_file, output_file)