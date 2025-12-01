import pandas as pd
import os


def merge_cve_scores(mitre_file, nist_file, output_file):
    """
    Fusionne deux fichiers CSV de scores CVE en complétant les scores manquants
    et en combinant toutes les entrées en une seule liste plus complète.

    Args:
        mitre_file (str): Chemin vers le fichier CSV des scores MITRE
        nist_file (str): Chemin vers le fichier CSV des scores NIST
        output_file (str): Chemin pour le fichier CSV fusionné de sortie
    """
    try:
        # Charger les deux fichiers CSV
        print(f"Chargement des données MITRE de {mitre_file}...")
        mitre_data = pd.read_csv(mitre_file)

        print(f"Chargement des données NIST de {nist_file}...")
        nist_data = pd.read_csv(nist_file)

        # Statistiques initiales
        print("\nStatistiques initiales:")
        print(f"Entrées MITRE: {len(mitre_data)}")
        print(f"Entrées NIST: {len(nist_data)}")
        print(f"Entrées MITRE avec score: {mitre_data['CVSSv3_Score'].notna().sum()}")
        print(f"Entrées MITRE sans score: {mitre_data['CVSSv3_Score'].isna().sum()}")

        # Convertir NaN en None pour faciliter la fusion
        mitre_data = mitre_data.where(pd.notna(mitre_data), None)
        nist_data = nist_data.where(pd.notna(nist_data), None)

        # Créer un dictionnaire des données NIST pour un accès plus rapide
        nist_dict = {row['CVE_ID']: row for _, row in nist_data.iterrows()}

        # Compléter les scores manquants dans MITRE avec ceux de NIST
        scores_completed = 0

        # Créer une copie des données MITRE pour la fusion
        merged_data = mitre_data.copy()

        for index, row in merged_data.iterrows():
            cve_id = row['CVE_ID']

            # Si pas de score dans MITRE mais présent dans NIST
            if (pd.isna(row['CVSSv3_Score']) or row['CVSSv3_Score'] == 'N/A') and cve_id in nist_dict:
                nist_row = nist_dict[cve_id]
                if not pd.isna(nist_row['CVSSv3_Score']) and nist_row['CVSSv3_Score'] != 'N/A':
                    merged_data.at[index, 'CVSSv3_Score'] = nist_row['CVSSv3_Score']
                    merged_data.at[index, 'Severity'] = nist_row['Severity']
                    scores_completed += 1

        # Identifier les entrées uniquement dans NIST
        mitre_ids = set(mitre_data['CVE_ID'])
        nist_only = nist_data[~nist_data['CVE_ID'].isin(mitre_ids)]

        # Fusionner les données
        final_data = pd.concat([merged_data, nist_only], ignore_index=True)

        # Statistiques finales
        final_without_score = final_data['CVSSv3_Score'].isna().sum()

        print("\nStatistiques de fusion:")
        print(f"Scores complétés depuis NIST: {scores_completed}")
        print(f"Entrées ajoutées depuis NIST: {len(nist_only)}")
        print(f"Total final d'entrées: {len(final_data)}")
        print(f"Entrées finales sans score: {final_without_score}")

        # Remplacer les scores manquants par 0
        final_data['CVSSv3_Score'] = final_data['CVSSv3_Score'].fillna(0)

        # Vérifier s'il reste des scores manquants après remplacement
        remaining_nulls = final_data['CVSSv3_Score'].isna().sum()
        if remaining_nulls > 0:
            print(f"ATTENTION: {remaining_nulls} scores sont toujours null après remplacement")
        else:
            print("Tous les scores manquants ont été remplacés par 0")

        # Sauvegarder les données fusionnées
        print(f"\nSauvegarde des données fusionnées dans {output_file}...")
        final_data.to_csv(output_file, index=False)

        print(f"Fusion terminée avec succès. Le fichier a été sauvegardé dans {output_file}")

        return final_data

    except Exception as e:
        print(f"Une erreur est survenue lors de la fusion: {e}")
        return None


# Exemple d'utilisation
if __name__ == "__main__":
    # Chemins des fichiers (à modifier selon vos besoins)
    mitre_file = "results/2-liste_cve_scores-mitre.csv"
    nist_file = "results/2-liste_cve_scores-nist.csv"
    output_file = "results/2-liste_cve_scores-nist-mitre.csv"

    # Créer le dossier de résultats s'il n'existe pas
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Exécuter la fusion
    merged_data = merge_cve_scores(mitre_file, nist_file, output_file)

    # Afficher un exemple des 5 premières lignes du résultat
    if merged_data is not None:
        print("\nAperçu des données fusionnées (5 premières lignes):")
        print(merged_data.head(5))