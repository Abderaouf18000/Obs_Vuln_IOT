import pandas as pd
import numpy as np


def analyze_correction_times(input_file, output_file):
    # Lire le fichier CSV
    df = pd.read_csv(input_file)

    print("\n=== DIAGNOSTICS ===")
    print(f"Nombre total de lignes : {len(df)}")
    print(f"Colonnes présentes : {df.columns.tolist()}")
    print(f"Premiers enregistrements :")
    print(df.head())

    # Assurer que Severity est une chaîne de caractères
    df['Severity'] = df['Severity'].astype(str).str.upper()

    # Assurer que Temps_de_correction est numérique
    df['Temps_de_correction'] = pd.to_numeric(df['Temps_de_correction'], errors='coerce')

    print(f"Valeurs uniques dans Severity : {sorted(df['Severity'].unique())}")
    print(f"Top 10 vendeurs par nombre d'enregistrements :")
    print(df['Vendor'].value_counts().head(10))
    print(f"Valeurs manquantes par colonne :")
    print(df.isna().sum())
    print("=====================")

    # Après normalisation, vérifier les valeurs uniques
    severity_values = sorted(df['Severity'].unique())
    print(f"Valeurs uniques dans Severity après normalisation : {severity_values}")

    # Initialiser une liste pour stocker les résultats
    results_list = []

    # Récupérer la liste unique des vendeurs
    vendors = df['Vendor'].unique()

    # Pour chaque vendeur, calculer les temps moyens par niveau de sévérité
    for vendor in vendors:
        vendor_data = df[df['Vendor'] == vendor]

        row = {'Vendor': vendor}

        # Adapter dynamiquement les valeurs de sévérité présentes
        standard_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        severities_to_check = []

        for sev in standard_severities:
            if sev in severity_values:
                severities_to_check.append(sev)

        # Si aucune des valeurs standard n'est présente, utiliser celles trouvées
        if not severities_to_check:
            # Exclure 'nan' ou 'NAN' qui pourraient être présents
            severities_to_check = [s for s in severity_values if s.lower() != 'nan']

        print(f"Recherche des sévérités : {severities_to_check} pour le vendeur {vendor}")

        # Calculer pour chaque niveau de sévérité
        has_data = False
        for severity in severities_to_check:
            severity_data = vendor_data[vendor_data['Severity'] == severity]

            if len(severity_data) > 0:
                # Calculer la moyenne des temps de correction
                mean_time = severity_data['Temps_de_correction'].mean()
                count = len(severity_data)

                row[f'{severity}_avg'] = round(mean_time, 2)
                row[f'{severity}_count'] = int(count)  # Assurez-vous que c'est un int
                has_data = True
            else:
                row[f'{severity}_avg'] = np.nan
                row[f'{severity}_count'] = 0

        # Ajouter la ligne uniquement si des données ont été trouvées
        if has_data:
            results_list.append(row)

    # Vérifier si des résultats ont été obtenus
    if not results_list:
        print("ATTENTION: Aucun résultat n'a été trouvé avec les critères spécifiés!")
        return None, None

    # Créer le dataframe des résultats à partir de la liste
    results_df = pd.DataFrame(results_list)

    # Trier par nombre total de rapports (somme des comptes)
    count_columns = [col for col in results_df.columns if col.endswith('_count')]

    # Assurez-vous que toutes les colonnes de comptage sont numériques
    for col in count_columns:
        results_df[col] = pd.to_numeric(results_df[col], errors='coerce').fillna(0).astype(int)

    results_df['Total_count'] = results_df[count_columns].sum(axis=1)
    results_df = results_df.sort_values(by='Total_count', ascending=False)

    # Enregistrer les résultats dans un nouveau fichier CSV
    results_df.to_csv(output_file, index=False)

    print(f"Colonnes dans le DataFrame résultant : {results_df.columns.tolist()}")

    # Statistiques globales
    global_stats = {
        'Total_vendors': len(results_list)
    }

    # Ajouter des statistiques pour chaque niveau de sévérité présent
    for severity in severities_to_check:
        avg_col = f'{severity}_avg'
        count_col = f'{severity}_count'

        if avg_col in results_df.columns:
            global_stats[f'{severity}_avg'] = results_df[avg_col].mean()
            global_stats[f'{severity}_vendors'] = (results_df[count_col] > 0).sum()

    return results_df, global_stats


if __name__ == "__main__":
    input_file = "results/26-fusion_6_24-tmcpvscore.csv"
    output_file = "results/27-traitment_26.csv"

    results, stats = analyze_correction_times(input_file, output_file)

    if results is None:
        print("Aucun résultat n'a été généré. Vérifiez le fichier d'entrée.")
    else:
        print(f"Analyse terminée. Résultats enregistrés dans {output_file}")
        print(f"\nStatistiques globales:")
        print(f"Nombre total de vendeurs: {stats['Total_vendors']}")

        # Afficher les statistiques disponibles
        for key, value in stats.items():
            if key.endswith('_avg'):
                severity = key.replace('_avg', '')
                print(
                    f"Temps moyen de correction ({severity}): {value:.2f} jours ({stats.get(f'{severity}_vendors', 0)} vendeurs)")

        # Afficher les 10 premiers vendeurs par nombre total de rapports
        print("\nTop 10 des vendeurs par nombre de rapports:")
        top10 = results.head(10)
        for _, row in top10.iterrows():
            print(f"{row['Vendor']} (Total: {int(row['Total_count'])} rapports)")

            # Parcourir dynamiquement les colonnes de moyenne
            for col in row.index:
                if col.endswith('_avg') and not pd.isna(row[col]):
                    severity = col.replace('_avg', '')
                    count_col = f"{severity}_count"
                    if count_col in row.index:
                        print(f"  {severity}: {row[col]:.2f} jours ({int(row[count_col])} rapports)")
            print("")