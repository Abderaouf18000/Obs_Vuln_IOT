import pandas as pd
import csv
from collections import Counter

def count_vulnerabilities_by_vendor(input_file, output_file):
    try:
        # Lire le fichier CSV
        df = pd.read_csv(input_file)

        # Vérifier si les colonnes nécessaires existent
        required_columns = ['Vendor', 'CVE_ID']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"La colonne '{col}' est manquante dans le fichier CSV")

        # Compter les vulnérabilités uniques par vendeur
        vendor_vuln_counts = {}

        # Grouper par Vendor et compter les CVE_ID uniques
        vendor_groups = df.groupby('Vendor')['CVE_ID'].unique()

        for vendor, cve_ids in vendor_groups.items():
            vendor_vuln_counts[vendor] = len(cve_ids)

        # Trier les résultats par nombre de vulnérabilités (ordre décroissant)
        sorted_vendors = sorted(vendor_vuln_counts.items(), key=lambda x: x[1], reverse=True)

        # Écrire les résultats dans un nouveau fichier CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Vendor', 'Vulnerabilities_Count'])
            for vendor, count in sorted_vendors:
                writer.writerow([vendor, count])

        print(f"Résultats enregistrés dans {output_file}")
        print(f"Total des vendeurs traités: {len(sorted_vendors)}")

        # Afficher les 10 premiers vendeurs avec le plus de vulnérabilités
        print("\nTop 10 des vendeurs avec le plus de vulnérabilités:")
        for i, (vendor, count) in enumerate(sorted_vendors[:10], 1):
            print(f"{i}. {vendor}: {count} vulnérabilités")

        return sorted_vendors

    except Exception as e:
        print(f"Erreur lors du traitement du fichier: {e}")
        return None


# Utiliser la fonction
if __name__ == "__main__":
    input_file = "results/6-liste_vendeurs_h-nist.csv"
    output_file = "results/9-count_nbr_vuln_vendeur-nist.csv"

    count_vulnerabilities_by_vendor(input_file, output_file)