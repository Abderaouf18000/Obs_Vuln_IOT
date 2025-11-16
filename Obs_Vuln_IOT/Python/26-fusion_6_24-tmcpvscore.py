import pandas as pd
import os
import time


def merge_csv_files_without_vendor_cve_redundancy(vendor_products_file, cve_details_file, output_file):
    """
    Fusionne deux fichiers CSV sur la colonne CVE_ID en éliminant les redondances de CVE_ID par vendeur.

    Args:
        vendor_products_file (str): Fichier CSV avec les colonnes Vendor, Product, CVE_ID
        cve_details_file (str): Fichier CSV avec CVE_ID, CVSSv3_Score, Severity, Temps_de_correction
        output_file (str): Fichier CSV de sortie avec les données fusionnées sans redondance
    """
    start_time = time.time()

    # Charger les fichiers
    print(f"Chargement du fichier {vendor_products_file}...")
    vendor_df = pd.read_csv(vendor_products_file)

    print(f"Chargement du fichier {cve_details_file}...")
    details_df = pd.read_csv(cve_details_file)

    # Eliminer les redondances de CVE_ID par vendeur
    print("Elimination des redondances de CVE_ID par vendeur...")
    # Garder uniquement la première occurrence de chaque combinaison Vendor-CVE_ID
    vendor_df_unique = vendor_df.drop_duplicates(subset=['Vendor', 'CVE_ID'])

    # Afficher le nombre de lignes supprimées
    redundant_rows = len(vendor_df) - len(vendor_df_unique)
    print(f"Nombre de redondances supprimées: {redundant_rows}")

    # Fusionner sur CVE_ID
    print("Fusion des données...")
    merged_df = pd.merge(vendor_df_unique, details_df, on='CVE_ID', how='left')

    # Supprimer les colonnes spécifiées si nécessaire
    print("Suppression des colonnes Product et CVSSv3_Score...")
    columns_to_drop = ['Product', 'CVSSv3_Score']
    merged_df = merged_df.drop(columns=columns_to_drop, errors='ignore')

    # Créer le dossier de sortie si nécessaire
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Enregistrer le résultat
    print(f"Enregistrement dans {output_file}...")
    merged_df.to_csv(output_file, index=False)

    end_time = time.time()
    print(f"Terminé en {end_time - start_time:.2f} secondes")
    print(f"Nombre de lignes dans le fichier fusionné: {len(merged_df)}")


if __name__ == "__main__":
    # Chemins des fichiers
    vendor_products_file = "results/6-liste_vendeurs_h-nist.csv"
    cve_details_file = "results/25-fusion_2_24-tmcpv.csv"
    output_file = "results/26-fusion_6_24-tmcpvscore.csv"

    # Exécuter la fusion
    merge_csv_files_without_vendor_cve_redundancy(vendor_products_file, cve_details_file, output_file)