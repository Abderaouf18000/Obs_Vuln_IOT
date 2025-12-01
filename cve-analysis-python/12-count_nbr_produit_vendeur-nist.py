import os
import pandas as pd
import csv


def count_products_by_vendor(directory_path, output_file):
    try:
        # Vérifier si le chemin existe
        if not os.path.exists(directory_path):
            print(f"Le dossier {directory_path} n'existe pas.")
            return None

        # Vérifier si le chemin est un dossier
        if not os.path.isdir(directory_path):
            print(f"{directory_path} n'est pas un dossier.")
            return None

        # Dictionnaire pour stocker les résultats
        vendor_product_counts = {}

        # Parcourir tous les fichiers du dossier
        for filename in os.listdir(directory_path):
            if filename.lower().endswith('.csv'):
                # Extraire le nom du vendeur du nom de fichier (sans l'extension .csv)
                vendor_name = os.path.splitext(filename)[0]

                # Lire le fichier CSV
                file_path = os.path.join(directory_path, filename)
                try:
                    df = pd.read_csv(file_path)

                    # Compter le nombre de produits (nombre de lignes)
                    product_count = len(df)

                    # Stocker le résultat
                    vendor_product_counts[vendor_name] = product_count

                    print(f"Vendeur {vendor_name}: {product_count} produits")

                except Exception as e:
                    print(f"Erreur lors de la lecture de {filename}: {e}")

        # Trier les résultats par nombre de produits (ordre décroissant)
        sorted_vendors = sorted(vendor_product_counts.items(), key=lambda x: x[1], reverse=True)

        # Écrire les résultats dans un fichier CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Vendor', 'Products_Count'])
            for vendor, count in sorted_vendors:
                writer.writerow([vendor, count])

        print(f"\nRésultats enregistrés dans {output_file}")
        print(f"Total des vendeurs traités: {len(sorted_vendors)}")

        # Afficher le top 10 des vendeurs avec le plus de produits
        if sorted_vendors:
            print("\nTop 10 des vendeurs avec le plus de produits:")
            for i, (vendor, count) in enumerate(sorted_vendors[:10], 1):
                print(f"{i}. {vendor}: {count} produits")

        return sorted_vendors

    except Exception as e:
        print(f"Une erreur s'est produite: {e}")
        return None


# Exemple d'utilisation
if __name__ == "__main__":
    directory = "results/4-vendeurs/h"  # Dossier contenant les fichiers CSV des vendeurs
    output_file = "results/10-count_nbr_produit_vendeur-nist.csv"  # Fichier de sortie

    count_products_by_vendor(directory, output_file)