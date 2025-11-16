import json
import csv
import os


# Fonction pour extraire et afficher les détails des CPE OS à partir du fichier JSON
def extract_os_cpe_details(json_file):
    try:
        # Charger le contenu du fichier JSON
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Liste pour stocker les détails des CPE extraits
        cpe_os_details = []

        # Fonction récursive pour parcourir les enfants
        def extract_from_nodes(nodes):
            for node in nodes:
                # Extraire les CPE dans cpe_match
                cpe_matches = node.get("cpe_match", [])
                for cpe in cpe_matches:
                    cpe_uri = cpe.get("cpe23Uri", None)
                    if cpe_uri and cpe_uri.startswith("cpe:2.3:o:"):  # Filtrer uniquement les CPE OS
                        # Analyser les détails (vendeur, produit)
                        parts = cpe_uri.split(":")
                        vendor = parts[3] if len(parts) > 3 else "Unknown"
                        product = parts[4] if len(parts) > 4 else "Unknown"

                        # Ajouter les détails à la liste
                        cpe_os_details.append({
                            'Vendor': vendor,
                            'Product': product,
                        })

                # Si des enfants existent, appliquer la fonction récursivement
                if "children" in node and node["children"]:
                    extract_from_nodes(node["children"])

        # Parcourir les CVE_Items
        for item in data.get("CVE_Items", []):
            configurations = item.get("configurations", {})
            nodes = configurations.get("nodes", [])

            # Appeler la fonction récursive pour extraire les CPE des noeuds et de leurs enfants
            extract_from_nodes(nodes)

        return cpe_os_details

    except Exception as e:
        print(f"Une erreur est survenue : {e}")
        return []


# Fonction pour supprimer les doublons en fonction de "Vendor" et "Product"
def remove_duplicates(entries):
    unique_entries = []
    seen = set()
    for entry in entries:
        # Créer une clé unique basée sur Vendor et Product
        key = (entry['Vendor'], entry['Product'])
        if key not in seen:
            seen.add(key)
            unique_entries.append(entry)
    return unique_entries


# Fonction pour écrire un fichier CSV
def write_os_csv_file(os_cpe_details, output_csv_file):
    try:
        # Supprimer les doublons avant de sauvegarder
        unique_entries = remove_duplicates(os_cpe_details)

        # Écrire les détails dans un fichier CSV
        with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Vendor', 'Product']  # Supprimer la colonne Version
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Écrire un en-tête CSV
            writer.writeheader()

            # Ajouter toutes les entrées
            writer.writerows(unique_entries)

        print(f"Fichier CSV créé avec succès : {output_csv_file}")

    except Exception as e:
        print(f"Erreur lors de l'enregistrement du fichier CSV : {e}")


# Spécifier le fichier JSON et le fichier CSV de sortie
#json_file = 'cvelist_nist/nvdcve-1.1-2023.json'  # Remplacez par votre fichier
output_csv_file = 'results/7-liste_vendeurs_o-nist.csv'  # Répertoire et fichier CSV

# Extraire les détails des CPE OS
os_cpe_details = extract_os_cpe_details(json_file)

# Vérifier et afficher les résultats extraits
if os_cpe_details:
    print("Détails des CPE OS extraits (sans doublons ni colonne 'Version') :")
    for entry in os_cpe_details[:10]:  # Afficher les 10 premiers résultats
        print(f"Vendor: {entry['Vendor']}, Product: {entry['Product']}")

    # Créer un fichier CSV contenant les vendeurs de produits OS
    write_os_csv_file(os_cpe_details, output_csv_file)
else:
    print("Aucun détail de CPE OS n'a été extrait.")
