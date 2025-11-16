import json
import csv
import os


# Fonction pour extraire et afficher les détails des CPE Hardware à partir du fichier JSON
def extract_hardware_cpe_details_and_cve(json_file):
    try:
        # Charger le contenu du fichier JSON
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Liste pour stocker les détails des CPE extraits
        cpe_hardware_details = []

        # Fonction récursive pour parcourir les enfants
        def extract_from_nodes(nodes, cve_id):
            for node in nodes:
                # Extraire les CPE dans cpe_match
                cpe_matches = node.get("cpe_match", [])
                for cpe in cpe_matches:
                    cpe_uri = cpe.get("cpe23Uri", None)
                    if cpe_uri and cpe_uri.startswith("cpe:2.3:h:"):  # Filtrer uniquement les CPE Hardware
                        # Analyser les détails (vendeur, produit)
                        parts = cpe_uri.split(":")
                        vendor = parts[3] if len(parts) > 3 else "Unknown"
                        product = parts[4] if len(parts) > 4 else "Unknown"

                        # Ajouter les détails à la liste, incluant le CVE ID
                        cpe_hardware_details.append({
                            'Vendor': vendor,
                            'Product': product,
                            'CVE_ID': cve_id
                        })

                # Si des enfants existent, appliquer la fonction récursivement
                if "children" in node and node["children"]:
                    extract_from_nodes(node["children"], cve_id)

        # Parcourir les CVE_Items
        for item in data.get("CVE_Items", []):
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unknown CVE")  # Extraire le CVE ID
            nodes = item.get("configurations", {}).get("nodes", [])
            extract_from_nodes(nodes, cve_id)

        return cpe_hardware_details

    except Exception as e:
        print(f"Une erreur est survenue : {e}")
        return []


# Fonction pour supprimer les doublons en fonction de "Vendor", "Product", et "CVE ID"
def remove_duplicates(entries):
    unique_entries = []
    seen = set()
    for entry in entries:
        # Créer une clé unique basée sur Vendor, Product et CVE_ID
        key = (entry['Vendor'], entry['Product'], entry['CVE_ID'])
        if key not in seen:
            seen.add(key)
            unique_entries.append(entry)
    return unique_entries


# Fonction pour écrire un fichier CSV contenant les vendeurs hardware et leurs CVE ID
def write_hardware_csv_file(hardware_cpe_details, output_csv_file):
    try:
        # Supprimer les doublons avant de sauvegarder
        unique_entries = remove_duplicates(hardware_cpe_details)

        # Écrire les détails dans un fichier CSV
        with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Vendor', 'Product', 'CVE_ID']
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
output_csv_file = 'results/6-liste_vendeurs_h-nist.csv'  # Fichier CSV de sortie avec CVE IDs

# Extraire les détails des CPE hardware avec leurs CVE IDs
try:
    hardware_cpe_details = extract_hardware_cpe_details_and_cve(json_file)

    # Vérifier et afficher les résultats extraits
    if hardware_cpe_details:
        print("Détails des CPE hardware extraits (avec CVE IDs) :")
        for entry in hardware_cpe_details[:10]:  # Affichez seulement les 10 premiers résultats pour aperçu
            print(f"Vendor: {entry['Vendor']}, Product: {entry['Product']}, CVE_ID: {entry['CVE_ID']}")

        # Créer un fichier CSV contenant tous les vendeurs hardware avec leurs CVE IDs
        write_hardware_csv_file(hardware_cpe_details, output_csv_file)
    else:
        print("Aucun détail de CPE hardware n'a été extrait.")

except Exception as e:
    print(f"Une erreur générale est survenue : {e}")
