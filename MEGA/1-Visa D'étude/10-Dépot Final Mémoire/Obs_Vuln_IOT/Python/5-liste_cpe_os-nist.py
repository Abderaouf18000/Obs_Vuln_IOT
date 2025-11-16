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
                    if cpe_uri and cpe_uri.startswith("cpe:2.3:o"):  # Filtrer uniquement les CPE OS
                        # Analyser les détails (vendeur, produit, version)
                        parts = cpe_uri.split(":")
                        vendor = parts[3] if len(parts) > 3 else "Unknown"
                        product = parts[4] if len(parts) > 4 else "Unknown"
                        version = parts[5] if len(parts) > 5 else "Unknown"

                        # Ajouter les détails à la liste
                        cpe_os_details.append({
                            'Vendor': vendor,
                            'Product': product,
                            'Version': version
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


# Fonction pour supprimer les doublons en fonction de "Product" uniquement
def remove_duplicates_by_product(entries):
    unique_entries = []
    seen_products = set()  # Utilisation d'un set pour garder une trace des produits déjà vus
    for entry in entries:
        product = entry['Product']
        if product not in seen_products:
            seen_products.add(product)  # Marquer ce produit comme déjà vu
            unique_entries.append(entry)  # Ajouter l'entrée unique à la liste
    return unique_entries


# Fonction pour écrire un fichier CSV pour chaque vendeur, avec l'en-tête "Product OS"
def write_vendor_csv_files(os_cpe_details, output_dir):
    # Créer un répertoire de sortie s'il n'existe pas encore
    os.makedirs(output_dir, exist_ok=True)

    # Grouper les données par vendeur
    vendor_data = {}
    for entry in os_cpe_details:
        vendor = entry["Vendor"]
        if vendor not in vendor_data:
            vendor_data[vendor] = []
        vendor_data[vendor].append(entry)

    # Créer un fichier CSV pour chaque vendeur
    for vendor, entries in vendor_data.items():
        # Supprimer les doublons en fonction de "Product" uniquement
        unique_entries = remove_duplicates_by_product(entries)

        # Générer un nom de fichier basé sur le vendeur
        safe_vendor_name = vendor.replace(" ", "_").replace("/", "_")
        csv_file = os.path.join(output_dir, f"{safe_vendor_name}.csv")

        # Sauvegarder uniquement le champ "Product OS" dans le fichier CSV
        with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Product OS']  # Changer l'en-tête de colonne
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            # Écrire uniquement la valeur de la clé "Product", avec l'en-tête "Product OS"
            for entry in unique_entries:
                writer.writerow({'Product OS': entry['Product']})

        print(f"Fichier CSV créé pour {vendor} : {csv_file}")

def vider_dossier(chemin_dossier):
    """
    Vide le contenu d'un dossier sans supprimer le dossier lui-même.

    Args:
        chemin_dossier: Chemin du dossier à vider
    """
    import shutil
    import os

    # Vérifier si le dossier existe
    if os.path.exists(chemin_dossier):
        # Supprimer tous les fichiers et sous-dossiers
        for fichier in os.listdir(chemin_dossier):
            chemin_complet = os.path.join(chemin_dossier, fichier)
            if os.path.isfile(chemin_complet):
                os.unlink(chemin_complet)
            elif os.path.isdir(chemin_complet):
                shutil.rmtree(chemin_complet)
        print(f"Dossier vidé: {chemin_dossier}")
    else:
        # Créer le dossier s'il n'existe pas
        os.makedirs(chemin_dossier, exist_ok=True)
        print(f"Dossier créé: {chemin_dossier}")

# Spécifier le fichier JSON et le répertoire de sortie
#json_file = 'cvelist_nist/nvdcve-1.1-2023.json'  # Remplacez par votre fichier
output_dir = 'results/4-vendeurs/o'  # Répertoire où les fichiers CSV des vendeurs seront enregistrés
vider_dossier(output_dir)

# Extraire les détails des OS CPE
os_cpe_details = extract_os_cpe_details(json_file)

# Vérifier et afficher les résultats extraits
if os_cpe_details:
    print("Détails des CPE OS extraits :")
    for entry in os_cpe_details[:10]:  # Affichez seulement les 10 premiers pour aperçu
        print(f"Vendor : {entry['Vendor']}, Product : {entry['Product']}, Version : {entry['Version']}")

    # Créer un fichier CSV pour chaque vendeur, avec l'en-tête "Product OS"
    write_vendor_csv_files(os_cpe_details, output_dir)
else:
    print("Aucun détail de CPE OS n'a été extrait.")
