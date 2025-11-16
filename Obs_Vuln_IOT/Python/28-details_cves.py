import json
import csv
import os
from datetime import datetime


def convert_cve_json_to_csv(json_file_path, output_csv_path=None):
    """
    Convertit un fichier JSON contenant des données CVE en un fichier CSV

    Args:
        json_file_path (str): Chemin vers le fichier JSON contenant les données CVE
        output_csv_path (str, optional): Chemin pour le fichier CSV de sortie.
                                        Si non spécifié, utilise le même nom que le fichier d'entrée avec l'extension .csv

    Returns:
        str: Chemin du fichier CSV créé
    """
    # Déterminer le chemin de sortie si non spécifié
    if output_csv_path is None:
        base_name = os.path.splitext(json_file_path)[0]
        output_csv_path = f"{base_name}.csv"

    # Charger les données JSON
    try:
        with open(json_file_path, 'r', encoding='utf-8') as file:
            json_data = json.load(file)
    except json.JSONDecodeError:
        print(f"Erreur: Le fichier {json_file_path} n'est pas un JSON valide.")
        return None
    except FileNotFoundError:
        print(f"Erreur: Le fichier {json_file_path} n'a pas été trouvé.")
        return None

    # Vérifier la structure du fichier JSON
    cve_items = None

    # Vérifier différentes structures possibles de fichier CVE
    if 'CVE_Items' in json_data:
        cve_items = json_data['CVE_Items']
    elif 'CVE_data_numberOfCVEs' in json_data and 'CVE_Items' in json_data:
        cve_items = json_data['CVE_Items']
    elif isinstance(json_data, list):
        cve_items = json_data
    else:
        print("Structure de données CVE non reconnue.")
        return None

    # Préparer l'écriture du CSV
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)

        # Écrire l'en-tête
        csv_writer.writerow(['CVE_ID', 'Description', 'Date_Publication', 'Date_Modification'])

        # Parcourir chaque entrée CVE
        for item in cve_items:
            cve_id = None
            description = "Non disponible"
            published_date = "Non disponible"
            last_modified_date = "Non disponible"

            # Extraire l'ID CVE
            if 'cve' in item and 'CVE_data_meta' in item['cve'] and 'ID' in item['cve']['CVE_data_meta']:
                cve_id = item['cve']['CVE_data_meta']['ID']

            # Extraire la description
            if 'cve' in item and 'description' in item['cve'] and 'description_data' in item['cve']['description']:
                for desc_data in item['cve']['description']['description_data']:
                    if desc_data.get('lang') == 'en':
                        description = desc_data.get('value', 'Non disponible')
                        break

            # Extraire les dates
            if 'publishedDate' in item:
                published_date = item['publishedDate']

            if 'lastModifiedDate' in item:
                last_modified_date = item['lastModifiedDate']

            # Formater les dates si nécessaire
            try:
                if published_date != "Non disponible":
                    published_date = datetime.strptime(published_date, "%Y-%m-%dT%H:%M%z").strftime("%Y-%m-%d")
            except (ValueError, TypeError):
                pass

            try:
                if last_modified_date != "Non disponible":
                    last_modified_date = datetime.strptime(last_modified_date, "%Y-%m-%dT%H:%M%z").strftime("%Y-%m-%d")
            except (ValueError, TypeError):
                pass

            # Écrire la ligne dans le CSV
            if cve_id:  # Seulement écrire les entrées avec un ID CVE valide
                csv_writer.writerow([cve_id, description, published_date, last_modified_date])

    print(f"Conversion terminée. Fichier CSV créé: {output_csv_path}")
    return output_csv_path


# Exemple d'utilisation
if __name__ == "__main__":
    #json_file = "cvelist_nist/nvdcve-1.1-2019.json"
    output_file = "results/28-details_cves.csv"
    convert_cve_json_to_csv(json_file, output_file)