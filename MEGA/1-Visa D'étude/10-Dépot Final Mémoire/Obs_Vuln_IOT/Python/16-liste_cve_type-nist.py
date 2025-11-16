import json
import csv
import os


def extract_vuln_types(json_file, output_csv_file):
    """
    Extrait les types de vulnérabilités (CWE) à partir d'un fichier JSON au format NIST NVD
    et les sauvegarde dans un fichier CSV.

    Args:
        json_file (str): Chemin vers le fichier JSON contenant les données CVE
        output_csv_file (str): Chemin pour le fichier CSV de sortie
    """
    try:
        # Lecture du contenu du fichier JSON
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Accède à la liste des CVE_Items
        cve_items = data.get("CVE_Items", [])

        # Liste pour stocker les données extraites
        extracted_data = []

        for item in cve_items:
            # Extraction de l'ID CVE
            cve_id = item['cve']['CVE_data_meta']['ID']

            # Initialisation des variables pour stocker les informations sur les types de vulnérabilités
            cwe_ids = []

            # Extraction des types de vulnérabilités (CWE)
            if "problemtype" in item['cve'] and "problemtype_data" in item['cve']['problemtype']:
                for problemtype in item['cve']['problemtype']['problemtype_data']:
                    if "description" in problemtype:
                        for desc in problemtype['description']:
                            if "value" in desc and desc.get("lang", "") == "en":
                                value = desc['value']
                                # Vérifier si le value contient un CWE ID
                                if value.startswith('CWE-'):
                                    # Extraire uniquement l'identifiant CWE (par exemple, CWE-79)
                                    cwe_id = value.split()[0]
                                    cwe_ids.append(cwe_id)

            # Si aucun CWE n'est trouvé, utiliser "Unknown" comme valeur par défaut
            if not cwe_ids:
                cwe_ids = [" "]

            # Ajout des données extraites dans la liste
            for cwe_id in cwe_ids:
                extracted_data.append([cve_id, cwe_id])

        # Enregistrement des données dans le fichier CSV
        with open(output_csv_file, 'w', encoding='utf-8', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Écriture de l'en-tête
            csv_writer.writerow(['CVE_ID', 'CWE_ID'])
            # Écriture des données
            csv_writer.writerows(extracted_data)

        print(f"Extraction des types de vulnérabilités terminée avec succès! {len(extracted_data)} entrées extraites.")
        print(f"Résultat sauvegardé dans le fichier : {output_csv_file}")

    except Exception as e:
        print(f"Une erreur est survenue : {e}")


# Spécifiez les fichiers JSON en entrée et CSV en sortie
#json_file = 'cvelist_nist/nvdcve-1.1-2023.json'  # Remplacez par votre fichier JSON
output_csv_file = 'results/16-liste_cve_type-nist.csv'

# Création du dossier de résultats si nécessaire
output_dir = os.path.dirname(output_csv_file)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Appelle la fonction pour extraire les données et les sauvegarder dans un fichier CSV
extract_vuln_types(json_file, output_csv_file)