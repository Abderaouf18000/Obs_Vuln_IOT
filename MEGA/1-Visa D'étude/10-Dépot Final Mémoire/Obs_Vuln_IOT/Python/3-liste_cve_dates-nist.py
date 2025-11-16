import json
import csv


# Fonction pour extraire les CVE_ID, date de publication et date de modification
def extract_cve_dates(json_file, output_csv_file):
    try:
        # Lecture du contenu du fichier JSON
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Accède à la liste des CVE_Items
        cve_items = data.get("CVE_Items", [])

        # Liste pour stocker les données à sauvegarder
        extracted_data = []

        for item in cve_items:
            # Extraction de l'ID CVE
            cve_id = item['cve']['CVE_data_meta']['ID']

            # Extraction des dates de publication et de modification
            published_date = item.get("publishedDate", "N/A")
            last_modified_date = item.get("lastModifiedDate", "N/A")

            # Ajout des données extraites dans la liste
            extracted_data.append([cve_id, published_date, last_modified_date])

        # Enregistrement des données dans le fichier CSV
        with open(output_csv_file, 'w', encoding='utf-8', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Écriture de l'en-tête
            csv_writer.writerow(['CVE_ID', 'PublishedDate', 'LastModifiedDate'])
            # Écriture des données
            csv_writer.writerows(extracted_data)

        print(f"Données extraites avec succès dans le fichier : {output_csv_file}")

    except Exception as e:
        print(f"Une erreur est survenue : {e}")


# Spécifiez les fichiers JSON en entrée et CSV en sortie
#json_file = 'cvelist_nist/nvdcve-1.1-2023.json'  # Remplacez par votre fichier JSON
output_csv_file = 'results/3-liste_cve_dates-nist.csv'

# Appelle la fonction pour extraire les données et les sauvegarder dans un fichier CSV
extract_cve_dates(json_file, output_csv_file)
