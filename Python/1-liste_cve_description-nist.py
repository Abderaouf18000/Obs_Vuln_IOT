import json
import csv

# Fonction principale pour traiter le fichier JSON
def extract_cve_data(json_file, output_csv_file):
    try:
        # Charge le contenu du fichier JSON
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Accède à la liste des CVE_Items
        cve_items = data.get("CVE_Items", [])

        # Stocke les données extraites (CVE_ID et descriptions) dans une liste
        extracted_data = []
        for item in cve_items:
            cve_id = item['cve']['CVE_data_meta']['ID']  # Extraction de l'ID CVE
            # Extraction de la description en anglais
            description_data = item['cve']['description']['description_data']
            description = ""
            for desc in description_data:
                if desc['lang'] == "en":  # Vérifie si la description est en anglais
                    description = desc['value']
                    break
            extracted_data.append([cve_id, description])

        # Enregistre les données extraites dans un fichier CSV
        with open(output_csv_file, 'w', encoding='utf-8', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Écriture de l'en-tête
            csv_writer.writerow(['CVE_ID', 'Description'])
            # Écriture des données
            csv_writer.writerows(extracted_data)

        print(f"Données extraites avec succès dans le fichier : {output_csv_file}")

    except Exception as e:
        print(f"Une erreur est survenue : {e}")


# Nom du fichier JSON en entrée et CSV en sortie
#json_file = 'cvelist_nist/nvdcve-1.1-2023.json'  # Remplacez par le nom ou le chemin de votre fichier JSON
output_csv_file = 'results/1-liste_cve_descrition-nist.csv'

# Appelle la fonction pour extraire les données et écrire le fichier CSV
extract_cve_data(json_file, output_csv_file)
