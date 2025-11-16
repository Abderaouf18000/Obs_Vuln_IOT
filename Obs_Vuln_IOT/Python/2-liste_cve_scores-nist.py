import json
import csv


# Fonction pour extraire les CVE_ID, scores CVSS v3 et classification
def extract_cve_scores(json_file, output_csv_file):
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

            # Extraction du score CVSS v3 (s'il existe)
            score_cvss3 = None
            severity = "N/A"  # Par défaut, si aucun score n'est disponible
            if "impact" in item and "baseMetricV3" in item["impact"]:
                score_cvss3 = item["impact"]["baseMetricV3"].get("cvssV3", {}).get("baseScore", None)

                # Déterminer la classification de la vulnérabilité (severity) en fonction du score
                if score_cvss3 is not None:
                    if 0.1 <= score_cvss3 <= 3.9:
                        severity = "LOW"
                    elif 4.0 <= score_cvss3 <= 6.9:
                        severity = "MEDIUM"
                    elif 7.0 <= score_cvss3 <= 8.9:
                        severity = "HIGH"
                    elif 9.0 <= score_cvss3 <= 10.0:
                        severity = "CRITICAL"

            # Ajout des données extraites dans la liste
            extracted_data.append([cve_id, score_cvss3, severity])

        # Enregistrement des données dans le fichier CSV
        with open(output_csv_file, 'w', encoding='utf-8', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Écriture de l'en-tête
            csv_writer.writerow(['CVE_ID', 'CVSSv3_Score', 'Severity'])
            # Écriture des données
            csv_writer.writerows(extracted_data)

        print(f"Données extraites avec succès dans le fichier : {output_csv_file}")

    except Exception as e:
        print(f"Une erreur est survenue : {e}")


# Spécifiez les fichiers JSON en entrée et CSV en sortie
#json_file = 'cvelist_nist/nvdcve-1.1-2023.json'  # Remplacez par votre fichier JSON
output_csv_file = 'results/2-liste_cve_scores-nist.csv'

# Appelle la fonction pour extraire les données et les sauvegarder dans un fichier CSV
extract_cve_scores(json_file, output_csv_file)