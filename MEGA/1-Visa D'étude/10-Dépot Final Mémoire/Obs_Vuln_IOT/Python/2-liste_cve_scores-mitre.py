import json
import csv
import os
import glob


# Fonction pour extraire les CVE_ID, scores CVSS v3 et classification
def extract_cve_scores_from_folder(json_folder, output_csv_file):
    try:
        # Liste pour stocker les données à sauvegarder
        extracted_data = []

        # Obtenir tous les fichiers JSON dans le dossier
        json_files = glob.glob(os.path.join(json_folder, "*.json"))

        # Nombre total de fichiers
        total_files = len(json_files)
        print(f"Traitement de {total_files} fichiers JSON...")

        # Compteur pour suivre la progression
        counter = 0

        for json_file in json_files:
            counter += 1
            if counter % 100 == 0:
                print(f"Progression: {counter}/{total_files} fichiers traités")

            try:
                # Lecture du contenu du fichier JSON
                with open(json_file, 'r', encoding='utf-8') as file:
                    data = json.load(file)

                # Obtenir l'ID CVE à partir des métadonnées
                cve_id = data.get("cveMetadata", {}).get("cveId")

                # Variables pour stocker les informations extraites
                score_cvss3 = None
                severity = "N/A"

                # Chercher les métriques CVSS dans les conteneurs
                if "containers" in data and "cna" in data["containers"]:
                    metrics = data["containers"]["cna"].get("metrics", [])

                    for metric in metrics:
                        # Vérifier s'il y a des métriques CVSS V3.1
                        if "cvssV3_1" in metric:
                            cvss_data = metric["cvssV3_1"]
                            score_cvss3 = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity", "N/A")
                            break
                        # Si pas de CVSS V3.1, chercher CVSS V3.0
                        elif "cvssV3_0" in metric:
                            cvss_data = metric["cvssV3_0"]
                            score_cvss3 = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity", "N/A")
                            break

                # Si nous avons un ID CVE, ajouter aux données extraites
                if cve_id:
                    extracted_data.append([cve_id, score_cvss3, severity])

            except Exception as e:
                print(f"Erreur lors du traitement du fichier {json_file}: {e}")
                continue

        # Enregistrement des données dans le fichier CSV
        with open(output_csv_file, 'w', encoding='utf-8', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Écriture de l'en-tête
            csv_writer.writerow(['CVE_ID', 'CVSSv3_Score', 'Severity'])
            # Écriture des données
            csv_writer.writerows(extracted_data)

        print(f"Données extraites avec succès dans le fichier : {output_csv_file}")
        print(f"Nombre total de CVE traités : {len(extracted_data)}")

    except Exception as e:
        print(f"Une erreur est survenue : {e}")


# Spécifiez le dossier contenant les fichiers JSON et le fichier CSV en sortie
#json_folder = 'cvelist_mitre_2023/'
output_csv_file = 'results/2-liste_cve_scores-mitre.csv'

# Appelle la fonction pour extraire les données et les sauvegarder dans un fichier CSV
extract_cve_scores_from_folder(json_folder, output_csv_file)