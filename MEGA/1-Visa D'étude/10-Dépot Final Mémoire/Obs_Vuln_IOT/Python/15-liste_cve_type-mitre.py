import os
import json
import csv


def extract_vulnerability_types(folder_path, output_csv):
    cve_types = []

    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(folder_path, filename)

            with open(file_path, "r", encoding="utf-8") as file:
                try:
                    data = json.load(file)
                    cve_id = data.get("cveMetadata", {}).get("cveId", "Unknown")

                    problem_types = data.get("containers", {}).get("cna", {}).get("problemTypes", [])
                    cwe_list = [desc.get("description", "Unknown") for p in problem_types for desc in
                                p.get("descriptions", [])]

                    # Remplacer "N/A", "unknown" (avec des variantes de casse) et autres valeurs par une chaîne vide
                    cwe_list = [cwe if cwe.strip().lower() not in ["n/a", "unknown"] else "" for cwe in cwe_list]

                    # Si la liste est vide, assigner une valeur vide par défaut
                    if not cwe_list:
                        cwe_list = [""]

                    for cwe in cwe_list:
                        cve_types.append((cve_id, cwe))

                except json.JSONDecodeError:
                    print(f"Erreur lors de la lecture du fichier {filename}")

    # Trier les résultats par CVE-ID
    cve_types.sort(key=lambda x: x[0])

    # Écriture dans un fichier CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["CVE-ID", "Type de Vulnérabilité (CWE)"])
        writer.writerows(cve_types)

    print(f"Extraction terminée. Résultats enregistrés dans '{output_csv}'.")


# 📌 Spécifiez le dossier contenant les fichiers JSON et le fichier de sortie CSV
#folder_path = "cvelist_mitre_2023"
output_csv = "results/15-liste_cve_type-mitres.csv"

extract_vulnerability_types(folder_path, output_csv)