#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extracteur de paires CVE-CWE à partir d'un fichier CSV

Ce script analyse un fichier CSV avec la structure:
- CVE_ID
- Type de Vulnérabilité (CWE)
- CWE_ID

Il extrait toutes les paires CVE-CWE et les enregistre dans un nouveau CSV,
en gardant uniquement le numéro CWE (sans le préfixe "CWE-").
"""

import csv
import re

# Définir les chemins des fichiers directement
INPUT_FILE = "results/17-liste_cve_type-mitre-nist.csv"
OUTPUT_FILE = "results/18-traitement_cve_type-nist-mitre.csv"

def extract_cwe_ids(text):
    """
    Extrait tous les CWE IDs d'un texte et retourne seulement les numéros.
    """
    if not text or text.strip() == '' or text.strip() == ' ':
        return []

    # Extraire les CWE-XXX et capturer seulement la partie numérique
    matches = re.findall(r'CWE-(\d+)', text)
    return matches  # Retourne les numéros sans le préfixe CWE-

def process_csv():
    """
    Traite le fichier CSV et extrait les paires CVE-CWE.
    """
    results = []
    cves_with_cwe = set()

    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as infile:
            reader = csv.reader(infile)
            headers = next(reader)  # Lire les en-têtes

            for row in reader:
                if len(row) < 3:
                    continue

                cve_id = row[0].strip()
                type_vuln = row[1].strip()
                cwe_id_col = row[2].strip()

                # Chercher les CWEs dans la colonne CWE_ID
                cwe_ids = extract_cwe_ids(cwe_id_col)

                # Si aucun CWE n'est trouvé dans CWE_ID, chercher dans la colonne Type
                if not cwe_ids:
                    cwe_ids = extract_cwe_ids(type_vuln)

                # Si on a trouvé des CWEs, créer les paires
                if cwe_ids:
                    cves_with_cwe.add(cve_id)
                    for cwe_id in cwe_ids:
                        results.append([cve_id, cwe_id])  # cwe_id est déjà juste le numéro

        # Écrire les résultats dans le fichier de sortie
        with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(['cve_id', 'cwe_id'])
            writer.writerows(results)

        # Afficher des statistiques
        print(f"Traitement terminé.")
        print(f"- Nombre total de paires CVE-CWE: {len(results)}")
        print(f"- Nombre de CVEs avec au moins un CWE: {len(cves_with_cwe)}")

    except Exception as e:
        print(f"Erreur lors du traitement du fichier: {str(e)}")

if __name__ == "__main__":
    process_csv()