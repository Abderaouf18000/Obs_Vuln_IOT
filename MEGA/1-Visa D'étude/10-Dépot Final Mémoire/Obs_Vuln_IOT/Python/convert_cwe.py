import csv
import os
import re


def extract_cwe_info(input_file, output_file):
    """
    Lit un fichier CSV contenant les données CWE au format brut et extrait les informations
    importantes dans un format plus structuré.

    Args:
        input_file (str): Chemin vers le fichier CSV contenant les données CWE
        output_file (str): Chemin pour le fichier CSV de sortie
    """
    try:
        # Lire le contenu du fichier
        with open(input_file, 'r', encoding='utf-8') as file:
            content = file.read()

        # Expression régulière pour extraire chaque entrée CWE
        # Chaque entrée commence par un nombre (CWE-ID) suivi d'une virgule et d'un nom entre guillemets
        cwe_pattern = r'(\d+),"([^"]+)",([^,]+),([^,]+),"([^"]+)","([^"]*)"'
        cwe_entries = re.findall(cwe_pattern, content)

        # Préparer les données à écrire
        extracted_data = []

        # Pour chaque entrée CWE trouvée, extraire les informations
        for entry in cwe_entries:
            cwe_id = entry[0]
            name = entry[1]
            abstraction = entry[2]
            status = entry[3]
            description = entry[4]
            # Nettoyer la description (enlever les doubles espaces, sauts de ligne, etc.)
            description = re.sub(r'\s+', ' ', description).strip()

            # Ajouter les données extraites à la liste
            extracted_data.append([cwe_id, name, abstraction, status, description])

        # Écriture des données dans le fichier CSV
        with open(output_file, 'w', encoding='utf-8', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Écriture de l'en-tête
            csv_writer.writerow(['CWE-ID', 'Name', 'Abstraction', 'Status', 'Description'])
            # Écriture des données
            csv_writer.writerows(extracted_data)

        print(f"Extraction des informations CWE terminée avec succès!")
        print(f"Nombre d'entrées extraites: {len(extracted_data)}")
        print(f"Résultat sauvegardé dans le fichier : {output_file}")

    except Exception as e:
        print(f"Une erreur est survenue : {e}")


# Spécifier les fichiers en entrée et en sortie
input_file = 'results/1000.csv'  # Remplacez par votre fichier CSV
output_file = 'results/convert_cwe.csv'

# Création du dossier de résultats si nécessaire
output_dir = os.path.dirname(output_file)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Appelle la fonction pour extraire les données
extract_cwe_info(input_file, output_file)