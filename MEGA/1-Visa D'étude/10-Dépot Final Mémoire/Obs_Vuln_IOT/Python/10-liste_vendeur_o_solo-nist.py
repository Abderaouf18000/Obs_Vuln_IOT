import os
import csv


def extract_csv_file_names_without_extension(input_directory, output_file):
    """
    Parcourt un dossier pour extraire les noms des fichiers CSV sans leur extension
    et les enregistrer dans un fichier CSV.

    Args:
        input_directory (str): Chemin vers le dossier contenant les fichiers CSV.
        output_file (str): Chemin vers le fichier de sortie pour enregistrer les noms de fichiers.
    """
    try:
        # Vérifier si le dossier existe
        if not os.path.exists(input_directory):
            print(f"Le dossier '{input_directory}' n'existe pas.")
            return

        # Récupérer la liste des fichiers CSV dans le dossier sans l'extension .csv
        file_names = [os.path.splitext(f)[0] for f in os.listdir(input_directory) if f.endswith('.csv')]

        # Vérification si aucun fichier CSV n'est trouvé
        if not file_names:
            print("Aucun fichier CSV trouvé dans le dossier spécifié.")
            return

        # Enregistrer les noms des fichiers dans un fichier CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as output_csv:
            writer = csv.writer(output_csv)
            writer.writerow(['File Name'])  # En-tête
            for file_name in file_names:
                writer.writerow([file_name])  # Écrire chaque nom de fichier sans l'extension

        print(f"Les noms des fichiers CSV (sans extension) ont été enregistrés dans : {output_file}")

    except Exception as e:
        print(f"Une erreur est survenue : {e}")


# Exemple d'utilisation
input_directory = 'results/4-vendeurs/o'  # Dossier contenant les fichiers CSV
output_file = 'results/4-vendeurs/o/liste_vendeur_o_solo-nist.csv'  # Fichier qui contiendra les noms des fichiers

extract_csv_file_names_without_extension(input_directory, output_file)
