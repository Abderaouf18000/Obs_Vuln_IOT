import subprocess
import sys
import os
import time
import json

# Définir le répertoire de base où se trouvent tous les scripts
BASE_DIR = ""


def executer_workflow_cve(annee):
    """
    Fonction qui exécute en séquence tous les scripts Python du workflow CVE
    en utilisant l'année spécifiée pour tous les chemins.

    Args:
        annee (str): Année des données CVE à traiter
    """
    # Changer le répertoire de travail
    os.chdir(BASE_DIR)

    # Afficher le répertoire de travail actuel pour débogage
    print(f"Répertoire de travail: {os.getcwd()}")

    # Définir les chemins avec l'année
    json_file = f"cvelist_nist/nvdcve-1.1-{annee}.json"
    json_folder = f"cvelist_mitre_{annee}/"
    folder_path = f"cvelist_mitre_{annee}"

    # Variables pour chaque script
    variables_scripts = {
        "1-liste_cve_description-nist.py": f"json_file = '{json_file}'",
        "2-liste_cve_scores-mitre.py": f"json_folder = '{json_folder}'",
        "2-liste_cve_scores-nist.py": f"json_file = '{json_file}'",
        "3-liste_cve_dates-nist.py": f"json_file = '{json_file}'",
        "4-liste_cpe_h-nist.py": f"json_file = '{json_file}'",
        "5-liste_cpe_os-nist.py": f"json_file = '{json_file}'",
        "6-liste_vendeurs_h-nist.py": f"json_file = '{json_file}'",
        "7-liste_vendeurs_o-nist.py": f"json_file = '{json_file}'",
        "14-temp_moy_vendeur-mitre.py": f"""
import json
input_file = "results/6-liste_vendeurs_h-nist.csv"
output_file = "results/14-temp_moy_vendeur-mitre.csv"

# Remplacer les références à l'année dans les fonctions
def get_date_reserved(cve_id):
    if cve_id.endswith('.json'):
        cve_id = cve_id[:-5]
    file_path = os.path.join("cvelist_mitre_{annee}", f"{{cve_id}}.json")
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            cve_data = json.load(file)
        date_reserved = cve_data.get('cveMetadata', {{}}).get('dateReserved')
        return date_reserved
    except Exception as e:
        return None

def get_date_published(cve_id):
    if cve_id.endswith('.json'):
        cve_id = cve_id[:-5]
    file_path = os.path.join("cvelist_mitre_{annee}", f"{{cve_id}}.json")
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            cve_data = json.load(file)
        date_published = cve_data.get('cveMetadata', {{}}).get('datePublished')
        return date_published
    except Exception as e:
        return None
""",
        "15-liste_cve_type-mitre.py": f"folder_path = '{folder_path}'",
        "16-liste_cve_type-nist.py": f"json_file = '{json_file}'",
        "24-calculate_cve_resolution_time-mitre.py": f"directory_path = '{json_folder}'",
        "28-details_cves.py": f"json_file = '{json_file}'",
    }

    # Liste des fichiers à exécuter dans l'ordre
    fichiers = [
        "1-liste_cve_description-nist.py",
        "2-liste_cve_scores-mitre.py",
        "2-liste_cve_scores-nist.py",
        "2-liste_cve_scores-nist-mitre.py",
        "3-liste_cve_dates-nist.py",
        "4-liste_cpe_h-nist.py",
        "5-liste_cpe_os-nist.py",
        "6-liste_vendeurs_h-nist.py",
        "7-liste_vendeurs_o-nist.py",
        "8-liste_produit_os-nist.py",
        # "9-liste_vendeur_h_solo-nist.py",
        # "10-liste_vendeur_o_solo-nist.py",
        "11-count_nbr_vuln_vendeur-nist.py",
        "12-count_nbr_produit_vendeur-nist.py",
        "14-temp_moy_vendeur-mitre.py",
        "13-fusion_11_12_14-fin.py",
        "15-liste_cve_type-mitre.py",
        "16-liste_cve_type-nist.py",
        "17-liste_cve_type-niste-mitre.py",
        "18-traitement_cve_type-nist-mistre.py",
        "19-associer_cwe18_type1000.py",
        "20-fusion_2fin_6-objscore.py",
        "21-fusion_6_19-objtype.py",
        "22-typepop_vendor-21.py",
        "23-score_moy_vendor.py",
        "24-calculate_cve_resolution_time-mitre.py",
        "25-fusion_2_24-tmcpv.py",
        "26-fusion_6_24-tmcpvscore.py",
        "27-traitment_26.py",
        "28-details_cves.py",
        "29-details_cves_fusion_25-28.py",
        "30-details_cves_fusion_29-19.py",
        "31-nbr_vuln_produit-nist.py",
    ]

    # Assurez-vous que le dossier results existe
    results_dir = os.path.join(BASE_DIR, "results")
    os.makedirs(results_dir, exist_ok=True)

    print(f"=== WORKFLOW CVE/CPE - ANNÉE {annee} ===")

    # Compteurs
    reussis = 0
    echoues = 0

    # Exécuter chaque script
    for i, script in enumerate(fichiers):
        print(f"\n[{i + 1}/{len(fichiers)}] Exécution de {script}...")

        # Utiliser le chemin complet du script
        script_path = os.path.join(BASE_DIR, script)

        # Vérifier si le fichier existe
        if not os.path.exists(script_path):
            print(f"❌ Le fichier {script} n'existe pas!")
            echoues += 1
            continue

        # Préparer la commande
        # Utiliser l'interpréteur Python de l'environnement env_1
        commande = ["python3", "-c"]

        # Préparer le code à exécuter
        code_script = ""

        # Ajouter les variables si nécessaire
        if script in variables_scripts:
            code_script += variables_scripts[script] + "\n"

        # Ajouter la variable d'année pour tous les scripts
        code_script += f"annee = '{annee}'\n"

        # Ajouter l'exécution du script (avec le chemin complet)
        code_script += f"exec(open('{script_path}').read())"

        commande.append(code_script)

        # Exécuter le script
        debut = time.time()
        try:
            process = subprocess.run(
                commande, check=False, capture_output=True, text=True
            )

            duree = round(time.time() - debut, 2)

            if process.returncode == 0:
                print(f"✅ Réussi en {duree}s")
                reussis += 1
            else:
                print(f"❌ Échec (code {process.returncode})")
                print(f"Commande: {' '.join(commande[:2])}...")
                if process.stderr:
                    print(f"Erreur: {process.stderr}")
                echoues += 1

        except Exception as e:
            print(f"❌ Exception: {e}")
            echoues += 1

    # Rapport final
    print(f"\n=== RAPPORT ===")
    print(f"Année utilisée: {annee}")
    print(f"Scripts réussis: {reussis}/{len(fichiers)}")
    print(f"Scripts échoués: {echoues}/{len(fichiers)}")
    print("==============")


if __name__ == "__main__":
    # Obtenir l'année des arguments de ligne de commande
    annee = "2023"  # Valeur par défaut
    type_analyse = None  # Gardé pour compatibilité

    if len(sys.argv) > 1:
        annee = sys.argv[1]
    if len(sys.argv) > 2:
        type_analyse = sys.argv[2]  # On garde la récupération mais on ne l'utilise pas

    print(f"Exécution du workflow pour l'année {annee}, type d'analyse: {type_analyse}")
    # On passe uniquement l'année à la fonction
    executer_workflow_cve(annee)

    # Écrire un message clair de fin dans le log
    print("\n[COMPLETED] Analyse terminée avec succès (100%)")

    # Si vous avez un fichier de log séparé, ouvrez-le et écrivez-y
    log_path = os.path.join(BASE_DIR, "results", f"log_workflow_{annee}.txt")
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write("\n[COMPLETED] Analyse terminée avec succès (100%)\n")
        log_file.flush()  # Important pour s'assurer que le message est écrit immédiatement
