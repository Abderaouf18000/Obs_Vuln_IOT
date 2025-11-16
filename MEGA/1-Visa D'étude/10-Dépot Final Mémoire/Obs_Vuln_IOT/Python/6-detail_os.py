import json
import re
import csv
import os


def extract_vulnerabilities_by_os(file_path, os_name):
    """
    Extrait les vulnérabilités liées à un système d'exploitation spécifique à partir d'un fichier JSON CVE.

    Args:
        file_path (str): Chemin vers le fichier JSON contenant les données CVE
        os_name (str): Nom du système d'exploitation à rechercher

    Returns:
        list: Liste de dictionnaires contenant les informations des vulnérabilités correspondantes
    """
    # Charger le fichier JSON
    try:
        with open(file_path, 'r') as file:
            cve_data = json.load(file)
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier: {e}")
        return []

    # Liste pour stocker les vulnérabilités correspondantes
    matching_vulnerabilities = []

    # Pattern regex pour rechercher le système d'exploitation (insensible à la casse)
    try:
        os_pattern = re.compile(rf'{re.escape(os_name)}', re.IGNORECASE)
    except:
        print(f"Erreur lors de la création du pattern regex pour: {os_name}")
        return []

    # Parcourir toutes les entrées CVE
    for item in cve_data.get('CVE_Items', []):
        # Vérifier dans les configurations CPE
        configurations = item.get('configurations', {})
        nodes = configurations.get('nodes', [])

        os_match = False
        product_name = "N/A"

        # Parcourir tous les nœuds de configuration
        for node in nodes:
            # Vérifier les correspondances CPE
            for cpe_match in node.get('cpe_match', []):
                cpe_uri = cpe_match.get('cpe23Uri', '')

                # Si l'OS est trouvé dans l'URI CPE
                if os_pattern.search(cpe_uri):
                    os_match = True
                    # Extraire seulement le nom du produit du CPE (sans le vendeur)
                    try:
                        # Format standard CPE: cpe:2.3:a:vendor:product:version:...
                        parts = cpe_uri.split(':')
                        if len(parts) > 5:
                            product = parts[4]
                            product_name = product
                    except:
                        product_name = "Unknown"
                    break

            # Vérifier aussi dans les enfants du nœud
            for child in node.get('children', []):
                for cpe_match in child.get('cpe_match', []):
                    cpe_uri = cpe_match.get('cpe23Uri', '')
                    if os_pattern.search(cpe_uri):
                        os_match = True
                        # Extraire seulement le nom du produit du CPE (sans le vendeur)
                        try:
                            parts = cpe_uri.split(':')
                            if len(parts) > 5:
                                product = parts[4]
                                product_name = product
                        except:
                            product_name = "Unknown"
                        break

            if os_match:
                break

        # Vérifier aussi dans la description
        description = item.get('cve', {}).get('description', {}).get('description_data', [])
        for desc in description:
            if os_pattern.search(desc.get('value', '')):
                os_match = True
                # Si nous n'avons pas trouvé de produit dans les CPE, essayons d'en extraire un de la description
                if product_name == "N/A":
                    # Cette extraction est simpliste et peut nécessiter des ajustements
                    desc_value = desc.get('value', '')
                    if "in " in desc_value:
                        try:
                            # Tentative d'extraction du format courant "in Product X"
                            product_candidate = desc_value.split("in ")[1].split(" ")[0]
                            product_name = product_candidate
                        except:
                            pass
                break

        # Si une correspondance est trouvée, ajouter la vulnérabilité à la liste
        if os_match:
            # Extraire les informations pertinentes
            cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'N/A')

            # Obtenir la description
            description_text = "N/A"
            for desc in item.get('cve', {}).get('description', {}).get('description_data', []):
                if desc.get('lang') == 'en':
                    description_text = desc.get('value', 'N/A')
                    break

            # Obtenir la sévérité et le score CVSS
            severity = "N/A"
            cvss_score = "N/A"
            impact = item.get('impact', {})
            if 'baseMetricV3' in impact:
                cvss = impact['baseMetricV3'].get('cvssV3', {})
                severity = cvss.get('baseSeverity', 'N/A')
                cvss_score = cvss.get('baseScore', 'N/A')

            # Ajouter à la liste des résultats
            matching_vulnerabilities.append({
                'CVE_ID': cve_id,
                'Product_OS': os_name,
                'Severity': severity,
                'CVSS_Score': cvss_score,
                'Published_Date': item.get('publishedDate', 'N/A'),
                'Last_Modified_Date': item.get('lastModifiedDate', 'N/A')
            })

    return matching_vulnerabilities


def process_os_list_from_csv(csv_path, cve_json_path, output_csv_path, max_os=None):
    """
    Lit un fichier CSV contenant une liste d'OS, extrait les vulnérabilités pour chaque OS
    et les sauvegarde dans un fichier CSV complet.

    Args:
        csv_path (str): Chemin vers le fichier CSV contenant la liste des OS
        cve_json_path (str): Chemin vers le fichier JSON contenant les données CVE
        output_csv_path (str): Chemin pour sauvegarder le fichier CSV résultat
        max_os (int, optional): Nombre maximum d'OS à traiter (utile pour les tests)
    """
    # Lire le fichier CSV pour extraire la liste des OS
    os_list = []
    vendor_dict = {}  # Pour conserver les associations OS -> Vendor et Product H

    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if 'Product OS' in row and row['Product OS'] and row['Product OS'] not in os_list:
                    os_list.append(row['Product OS'])
                    # Stocker les informations vendor et product pour cet OS
                    vendor_dict[row['Product OS']] = {
                        'Vendor': row.get('Vendor', 'N/A'),
                        'Product_H': row.get('Product H', 'N/A')
                    }
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier CSV {csv_path}: {e}")
        return

    print(f"Nombre total d'OS uniques trouvés: {len(os_list)}")

    # Limiter le nombre d'OS à traiter si spécifié
    if max_os is not None and max_os > 0:
        os_list = os_list[:max_os]
        print(f"Limitation à {max_os} OS pour le traitement")

    # Créer le fichier CSV de sortie
    fieldnames = ['CVE_ID', 'Product_OS', 'Vendor', 'Product_H',
                  'Severity', 'CVSS_Score', 'Published_Date', 'Last_Modified_Date']

    # Vérifier si le répertoire de sortie existe, sinon le créer
    output_dir = os.path.dirname(output_csv_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Compteurs pour le suivi
        total_vulns = 0
        os_with_vulns = 0

        # Traiter chaque OS
        print(f"Traitement des OS en cours...")
        total_os = len(os_list)

        for i, os_name in enumerate(os_list):
            # Afficher la progression
            progress = (i + 1) / total_os * 100
            print(f"Traitement de l'OS {i + 1}/{total_os} ({progress:.1f}%): {os_name}")

            # Extraire les vulnérabilités pour cet OS
            vulnerabilities = extract_vulnerabilities_by_os(cve_json_path, os_name)

            # Si des vulnérabilités sont trouvées
            if vulnerabilities:
                os_with_vulns += 1
                total_vulns += len(vulnerabilities)
                print(f"  → {len(vulnerabilities)} vulnérabilités trouvées")

                # Ajouter les informations Vendor et Product H à chaque vulnérabilité
                for vuln in vulnerabilities:
                    vuln['Vendor'] = vendor_dict[os_name]['Vendor']
                    vuln['Product_H'] = vendor_dict[os_name]['Product_H']

                    # Écrire dans le CSV
                    writer.writerow(vuln)
            else:
                print(f"  → Aucune vulnérabilité trouvée")

    # Afficher les statistiques finales
    print("\nTraitement terminé!")
    print(f"Nombre d'OS traités: {len(os_list)}")
    print(f"Nombre d'OS avec des vulnérabilités: {os_with_vulns}")
    print(f"Nombre total de vulnérabilités trouvées: {total_vulns}")
    print(f"Résultats sauvegardés dans: {output_csv_path}")


if __name__ == "__main__":
    # Définir les chemins des fichiers
    csv_input_path = "/Users/abderaoufbouhali/PycharmProjects/Mémoire/results/8-liste_produit_os-nist.csv"
    cve_json_path = "/Users/abderaoufbouhali/PycharmProjects/Mémoire/cvelist_nist/nvdcve-1.1-2024.json"
    csv_output_path = "vulnerabilites_completes.csv"

    # Limiter le nombre d'OS à traiter pour les tests (None pour tous)
    max_os = 50  # Mettre None pour traiter tous les OS

    # Exécuter le processus
    process_os_list_from_csv(csv_input_path, cve_json_path, csv_output_path, max_os)