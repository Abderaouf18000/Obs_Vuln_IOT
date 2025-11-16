import os
import json
import csv
import math
from datetime import datetime
from collections import defaultdict

def parse_iso_date(date_str):
    """Convertit une chaîne de date ISO en objet datetime."""
    if not date_str:
        return None
    # Toujours convertir en datetime avec fuseau horaire (offset-aware)
    if 'Z' in date_str:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    elif '+' in date_str or '-' in date_str and 'T' in date_str and date_str.rfind('-') > date_str.find('T'):
        # Le format contient déjà une information de fuseau horaire
        return datetime.fromisoformat(date_str)
    else:
        # Pas d'information de fuseau horaire, considérer comme UTC
        return datetime.fromisoformat(date_str + '+00:00')

def calculate_fix_time(reserved_date, published_date):
    """Calcule le temps de correction en jours entre la réservation et la publication."""
    if not reserved_date or not published_date:
        return None

    reserved = parse_iso_date(reserved_date)
    published = parse_iso_date(published_date)

    if not reserved or not published:
        return None

    # Calculer la différence en jours
    diff = published - reserved
    return diff.days

def get_date_reserved(cve_id):
    """Récupère la date de réservation pour un CVE donné."""
    # Extraire juste l'ID CVE sans l'extension .json si elle existe
    if cve_id.endswith('.json'):
        cve_id = cve_id[:-5]

    # Construire le chemin du fichier correctement
    file_path = os.path.join(f"cvelist_mitre_{annee}", f"{cve_id}.json")

    try:
        # Ouvrir et charger le fichier JSON
        with open(file_path, 'r', encoding='utf-8') as file:
            cve_data = json.load(file)

        # Extraire la date de réservation
        date_reserved = cve_data.get('cveMetadata', {}).get('dateReserved')
        return date_reserved
    except Exception as e:
        # Silencer la plupart des erreurs pour éviter une sortie trop verbeuse
        return None

def get_date_published(cve_id):
    """Récupère la date de publication pour un CVE donné."""
    # Extraire juste l'ID CVE sans l'extension .json si elle existe
    if cve_id.endswith('.json'):
        cve_id = cve_id[:-5]

    # Construire le chemin du fichier correctement
    file_path = os.path.join(f"cvelist_mitre_{annee}", f"{cve_id}.json")

    try:
        # Ouvrir et charger le fichier JSON
        with open(file_path, 'r', encoding='utf-8') as file:
            cve_data = json.load(file)

        # Extraire la date de publication
        date_published = cve_data.get('cveMetadata', {}).get('datePublished')
        return date_published
    except Exception as e:
        # Silencer la plupart des erreurs pour éviter une sortie trop verbeuse
        return None

def process_vulnerability(vendor, product, cve_id, vendor_products):
    """Traite une vulnérabilité et l'ajoute à la structure de données."""
    # Récupérer les dates et calculer le temps de correction
    date_reserved = get_date_reserved(cve_id)
    date_published = get_date_published(cve_id)
    fix_time = calculate_fix_time(date_reserved, date_published)

    # Stocker les données
    vendor_products[vendor.lower()][product.lower()].append({
        'cve_id': cve_id,
        'date_reserved': date_reserved,
        'date_published': date_published,
        'fix_time': fix_time
    })

def analyze_vulnerabilities_by_vendor(input_file, output_file):
    """
    Analyse les vulnérabilités par vendeur et produit, calcule le temps de correction.

    Args:
        input_file: Chemin vers le fichier CSV d'entrée
        output_file: Chemin pour le fichier CSV de sortie
    """
    # Structure pour stocker les données par vendeur et produit
    vendor_products = defaultdict(lambda: defaultdict(list))
    processed_count = 0
    skipped_count = 0

    # Vérifier si le dossier de sortie existe, sinon le créer
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Dossier créé: {output_dir}")

    # Lire le fichier CSV d'entrée avec l'en-tête
    with open(input_file, 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)

        # Vérifier si la première ligne est un en-tête
        first_row = next(csv_reader, None)
        has_header = False

        if first_row and len(first_row) == 3:
            # Vérifier si c'est un en-tête ou une ligne de données
            if first_row[0].lower() == 'vendor' and first_row[1].lower() == 'product' and first_row[2].lower() == 'cve_id':
                has_header = True
                print("En-tête détecté et ignoré.")
            else:
                # C'est une ligne de données, la traiter
                vendor, product, cve_id = first_row
                process_vulnerability(vendor, product, cve_id, vendor_products)
                processed_count += 1

        # Traiter le reste des lignes
        total_rows = 1  # Commencer à 1 car nous avons déjà traité la première ligne
        for row in csv_reader:
            total_rows += 1
            if total_rows % 1000 == 0:
                print(f"Traitement de la ligne {total_rows}...")

            if len(row) != 3:
                print(f"Format de ligne incorrect (colonnes: {len(row)}): {row}")
                skipped_count += 1
                continue

            vendor, product, cve_id = row
            process_vulnerability(vendor, product, cve_id, vendor_products)
            processed_count += 1

    print(f"Total de lignes traitées: {processed_count}")
    print(f"Lignes ignorées: {skipped_count}")

    # Calculer les statistiques et écrire les résultats
    with open(output_file, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['Vendor', 'Product', 'CVE_Count', 'Avg_Fix_Time', 'Min_Fix_Time', 'Max_Fix_Time', 'CVE_IDs'])

        total_vendors = len(vendor_products)
        current_vendor = 0
        ignored_count = 0

        for vendor in sorted(vendor_products.keys()):
            current_vendor += 1
            if current_vendor % 10 == 0:
                print(f"Écriture des données du vendeur {current_vendor}/{total_vendors}...")

            for product, vulnerabilities in sorted(vendor_products[vendor].items()):
                # Calculer les statistiques pour ce produit
                cve_count = len(vulnerabilities)
                fix_times = [v['fix_time'] for v in vulnerabilities if v['fix_time'] is not None]

                # Si aucun temps de correction n'est disponible, ignorer cette ligne
                if not fix_times:
                    ignored_count += 1
                    continue

                avg_fix_time = sum(fix_times) / len(fix_times)
                min_fix_time = min(fix_times)
                max_fix_time = max(fix_times)

                # Liste des CVEs pour ce produit (limiter à 10 pour éviter des cellules trop grandes)
                cve_ids = [v['cve_id'] for v in vulnerabilities][:10]
                if len(vulnerabilities) > 10:
                    cve_ids.append(f"... et {len(vulnerabilities) - 10} autres")

                writer.writerow([
                    vendor,
                    product,
                    cve_count,
                    math.ceil(avg_fix_time),
                    min_fix_time,
                    max_fix_time,
                    ', '.join(cve_ids)
                ])

        print(f"Nombre de lignes ignorées car sans données de temps de correction: {ignored_count}")

    # Écrire un fichier de statistiques par vendeur simplifié
    vendor_stats_file = "results/14-temp_moy_vendeur-mitre.csv"  # Nom fixe comme demandé
    with open(vendor_stats_file, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        # En-tête simplifié avec seulement Vendor et Avg_Fix_Time
        writer.writerow(['Vendor', 'Avg_Fix_Time'])

        # Structure pour stocker les temps moyens par vendeur
        vendor_avg_times = {}

        # Calculer le temps moyen de correction pour chaque vendeur
        for vendor in vendor_products:
            all_fix_times = []
            for vulnerabilities in vendor_products[vendor].values():
                all_fix_times.extend([v['fix_time'] for v in vulnerabilities if v['fix_time'] is not None])

            # Ignorer ce vendeur s'il n'a aucun temps de correction valide
            if not all_fix_times:
                continue

            avg_fix_time = sum(all_fix_times) / len(all_fix_times)
            vendor_avg_times[vendor] = avg_fix_time

        # Trier les vendeurs par temps moyen de correction (ordre croissant)
        sorted_vendors = sorted(vendor_avg_times.items(), key=lambda x: x[1])

        # Écrire les données
        for vendor, avg_time in sorted_vendors:
            # Arrondir à l'entier supérieur et garantir une valeur minimale de 1
            fix_time_value = max(1, math.ceil(avg_time))
            writer.writerow([
                vendor,
                fix_time_value
            ])

    print(f"Analyse terminée. Résultats enregistrés dans {output_file}")
    print(f"Statistiques par vendeur enregistrées dans {vendor_stats_file}")

# Exemple d'utilisation
if __name__ == "__main__":
    input_file = "results/6-liste_vendeurs_h-nist.csv"  # Votre fichier CSV d'entrée
    output_file = "results/14-temp_moy_vendeur-mitre.csv"  # Fichier CSV de sortie

    analyze_vulnerabilities_by_vendor(input_file, output_file)