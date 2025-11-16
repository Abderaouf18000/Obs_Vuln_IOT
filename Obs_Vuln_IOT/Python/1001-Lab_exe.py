import json
import os
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import matplotlib as mpl

def extract_vendor_from_cpe(cpe):
    """
    Extrait le nom du vendeur d'une chaîne CPE.
    Exemple: cpe:2.3:a:paloaltonetworks:pan-os:*:*:*:*:*:*:*:* -> paloaltonetworks
    """
    parts = cpe.split(':')
    if len(parts) > 4:
        return parts[3].lower()
    return None

def analyze_cve_vendors(json_files):
    """
    Analyse les fichiers JSON de CVE pour extraire les vendeurs avec le plus grand nombre 
    de vulnérabilités critiques et élevées.
    
    Args:
        json_files (list): Liste des chemins vers les fichiers JSON
        
    Returns:
        dict: Statistiques des vendeurs
    """
    # Initialiser les compteurs
    vendor_severity_counts = {}
    total_cves = 0
    total_critical_high = 0
    
    print("Analyse des fichiers CVE...")
    
    # Parcourir chaque fichier
    for file_path in json_files:
        year = os.path.basename(file_path).split('-')[-1].split('.')[0]
        print(f"  Traitement du fichier {os.path.basename(file_path)} (année {year})...")
        
        try:
            with open(file_path, 'r') as f:
                cve_data = json.load(f)
            
            # Parcourir chaque élément CVE
            for item in cve_data.get("CVE_Items", []):
                total_cves += 1
                
                # Vérifier la sévérité
                impact = item.get("impact", {})
                base_metric_v3 = impact.get("baseMetricV3", {})
                cvss_v3 = base_metric_v3.get("cvssV3", {})
                severity = cvss_v3.get("baseSeverity", "")
                
                # Ne traiter que les vulnérabilités CRITICAL et HIGH
                if severity not in ["CRITICAL", "HIGH"]:
                    continue
                
                total_critical_high += 1
                
                # Extraire les informations sur les produits affectés
                configurations = item.get("configurations", {})
                nodes = configurations.get("nodes", [])
                
                vendors = set()  # Ensemble pour éliminer les doublons
                
                # Parcourir tous les nœuds de configuration
                for node in nodes:
                    # Traiter les correspondances CPE directes
                    for cpe_match in node.get("cpe_match", []):
                        if cpe_match.get("vulnerable", False):
                            cpe = cpe_match.get("cpe23Uri", "")
                            vendor = extract_vendor_from_cpe(cpe)
                            if vendor:
                                vendors.add(vendor)
                    
                    # Traiter les nœuds enfants
                    for child in node.get("children", []):
                        for cpe_match in child.get("cpe_match", []):
                            if cpe_match.get("vulnerable", False):
                                cpe = cpe_match.get("cpe23Uri", "")
                                vendor = extract_vendor_from_cpe(cpe)
                                if vendor:
                                    vendors.add(vendor)
                
                # Mettre à jour les compteurs pour chaque vendeur
                for vendor in vendors:
                    if vendor not in vendor_severity_counts:
                        vendor_severity_counts[vendor] = {
                            "CRITICAL": 0,
                            "HIGH": 0,
                            "TOTAL": 0,
                            "YEARS": {str(y): 0 for y in range(2019, 2025)}
                        }
                    
                    vendor_severity_counts[vendor][severity] += 1
                    vendor_severity_counts[vendor]["TOTAL"] += 1
                    vendor_severity_counts[vendor]["YEARS"][year] += 1
        
        except Exception as e:
            print(f"Erreur lors de l'analyse du fichier {file_path}: {str(e)}")
    
    return {
        "vendor_counts": vendor_severity_counts,
        "total_cves": total_cves,
        "total_critical_high": total_critical_high
    }

def setup_ieee_style():
    """Configure le style graphique conforme aux normes IEEE"""
    # Configuration des paramètres de style IEEE
    mpl.rcParams.update({
        # Police et texte
        'font.family': 'serif',
        'font.serif': ['Times New Roman', 'DejaVu Serif', 'serif'],
        'font.size': 8,
        'axes.titlesize': 10,
        'axes.labelsize': 10,
        'xtick.labelsize': 8,
        'ytick.labelsize': 8,
        'legend.fontsize': 8,
        
        # Éléments graphiques
        'axes.linewidth': 0.5,
        'grid.linewidth': 0.5,
        'lines.linewidth': 1.0,
        'patch.linewidth': 0.5,
        'xtick.major.width': 0.5,
        'ytick.major.width': 0.5,
        'xtick.minor.width': 0.5,
        'ytick.minor.width': 0.5,
        
        # Mise en page
        'figure.dpi': 600,
        'savefig.dpi': 600,
        'savefig.format': 'pdf',
        'savefig.bbox': 'tight',
        
        # Style général
        'axes.grid': True,
        'grid.alpha': 0.3,
        'grid.linestyle': '--',
        'figure.autolayout': True
    })

def create_top_vendors_chart_ieee(vendor_stats, output_path="top_10_vendors_critical_high_ieee.pdf"):
    """
    Crée un graphique des 10 principaux vendeurs au format IEEE.
    
    Args:
        vendor_stats (dict): Statistiques des vendeurs
        output_path (str): Chemin pour sauvegarder le graphique
    """
    # Configuration du style IEEE
    setup_ieee_style()
    
    # Obtenir les 10 principaux vendeurs
    sorted_vendors = sorted(
        [(v, k) for k, v in vendor_stats["vendor_counts"].items()],
        key=lambda x: x[0]["TOTAL"],
        reverse=True
    )
    
    top_vendors = sorted_vendors[:10]
    
    # Préparer les données
    vendors = [v[1] for v in top_vendors]
    critical_counts = [v[0]["CRITICAL"] for v in top_vendors]
    high_counts = [v[0]["HIGH"] for v in top_vendors]
    
    # Créer un DataFrame pour faciliter la manipulation
    df = pd.DataFrame({
        'Vendor': vendors,
        'CRITICAL': critical_counts,
        'HIGH': high_counts
    })
    
    # Calculer le total et trier
    df['Total'] = df['CRITICAL'] + df['HIGH']
    df = df.sort_values('Total', ascending=True)  # Ordre croissant pour le graphique horizontal
    
    # Créer la figure à la taille IEEE deux colonnes (18.2 cm de large)
    # Conversion en pouces: 18.2 cm ÷ 2.54 = 7.17 in, hauteur proportionnelle
    fig, ax = plt.subplots(figsize=(7.17, 5.0))
    
    # Définir les hachures pour différencier en niveaux de gris
    patterns = ['///', '...']
    
    # Créer les barres horizontales
    y_pos = range(len(df['Vendor']))
    bars_high = ax.barh(y_pos, df['HIGH'], color='lightgray', edgecolor='black', 
                       hatch=patterns[1], linewidth=0.5, label='HIGH')
    bars_critical = ax.barh(y_pos, df['CRITICAL'], left=df['HIGH'], color='darkgray', 
                           edgecolor='black', hatch=patterns[0], linewidth=0.5, label='CRITICAL')
    
    # Configurer les étiquettes
    ax.set_yticks(y_pos)
    ax.set_yticklabels(df['Vendor'])
    
    # Ajouter les totaux à la fin des barres
    for i, (bar_high, bar_critical) in enumerate(zip(bars_high, bars_critical)):
        width_high = bar_high.get_width()
        width_critical = bar_critical.get_width()
        total = width_high + width_critical
        ax.text(total + 5, i, f'{int(total)}', va='center', fontsize=8)
    
    # Configurer les axes
    ax.set_xlabel('Number of Vulnerabilities')
    ax.set_ylabel('Vendor')
    
    # Légende
    ax.legend(loc='lower right', frameon=True)
    
    # Enlever les bordures superflues
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    # Ajuster l'aspect
    plt.tight_layout()
    
    # Sauvegarder en formats vectoriel (PDF) et bitmap (PNG)
    plt.savefig(output_path, format='pdf')
    plt.savefig(output_path.replace('.pdf', '.png'), format='png')
    plt.close()
    
    # Ajouter un titre en dessous du graphique (convention IEEE)
    print(f"Fig. 1. Top 10 Vendors by Critical and High Vulnerabilities (2019-2024)")

def create_yearly_trend_chart_ieee(vendor_stats, output_path="vendor_yearly_trends_ieee.pdf"):
    """
    Crée un graphique de tendance annuelle au format IEEE pour les 5 principaux vendeurs.
    
    Args:
        vendor_stats (dict): Statistiques des vendeurs
        output_path (str): Chemin pour sauvegarder le graphique
    """
    # Configuration du style IEEE
    setup_ieee_style()
    
    # Obtenir les 5 principaux vendeurs
    sorted_vendors = sorted(
        [(v, k) for k, v in vendor_stats["vendor_counts"].items()],
        key=lambda x: x[0]["TOTAL"],
        reverse=True
    )
    
    top_5_vendors = sorted_vendors[:5]
    
    # Préparer les données
    years = [str(y) for y in range(2019, 2025)]
    
    # Créer la figure à la taille IEEE une colonne (8.8 cm de large)
    # Conversion en pouces: 8.8 cm ÷ 2.54 = 3.46 in
    fig, ax = plt.subplots(figsize=(3.46, 3.0))
    
    # Styles de ligne et marqueurs différenciables en niveaux de gris
    line_styles = ['-', '--', '-.', ':', '-']
    markers = ['o', 's', '^', 'x', 'd']
    colors = ['black', 'dimgray', 'darkgray', 'gray', 'lightgray']
    
    # Tracer les lignes
    for i, (vendor_data, vendor_name) in enumerate(top_5_vendors):
        yearly_data = [vendor_data["YEARS"].get(year, 0) for year in years]
        ax.plot(years, yearly_data, 
                marker=markers[i], 
                linestyle=line_styles[i],
                color=colors[i],
                markersize=4,
                label=vendor_name)
    
    # Configurer les axes
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of Vulnerabilities (CRITICAL + HIGH)')
    
    # Légende compacte
    ax.legend(frameon=True, loc='best')
    
    # Enlever les bordures superflues
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    # Ajuster l'aspect
    plt.tight_layout()
    
    # Sauvegarder en formats vectoriel (PDF) et bitmap (PNG)
    plt.savefig(output_path, format='pdf')
    plt.savefig(output_path.replace('.pdf', '.png'), format='png')
    plt.close()
    
    # Ajouter un titre en dessous du graphique (convention IEEE)
    print(f"Fig. 2. Annual Trend of Critical and High Vulnerabilities for Top 5 Vendors (2019-2024)")

def export_to_csv(vendor_stats, output_path="vendor_vulnerability_stats.csv"):
    """
    Exporte les statistiques des vendeurs vers un fichier CSV.
    
    Args:
        vendor_stats (dict): Statistiques des vendeurs
        output_path (str): Chemin pour sauvegarder le fichier CSV
    """
    # Créer une liste de dictionnaires pour le DataFrame
    data = []
    for vendor, stats in vendor_stats["vendor_counts"].items():
        row = {
            'Vendor': vendor,
            'CRITICAL': stats["CRITICAL"],
            'HIGH': stats["HIGH"],
            'TOTAL': stats["TOTAL"]
        }
        # Ajouter les données annuelles
        for year in range(2019, 2025):
            row[f'Year_{year}'] = stats["YEARS"].get(str(year), 0)
        
        data.append(row)
    
    # Créer le DataFrame et trier par total décroissant
    df = pd.DataFrame(data)
    df = df.sort_values('TOTAL', ascending=False)
    
    # Exporter vers CSV
    df.to_csv(output_path, index=False)
    print(f"Données exportées vers {output_path}")

def main():
    # Liste des fichiers à analyser avec les chemins complets
    json_files = [
        "/Users/abderaoufbouhali/PycharmProjects/Mémoire/cvelist_nist/nvdcve-1.1-2019.json",
        "/Users/abderaoufbouhali/PycharmProjects/Mémoire/cvelist_nist/nvdcve-1.1-2020.json",
        "/Users/abderaoufbouhali/PycharmProjects/Mémoire/cvelist_nist/nvdcve-1.1-2021.json",
        "/Users/abderaoufbouhali/PycharmProjects/Mémoire/cvelist_nist/nvdcve-1.1-2022.json",
        "/Users/abderaoufbouhali/PycharmProjects/Mémoire/cvelist_nist/nvdcve-1.1-2023.json",
        "/Users/abderaoufbouhali/PycharmProjects/Mémoire/cvelist_nist/nvdcve-1.1-2024.json"
    ]
    
    # Définir le répertoire de sortie spécifié
    output_dir = "/Users/abderaoufbouhali/PycharmProjects/Mémoire/lab_exe"
    
    # Créer le répertoire s'il n'existe pas
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Répertoire créé: {output_dir}")
    
    # Vérifier l'existence des fichiers
    for file_path in json_files:
        if not os.path.exists(file_path):
            print(f"Erreur: Le fichier {file_path} n'a pas été trouvé.")
            return
    
    # Analyser les fichiers
    vendor_stats = analyze_cve_vendors(json_files)
    
    # Afficher les statistiques générales
    print(f"\nNombre total de CVE analysées: {vendor_stats['total_cves']}")
    print(f"Nombre de CVE critiques et élevées: {vendor_stats['total_critical_high']}")
    
    # Afficher les 10 principaux vendeurs
    sorted_vendors = sorted(
        vendor_stats["vendor_counts"].items(),
        key=lambda x: x[1]["TOTAL"],
        reverse=True
    )
    
    print("\nTop 10 des vendeurs avec le plus grand nombre de vulnérabilités critiques et élevées:")
    for i, (vendor, stats) in enumerate(sorted_vendors[:10], 1):
        print(f"{i}. {vendor}: {stats['TOTAL']} (CRITICAL: {stats['CRITICAL']}, HIGH: {stats['HIGH']})")
    
    # Exporter les données
    csv_path = os.path.join(output_dir, "vendor_vulnerability_stats.csv")
    export_to_csv(vendor_stats, csv_path)
    
    # Créer les graphiques au format IEEE
    chart1_path = os.path.join(output_dir, "top_10_vendors_critical_high_ieee.pdf")
    chart2_path = os.path.join(output_dir, "vendor_yearly_trends_ieee.pdf")
    create_top_vendors_chart_ieee(vendor_stats, chart1_path)
    create_yearly_trend_chart_ieee(vendor_stats, chart2_path)
    
    print(f"\nGraphiques générés: {chart1_path} et {chart2_path}")
    print(f"Données exportées vers: {csv_path}")

if __name__ == "__main__":
    main()