import pandas as pd
from collections import Counter
import os


def analyser_vulnerabilites_par_vendeur(fichier_fusionne, fichier_sortie=None):
    """
    Analyse le fichier fusionné et extrait uniquement le vendeur et sa vulnérabilité la plus courante.
    Ignore les vulnérabilités avec le nom "Nom non trouvé" ou "Inconnu".

    Args:
        fichier_fusionne (str): Chemin du fichier CSV fusionné
        fichier_sortie (str, optional): Chemin du fichier CSV de sortie. Si None, ne sauvegarde pas le résultat.

    Returns:
        pandas.DataFrame: DataFrame contenant uniquement les vendeurs et leurs types de vulnérabilité les plus courants
    """
    print(f"Chargement du fichier {fichier_fusionne}...")
    df = pd.read_csv(fichier_fusionne)

    # Supprimer les lignes sans type de vulnérabilité (cwe_name)
    df = df.dropna(subset=['cwe_name'])

    # Supprimer les lignes avec "Nom non trouvé" ou "Inconnu"
    df = df[~df['cwe_name'].isin(["Nom non trouvé", "Inconnu"])]

    # Initialiser la liste pour stocker les résultats
    resultats = []

    # Pour chaque vendeur unique, trouver le type de vulnérabilité le plus courant
    for vendeur in df['Vendor'].unique():
        # Filtrer les données pour ce vendeur
        df_vendeur = df[df['Vendor'] == vendeur]

        # Compter les types de vulnérabilités
        vuln_counts = Counter(df_vendeur['cwe_name'])

        # Vérifier s'il y a des vulnérabilités valides pour ce vendeur
        if not vuln_counts:
            print(f"Aucune vulnérabilité valide trouvée pour {vendeur}")
            continue  # Passer au vendeur suivant

        # Trouver le type le plus courant
        most_common = vuln_counts.most_common(1)
        if most_common:
            top_vuln, count = most_common[0]

            # Ajouter aux résultats (uniquement Vendor et Top_Vulnerability)
            resultats.append({
                'Vendor': vendeur,
                'Top_Vulnerability': top_vuln
            })
        else:
            print(f"Aucune vulnérabilité trouvée pour {vendeur} après filtrage")

    # Créer un DataFrame avec les résultats
    df_resultats = pd.DataFrame(resultats)

    # Vérifier si des résultats ont été trouvés
    if df_resultats.empty:
        print("Aucun résultat trouvé après filtrage des vulnérabilités non valides")
        return df_resultats

    # Trier par Vendor pour une meilleure lisibilité
    df_resultats = df_resultats.sort_values('Vendor').reset_index(drop=True)

    # Afficher les résultats
    print("\nVendeurs et leurs types de vulnérabilité les plus courants :")
    for i, row in df_resultats.iterrows():
        print(f"{row['Vendor']}: {row['Top_Vulnerability']}")

    # Sauvegarder les résultats si un fichier de sortie est spécifié
    if fichier_sortie:
        # Créer le dossier de sortie s'il n'existe pas
        os.makedirs(os.path.dirname(fichier_sortie), exist_ok=True)

        df_resultats.to_csv(fichier_sortie, index=False)
        print(f"\nLes résultats ont été enregistrés dans '{fichier_sortie}'")

    return df_resultats


# Utilisation de la fonction
if __name__ == "__main__":
    fichier_fusionne = "results/21-fusion_6_19-objtype.csv"
    fichier_sortie = "results/22-typepop_vendor-21.csv"

    df_resultats = analyser_vulnerabilites_par_vendeur(
        fichier_fusionne=fichier_fusionne,
        fichier_sortie=fichier_sortie
    )