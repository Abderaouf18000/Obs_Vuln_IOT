import pandas as pd
import time

def calculer_vulnerabilites_par_produit(fichier_entree, fichier_sortie):
    """
    Calcule le nombre de vulnérabilités par produit et génère un fichier CSV avec les résultats.

    Args:
        fichier_entree (str): Chemin vers le fichier CSV d'entrée
        fichier_sortie (str): Chemin où sauvegarder le fichier CSV de résultats
    """
    print(f"Début de l'analyse du fichier : {fichier_entree}")
    debut = time.time()

    # Chargement du fichier CSV
    print("Chargement des données...")
    df = pd.read_csv(fichier_entree)

    # Afficher des informations sur le DataFrame chargé
    print(f"\nInformations sur le fichier d'entrée :")
    print(f"Nombre de lignes : {df.shape[0]}")
    print(f"Nombre de colonnes : {df.shape[1]}")
    print(f"Colonnes : {df.columns.tolist()}")

    # Vérifier si les colonnes nécessaires existent
    colonnes_requises = ['Vendor', 'Product', 'CVE_ID']
    for colonne in colonnes_requises:
        if colonne not in df.columns:
            print(f"ERREUR : La colonne '{colonne}' n'existe pas dans le fichier d'entrée")
            return

    # Compter le nombre de CVE_ID uniques par combinaison Vendor-Product
    print("\nCalcul du nombre de vulnérabilités par produit...")
    vulnerabilites_par_produit = df.groupby(['Product'])['CVE_ID'].nunique().reset_index()
    vulnerabilites_par_produit.rename(columns={'CVE_ID': 'Nombre_Vulnerabilites'}, inplace=True)

    # Trier par nombre de vulnérabilités (décroissant)
    vulnerabilites_par_produit.sort_values('Nombre_Vulnerabilites', ascending=False, inplace=True)

    # Statistiques sur les résultats
    print("\nStatistiques sur les vulnérabilités par produit :")
    print(f"Nombre total de produits uniques : {len(vulnerabilites_par_produit)}")
    print(f"Nombre total de vulnérabilités : {vulnerabilites_par_produit['Nombre_Vulnerabilites'].sum()}")
    print(f"Nombre moyen de vulnérabilités par produit : {vulnerabilites_par_produit['Nombre_Vulnerabilites'].mean():.2f}")
    print(f"Nombre maximum de vulnérabilités pour un produit : {vulnerabilites_par_produit['Nombre_Vulnerabilites'].max()}")

    # Top 10 des produits avec le plus de vulnérabilités
    print("\nTop 10 des produits avec le plus de vulnérabilités :")
    top_10 = vulnerabilites_par_produit.head(10)
    for _, row in top_10.iterrows():
        print(f"  - {row['Product']} : {row['Nombre_Vulnerabilites']} vulnérabilités")

    # Sauvegarder les résultats dans un fichier CSV
    print(f"\nSauvegarde des résultats dans : {fichier_sortie}")
    vulnerabilites_par_produit.to_csv(fichier_sortie, index=False)

    fin = time.time()
    duree = fin - debut
    print(f"\nTraitement terminé en {duree:.2f} secondes")
    print(f"Le fichier de résultats contient {len(vulnerabilites_par_produit)} lignes")

    return vulnerabilites_par_produit

if __name__ == "__main__":
    fichier_entree = "results/6-liste_vendeurs_h-nist.csv"
    fichier_sortie = "results/31-nbr_vuln_produit-nist.csv"

    resultats = calculer_vulnerabilites_par_produit(fichier_entree, fichier_sortie)