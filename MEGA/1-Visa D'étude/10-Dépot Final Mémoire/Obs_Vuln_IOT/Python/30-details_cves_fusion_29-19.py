import pandas as pd
import os
import csv


def fusionner_cve_cwe(fichier_cve, fichier_cwe, fichier_sortie=None):
    """
    Fusionne un fichier CSV contenant des détails CVE avec un fichier CSV
    contenant des associations CVE-CWE.

    Args:
        fichier_cve (str): Chemin vers le fichier CSV contenant les détails CVE
        fichier_cwe (str): Chemin vers le fichier CSV contenant les associations CVE-CWE
        fichier_sortie (str, optional): Chemin pour le fichier CSV fusionné.
                                       Si non spécifié, un nom par défaut sera généré.

    Returns:
        str: Chemin du fichier CSV créé
    """
    # Déterminer le chemin de sortie si non spécifié
    if fichier_sortie is None:
        base_name1 = os.path.splitext(os.path.basename(fichier_cve))[0]
        base_name2 = os.path.splitext(os.path.basename(fichier_cwe))[0]
        fichier_sortie = f"fusion_{base_name1}_{base_name2}.csv"

    # S'assurer que le dossier de sortie existe
    dossier_sortie = os.path.dirname(fichier_sortie)
    if dossier_sortie and not os.path.exists(dossier_sortie):
        print(f"Création du dossier de sortie: {dossier_sortie}")
        os.makedirs(dossier_sortie)

    try:
        # Essayer différents encodages et paramètres pour lire les fichiers CSV
        encodages = ['utf-8', 'latin1', 'ISO-8859-1', 'cp1252']
        df_cve = None
        df_cwe = None

        # Essayer de lire le fichier CVE avec différents paramètres
        print(f"Lecture du fichier détails CVE: {fichier_cve}...")
        for encoding in encodages:
            try:
                print(f"  Essai avec l'encodage: {encoding}")
                df_cve = pd.read_csv(
                    fichier_cve,
                    encoding=encoding,
                    quoting=csv.QUOTE_ALL,  # Forcer la lecture des guillemets
                    escapechar='\\',  # Caractère d'échappement
                    on_bad_lines='warn',  # Ignorer les lignes malformées
                    engine='python'  # Utiliser le moteur Python plus permissif
                )
                print(f"  Succès avec l'encodage: {encoding}")
                break
            except Exception as e:
                print(f"  Échec avec l'encodage {encoding}: {str(e)}")
                try:
                    # Essayer avec engine='c' est plus rapide mais moins permissif
                    print(f"  Nouvel essai avec {encoding} et engine='c'")
                    df_cve = pd.read_csv(
                        fichier_cve,
                        encoding=encoding,
                        engine='c',
                        on_bad_lines='warn',
                        error_bad_lines=False,
                        warn_bad_lines=True,
                        low_memory=False
                    )
                    print(f"  Succès avec l'encodage: {encoding} et engine='c'")
                    break
                except Exception as e2:
                    print(f"  Échec du deuxième essai: {str(e2)}")

        # Vérifier si la lecture a réussi
        if df_cve is None:
            print("Impossible de lire le fichier CVE après plusieurs tentatives.")
            return None

        # Essayer de lire le fichier CWE
        print(f"Lecture du fichier associations CWE: {fichier_cwe}...")
        for encoding in encodages:
            try:
                print(f"  Essai avec l'encodage: {encoding}")
                df_cwe = pd.read_csv(
                    fichier_cwe,
                    encoding=encoding,
                    quoting=csv.QUOTE_ALL,
                    on_bad_lines='warn',
                    engine='python'
                )
                print(f"  Succès avec l'encodage: {encoding}")
                break
            except Exception as e:
                print(f"  Échec avec l'encodage {encoding}: {str(e)}")
                try:
                    print(f"  Nouvel essai avec {encoding} et engine='c'")
                    df_cwe = pd.read_csv(
                        fichier_cwe,
                        encoding=encoding,
                        engine='c',
                        on_bad_lines='warn',
                        error_bad_lines=False,
                        warn_bad_lines=True,
                        low_memory=False
                    )
                    print(f"  Succès avec l'encodage: {encoding} et engine='c'")
                    break
                except Exception as e2:
                    print(f"  Échec du deuxième essai: {str(e2)}")

        # Vérifier si la lecture a réussi
        if df_cwe is None:
            print("Impossible de lire le fichier CWE après plusieurs tentatives.")
            return None

        # Afficher des informations sur les dataframes lus
        print(f"\nInformations sur les fichiers lus:")
        print(f"Fichier CVE: {len(df_cve)} lignes, {len(df_cve.columns)} colonnes")
        print(f"Fichier CWE: {len(df_cwe)} lignes, {len(df_cwe.columns)} colonnes")
        print(f"Colonnes du fichier CVE: {df_cve.columns.tolist()}")
        print(f"Colonnes du fichier CWE: {df_cwe.columns.tolist()}")

        # Normaliser les noms de colonnes pour faciliter la correspondance
        df_cve_copy = df_cve.copy()
        df_cwe_copy = df_cwe.copy()

        # Vérifier et standardiser les noms de colonnes CVE_ID/cve_id
        cve_id_col_cve = None
        for col in df_cve.columns:
            if col.lower() == 'cve_id':
                cve_id_col_cve = col
                break

        cve_id_col_cwe = None
        for col in df_cwe.columns:
            if col.lower() == 'cve_id':
                cve_id_col_cwe = col
                break

        if cve_id_col_cve is None:
            print("Erreur: Le fichier CVE doit contenir une colonne 'CVE_ID' ou 'cve_id'")
            return None

        if cve_id_col_cwe is None:
            print("Erreur: Le fichier CWE doit contenir une colonne 'CVE_ID' ou 'cve_id'")
            return None

        # Afficher les noms de colonnes trouvés
        print(f"\nColonne d'ID CVE trouvée dans le fichier CVE: {cve_id_col_cve}")
        print(f"Colonne d'ID CVE trouvée dans le fichier CWE: {cve_id_col_cwe}")

        # Renommer les colonnes pour la jointure si nécessaire
        if cve_id_col_cve != 'CVE_ID':
            df_cve_copy.rename(columns={cve_id_col_cve: 'CVE_ID'}, inplace=True)
            print(f"Colonne {cve_id_col_cve} renommée en 'CVE_ID' dans le fichier CVE")

        if cve_id_col_cwe != 'CVE_ID':
            df_cwe_copy.rename(columns={cve_id_col_cwe: 'CVE_ID'}, inplace=True)
            print(f"Colonne {cve_id_col_cwe} renommée en 'CVE_ID' dans le fichier CWE")

        # Afficher quelques informations sur les données avant la fusion
        print(f"\nNombre de CVE dans le fichier détails: {len(df_cve)}")
        print(f"Nombre d'associations CVE-CWE: {len(df_cwe)}")

        # Afficher quelques exemples de valeurs d'ID CVE
        print("\nExemples d'ID CVE dans le fichier CVE:")
        print(df_cve_copy['CVE_ID'].head().tolist())
        print("\nExemples d'ID CVE dans le fichier CWE:")
        print(df_cwe_copy['CVE_ID'].head().tolist())

        # Vérifier si des CVE ont plusieurs CWE associés
        try:
            cwe_par_cve = df_cwe_copy.groupby('CVE_ID').size()
            print(f"\nNombre moyen de CWE par CVE: {cwe_par_cve.mean():.2f}")
            print(f"Nombre max de CWE pour une seule CVE: {cwe_par_cve.max()}")
        except Exception as e:
            print(f"Erreur lors du calcul des statistiques de CWE par CVE: {str(e)}")

        # Fusionner les deux DataFrames
        print("\nFusion des données...")
        df_fusionne = pd.merge(df_cve_copy, df_cwe_copy, on='CVE_ID', how='left')

        print(f"Résultat de la fusion: {len(df_fusionne)} lignes, {len(df_fusionne.columns)} colonnes")

        # Compter le nombre de CVE qui ont au moins un CWE associé
        cve_avec_cwe = 0
        if 'cwe_id' in df_fusionne.columns:
            cve_avec_cwe = df_fusionne['cwe_id'].notna().sum()
            print(f"Utilisation de la colonne 'cwe_id' pour le comptage")
        elif 'CWE_ID' in df_fusionne.columns:
            cve_avec_cwe = df_fusionne['CWE_ID'].notna().sum()
            print(f"Utilisation de la colonne 'CWE_ID' pour le comptage")
        else:
            colonnes_cwe = [col for col in df_fusionne.columns if 'cwe' in col.lower()]
            if colonnes_cwe:
                cve_avec_cwe = df_fusionne[colonnes_cwe[0]].notna().sum()
                print(f"Utilisation de la colonne '{colonnes_cwe[0]}' pour le comptage")
            else:
                print("Aucune colonne CWE trouvée pour le comptage")

        print(f"Nombre de CVE avec au moins un CWE associé: {cve_avec_cwe}")
        print(f"Pourcentage de CVE avec CWE: {(cve_avec_cwe / len(df_cve) * 100):.2f}%")

        # Écrire le DataFrame fusionné dans un nouveau fichier CSV
        try:
            df_fusionne.to_csv(fichier_sortie, index=False, encoding='utf-8')
            print(f"Fusion terminée. Fichier CSV créé: {fichier_sortie}")
        except Exception as e:
            print(f"Erreur lors de l'écriture du fichier CSV: {str(e)}")
            # Essayer avec un autre encodage
            try:
                df_fusionne.to_csv(fichier_sortie, index=False, encoding='latin1')
                print(f"Fusion terminée (encodage latin1). Fichier CSV créé: {fichier_sortie}")
            except Exception as e2:
                print(f"Erreur lors de la seconde tentative d'écriture: {str(e2)}")
                return None

        return fichier_sortie

    except Exception as e:
        print(f"Erreur lors de la fusion des fichiers: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


# Exemple d'utilisation
if __name__ == "__main__":
    # Chemin des fichiers - Vous pouvez ajuster si nécessaire
    fichier_cve = "results/29-details_cves_fusion_25-28.csv"  # Utilisez le chemin exact tel qu'indiqué dans l'erreur
    fichier_cwe = "results/19-associer_cwe18_type1000.csv"  # Utilisez le chemin exact tel qu'indiqué dans le code original
    fichier_sortie = "results/30-details_cves_fusion_29-19.csv"

    # Si les fichiers existent à d'autres emplacements, vous pouvez les spécifier ici
    # Si vous n'êtes pas sûr, vérifiez si les fichiers existent à ces emplacements
    import glob

    print("\nRecherche des fichiers CSV disponibles:")
    csv_files = glob.glob("*.csv") + glob.glob("results/*.csv")
    for file in csv_files:
        print(f"  - {file}")

    # Tentative de fusion avec les chemins originaux
    print("\nTentative de fusion avec les chemins originaux...")
    result = fusionner_cve_cwe(fichier_cve, fichier_cwe, fichier_sortie)

    # Si la première tentative échoue, essayer avec les chemins alternatifs
    if result is None:
        print("\nLa première tentative a échoué. Essai avec des chemins alternatifs...")

        # Recherche de chemins alternatifs basés sur les noms de fichiers
        alt_cve = None
        alt_cwe = None

        for file in csv_files:
            if "details_cves" in file.lower() or "29" in file:
                alt_cve = file
                print(f"  Possible fichier CVE trouvé: {alt_cve}")
            elif "associer_cwe" in file.lower() or "19" in file:
                alt_cwe = file
                print(f"  Possible fichier CWE trouvé: {alt_cwe}")

        if alt_cve and alt_cwe:
            print(f"\nTentative avec les fichiers trouvés:")
            print(f"  CVE: {alt_cve}")
            print(f"  CWE: {alt_cwe}")
            fichier_sortie_alt = "30-details_cves_fusion_29-19.csv"  # Simplifier le chemin de sortie
            fusionner_cve_cwe(alt_cve, alt_cwe, fichier_sortie_alt)