import pandas as pd


def merge_multiple_csv_files(file_paths, output_path, merge_type='inner', on_column=None, priority_order=None):
    """
    Fusionne plusieurs fichiers CSV selon une méthode de jointure et trie selon un ordre de priorité.

    Parameters:
    file_paths (list): Liste des chemins vers les fichiers CSV à fusionner.
    output_path (str): Chemin pour enregistrer le fichier CSV fusionné.
    merge_type (str): Type de fusion ('inner', 'outer', 'left', 'right').
    on_column (str or list): Colonne(s) à utiliser pour la jointure.
    priority_order (list): Ordre de priorité pour trier les données sur la colonne de jointure.

    Returns:
    bool: True si la fusion a réussi, False sinon.
    """
    try:
        # Vérification des fichiers et colonnes à joindre
        if len(file_paths) < 2:
            raise ValueError("Vous devez spécifier au moins deux fichiers à fusionner")

        if on_column is None:
            raise ValueError("Pour une jointure, vous devez spécifier la/les colonne(s) avec 'on_column'")

        # Lire le premier fichier
        result = pd.read_csv(file_paths[0])
        print(f"Fichier 1: {file_paths[0]}")
        print(f"  - Nombre de lignes: {len(result)}")
        print(f"  - Colonnes: {', '.join(result.columns)}")

        # Fusionner les fichiers un par un
        for i, file_path in enumerate(file_paths[1:], 2):
            df = pd.read_csv(file_path)
            print(f"\nFichier {i}: {file_path}")
            print(f"  - Nombre de lignes: {len(df)}")
            print(f"  - Colonnes: {', '.join(df.columns)}")

            # Effectuer la jointure
            result = pd.merge(result, df, on=on_column, how=merge_type)
            print(f"  - Fusion par jointure (type: {merge_type}) sur la/les colonne(s): {on_column}")
            print(f"  - Résultat intermédiaire: {len(result)} lignes")

        # Si un ordre de priorité est spécifié
        if priority_order is not None:
            # Nettoyer la liste de priorité (supprimer les doublons)
            priority_order = list(dict.fromkeys(priority_order))
            print(f"\nTriage selon l'ordre de priorité : {priority_order}")

            # Créer une colonne temporaire avec les valeurs en minuscules pour la correspondance insensible à la casse
            result['_temp_vendor_lower'] = result[on_column].str.lower()

            # Créer un dictionnaire de mapping pour l'ordre de priorité (insensible à la casse)
            priority_dict = {vendor.lower(): i for i, vendor in enumerate(priority_order)}

            # Créer une colonne d'ordre de priorité (les vendeurs non listés auront une valeur élevée)
            result['_priority'] = result['_temp_vendor_lower'].apply(
                lambda x: priority_dict.get(x, len(priority_order))
            )

            # Trier par priorité
            result = result.sort_values('_priority')

            # Supprimer les colonnes temporaires
            result = result.drop(columns=['_temp_vendor_lower', '_priority'])

        # Enregistrer le résultat final
        result.to_csv(output_path, index=False)

        print(f"\nRésultat final:")
        print(f"  - Nombre de lignes: {len(result)}")
        print(f"  - Colonnes: {', '.join(result.columns)}")
        print(f"  - Enregistré dans: {output_path}")

        # Afficher les premiers vendeurs pour vérification
        print("\nPremiers vendeurs dans le résultat :")
        print(result[on_column].head(10).to_list())

        return True

    except Exception as e:
        print(f"Erreur lors de la fusion des fichiers: {e}")
        return False


# Exemple d'utilisation
if __name__ == "__main__":
    # Définir l'ordre de priorité des vendeurs (nettoyé, sans doublons)
    priorite_vendeurs = ['google', 'samsung', 'apple', 'nvidia', 'dell', 'cisco', 'dlink', 'lenovo']

    # Fusionner trois fichiers avec une jointure sur la colonne "Vendor" et trier selon l'ordre de priorité
    merge_multiple_csv_files(
        file_paths=[
            "results/9-count_nbr_vuln_vendeur-nist.csv",
            "results/10-count_nbr_produit_vendeur-nist.csv",
            "results/14-temp_moy_vendeur-mitre.csv"
        ],
        output_path="results/11-fusion_9_10_14-fin.csv",
        merge_type="outer",  # "outer" pour inclure tous les vendeurs
        on_column="Vendor",
        priority_order=priorite_vendeurs
    )
