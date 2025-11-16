import pandas as pd


def generer_meilleures_associations(fichier_h, fichier_o, fichier_sortie):
    """
    Génère les meilleures associations entre produits matériels et OS

    Args:
        fichier_h (str): Chemin vers le fichier CSV de produits matériels
        fichier_o (str): Chemin vers le fichier CSV des OS existants
        fichier_sortie (str): Chemin du fichier de sortie pour les meilleures associations
    """
    # Lire les fichiers CSV
    df_h = pd.read_csv(fichier_h)
    df_o = pd.read_csv(fichier_o)

    print(f"Produits matériels chargés: {len(df_h)}")
    print(f"Systèmes d'exploitation chargés: {len(df_o)}")

    # Créer un dictionnaire des OS par fabricant
    os_par_fabricant = {}
    for _, row in df_o.iterrows():
        vendor = row['Vendor']
        product = row['Product']

        if vendor not in os_par_fabricant:
            os_par_fabricant[vendor] = []

        os_par_fabricant[vendor].append(product)

    # Créer les associations
    resultats = []
    for _, row in df_h.iterrows():
        vendor = row['Vendor']
        product = row['Product']
        firmware = f"{product}_firmware"

        # Vérifier si un OS correspondant existe déjà
        best_os = firmware  # Par défaut, utiliser le firmware

        if vendor in os_par_fabricant:
            # Si le firmware existe déjà, l'utiliser
            if firmware in os_par_fabricant[vendor]:
                best_os = firmware
            else:
                # Chercher une correspondance partielle
                for os in os_par_fabricant[vendor]:
                    if product.lower() in os.lower() or os.lower() in product.lower():
                        best_os = os
                        break

        resultats.append({
            'Vendor': vendor,
            'Product H': product,
            'Product OS': best_os
        })

    # Convertir en DataFrame et sauvegarder
    df_resultats = pd.DataFrame(resultats)

    # Sauvegarder uniquement les meilleures associations
    df_resultats.to_csv(fichier_sortie, index=False)
    print(f"Meilleures associations sauvegardées dans {fichier_sortie}")

    return df_resultats


def main():
    fichier_h = 'results/6-liste_vendeurs_h-nist.csv'
    fichier_o = 'results/7-liste_vendeurs_o-nist.csv'
    fichier_sortie = 'results/8-liste_produit_os-nist.csv'

    print("Génération des meilleures associations entre produits et OS...")
    generer_meilleures_associations(fichier_h, fichier_o, fichier_sortie)
    print("Traitement terminé.")


if __name__ == "__main__":
    main()