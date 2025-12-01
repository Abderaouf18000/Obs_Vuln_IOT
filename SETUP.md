# External Data Setup Guide

This guide details the required structure for the project's **external data**. These files are **not tracked by Git** because they are too voluminous, ensuring the repository remains lightweight and fast to clone.

---

## Data Exclusion Policy

The directories listed below must be populated via a separate download script/bundle.

## Data Placement

All paths listed below are **relative to the project root directory** (where this file is located). The application expects this structure to exist before execution.

* `public_html/cve-analysis/2-Prédiction_vendeurs_2024.csv`
* `Python/cvelist_mitre_YYYY/`: from 2015 to 2025
* `Python/cvelist_nist/`
* `Python/produit/`
* `Python/results/`
