import os
import json
import csv
from datetime import datetime, timezone
import dateutil.parser


def calculate_cve_resolution_time(directory_path, output_file_path):
    """
    Process all JSON files in a directory to calculate the time between dateReserved and datePublished.
    Silently ignore files without required information.

    Args:
        directory_path (str): Path to the directory containing CVE JSON files
        output_file_path (str): Path to save the output CSV file

    Returns:
        dict: Dictionary containing CVE_ID and resolution time in days
    """
    results = {}
    errors = 0
    processed = 0
    skipped = 0

    def ensure_timezone_aware(dt):
        """Convert naive datetime to aware datetime if needed"""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    # Iterate through all files in the directory
    total_files = len([f for f in os.listdir(directory_path) if f.endswith('.json')])
    print(f"Processing {total_files} JSON files...")

    for filename in os.listdir(directory_path):
        if filename.endswith('.json'):
            file_path = os.path.join(directory_path, filename)

            try:
                # Read JSON file
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Extract CVE ID and dates from the structure
                cve_metadata = data.get('cveMetadata', {})
                cve_id = cve_metadata.get('cveId')
                date_reserved_str = cve_metadata.get('dateReserved')
                date_published_str = cve_metadata.get('datePublished')

                # Skip if required data is missing (silently)
                if not cve_id or not date_reserved_str or not date_published_str:
                    skipped += 1
                    continue

                try:
                    # Parse dates and ensure they're timezone-aware
                    date_reserved = ensure_timezone_aware(dateutil.parser.parse(date_reserved_str))
                    date_published = ensure_timezone_aware(dateutil.parser.parse(date_published_str))

                    # Calculate time difference in days
                    time_diff = (date_published - date_reserved).days

                    # If days is 0, set it to 1 as specified
                    if time_diff == 0:
                        time_diff = 1

                    # Store result
                    results[cve_id] = time_diff
                    processed += 1
                except Exception:
                    errors += 1

            except Exception:
                errors += 1

    # Write results to output CSV file
    with open(output_file_path, 'w', newline='', encoding='utf-8') as f:
        csv_writer = csv.writer(f)
        # Write header
        csv_writer.writerow(['CVE_ID', 'Temps_de_correction'])

        # Write data rows
        for cve_id, time_diff in sorted(results.items()):
            csv_writer.writerow([cve_id, time_diff])

    print(f"Results written to {output_file_path}")
    print(f"Total files: {total_files}")
    print(f"Successfully processed: {processed} files")
    print(f"Skipped (missing data): {skipped} files")
    print(f"Errors: {errors} files")

    return results


# Example usage
if __name__ == "__main__":
    # Paths for the CVE files and output
    #directory_path = "./cvelist_mitre_2023"
    output_file_path = "results/24-calculate_cve_resolution_time-mitre.csv"

    results = calculate_cve_resolution_time(directory_path, output_file_path)

    # Calculate and print average resolution time
    if results:
        avg_time = sum(results.values()) / len(results)
        print(f"Average resolution time: {avg_time:.2f} days")

        # Find min and max resolution times
        min_time = min(results.values())
        max_time = max(results.values())
        min_cve = [cve for cve, time in results.items() if time == min_time][0]
        max_cve = [cve for cve, time in results.items() if time == max_time][0]

        print(f"Minimum resolution time: {min_time} days (CVE: {min_cve})")
        print(f"Maximum resolution time: {max_time} days (CVE: {max_cve})")
        print(f"Total CVEs processed successfully: {len(results)}")