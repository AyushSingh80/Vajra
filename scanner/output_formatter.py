# scanner/output_formatter.py
import json
import csv
from typing import List, Dict, Any

def save_json(results: List[Dict[str, Any]], filename: str):
    """
    Saves scan results to a JSON file.

    Args:
        results: A list of dictionaries, where each dictionary represents a scan result.
        filename: The name of the JSON file to save to.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
    except IOError as e:
        print(f"Error saving JSON to {filename}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while saving JSON: {e}")

def save_csv(results: List[Dict[str, Any]], filename: str):
    """
    Saves scan results to a CSV file.

    Args:
        results: A list of dictionaries, where each dictionary represents a scan result.
        filename: The name of the CSV file to save to.
    """
    if not results:
        print(f"No results to save to CSV for {filename}.")
        return

    # Determine headers from the first result's keys, ensuring 'service' is present
    headers = list(results[0].keys())
    if 'service' not in headers:
        headers.append('service') # Ensure 'service' column exists even if first result doesn't have it

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for entry in results:
                # Use .get() with a default value to handle missing keys gracefully
                row = {key: entry.get(key, '') for key in headers}
                writer.writerow(row)
    except IOError as e:
        print(f"Error saving CSV to {filename}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while saving CSV: {e}")