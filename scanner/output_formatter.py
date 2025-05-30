# scanner/output_formatter.py
import json
import csv

def save_json(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

def save_csv(results, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Host', 'Port', 'Status', 'Service'])
        for entry in results:
            writer.writerow([entry['host'], entry['port'], entry['status'], entry.get('service', '-')])
