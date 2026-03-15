import json
import csv
from datetime import datetime

def export_json(results, target, filename):
    data = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "total_open": len(results),
        "results": results
    }
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def export_csv(results, target, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "Port", "Protocol", "State", "Service", "Version"])
        for res in results:
            writer.writerow([
                target,
                res["port"],
                res["protocol"],
                res["state"],
                res["service"],
                res["version"]
            ])
