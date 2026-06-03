import sys
import json
import csv
import os
import logging
from datetime import datetime

# Percorso standard dove l'app "Search" di Splunk salva i lookup
SPLUNK_CSV = "/opt/splunk/etc/apps/search/lookups/risk_scores.csv"

def setup_logging():
    logging.basicConfig(
        filename="/opt/splunk/var/log/splunk/opa_risk_updater.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

def update_risk_scores(config):
    opa_path = config.get("param.opa_json_path", "/opa_data/risk_scores.json")

    if not os.path.exists(SPLUNK_CSV):
        logging.warning(f"CSV non trovato: {SPLUNK_CSV}")
        return

    # Leggi il JSON esistente per non sovrascrivere utenti non presenti nell'attuale export CSV
    existing = {}
    if os.path.exists(opa_path):
        try:
            with open(opa_path) as f:
                existing = json.load(f)
        except Exception as e:
            logging.warning(f"JSON esistente non leggibile: {e}")

    # Aggiorna il dizionario con i nuovi dati calcolati da Splunk
    updated = 0
    with open(SPLUNK_CSV, newline="") as f:
        for row in csv.DictReader(f):
            user_id = row.get("user_id", "").strip()
            if not user_id or user_id == "unknown":
                continue

            existing[user_id] = {
                "risk_score":   int(float(row.get("risk_score", 10))),
                "is_anomaly":   row.get("isAnomaly", "0") == "1",
                "denied_count": int(float(row.get("denied_count", 0))),
                "updated_at":   datetime.utcnow().isoformat()
            }
            updated += 1
            logging.info(f"Aggiornato {user_id} → risk_score={existing[user_id]['risk_score']}")

    # Scrivi il file JSON aggiornato nel volume condiviso con OPA
    with open(opa_path, "w") as f:
        json.dump(existing, f, indent=2)

    logging.info(f"Completato: {updated} utenti aggiornati")

if __name__ == "__main__":
    setup_logging()
    payload = json.loads(sys.stdin.read())
    config  = payload.get("configuration", {})
    update_risk_scores(config)
