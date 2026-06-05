import sys
import json
import csv
import os
import logging
from datetime import datetime

# Percorso standard dove l'app "Search" di Splunk salva i lookup
SPLUNK_CSV = "/opt/splunk/etc/apps/search/lookups/historical_risk_scores.csv"

def setup_logging():
    logging.basicConfig(
        filename="/opt/splunk/var/log/splunk/opa_risk_updater.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

def update_risk_scores(config):
    # Rimossa la sovrascrittura successiva e corretta l'assegnazione
    opa_path = config.get("param.opa_json_path", "/opa_data/risk_scores.json")

    if not os.path.exists(SPLUNK_CSV):
        logging.warning(f"CSV non trovato: {SPLUNK_CSV}")
        return

    # 1. LETTURA (Forza la presenza della root key)
    existing_data = {"risk_scores": {}}
    if os.path.exists(opa_path):
        try:
            with open(opa_path, "r") as f:
                existing_data = json.load(f)
        except Exception as e:
            logging.warning(f"Errore lettura JSON: {e}")

    # Assicurati che la chiave esista per evitare errori
    if "risk_scores" not in existing_data:
        existing_data["risk_scores"] = {}

    # Aggiorna il dizionario con i nuovi dati calcolati da Splunk
    updated = 0
    with open(SPLUNK_CSV, newline="") as f:
        for row in csv.DictReader(f):
            user_id = row.get("user_id", "").strip()
            if not user_id or user_id == "unknown":
                continue

            # Puntatore corretto a existing_data e alla chiave radice "risk_scores"
            existing_data["risk_scores"][user_id] = {
                "risk_score":   int(float(row.get("risk_score", 10))),
                "is_anomaly":   row.get("isAnomaly", "0") == "1",
                "denied_count": int(float(row.get("denied_count", 0))),
                "updated_at":   datetime.utcnow().isoformat()
            }
            updated += 1
            logging.info(f"Aggiornato {user_id} → risk_score={existing_data['risk_scores'][user_id]['risk_score']}")

    # SCRITTURA
    with open(opa_path, "w") as f:
        json.dump(existing_data, f, indent=2)

    logging.info(f"Completato: {updated} utenti aggiornati")

if __name__ == "__main__":
    setup_logging()
    payload = json.loads(sys.stdin.read())
    config  = payload.get("configuration", {})
    update_risk_scores(config)
