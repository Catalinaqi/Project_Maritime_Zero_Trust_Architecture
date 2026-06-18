import sys
import json
import csv
import os
import logging
from datetime import datetime


# Lookup CSV prodotto da Splunk con i risk score calcolati dinamicamente.
# Deve essere coerente con savedsearches.conf e con lo script di test.
SPLUNK_CSV = "/opt/splunk/etc/apps/opa_risk_updater/lookups/historical_risk_scores.csv"

# Log dello script dentro il container Splunk.
LOG_FILE = "/opt/splunk/var/log/splunk/opa_risk_updater.log"

# Path del JSON condiviso con OPA tramite docker-compose.
DEFAULT_OPA_JSON_PATH = "/opa_data/risk_data/risk_scores.json"


def setup_logging():
    """
    Configura il logging dello script.

    I log vengono salvati in Splunk, così puoi verificare se il risk score
    è stato aggiornato correttamente.
    """
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )


def load_existing_risk_scores(opa_path):
    """
Legge il JSON usato da OPA.

La policy OPA legge:

    data.risk_data.risk_scores[user_id].risk_score

Il file JSON deve avere questa struttura:

    {
      "risk_scores": {
        "operatore_ancona": {
          "risk_score": 10
        }
      }
    }

Poiché il file viene montato in OPA come:

    /policies/risk_data/risk_scores.json

OPA lo espone come:

    data.risk_data.risk_scores
"""

    default_data = {"risk_scores": {}}

    if not os.path.exists(opa_path):
        logging.warning(f"File JSON OPA non trovato. Verrà creato: {opa_path}")
        return default_data

    try:
        with open(opa_path, "r") as f:
            data = json.load(f)

        if isinstance(data, dict) and "risk_scores" in data:
            if isinstance(data["risk_scores"], dict):
                return data

            logging.warning("Campo 'risk_scores' non valido. Reinizializzo il JSON.")
            return default_data

        if isinstance(data, dict):
            logging.info("Rilevata vecchia struttura piatta. Conversione automatica.")
            return {"risk_scores": data}

        logging.warning("Struttura JSON non valida. Reinizializzo il JSON.")
        return default_data

    except Exception as e:
        logging.warning(f"JSON OPA non leggibile: {e}")
        return default_data


def safe_int(value, default=0):
    """
    Converte in intero valori provenienti da Splunk.

    Splunk può salvare numeri come stringhe, ad esempio "10" oppure "10.0".
    """
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except Exception:
        return default


def safe_bool(value):
    """
    Converte valori testuali/numerici di Splunk in booleano.
    """
    if value is None:
        return False

    return str(value).strip().lower() in ["1", "true", "yes"]


def update_risk_scores(config):
    """
    Aggiorna il JSON letto da OPA partendo dal CSV prodotto da Splunk.
    """
    opa_path = config.get("param.opa_json_path", DEFAULT_OPA_JSON_PATH)

    logging.info(f"Avvio aggiornamento risk score. CSV={SPLUNK_CSV}, OPA_JSON={opa_path}")

    if not os.path.exists(SPLUNK_CSV):
        logging.warning(f"CSV Splunk non trovato: {SPLUNK_CSV}")
        return

    existing = load_existing_risk_scores(opa_path)

    updated = 0
    skipped = 0

    try:
        with open(SPLUNK_CSV, newline="") as f:
            reader = csv.DictReader(f)

            for row in reader:
                user_id = row.get("user_id", "").strip()

                if not user_id or user_id == "unknown":
                    skipped += 1
                    continue

                risk_score = safe_int(row.get("risk_score"), 10)
                denied_count = safe_int(row.get("denied_count"), 0)
                is_anomaly = safe_bool(row.get("isAnomaly"))

                existing["risk_scores"][user_id] = {
                    "risk_score": risk_score,
                    "is_anomaly": is_anomaly,
                    "denied_count": denied_count,
                    "updated_at": datetime.utcnow().isoformat()
                }

                updated += 1

                logging.info(
                    f"Aggiornato {user_id} -> "
                    f"risk_score={risk_score}, "
                    f"is_anomaly={is_anomaly}, "
                    f"denied_count={denied_count}"
                )

    except Exception as e:
        logging.error(f"Errore durante la lettura del CSV Splunk: {e}")
        return

    try:
        os.makedirs(os.path.dirname(opa_path), exist_ok=True)

        with open(opa_path, "w") as f:
            json.dump(existing, f, indent=2)

        logging.info(
            f"Aggiornamento completato: {updated} utenti aggiornati, {skipped} righe ignorate"
        )

    except Exception as e:
        logging.error(f"Errore durante la scrittura del JSON OPA: {e}")


if __name__ == "__main__":
    setup_logging()

    try:
        raw_input = sys.stdin.read()
        payload = json.loads(raw_input) if raw_input.strip() else {}
        config = payload.get("configuration", {})
        update_risk_scores(config)

    except Exception as e:
        logging.error(f"Errore generale nello script opa_risk_updater: {e}")
        sys.exit(1)
