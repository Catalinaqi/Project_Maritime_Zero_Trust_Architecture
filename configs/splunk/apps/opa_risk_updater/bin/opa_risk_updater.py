#!/usr/bin/env python3
"""
Aggiornamento dei risk score OPA da Splunk.

Legge il lookup CSV aggiornato dalla saved search di Splunk e riscrive
il documento JSON osservato da OPA. La scrittura è atomica per evitare
che OPA legga un file parzialmente aggiornato.

Il documento JSON segue il formato piatto atteso dalla policy OPA:
  {
    "operatore_ancona": { "risk_score": 10, "is_anomaly": false, ... },
    ...
  }
"""

import csv
import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone

CSV_PATH = "/opt/splunk/etc/apps/opa_risk_updater/lookups/historical_risk_scores.csv"
DEFAULT_JSON_PATH = "/opa_data/risk_data/risk_scores.json"
LOG_PATH = "/opt/splunk/var/log/splunk/opa_risk_updater.log"


def configure_logging():
    """Configura il file di log Splunk, con fallback su stderr."""
    log_format = "%(asctime)s %(levelname)s %(message)s"
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format=log_format)
    except OSError:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO, format=log_format)


def as_int(value, default):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def as_bool(value):
    return str(value).strip().lower() in {"1", "true", "yes"}


def load_current(path):
    """Carica il JSON corrente o restituisce un dizionario vuoto."""
    try:
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError) as error:
        logging.warning("Baseline non leggibile: %s", error)
    return {}


def atomic_write(path, data):
    """
    Scrive il documento JSON in modo atomico.

    I permessi 0644 consentono al processo OPA, eseguito con un utente
    non privilegiato, di leggere il file generato da Splunk.
    """
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    os.chmod(directory, 0o755)

    # mkstemp crea il file con permessi 0600; vengono ampliati prima del rename.
    descriptor, temporary_path = tempfile.mkstemp(
        prefix="risk-",
        suffix=".json",
        dir=directory,
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")

        os.chmod(temporary_path, 0o644)
        # Sostituzione atomica: OPA non legge mai un file incompleto.
        os.replace(temporary_path, path)
        os.chmod(path, 0o644)

    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def update(configuration):
    destination = configuration.get("param.opa_json_path", DEFAULT_JSON_PATH)
    if not os.path.exists(CSV_PATH):
        logging.warning("Lookup non trovato: %s", CSV_PATH)
        return

    # Carica lo stato corrente per preservare utenti non presenti nel CSV.
    data = load_current(destination)

    with open(CSV_PATH, newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            user_id = (row.get("user_id") or "").strip()
            if not user_id or user_id == "unknown":
                continue
            # Il documento JSON è piatto: la chiave è direttamente lo user_id.
            data[user_id] = {
                "risk_score":   max(0, min(100, as_int(row.get("risk_score"), 100))),
                "is_anomaly":   as_bool(row.get("isAnomaly")),
                "denied_count": as_int(row.get("denied_count"), 0),
                "updated_at":   datetime.now(timezone.utc).isoformat(),
            }

    atomic_write(destination, data)
    logging.info("Risk score aggiornati in %s", destination)


if __name__ == "__main__":
    configure_logging()
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        update(payload.get("configuration", {}))
    except Exception as error:
        logging.exception("Aggiornamento fallito: %s", error)
        raise
