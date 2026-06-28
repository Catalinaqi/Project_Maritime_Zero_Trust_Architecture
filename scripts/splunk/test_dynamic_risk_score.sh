#!/usr/bin/env bash

# Demo controllata del risk score dinamico tramite Splunk.
#
# Obiettivo:
# 1. avviare i servizi principali dell'architettura;
# 2. inviare 8 eventi OPA sintetici tramite Splunk HEC;
# 3. verificare che HEC abbia accettato tutti gli eventi;
# 4. verificare, tramite la Search API di Splunk, che gli 8 eventi siano
#    stati realmente indicizzati;
# 5. generare un vero alert Snort critico dal client SOC;
# 6. verificare che l'alert Snort sia stato indicizzato;
# 7. stampare a terminale gli eventi trovati e le query SPL da utilizzare
#    nell'interfaccia web di Splunk.
#
# Questo script NON modifica manualmente historical_risk_scores.csv.
# Il CSV deve essere aggiornato dalla saved search configurata in Splunk.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Carica le funzioni comuni già utilizzate dagli altri test.
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib_test_helpers.sh"

EXPECTED_EVENTS=8
EXPECTED_SNORT_EVENTS=1
HEC_ACCEPTED_EVENTS=0
TEST_RUN_ID="opa-demo-$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVENT_SOURCE="dynamic-risk-test"

# Gli eventi sono distribuiti in modo che operatore_ancona accumuli
# 6 decisioni negate e superi la soglia denied_count > 5 della saved search.
# Gli altri due eventi mostrano che Splunk riceve chiamate associate anche
# ad altri utenti e contesti di rete.
EVENTS=(
  "1|operatore_ancona|D-001|vpn_net|172.20.11.31|GET|/all|false|Lettura globale non autorizzata"
  "2|operatore_ancona|D-001|vpn_net|172.20.11.31|POST|/risorse|false|Creazione risorsa non autorizzata"
  "3|operatore_ancona|D-001|vpn_net|172.20.11.31|DELETE|/risorse|false|Eliminazione risorsa non autorizzata"
  "4|operatore_ancona|D-001|vpn_net|172.20.11.31|POST|/dispositivi|false|Modifica dispositivi non autorizzata"
  "5|operatore_ancona|D-001|vpn_net|172.20.11.31|PUT|/risorse|false|Aggiornamento risorsa non autorizzato"
  "6|operatore_ancona|D-001|vpn_net|172.20.11.31|DELETE|/all|false|Operazione amministrativa non autorizzata"
  "7|capitano_claudia|D-002|satellite_net|172.20.12.31|DELETE|/risorse|false|Eliminazione non consentita al capitano"
  "8|soc_admin|D-SOC|corporate_net|172.20.10.31|GET|/all|true|Operazione amministrativa consentita"
)

read_project_env_demo() {
  local key="${1:-}"
  local default_value="${2:-}"
  local value=""

  if [ -n "$key" ] && [ -f "$PROJECT_ROOT/.env" ]; then
    value="$(sed -n "s/^${key}=//p" "$PROJECT_ROOT/.env" | tail -n 1 | tr -d '\r')"
    value="${value#\"}"
    value="${value%\"}"
    value="${value#\'}"
    value="${value%\'}"
  fi

  if [ -z "$value" ]; then
    value="$default_value"
  fi

  printf '%s' "$value"
}

wait_for_splunk_hec_demo() {
  local token=""
  local response=""
  local attempt=1
  local max_attempts=60

  token="$(read_project_env_demo SPLUNK_HEC_TOKEN 'f34d1b82-628b-4b2a-8951-b8401314b875')"

  echo "Attendo Splunk HEC sulla porta 8088..."

  while [ "$attempt" -le "$max_attempts" ]; do
    response="$(
      curl -sS \
        -H "Authorization: Splunk $token" \
        http://localhost:8088/services/collector/health 2>/dev/null || true
    )"

    if printf '%s' "$response" | grep -Eq 'HEC is healthy|"code"[[:space:]]*:[[:space:]]*17'; then
      echo "Splunk HEC raggiungibile e pronto."
      return 0
    fi

    echo "Tentativo HEC $attempt/$max_attempts: servizio non ancora pronto."
    sleep 2
    attempt=$((attempt + 1))
  done

  echo "ERRORE: Splunk HEC non è raggiungibile su http://localhost:8088."
  return 1
}

wait_for_splunk_search_api_demo() {
  local password=""
  local response=""
  local attempt=1
  local max_attempts=60

  password="$(read_project_env_demo SPLUNK_PASSWORD 'zerotrust')"

  echo "Attendo la Search API di Splunk sulla porta interna 8089..."

  while [ "$attempt" -le "$max_attempts" ]; do
    response="$(
      compose exec -T \
        -e SPLUNK_TEST_PASSWORD="$password" \
        siem_central \
        sh -lc '
          curl -ksS \
            -u "admin:${SPLUNK_TEST_PASSWORD}" \
            "https://localhost:8089/services/server/info?output_mode=json"
        ' 2>/dev/null || true
    )"

    if printf '%s' "$response" | grep -q '"entry"'; then
      echo "Search API di Splunk raggiungibile."
      return 0
    fi

    echo "Tentativo Search API $attempt/$max_attempts: servizio non ancora pronto."
    sleep 2
    attempt=$((attempt + 1))
  done

  echo "ERRORE: la Search API di Splunk non è disponibile."
  return 1
}

print_event_header_demo() {
  local event_id="$1"
  local user_id="$2"
  local device_id="$3"
  local network="$4"
  local source_ip="$5"
  local method="$6"
  local endpoint="$7"
  local result="$8"
  local description="$9"
  local decision_label="DENY"

  if [ "$result" = "true" ]; then
    decision_label="ALLOW"
  fi

  echo "------------------------------------------------------------"
  echo "Evento sintetico OPA #$event_id/$EXPECTED_EVENTS"
  echo "Test run ID:       $TEST_RUN_ID"
  echo "Utente:            $user_id"
  echo "Device:            $device_id"
  echo "Rete:              $network"
  echo "IP sorgente:       $source_ip"
  echo "Operazione:        $method $endpoint"
  echo "Decisione OPA:     $decision_label (result=$result)"
  echo "Descrizione:       $description"
  echo "Destinazione:      Splunk HEC / sourcetype=opa_decision"
}

send_opa_event_demo() {
  local event_id="$1"
  local user_id="$2"
  local device_id="$3"
  local network="$4"
  local source_ip="$5"
  local method="$6"
  local endpoint="$7"
  local result="$8"
  local description="$9"

  local token=""
  local timestamp=""
  local payload=""
  local response=""

  token="$(read_project_env_demo SPLUNK_HEC_TOKEN 'f34d1b82-628b-4b2a-8951-b8401314b875')"
  timestamp="$(date +%s)"

  # Il corpo dell'evento mantiene i campi attesi dalla saved search reale.
  payload="$(
    printf '{"time":%s,"host":"zta-risk-demo","source":"%s","sourcetype":"opa_decision","index":"main","event":{"test_run_id":"%s","event_id":"%s","x-user-id":"%s","result":%s,"method":"%s","request_path":"%s","device_id":"%s","network":"%s","description":"%s","source":{"address":{"socketAddress":{"address":"%s"}}}}}' \
      "$timestamp" \
      "$EVENT_SOURCE" \
      "$TEST_RUN_ID" \
      "$event_id" \
      "$user_id" \
      "$result" \
      "$method" \
      "$endpoint" \
      "$device_id" \
      "$network" \
      "$description" \
      "$source_ip"
  )"

  response="$(
    curl -sS \
      -H "Authorization: Splunk $token" \
      -H 'Content-Type: application/json' \
      -d "$payload" \
      http://localhost:8088/services/collector/event 2>&1 || true
  )"

  echo "Risposta HEC:      $response"

  if printf '%s' "$response" | grep -Eq '"code"[[:space:]]*:[[:space:]]*0'; then
    HEC_ACCEPTED_EVENTS=$((HEC_ACCEPTED_EVENTS + 1))
    echo "Esito invio:       OK - evento accettato da HEC"
    echo ""
    return 0
  fi

  echo "Esito invio:       FALLITO"
  echo ""
  return 1
}

run_splunk_search_json_demo() {
  local query="$1"
  local password=""

  password="$(read_project_env_demo SPLUNK_PASSWORD 'zerotrust')"

  compose exec -T \
    -e SPLUNK_TEST_PASSWORD="$password" \
    -e SPLUNK_TEST_QUERY="$query" \
    siem_central \
    sh -lc '
      curl -ksS \
        -u "admin:${SPLUNK_TEST_PASSWORD}" \
        --data-urlencode "search=${SPLUNK_TEST_QUERY}" \
        --data-urlencode "output_mode=json" \
        "https://localhost:8089/services/search/jobs/export"
    '
}

run_splunk_search_csv_demo() {
  local query="$1"
  local password=""

  password="$(read_project_env_demo SPLUNK_PASSWORD 'zerotrust')"

  compose exec -T \
    -e SPLUNK_TEST_PASSWORD="$password" \
    -e SPLUNK_TEST_QUERY="$query" \
    siem_central \
    sh -lc '
      curl -ksS \
        -u "admin:${SPLUNK_TEST_PASSWORD}" \
        --data-urlencode "search=${SPLUNK_TEST_QUERY}" \
        --data-urlencode "output_mode=csv" \
        "https://localhost:8089/services/search/jobs/export"
    '
}

wait_for_exact_events_demo() {
  local attempt=1
  local max_attempts=30
  local query=""
  local response=""
  local received_count="0"
  local unique_events="0"

  query="search index=main sourcetype=opa_decision source=\"$EVENT_SOURCE\" earliest=-15m | spath path=test_run_id output=test_run_id | spath path=event_id output=event_id | search test_run_id=\"$TEST_RUN_ID\" | stats count as received_count dc(event_id) as unique_events"

  echo "Verifico che Splunk abbia indicizzato esattamente $EXPECTED_EVENTS eventi..."

  while [ "$attempt" -le "$max_attempts" ]; do
    response="$(run_splunk_search_json_demo "$query" 2>&1 || true)"

    received_count="$(
      printf '%s\n' "$response" \
        | sed -n 's/.*"received_count":"\([0-9][0-9]*\)".*/\1/p' \
        | tail -n 1
    )"

    unique_events="$(
      printf '%s\n' "$response" \
        | sed -n 's/.*"unique_events":"\([0-9][0-9]*\)".*/\1/p' \
        | tail -n 1
    )"

    received_count="${received_count:-0}"
    unique_events="${unique_events:-0}"

    echo "Tentativo $attempt/$max_attempts: ricevuti=$received_count, univoci=$unique_events"

    if [ "$received_count" -eq "$EXPECTED_EVENTS" ] && \
       [ "$unique_events" -eq "$EXPECTED_EVENTS" ]; then
      echo "VERIFICA SPLUNK: OK - tutti gli 8 eventi sono indicizzati."
      return 0
    fi

    sleep 2
    attempt=$((attempt + 1))
  done

  echo "ERRORE: Splunk non mostra tutti gli eventi del test run $TEST_RUN_ID."
  echo "Ultima risposta della Search API:"
  printf '%s\n' "$response"
  return 1
}

print_indexed_events_demo() {
  local query=""

  query="search index=main sourcetype=opa_decision source=\"$EVENT_SOURCE\" earliest=-15m | spath path=test_run_id output=test_run_id | spath path=event_id output=event_id | spath path=\"x-user-id\" output=user_id | spath path=method output=method | spath path=request_path output=request_path | spath path=device_id output=device_id | spath path=network output=network | spath path=\"source.address.socketAddress.address\" output=src_ip | spath path=result output=result | search test_run_id=\"$TEST_RUN_ID\" | table _time event_id user_id method request_path device_id network src_ip result | sort 0 event_id"

  print_section "EVENTI REALMENTE TROVATI IN SPLUNK"
  run_splunk_search_csv_demo "$query"
  echo ""
}

generate_soc_admin_snort_alert_demo() {
  print_section "FASE 4 - GENERAZIONE ALERT SNORT CRITICO PER SOC_ADMIN"

  echo "Utente osservato:   soc_admin"
  echo "Device:             D-SOC"
  echo "Client Docker:      client_dsoc_tpm"
  echo "IP sorgente:        172.20.10.31"
  echo "Traffico generato:  tentativo TCP SYN anomalo verso una porta non esposta del sensore Snort"
  echo "Regola attesa:      1:999902:* - TCP SYN SCAN ATTEMPT"
  echo "Effetto atteso:     snort_critical_count > 0, risk_score=90, isAnomaly=1"
  echo ""

  compose exec -T \
    client_dsoc_tpm \
    sh -lc 'curl -sS --connect-timeout 3 http://ids_network_monitor:1/ >/dev/null 2>&1 || true'

  echo "Traffico anomalo generato dal client SOC."
}

wait_for_soc_admin_snort_alert_demo() {
  local attempt=1
  local max_attempts=30
  local query=""
  local response=""
  local alert_count="0"

  query='search index=main sourcetype=snort_alert_json earliest=-10m | spath path=src_ap output=src_ap | spath path=dst_ap output=dst_ap | spath path=rule output=rule | spath path=msg output=msg | spath path=dir output=dir | rex field=src_ap "^(?<src_ip>[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):" | search src_ip="172.20.10.31" dir="C2S" rule="1:999902:*" | stats count as alert_count'

  echo "Verifico che Splunk abbia indicizzato l alert Snort del SOC..."

  while [ "$attempt" -le "$max_attempts" ]; do
    response="$(run_splunk_search_json_demo "$query" 2>&1 || true)"

    alert_count="$(
      printf '%s\n' "$response" \
        | sed -n 's/.*"alert_count":"\([0-9][0-9]*\)".*/\1/p' \
        | tail -n 1
    )"
    alert_count="${alert_count:-0}"

    echo "Tentativo $attempt/$max_attempts: alert Snort trovati=$alert_count"

    if [ "$alert_count" -ge "$EXPECTED_SNORT_EVENTS" ]; then
      echo "VERIFICA SNORT/SPLUNK: OK - alert critico del SOC indicizzato."
      return 0
    fi

    sleep 2
    attempt=$((attempt + 1))
  done

  echo "ERRORE: Splunk non mostra l alert Snort atteso per soc_admin."
  echo "Ultima risposta della Search API:"
  printf '%s\n' "$response"
  return 1
}

print_soc_admin_snort_events_demo() {
  local query=""

  query='search index=main sourcetype=snort_alert_json earliest=-10m | spath path=src_ap output=src_ap | spath path=dst_ap output=dst_ap | spath path=rule output=rule | spath path=msg output=msg | spath path=proto output=proto | spath path=dir output=dir | spath path=action output=action | rex field=src_ap "^(?<src_ip>[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):" | lookup snort_device_mapping.csv src_ip OUTPUT user_id device_id trust_level | search src_ip="172.20.10.31" | table _time user_id device_id trust_level src_ip dst_ap proto dir rule msg action | sort - _time'

  print_section "ALERT SNORT DEL SOC REALMENTE TROVATI IN SPLUNK"
  run_splunk_search_csv_demo "$query"
  echo ""
}

print_spl_queries_demo() {
  print_section "QUERY SPL DA ESEGUIRE NELL'INTERFACCIA SPLUNK"

  echo "Test run ID da usare: $TEST_RUN_ID"
  echo "Apri: http://localhost:8000 -> Search & Reporting"
  echo "Imposta l'intervallo temporale su: Last 15 minutes"
  echo ""

  echo "1) Verifica degli 8 eventi ricevuti"
  cat <<EOF_QUERY_1
index=main sourcetype=opa_decision source="$EVENT_SOURCE" earliest=-15m
| spath path=test_run_id output=test_run_id
| spath path=event_id output=event_id
| search test_run_id="$TEST_RUN_ID"
| stats count AS eventi_ricevuti dc(event_id) AS eventi_univoci
EOF_QUERY_1

  echo ""
  echo "2) Tabella dettagliata delle chiamate sintetiche"
  cat <<EOF_QUERY_2
index=main sourcetype=opa_decision source="$EVENT_SOURCE" earliest=-15m
| spath path=test_run_id output=test_run_id
| spath path=event_id output=event_id
| spath path="x-user-id" output=user_id
| spath path=method output=method
| spath path=request_path output=endpoint
| spath path=device_id output=device_id
| spath path=network output=network
| spath path="source.address.socketAddress.address" output=src_ip
| spath path=result output=decisione
| search test_run_id="$TEST_RUN_ID"
| table _time event_id user_id device_id network src_ip method endpoint decisione
| sort 0 event_id
EOF_QUERY_2

  echo ""
  echo "3) Conteggio dei DENY e calcolo dimostrativo del risk score per utente"
  cat <<EOF_QUERY_3
index=main sourcetype=opa_decision source="$EVENT_SOURCE" earliest=-15m
| spath path=test_run_id output=test_run_id
| spath path="x-user-id" output=user_id
| spath path=result output=decisione
| spath path="source.address.socketAddress.address" output=src_ip
| search test_run_id="$TEST_RUN_ID"
| eval is_denied=if(decisione="false",1,0)
| stats sum(is_denied) AS denied_count dc(src_ip) AS unique_ips by user_id
| eval risk_score=case(denied_count>5,80,denied_count>2,60,unique_ips>3,30,denied_count>0,20,true(),10)
| eval isAnomaly=if(denied_count>5,1,0)
| sort - risk_score
EOF_QUERY_3

  echo ""
  echo "4) Controllo del CSV aggiornato dalla saved search schedulata"
  cat <<'EOF_QUERY_4'
| inputlookup historical_risk_scores.csv
| sort - updated_at
EOF_QUERY_4

  echo ""
  echo "5) Log Snort dettagliati con associazione a utente e device"
  cat <<'EOF_QUERY_5'
index=main sourcetype=snort_alert_json earliest=-15m
| spath
| rex field=src_ap "^(?<src_ip>\d+\.\d+\.\d+\.\d+):"
| lookup snort_device_mapping.csv src_ip OUTPUT user_id device_id trust_level
| table _time user_id device_id trust_level src_ip dst_ap proto dir rule msg action
| sort - _time
EOF_QUERY_5

  echo ""
  echo "6) Solo alert Snort critici associati a soc_admin"
  cat <<'EOF_QUERY_6'
index=main sourcetype=snort_alert_json earliest=-15m
| spath
| rex field=src_ap "^(?<src_ip>\d+\.\d+\.\d+\.\d+):"
| lookup snort_device_mapping.csv src_ip OUTPUT user_id device_id trust_level
| eval is_critical=if(match(coalesce(msg,rule),"CRITICAL|DIRECT|BYPASS|ATTEMPT|INTRUDER|1:999902:"),1,0)
| search user_id="soc_admin" is_critical=1
| table _time user_id device_id trust_level src_ip dst_ap rule msg action
| sort - _time
EOF_QUERY_6

  echo ""
  echo "Nota: la saved search 'Calcolo Dinamico Risk Score OPA' viene eseguita ogni minuto"
  echo "e considera gli ultimi 5 minuti. Attendi al massimo un ciclo prima della query 4."
}

print_section "TEST EVENTI OPA SINTETICI -> SPLUNK"

echo "Obiettivo: inviare 8 decision log OPA sintetici e verificare"
echo "           che Splunk li abbia realmente indicizzati."
echo "Test run ID:       $TEST_RUN_ID"
echo "Eventi attesi:     $EXPECTED_EVENTS"
echo "Sourcetype:        opa_decision"
echo "Source Splunk:     $EVENT_SOURCE"
echo "Saved search:      Calcolo Dinamico Risk Score OPA"
echo "Aggiornamento CSV: gestito da Splunk, non forzato dallo script"
echo ""
echo "Distribuzione eventi OPA:"
echo "- operatore_ancona: 6 DENY -> risk score atteso 80, isAnomaly=1"
echo "- capitano_claudia: 1 DELETE negato -> risk score atteso 20"
echo "- soc_admin:        1 ALLOW -> nessun aumento dovuto a OPA"
echo "Evento Snort reale:"
echo "- soc_admin/D-SOC: tentativo TCP SYN anomalo rilevato da Snort -> risk score atteso 90, isAnomaly=1"

# Avvia realmente i componenti core dell'architettura, inclusi OPA, Splunk,
# Envoy e Snort. I client TPM sono necessari per generare il traffico
# Snort reale associato al device D-SOC.
start_base_services
start_testing_clients
wait_for_opa_health
wait_for_splunk_hec_demo
wait_for_splunk_search_api_demo

print_section "FASE 0 - BASELINE E ACCESSO SOC PRIMA DELL ANOMALIA"
set_static_risk_scores_baseline
run_access_test \
  "ALLOW iniziale - soc_admin prima dell alert Snort" \
  "client_dsoc_tpm" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200"

print_section "FASE 1 - INVIO DEGLI 8 EVENTI OPA SINTETICI"

for record in "${EVENTS[@]}"; do
  IFS='|' read -r \
    event_id \
    user_id \
    device_id \
    network \
    source_ip \
    method \
    endpoint \
    result \
    description <<< "$record"

  print_event_header_demo \
    "$event_id" \
    "$user_id" \
    "$device_id" \
    "$network" \
    "$source_ip" \
    "$method" \
    "$endpoint" \
    "$result" \
    "$description"

  if ! send_opa_event_demo \
    "$event_id" \
    "$user_id" \
    "$device_id" \
    "$network" \
    "$source_ip" \
    "$method" \
    "$endpoint" \
    "$result" \
    "$description"; then
    echo "ATTENZIONE: l evento #$event_id non è stato accettato da HEC."
    echo ""
  fi
done

print_section "FASE 2 - VERIFICA DELLE RISPOSTE HEC"

echo "Eventi inviati:             $EXPECTED_EVENTS"
echo "Eventi accettati da HEC:    $HEC_ACCEPTED_EVENTS"

if [ "$HEC_ACCEPTED_EVENTS" -ne "$EXPECTED_EVENTS" ]; then
  echo "ESITO HEC: FALLITO"
  exit 1
fi

echo "ESITO HEC: OK"

print_section "FASE 3 - VERIFICA DELL'INDICIZZAZIONE IN SPLUNK"
wait_for_exact_events_demo
print_indexed_events_demo

generate_soc_admin_snort_alert_demo
wait_for_soc_admin_snort_alert_demo
print_soc_admin_snort_events_demo

print_section "ESITO FINALE"
echo "HEC ha accettato:           $HEC_ACCEPTED_EVENTS/$EXPECTED_EVENTS eventi"
echo "Splunk ha indicizzato:      $EXPECTED_EVENTS/$EXPECTED_EVENTS eventi OPA univoci"
echo "Snort/Splunk:               alert critico SOC indicizzato"
echo "Test run ID:                $TEST_RUN_ID"
echo "ESITO COMPLESSIVO:          OK"
echo ""
echo "Il CSV historical_risk_scores.csv non viene modificato direttamente."
echo "Sarà la saved search schedulata di Splunk ad aggiornarlo al prossimo ciclo."
echo "Valori attesi: operatore_ancona=80, capitano_claudia=20, soc_admin=90/isAnomaly=1."
echo "Con la policy aggiornata, soc_admin viene negato quando is_anomaly=true."

print_spl_queries_demo
