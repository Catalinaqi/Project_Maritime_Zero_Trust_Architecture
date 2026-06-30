-- =============================================================================
-- SNORT 3 IDS - MARITIME ZERO TRUST ARCHITECTURE
-- =============================================================================
--
-- Questo file rappresenta il template principale della configurazione Snort.
--
-- Le variabili nella forma ${NOME_VARIABILE} vengono sostituite
-- dall'entrypoint tramite envsubst prima dell'avvio di Snort.
--
-- Snort opera come IDS passivo:
--
-- client -> firewall_perimeter -> pep_gateway
--                   |
--                   +-> Snort osserva il traffico
--
-- Snort non riceve il traffico come server e non effettua alcun inoltro.
-- =============================================================================


-- =============================================================================
-- 1. DATA ACQUISITION - DAQ
-- =============================================================================
--
-- Il modulo AFPacket permette a Snort di osservare passivamente il traffico
-- sulle interfacce client del namespace condiviso con il firewall.
--
-- Non viene utilizzata la modalità inline e non viene utilizzato -Q.
-- =============================================================================

daq = {
    module_dirs = {
        '/usr/local/lib/daq'
    },

    modules = {
        {
            name = 'afpacket',
            mode = 'passive'
        }
    }
}


-- =============================================================================
-- 2. MOTORE DI RICERCA DEI PATTERN
-- =============================================================================
--
-- Configura il motore utilizzato per cercare le sequenze definite
-- all'interno delle regole Snort.
-- =============================================================================

search_engine = {
    search_method = 'ac_bnfa'
}


-- =============================================================================
-- 3. RIASSEMBLAGGIO DEI FLUSSI
-- =============================================================================
--
-- Permette a Snort di ricostruire correttamente i flussi di rete.
-- Questo limita le tecniche di evasione basate su frammentazione
-- e segmentazione dei pacchetti.
-- =============================================================================

stream = {
}

stream_tcp = {
    -- Le sessioni TCP inattive vengono rimosse dopo 60 secondi.
    session_timeout = 60
}

stream_udp = {
}

stream_icmp = {
}

stream_ip = {
}


-- =============================================================================
-- 4. ISPETTORI APPLICATIVI
-- =============================================================================
--
-- Abilita gli ispettori necessari per classificare e analizzare
-- i protocolli applicativi supportati.
-- =============================================================================

http_inspect = {
}

binder = {
}


-- =============================================================================
-- 5. OUTPUT JSON PER SPLUNK
-- =============================================================================
--
-- Gli alert vengono salvati nel file:
--
-- /var/log/snort/alert_json.txt
--
-- Il volume snort_logs viene condiviso con Splunk, che legge il file
-- attraverso la configurazione inputs.conf.
-- =============================================================================

alert_json = {
    -- Scrive gli eventi su file.
    file = true,

    -- Limite del file di log gestito dal modulo.
    limit = 10,

    -- Campi inseriti in ogni evento JSON.
    fields = table.concat({
        'timestamp',
        'pkt_num',
        'proto',
        'pkt_gen',
        'pkt_len',
        'dir',
        'src_ap',
        'dst_ap',
        'rule',
        'action'
    }, ' ')
}


-- =============================================================================
-- 6. VARIABILI DI RETE E REGOLE IPS
-- =============================================================================
--
-- Le variabili vengono lette dal docker-compose.yml e sostituite
-- dall'entrypoint prima dell'avvio di Snort.
-- =============================================================================

ips = {
    variables = {

        -- ---------------------------------------------------------------------
        -- Reti della Maritime Zero Trust Architecture
        -- ---------------------------------------------------------------------
        nets = {
            -- Insieme delle reti considerate appartenenti all'architettura.
            HOME_NET = '${ZTA_HOME_NET}',

            -- Tutto ciò che non appartiene a HOME_NET.
            EXTERNAL_NET = '!${ZTA_HOME_NET}',

            -- Rete pubblica e non affidabile.
            PUBLIC_NET = '${ZTA_PUBLIC_NET}',

            -- Rete utilizzata dagli operatori tramite VPN.
            VPN_NET = '${ZTA_VPN_NET}',

            -- Rete utilizzata dai dispositivi satellitari.
            SATELLITE_NET = '${ZTA_SATELLITE_NET}',

            -- Rete corporate utilizzata dal SOC.
            CORPORATE_NET = '${ZTA_CORPORATE_NET}',

            -- Rete interna contenente API e MongoDB.
            BACKEND_NET = '${ZTA_BACKEND_NET}'
        },

        -- ---------------------------------------------------------------------
        -- Porte dei servizi
        -- ---------------------------------------------------------------------
        ports = {
            -- Porta mTLS di Envoy.
            PEP_PORT = '${ZTA_PEP_PORT}',

            -- Porte REST e gRPC di OPA.
            OPA_PORTS = '${ZTA_OPA_PORTS}',

            -- Porta MongoDB.
            MONGO_PORT = '${ZTA_MONGO_PORT}',

            -- Porta dell'API backend.
            API_PORT = '${ZTA_API_PORT}',

            -- Porte Web e HEC di Splunk.
            SIEM_PORTS = '${ZTA_SIEM_PORTS}',

            -- Porta amministrativa di Envoy.
            ADMIN_PORT = '${ZTA_ADMIN_PORT}'
        }
    },

    -- Carica il file contenente le regole personalizzate del progetto.
    rules = [[
        include /etc/snort/snort-zta.rules
    ]]
}
