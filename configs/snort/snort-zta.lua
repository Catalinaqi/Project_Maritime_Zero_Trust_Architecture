-- =============================================================================
-- Snort 3 IDS Configuration (ZTA Master Template)
-- =============================================================================
-- Propósito: Configuración principal del sensor IDS para arquitectura Zero Trust.
-- Nota: Este archivo usa sintaxis ${VAR} para ser procesado por envsubst
--       en el entrypoint antes de arrancar Snort.
-- =============================================================================

-- STEP 1: DAQ (Data Acquisition)
-- Define cómo Snort captura los paquetes de la red virtual de Docker.
-- Se apunta explícitamente al directorio de compilación para evitar fallos de pcap.
-- pcap -> afpacket
daq = {
    module_dirs = { '/usr/local/lib/daq' },
    modules = { { name = 'afpacket', mode = 'passive' } }
}

-- STEP 2: Pattern Matching Engine
-- Motor de búsqueda de patrones (Deep Packet Inspection). 'ac_bnfa' ofrece
-- un excelente balance entre velocidad de detección y consumo de RAM.
search_engine = { search_method = 'ac_bnfa' }

-- STEP 3: Stream Reassembly
-- Ensamblaje de flujos. Vital para evitar evasiones de fragmentación L4/L7.
-- El timeout de TCP se reduce a 60s para liberar memoria rápidamente en el contenedor.
stream = { }
stream_tcp = { session_timeout = 60 }
stream_udp = { }
stream_icmp = { }
stream_ip = { }

-- STEP 4: Application Inspectors & Binder
-- Módulos de inspección de capa de aplicación. Necesarios para que Snort
-- entienda el tráfico HTTP en claro y aplique las reglas correctamente.
http_inspect = { }
binder = { }

-- STEP 5: Logging / SIEM Integration
-- Generación de alertas. Configurado estrictamente en JSON para facilitar
-- el parseo inmediato del HEC de Splunk y la extracción de entidades.
-- old1: fields = { 'timestamp', 'pkt_num', 'proto', 'pkt_gen', 'dir', 'src_addr', 'src_port', 'dst_addr', 'dst_port', 'action', 'msg', 'rule' }
-- old2: fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule msg action'
-- old3: fields = { 'timestamp', 'pkt_num', 'proto', 'pkt_gen', 'pkt_len', 'dir', 'src_addr', 'src_port', 'dst_addr', 'dst_port', 'rule', 'msg', 'action' }
alert_json = {
    file = true,
    limit = 10,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action'
}

-- STEP 6: IPS Configuration (Variables & Rules)
-- Define el modelo topológico ZTA (Redes y Puertos) inyectado dinámicamente
-- desde el docker-compose.yml y carga el archivo maestro de reglas.
ips = {
    variables = {
        nets = {
            HOME_NET      = '${ZTA_HOME_NET}',
            EXTERNAL_NET  = '!${ZTA_HOME_NET}',
            PUBLIC_NET    = '${ZTA_PUBLIC_NET}',
            VPN_NET       = '${ZTA_VPN_NET}',
            SATELLITE_NET = '${ZTA_SATELLITE_NET}',
            CORPORATE_NET = '${ZTA_CORPORATE_NET}',
            BACKEND_NET   = '${ZTA_BACKEND_NET}'
        },
        ports = {
            PEP_PORT   = '${ZTA_PEP_PORT}',
            OPA_PORTS  = '${ZTA_OPA_PORTS}',
            MONGO_PORT = '${ZTA_MONGO_PORT}',
            API_PORT   = '${ZTA_API_PORT}',
            SIEM_PORTS = '${ZTA_SIEM_PORTS}',
            ADMIN_PORT = '${ZTA_ADMIN_PORT}'
        }
    },
    rules = [[
        include /etc/snort/snort-zta.rules
    ]]
}
