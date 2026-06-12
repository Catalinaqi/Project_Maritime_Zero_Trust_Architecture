-- =============================================================================
-- Snort 3 IDS Configuration - MVP Lightweight Mode
-- =============================================================================
-- Author: Network Guardian (Snort/IDS)
-- Component: Layer 1 Intrusion Detection System
-- Purpose: Optimized for MVP (Snort + Splunk + Intruder) with minimal CPU load
-- Last Updated: 2026-06-08
-- =============================================================================

-- STEP 1: Network definitions (Simplified for MVP)
-- Using 'any' to ensure it captures intruder traffic regardless of the IP
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- STEP 2: DAQ (Data Acquisition)
daq = {
    module_dirs = { '/usr/local/lib/daq' },
    modules = {
        {
            name = 'pcap',
            mode = 'passive'
        }
    }
}

-- STEP 3: Pattern matching (Fast search algorithm)
search_engine = { search_method = 'ac_bnfa' }

-- STEP 4: Stream reassembly (Essential for basic TCP/ICMP)
stream = { }
stream_tcp = { session_timeout = 60 } -- Reduced from 180 to 60 to free up RAM quickly
stream_udp = { }
stream_icmp = { }
stream_ip = { }

-- STEP 5: HTTP inspection
http_inspect = { }

-- STEP 6: Binder
binder = { }

-- STEP 7: Output (CRITICAL FIX FOR SPLUNK!)
-- Disabled alert_fast to avoid unnecessarily duplicating logs in the MVP
alert_fast = { file = false }

-- KEY CHANGE: Changed 'file = false' to 'file = true'.
-- If set to false, Snort only writes to the console (stdout).
-- By setting it to 'true', Snort will create the 'alert_json.txt' file inside /var/log/snort,
-- which is exactly the path your volume shares with Splunk.
alert_json = {
    file = true,
    limit = 10
}

-- DISABLED FOR THE MVP: Saving binary PCAP files generates high disk and CPU usage.
-- Since we only want to validate that the alert reaches Splunk, we are turning it off temporarily.
-- log_pcap = { limit = 10 }

-- STEP 8: IPS configuration (UNIFIED)
ips = {
    -- Variable definitions
    variables = {
        nets = {
            HOME_NET    = 'any',
            EXTERNAL_NET = 'any'
        },
        ports = {}
    },
    -- Rule loading (THIS IS WHAT IS MISSING)
    rules = [[
        include /etc/snort/zta-mvp.rules
    ]]
}
