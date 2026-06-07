-- =============================================================================
-- Snort 3 IDS Configuration - Maritime Zero Trust Architecture
-- =============================================================================
-- Author: Network Guardian (Snort/IDS)
-- Component: Layer 1 Intrusion Detection System
-- Purpose: Define Snort 3 engine settings, inspection modules,
--          and output channels for ZTA traffic analysis
-- Data Creation: 2026-05-11
-- Last Updated: 2026-06-07
-- =============================================================================

-- STEP 1: Network definitions (Lua globals read by Snort internals)
HOME_NET = os.getenv('HOME_NET') or '172.20.0.0/16'
EXTERNAL_NET = 'any'

-- STEP 2: DAQ - afpacket supports INTERFACE=any on Linux/WSL2 -> pcap
daq = {
    module_dirs = { '/usr/local/lib/daq' },
    modules = {
        {
            name = 'pcap',
            mode = 'passive'
        }
    }
}

-- STEP 3: Pattern matching
search_engine = { search_method = 'ac_bnfa' }

-- STEP 4: Stream reassembly
stream = { }
stream_tcp = { session_timeout = 180 }
stream_udp = { }
stream_icmp = { }
stream_ip = { }

-- STEP 5: HTTP inspection
http_inspect = { }

-- STEP 6: Binder
binder = { }

-- STEP 7: Output - only options valid in 3.9.2.0
alert_fast = { file = true }
alert_json  = { file = true, limit = 10 }

-- STEP 8: IPS variables - rules loaded via -R in entrypoint
ips = {
    variables = {
        nets = {
            HOME_NET    = os.getenv('HOME_NET') or '172.20.0.0/16',
            EXTERNAL_NET = '!$HOME_NET'
        },
        ports = {}
    }
}
