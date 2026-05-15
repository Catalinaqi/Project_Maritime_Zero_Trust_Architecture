-- =============================================================================
-- Snort 3 IDS Configuration - Maritime Zero Trust
-- =============================================================================
-- Project: Maritime - Zero Trust Architecture (ZTA)
-- Author: Person 1 - Network Guardian (Snort/IDS)
-- Component: Layer 1 Intrusion Detection System
-- Purpose: Define Snort 3 engine settings, inspection modules,
--          and output channels for ZTA traffic analysis
-- Data Creation: 2026-05-11
-- Last Updated: 2026-05-15 (fixed: removed Snort 2 syntax from daq/stream_tcp)
-- =============================================================================
-- FIXES APPLIED:
--   - daq: removed 'module' and 'mode' (Snort 2 keys) -> use module_dirs
--   - stream_tcp: removed 'max_sessions' and 'reassembly' block (Snort 2 keys)
--   - HOME_NET: moved to variable readable by rules via ips.variables
-- =============================================================================

-- ============================================
-- STEP 1: Network Definitions
-- ============================================
-- These are Lua globals used by Snort 3 internally
HOME_NET = os.getenv('HOME_NET') or '172.20.0.0/16'
EXTERNAL_NET = 'any'

-- ============================================
-- STEP 2: Packet Acquisition (DAQ)
-- ============================================
-- Snort 3: daq uses 'module_dirs', NOT 'module'/'mode' (those are Snort 2)
daq = {
    module_dirs = { '/usr/local/lib/daq' },
    modules = {
        {
            name = 'pcap',
            mode = 'passive'
        }
    }
}

-- ============================================
-- STEP 3: Pattern Matching Engine
-- ============================================
search_engine = { search_method = 'ac_bnfa' }

-- ============================================
-- STEP 4: Stream Reassembly
-- ============================================
-- Snort 3: stream_tcp does NOT support 'max_sessions' or 'reassembly' block
stream = { }
stream_tcp = {
    session_timeout = 180
}
stream_udp = { }
stream_icmp = { }
stream_ip = { }

-- ============================================
-- STEP 5: HTTP Inspector
-- ============================================
http_inspect = { }

-- ============================================
-- STEP 6: Binder
-- ============================================
binder = { }

-- ============================================
-- STEP 7: Output Channels
-- ============================================
alert_fast = { file = true }

-- ============================================
-- STEP 8: Load Custom ZTA Rules
-- ============================================
ips = {
    variables = {
        nets = {
            HOME_NET = os.getenv('HOME_NET') or '172.20.0.0/16',
            EXTERNAL_NET = 'any'
        },
        ports = {}
    },
    include = '/etc/snort/rules/zta.rules'
}
