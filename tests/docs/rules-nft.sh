#!/usr/sbin/nft -f

# =============================================================================
# MARITIME ZERO TRUST ARCHITECTURE (ZTA)
# NFTABLES PERIMETER FIREWALL
#
# Flusso del traffico:
# Client (VPN/Satellite/Corp) → Firewall (Perimetro) → Envoy (Policy Enforcement Point)
#
# NOTA ZERO TRUST: L'indirizzo IP sorgente originale (del client) viene
# rigorosamente preservato. In questo modo OPA (Policy Decision Point)
# può autenticare e autorizzare la richiesta in base alla rete di origine reale.
# =============================================================================

# Svuota tutte le vecchie regole per garantire un avvio pulito del firewall.
flush ruleset

# =============================================================================
# TABELLA NAT (Network Address Translation)
# =============================================================================
table ip nat {

    # -------------------------------------------------------------------------
    # CHAIN PREROUTING (Port Forwarding / DNAT) -> DNAT diff SNAT (masquerade)
    #
    # Questa sezione gestisce il traffico in entrata verso il firewall.
    # Invece di esporre Envoy direttamente, il firewall fa da scudo e reindirizza
    # le richieste legittime (porta 8443) verso Envoy.
    # [VERIFICATO DA: Test 1 dello script di audit]
    # -------------------------------------------------------------------------
    chain prerouting {
        type nat hook prerouting priority dstnat;
        policy accept;

        # 1. Rete VPN: Redirige il traffico HTTPS dalla VPN verso Envoy.
        # [DA TESTARE: Verificare che una richiesta HTTPS (porta 8443)
        # proveniente dalla VPN venga reindirizzata all'IP di Envoy]
        ip saddr ${NFTABLES_VPN_NET} \
        ip daddr ${NFTABLES_FW_VPN_IP} \
        tcp dport ${NFTABLES_PEP_PORT} \
        dnat to ${NFTABLES_ENVOY_IP}:${NFTABLES_PEP_PORT}

        # 2. Rete Satellitare: Redirige il traffico HTTPS dalle navi verso Envoy.
        # [DA TESTARE: Verificare il DNAT per la rete Satellitare]
        ip saddr ${NFTABLES_SATELLITE_NET} \
        ip daddr ${NFTABLES_FW_SATELLITE_IP} \
        tcp dport ${NFTABLES_PEP_PORT} \
        dnat to ${NFTABLES_ENVOY_IP}:${NFTABLES_PEP_PORT}

        # 3. Rete Corporate: Redirige il traffico HTTPS dagli uffici verso Envoy.
        # [DA TESTARE: Verificare il DNAT per la rete Corporate]
        ip saddr ${NFTABLES_CORPORATE_NET} \
        ip daddr ${NFTABLES_FW_CORPORATE_IP} \
        tcp dport ${NFTABLES_PEP_PORT} \
        dnat to ${NFTABLES_ENVOY_IP}:${NFTABLES_PEP_PORT}

        # 4. Rete Pubblica (Internet): Redirige ad Envoy.
        # Filosofia ZTA: Non blocchiamo a livello di rete (L4), ma lasciamo
        # che sia OPA (L7) a negare l'accesso generando un log di sicurezza utile,
        # invece di far cadere la connessione in silenzio.
        # [DA TESTARE: Verificare il DNAT per la Rete Pubblica (Internet)]
        ip saddr ${NFTABLES_PUBLIC_NET} \
        ip daddr ${NFTABLES_FW_PUBLIC_IP} \
        tcp dport ${NFTABLES_PEP_PORT} \
        dnat to ${NFTABLES_ENVOY_IP}:${NFTABLES_PEP_PORT}
    }
}

# =============================================================================
# TABELLA FILTER (Filtraggio dei Pacchetti e Sicurezza)
# =============================================================================
table ip filter {

    # -------------------------------------------------------------------------
    # CHAIN INPUT (Protezione del Firewall stesso)
    #
    # Gestisce il traffico destinato DIRETTAMENTE al sistema operativo del firewall.
    # Tutte le porte non essenziali (Mongo, API, OPA, ecc.) sono bloccate per
    # ridurre la superficie d'attacco.
    # -------------------------------------------------------------------------
    chain input {
        type filter hook input priority filter;
        policy drop; # DEFAULT DENY: Blocca tutto ciò che non è elencato sotto.

        # Permette al firewall di comunicare con se stesso (es. per script interni).
        # [DA TESTARE: Inviare traffico all'interfaccia 127.0.0.1 per assicurarsi
        # che i processi locali non vengano interrotti dal firewall]
        # [VERIFICATO DA: Test 6 (Loopback)]
        iifname "lo" accept

        # Sicurezza anti-spoofing/malformed: scarta i pacchetti di stato non valido.
        ct state invalid drop

        # Permette il traffico di ritorno per le connessioni iniziate dal firewall.
        ct state established,related accept

        # Permette il ping (ICMP) verso l'IP del firewall per il monitoraggio della rete.
        # [DA TESTARE: Eseguire un comando 'ping' da un client verso l'IP
        # del firewall per verificare che ICMP sia consentito]
        # [VERIFICATO DA: Test 5 (ICMP verso il Firewall)]
        ip protocol icmp accept

        # Tutto il resto viene loggato prima di essere scartato.
        # Questo cattura chi tenta di accedere a Mongo/API scavalcando Envoy.
        # [DA TESTARE: Tentare una connessione verso porte non permesse sul firewall
        # (es. MongoDB sulla 27017 o API sulla 3000) e verificare che venga
        # bloccata e che generi un log con prefisso [NFT-INPUT-DROP] ]
        # [VERIFICATO DA: Test 2 (Bloccaggio porte non abilitate)]
        log prefix "[NFT-INPUT-DROP] " group 0
        drop
    }

    # -------------------------------------------------------------------------
    # CHAIN FORWARD (Routing tra le reti - Cuore della ZTA)
    #
    # Gestisce il traffico che DEVE ATTRAVERSARE il firewall per raggiungere
    # un'altra destinazione (es. dai client a Envoy, o tra due client).
    # -------------------------------------------------------------------------
    chain forward {
        type filter hook forward priority filter;
        policy drop; # DEFAULT DENY: Blocca il traffico inter-rete non autorizzato.

        # Sicurezza generale: scarta pacchetti corrotti o non validi.
        ct state invalid drop

        # Permette a Envoy di rispondere ai client. Se un client avvia la
        # connessione ed è permesso, la risposta passa in automatico.
        ct state established,related accept

        # =====================================================================
        # LISTA DI ACCESSO PERMESSA VERSO ENVOY (Micro-segmentazione positiva)
        # =====================================================================

        # Solo il traffico nuovo destinato rigorosamente alla porta 8443 di Envoy
        # viene permesso e conteggiato.
        # Il contatore ("counter") è essenziale per l'audit del Test 1.

        # [DA TESTARE: Verificare che il traffico nuovo generato dalle varie reti
        # (VPN, Sat, Corp, Public) destinato a Envoy passi correttamente,
        # e verificare matematicamente che il comando "counter" aumenti di valore]

        # Dalla VPN a Envoy
        ip saddr ${NFTABLES_VPN_NET} ip daddr ${NFTABLES_ENVOY_IP} tcp dport ${NFTABLES_PEP_PORT} ct state new counter accept

        # Dal Satellite (Navi) a Envoy
        ip saddr ${NFTABLES_SATELLITE_NET} ip daddr ${NFTABLES_ENVOY_IP} tcp dport ${NFTABLES_PEP_PORT} ct state new counter accept

        # Dalla Rete Corporate a Envoy
        ip saddr ${NFTABLES_CORPORATE_NET} ip daddr ${NFTABLES_ENVOY_IP} tcp dport ${NFTABLES_PEP_PORT} ct state new counter accept

        # Dalla Rete Pubblica a Envoy (OPA gestirà l'autenticazione)
        ip saddr ${NFTABLES_PUBLIC_NET} ip daddr ${NFTABLES_ENVOY_IP} tcp dport ${NFTABLES_PEP_PORT} ct state new counter accept

        # =====================================================================
        # PREVENZIONE DEI MOVIMENTI LATERALI (Micro-segmentazione negativa)
        # [VERIFICATO DA: Test 3 dello script di audit]
        # =====================================================================

        # Le reti non devono MAI parlarsi direttamente tra di loro per isolare
        # eventuali violazioni (containment). Ogni tentativo genera un avviso di sicurezza.
        #----------------------------------------------

        # Blocca traffico tra VPN e Satellite (e viceversa)
        #----------------------------------------------
        # [DA TESTARE: Inviare pacchetti da un client della VPN direttamente all'IP
        # di un client Satellitare. Verificare che la connessione vada in timeout
        # (drop) e cercare nel file ulogd.log la voce [NFT-LATERAL-VPN-SAT] ]
        ip saddr ${NFTABLES_VPN_NET} ip daddr ${NFTABLES_SATELLITE_NET} log prefix "[NFT-LATERAL-VPN-SAT] " group 0 drop
        # [DA TESTARE: Fare l'inverso, dal Satellite alla VPN, e cercare il log]
        ip saddr ${NFTABLES_SATELLITE_NET} ip daddr ${NFTABLES_VPN_NET} log prefix "[NFT-LATERAL-SAT-VPN] " group 0 drop

        # Blocca traffico da Rete Pubblica verso le reti interne
        #----------------------------------------------
        # [DA TESTARE: Assicurarsi che la rete pubblica non possa mai raggiungere
        # le subnet private VPN, Satellite e Corporate in modo diretto]
        ip saddr ${NFTABLES_PUBLIC_NET} ip daddr ${NFTABLES_VPN_NET} log prefix "[NFT-LATERAL-PUB-VPN] " group 0 drop
        ip saddr ${NFTABLES_PUBLIC_NET} ip daddr ${NFTABLES_SATELLITE_NET} log prefix "[NFT-LATERAL-PUB-SAT] " group 0 drop
        ip saddr ${NFTABLES_PUBLIC_NET} ip daddr ${NFTABLES_CORPORATE_NET} log prefix "[NFT-LATERAL-PUB-CORP] " group 0 drop

        # =====================================================================
        # DEFAULT DENY FINALE
        # =====================================================================

        # Qualsiasi tentativo di inoltro (forwarding) verso porte non permesse
        # (es. SSH sulla porta 22) finisce qui.
        # [VERIFICATO DA: Test 4 (Regola di Default Forward)]
        #----------------------------------------------
        # [DA TESTARE: Inviare traffico verso Envoy usando una porta diversa
        # dalla 8443 (ad esempio la porta SSH 22). Il traffico non corrisponderà
        # alle regole di 'ACCEPT' sopra, cadrà in questo blocco finale,
        # andrà in timeout e genererà il log [NFT-FORWARD-DROP] ]
        log prefix "[NFT-FORWARD-DROP] " group 0
        drop
    }

    # -------------------------------------------------------------------------
    # CHAIN OUTPUT
    #
    # Controlla il traffico generato dal firewall stesso verso l'esterno.
    # La policy è ACCEPT per permettere al firewall di inviare i log (syslog,
    # ulogd) verso i server SIEM (es. Splunk HEC) e per aggiornamenti pacchetti.
    # -------------------------------------------------------------------------
    chain output {
        type filter hook output priority filter;
        policy accept;
    }
}
