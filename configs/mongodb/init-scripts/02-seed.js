// Selezione del database del progetto
db = db.getSiblingDB('maritime_zta');

// 1. Popolamento Collezione Utenti (Metadati)
db.utenti.insertMany([
  {
    id_utente: "U-001",
    nome: "Marco Rossi",
    mansione: "Personale Banchina",
    porto_assegnato: "Ancona",
    livello_sicurezza: 2
  },
  {
    id_utente: "U-002",
    nome: "Elena Bianchi",
    mansione: "Comandante",
    nave_assegnata: "AF Claudia",
    livello_sicurezza: 4
  }
]);

// 2. Popolamento Collezione Risorse
// Le risorse sono differenziate per tipo e livello di sensibilità,
// così OPA può applicare un controllo RBAC più preciso in base al ruolo.
db.risorse.insertMany([
  {
    id_risorsa: "R-001",
    nome: "Manifesto carico AF Claudia",
    tipo_documento: "manifesto_carico",
    descrizione: "Documento operativo relativo a tratta, passeggeri e veicoli imbarcati.",
    nave: "AF Claudia",
    tratta: "Ancona-Durazzo",
    data_partenza: "2026-05-10T18:00:00Z",
    passeggeri_registrati: 450,
    veicoli_commerciali: 32,
    sensibilita: "media"
  },
  {
    id_risorsa: "R-002",
    nome: "Telemetria motori AF Marina",
    tipo_documento: "telemetria_motori",
    descrizione: "Dati tecnici relativi allo stato dei motori e ai consumi della nave.",
    nave: "AF Marina",
    tratta: "Bari-Durazzo",
    stato_propulsione: "Ottimale",
    velocita_nodi: 22,
    consumo_carburante_lh: 1800,
    sensibilita: "alta"
  },
  {
    id_risorsa: "R-003",
    nome: "Report sicurezza SOC",
    tipo_documento: "report_sicurezza",
    descrizione: "Report riservato del Security Operation Center sugli eventi di sicurezza.",
    area: "SOC",
    livello: "confidenziale",
    eventi_rilevati: 7,
    severita_massima: "alta",
    sensibilita: "critica"
  },
  {
    id_risorsa: "R-004",
    nome: "Registro dispositivi portuali",
    tipo_documento: "registro_dispositivi",
    descrizione: "Elenco dei dispositivi autorizzati nelle reti operative.",
    area: "Infrastruttura",
    dispositivi_registrati: ["D-001", "D-002", "D-SOC"],
    ultimo_aggiornamento: "2026-06-01T10:00:00Z",
    sensibilita: "media"
  }
]);

// 3. Popolamento Collezione Dispositivi (Identità Hardware)
db.dispositivi.insertMany([
  {
    id_dispositivo: "D-001",
    tipo: "Terminale Fisso Biglietteria",
    mac_address: "00:1B:44:11:3A:B7",
    posizione_fisica: "Terminal Ancona",
    fingerprint_ja3: "e7afb57c...",
    certificato_valido: true
  },
  {
    id_dispositivo: "D-002",
    tipo: "Tablet Rugged di Bordo",
    mac_address: "A4:C3:F0:88:12:9E",
    posizione_fisica: "Ponte Comando AF Claudia",
    fingerprint_ja3: "b4c2a19f...",
    certificato_valido: true
  }
]);
