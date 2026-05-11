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
db.risorse.insertMany([
  {
    id_risorsa: "R-001",
    tipo_documento: "Manifesto Carico",
    nave: "AF Claudia",
    tratta: "Ancona-Durazzo",
    data_partenza: "2026-05-10T18:00:00Z",
    passeggeri_registrati: 450,
    veicoli_commerciali: 32
  },
  {
    id_risorsa: "R-002",
    tipo_documento: "Telemetria Motori",
    nave: "AF Marina",
    tratta: "Bari-Durazzo",
    stato_propulsione: "Ottimale",
    velocita_nodi: 22,
    consumo_carburante_lh: 1800
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
