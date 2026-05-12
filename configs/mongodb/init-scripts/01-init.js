// Selezione del database del progetto
db = db.getSiblingDB('maritime_zta');

// 1. Creazione dei Ruoli Operativi
db.createRole({
  role: "ruolo_banchina",
  privileges: [
    { resource: { db: "maritime_zta", collection: "risorse" }, actions: ["find"] },
    { resource: { db: "maritime_zta", collection: "dispositivi" }, actions: ["find"] }
  ],
  roles: []
});

db.createRole({
  role: "ruolo_equipaggio",
  privileges: [
    { resource: { db: "maritime_zta", collection: "risorse" }, actions: ["find", "insert", "update"] },
    { resource: { db: "maritime_zta", collection: "dispositivi" }, actions: ["find"] }
  ],
  roles: []
});

db.createRole({
  role: "ruolo_gestione_flotta",
  privileges: [
    { resource: { db: "maritime_zta", collection: "" }, actions: ["find", "insert", "update", "remove"] }
  ],
  roles: []
});

// 2. Creazione degli Utenti per i test dei Client
db.createUser({
  user: "operatore_ancona",
  pwd: "password_banchina_123",
  roles: [{ role: "ruolo_banchina", db: "maritime_zta" }]
});

db.createUser({
  user: "capitano_claudia",
  pwd: "password_equipaggio_123",
  roles: [{ role: "ruolo_equipaggio", db: "maritime_zta" }]
});

db.createUser({
  user: "soc_admin",
  pwd: "password_flotta_123",
  roles: [{ role: "ruolo_gestione_flotta", db: "maritime_zta" }]
});
