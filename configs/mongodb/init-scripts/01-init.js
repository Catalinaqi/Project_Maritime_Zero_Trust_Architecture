// Inizializza il solo account applicativo usato dal backend.
// Le identità degli utenti finali sono autorizzate da OPA, non da MongoDB.
const databaseName = process.env.MONGO_DATABASE || "maritime_zta";
const appUser = process.env.MONGO_APP_USER;
const appPassword = process.env.MONGO_APP_PASSWORD;

if (!appUser || !appPassword) {
  throw new Error("MONGO_APP_USER e MONGO_APP_PASSWORD sono obbligatorie");
}

const applicationDb = db.getSiblingDB(databaseName);

applicationDb.createRole({
  role: "maritime_api_role",
  privileges: [
    {
      resource: { db: databaseName, collection: "utenti" },
      actions: ["find"]
    },
    {
      resource: { db: databaseName, collection: "dispositivi" },
      actions: ["find"]
    },
    {
      resource: { db: databaseName, collection: "risorse" },
      actions: ["find", "insert", "update", "remove"]
    }
  ],
  roles: []
});

applicationDb.createUser({
  user: appUser,
  pwd: appPassword,
  roles: [{ role: "maritime_api_role", db: databaseName }]
});
