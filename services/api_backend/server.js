"use strict";

// Espone l'API REST autorizzata da Envoy e legge i dati operativi da MongoDB.
const express = require("express");
const { MongoClient } = require("mongodb");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "64kb" }));

const PORT = Number(process.env.PORT || 3000);
const MONGO_HOST = process.env.MONGO_HOST || "db_primary";
const MONGO_PORT = process.env.MONGO_PORT || "27017";
const MONGO_DATABASE = process.env.MONGO_DATABASE || "maritime_zta";
const MONGO_APP_USER = process.env.MONGO_APP_USER;
const MONGO_APP_PASSWORD = process.env.MONGO_APP_PASSWORD;
const MONGO_APP_AUTH_DB = process.env.MONGO_APP_AUTH_DB || MONGO_DATABASE;
const MONGO_TLS_CA_FILE = process.env.MONGO_TLS_CA_FILE || "/certs/ca/ca.crt";
const MONGO_TLS_CERT_KEY_FILE =
  process.env.MONGO_TLS_CERT_KEY_FILE || "/certs/mongodb/api-client.pem";

if (!MONGO_APP_USER || !MONGO_APP_PASSWORD) {
  throw new Error("MONGO_APP_USER e MONGO_APP_PASSWORD sono obbligatorie");
}

const encodedUser = encodeURIComponent(MONGO_APP_USER);
const encodedPassword = encodeURIComponent(MONGO_APP_PASSWORD);
const mongoUri = `mongodb://${encodedUser}:${encodedPassword}@${MONGO_HOST}:${MONGO_PORT}/${MONGO_DATABASE}`;

const mongoClient = new MongoClient(mongoUri, {
  authSource: MONGO_APP_AUTH_DB,
  tls: true,
  tlsCAFile: MONGO_TLS_CA_FILE,
  tlsCertificateKeyFile: MONGO_TLS_CERT_KEY_FILE,
  serverSelectionTimeoutMS: 5000,
  connectTimeoutMS: 5000,
  maxPoolSize: 10
});

let database;

function identityFromRequest(req) {
  return {
    userId: req.get("x-zta-user-id") || "unknown",
    deviceId: req.get("x-zta-device-id") || "unknown",
    network: req.get("x-zta-network") || "unknown",
    riskScore: req.get("x-zta-risk-score") || "unknown"
  };
}

function audit(req, action, resourceId = null) {
  console.log(JSON.stringify({
    event: "api_access",
    action,
    resource_id: resourceId,
    identity: identityFromRequest(req),
    timestamp: new Date().toISOString()
  }));
}

function collectionResponse(collection, data) {
  return { service: "api_backend", source: "mongodb", collection, count: data.length, data };
}

app.get("/health", async (_req, res) => {
  try {
    const result = await database.command({ ping: 1 });
    return res.status(result.ok === 1 ? 200 : 503).json({
      service: "api_backend",
      status: result.ok === 1 ? "healthy" : "unhealthy",
      mongodb: result.ok === 1 ? "connected" : "unavailable"
    });
  } catch (_error) {
    return res.status(503).json({ service: "api_backend", status: "unhealthy", mongodb: "disconnected" });
  }
});

app.get("/", (_req, res) => {
  res.json({
    service: "api_backend",
    endpoints: [
      "GET /utenti", "GET /dispositivi", "GET /risorse", "GET /risorse/:id",
      "POST /risorse", "PUT /risorse/:id", "DELETE /risorse/:id", "GET /all"
    ]
  });
});

app.get("/utenti", async (req, res, next) => {
  try {
    audit(req, "find", "utenti");
    const data = await database.collection("utenti").find({}).toArray();
    res.json(collectionResponse("utenti", data));
  } catch (error) { next(error); }
});

app.get("/dispositivi", async (req, res, next) => {
  try {
    audit(req, "find", "dispositivi");
    const data = await database.collection("dispositivi").find({}).toArray();
    res.json(collectionResponse("dispositivi", data));
  } catch (error) { next(error); }
});

app.get("/risorse", async (req, res, next) => {
  try {
    audit(req, "find", "risorse");
    const data = await database.collection("risorse").find({}).toArray();
    res.json(collectionResponse("risorse", data));
  } catch (error) { next(error); }
});

app.get("/risorse/:id", async (req, res, next) => {
  try {
    audit(req, "find", req.params.id);
    const data = await database.collection("risorse").findOne({ id_risorsa: req.params.id });
    if (!data) return res.status(404).json({ error: "resource_not_found", id_risorsa: req.params.id });
    res.json({ service: "api_backend", source: "mongodb", collection: "risorse", count: 1, data });
  } catch (error) { next(error); }
});

app.post("/risorse", async (req, res, next) => {
  try {
    if (!req.body || typeof req.body.id_risorsa !== "string") {
      return res.status(400).json({ error: "id_risorsa_required" });
    }
    audit(req, "insert", req.body.id_risorsa);
    await database.collection("risorse").insertOne(req.body);
    res.status(201).json({ status: "created", id_risorsa: req.body.id_risorsa });
  } catch (error) {
    if (error && error.code === 11000) return res.status(409).json({ error: "resource_already_exists" });
    next(error);
  }
});

app.put("/risorse/:id", async (req, res, next) => {
  try {
    const update = { ...req.body };
    delete update._id;
    delete update.id_risorsa;
    if (Object.keys(update).length === 0) return res.status(400).json({ error: "empty_update" });
    audit(req, "update", req.params.id);
    const result = await database.collection("risorse").updateOne(
      { id_risorsa: req.params.id },
      { $set: update }
    );
    if (result.matchedCount === 0) return res.status(404).json({ error: "resource_not_found" });
    res.json({ status: "updated", id_risorsa: req.params.id });
  } catch (error) { next(error); }
});

app.delete("/risorse/:id", async (req, res, next) => {
  try {
    audit(req, "delete", req.params.id);
    const result = await database.collection("risorse").deleteOne({ id_risorsa: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: "resource_not_found" });
    res.status(204).send();
  } catch (error) { next(error); }
});

app.get("/all", async (req, res, next) => {
  try {
    audit(req, "find", "all");
    const [utenti, risorse, dispositivi] = await Promise.all([
      database.collection("utenti").find({}).toArray(),
      database.collection("risorse").find({}).toArray(),
      database.collection("dispositivi").find({}).toArray()
    ]);
    res.json({ service: "api_backend", source: "mongodb", data: { utenti, risorse, dispositivi } });
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  console.error(JSON.stringify({ event: "api_error", message: error.message, timestamp: new Date().toISOString() }));
  res.status(500).json({ error: "internal_server_error" });
});

async function shutdown(signal) {
  console.log(`[api_backend] Received ${signal}; closing MongoDB connection`);
  await mongoClient.close();
  process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

mongoClient.connect()
  .then(async () => {
    database = mongoClient.db(MONGO_DATABASE);
    await database.command({ ping: 1 });
    app.listen(PORT, "0.0.0.0", () => console.log(`[api_backend] Listening on port ${PORT}`));
  })
  .catch((error) => {
    console.error(`[api_backend] MongoDB connection failed: ${error.message}`);
    process.exit(1);
  });
