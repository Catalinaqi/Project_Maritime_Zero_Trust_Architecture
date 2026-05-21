const express = require("express");
const { MongoClient } = require("mongodb");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

const MONGO_HOST = process.env.MONGO_HOST || "db_primary";
const MONGO_PORT = process.env.MONGO_PORT || "27017";
const MONGO_DATABASE = process.env.MONGO_DATABASE || "maritime_zta";
const MONGO_ROOT_USER = process.env.MONGO_ROOT_USER || "admin";
const MONGO_ROOT_PASSWORD = process.env.MONGO_ROOT_PASSWORD || "admin_password";

const mongoUri = `mongodb://${MONGO_ROOT_USER}:${MONGO_ROOT_PASSWORD}@${MONGO_HOST}:${MONGO_PORT}/${MONGO_DATABASE}?authSource=admin`;

let db;

async function connectMongo() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  db = client.db(MONGO_DATABASE);
  console.log(`[api_backend] Connected to MongoDB database: ${MONGO_DATABASE}`);
}

function buildResponse(collection, data) {
  return {
    service: "api_backend",
    source: "mongodb",
    collection,
    count: data.length,
    data
  };
}

app.get("/health", (req, res) => {
  res.json({
    service: "api_backend",
    status: "ok"
  });
});

app.get("/", (req, res) => {
  res.json({
    service: "api_backend",
    message: "Maritime Zero Trust API Backend",
    endpoints: [
      "GET /utenti",
      "GET /risorse",
      "GET /dispositivi",
      "GET /all"
    ]
  });
});

app.get("/utenti", async (req, res) => {
  try {
    const utenti = await db.collection("utenti").find({}).toArray();
    res.json(buildResponse("utenti", utenti));
  } catch (error) {
    console.error("[api_backend] Error reading utenti:", error);
    res.status(500).json({ error: "Errore durante la lettura degli utenti" });
  }
});

app.get("/risorse", async (req, res) => {
  try {
    const risorse = await db.collection("risorse").find({}).toArray();
    res.json(buildResponse("risorse", risorse));
  } catch (error) {
    console.error("[api_backend] Error reading risorse:", error);
    res.status(500).json({ error: "Errore durante la lettura delle risorse" });
  }
});

app.get("/dispositivi", async (req, res) => {
  try {
    const dispositivi = await db.collection("dispositivi").find({}).toArray();
    res.json(buildResponse("dispositivi", dispositivi));
  } catch (error) {
    console.error("[api_backend] Error reading dispositivi:", error);
    res.status(500).json({ error: "Errore durante la lettura dei dispositivi" });
  }
});

app.get("/all", async (req, res) => {
  try {
    const [utenti, risorse, dispositivi] = await Promise.all([
      db.collection("utenti").find({}).toArray(),
      db.collection("risorse").find({}).toArray(),
      db.collection("dispositivi").find({}).toArray()
    ]);

    res.json({
      service: "api_backend",
      source: "mongodb",
      data: {
        utenti,
        risorse,
        dispositivi
      }
    });
  } catch (error) {
    console.error("[api_backend] Error reading all data:", error);
    res.status(500).json({ error: "Errore durante la lettura dei dati" });
  }
});

connectMongo()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`[api_backend] Server listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("[api_backend] MongoDB connection failed:", error);
    process.exit(1);
  });