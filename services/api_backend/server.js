// Importa Express per creare il server HTTP.
const express = require("express");

// Importa MongoClient per collegarsi a MongoDB.
const { MongoClient } = require("mongodb");

// Crea l'applicazione Express.
const app = express();

// Permette al backend di leggere richieste con corpo JSON.
app.use(express.json());

// Porta sulla quale viene esposto il backend.
const PORT = process.env.PORT || 3000;

// Configurazione della connessione a MongoDB.
// I valori vengono letti dalle variabili d'ambiente;
// in assenza di una variabile viene usato il valore predefinito.
const MONGO_HOST = process.env.MONGO_HOST || "db_primary";
const MONGO_PORT = process.env.MONGO_PORT || "27017";
const MONGO_DATABASE = process.env.MONGO_DATABASE || "maritime_zta";
const MONGO_ROOT_USER = process.env.MONGO_ROOT_USER || "admin";
const MONGO_ROOT_PASSWORD =
  process.env.MONGO_ROOT_PASSWORD || "admin_password";
const MONGO_TLS_CA_FILE =
  process.env.MONGO_TLS_CA_FILE || "/certs/mongodb/ca.crt";

// Connessione MongoDB con TLS.
//
// MongoDB accetta solamente connessioni cifrate.
// Il backend deve quindi:
// - abilitare TLS;
// - indicare la CA usata per verificare il certificato MongoDB;
// - autenticarsi sul database admin.
const mongoUri =
  `mongodb://${MONGO_ROOT_USER}:${MONGO_ROOT_PASSWORD}` +
  `@${MONGO_HOST}:${MONGO_PORT}/${MONGO_DATABASE}` +
  `?authSource=admin` +
  `&tls=true` +
  `&tlsCAFile=${MONGO_TLS_CA_FILE}`;

// Mantiene il riferimento al client MongoDB.
// Serve anche all'endpoint /health per verificare
// che la connessione sia stata inizializzata.
let mongoClient;

// Mantiene il riferimento al database usato dall'applicazione.
let db;

/**
 * Stabilisce la connessione iniziale con MongoDB.
 *
 * Il client viene salvato nella variabile globale mongoClient,
 * mentre il database viene salvato nella variabile globale db.
 */
async function connectMongo() {
  // Crea il client MongoDB.
  //
  // serverSelectionTimeoutMS limita il tempo di attesa quando
  // MongoDB non è disponibile. In questo modo anche /health
  // restituisce l'errore in tempi ragionevoli.
  mongoClient = new MongoClient(mongoUri, {
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000
  });

  // Apre la connessione TLS verso MongoDB.
  await mongoClient.connect();

  // Seleziona il database dell'applicazione.
  db = mongoClient.db(MONGO_DATABASE);

  // Esegue un primo ping per verificare che MongoDB
  // sia realmente raggiungibile.
  await db.command({ ping: 1 });

  console.log(
    `[api_backend] Connected to MongoDB database: ${MONGO_DATABASE}`
  );
}

/**
 * Costruisce il formato standard delle risposte
 * provenienti da una collezione MongoDB.
 *
 * @param {string} collection Nome della collezione MongoDB.
 * @param {Array} data Dati recuperati dalla collezione.
 * @returns {Object} Risposta JSON standardizzata.
 */
function buildResponse(collection, data) {
  return {
    service: "api_backend",
    source: "mongodb",
    collection,
    count: data.length,
    data
  };
}

/**
 * Healthcheck del backend.
 *
 * Questo endpoint non controlla solamente che Express sia attivo,
 * ma esegue anche un vero comando ping verso MongoDB.
 *
 * Risposte possibili:
 * - 200: backend e MongoDB funzionano;
 * - 503: backend attivo, ma MongoDB non è disponibile.
 */
app.get("/health", async (req, res) => {
  try {
    // Se la connessione non è ancora stata inizializzata,
    // il servizio non può essere considerato sano.
    if (!mongoClient || !db) {
      return res.status(503).json({
        service: "api_backend",
        status: "unhealthy",
        mongodb: "not_initialized",
        error: "Connessione a MongoDB non inizializzata"
      });
    }

    // Esegue un comando reale sul database.
    const pingResult = await db.command({ ping: 1 });

    // MongoDB dovrebbe rispondere con { ok: 1 }.
    // Se il valore è diverso, il servizio viene considerato non sano.
    if (pingResult.ok !== 1) {
      return res.status(503).json({
        service: "api_backend",
        status: "unhealthy",
        mongodb: "unavailable",
        error: "MongoDB non ha restituito una risposta valida"
      });
    }

    // Backend e MongoDB risultano entrambi disponibili.
    return res.status(200).json({
      service: "api_backend",
      status: "healthy",
      mongodb: "connected",
      database: MONGO_DATABASE
    });
  } catch (error) {
    // Il backend è attivo, ma il comando verso MongoDB è fallito.
    console.error(
      "[api_backend] MongoDB health check failed:",
      error.message
    );

    return res.status(503).json({
      service: "api_backend",
      status: "unhealthy",
      mongodb: "disconnected",
      error: "MongoDB non raggiungibile"
    });
  }
});

/**
 * Endpoint principale.
 *
 * Mostra una breve descrizione del servizio
 * e l'elenco degli endpoint disponibili.
 */
app.get("/", (req, res) => {
  res.json({
    service: "api_backend",
    message: "Maritime Zero Trust API Backend",
    endpoints: [
      "GET /health",
      "GET /utenti",
      "GET /risorse",
      "GET /risorse/:id",
      "GET /dispositivi",
      "GET /all"
    ]
  });
});

/**
 * Restituisce tutti gli utenti presenti in MongoDB.
 */
app.get("/utenti", async (req, res) => {
  try {
    // Legge tutti i documenti della collezione utenti.
    const utenti = await db.collection("utenti").find({}).toArray();

    // Restituisce i dati nel formato standard del backend.
    return res.json(buildResponse("utenti", utenti));
  } catch (error) {
    console.error("[api_backend] Error reading utenti:", error);

    return res.status(500).json({
      error: "Errore durante la lettura degli utenti"
    });
  }
});

/**
 * Restituisce tutte le risorse presenti in MongoDB.
 */
app.get("/risorse", async (req, res) => {
  try {
    // Legge tutti i documenti della collezione risorse.
    const risorse = await db.collection("risorse").find({}).toArray();

    // Restituisce i dati nel formato standard del backend.
    return res.json(buildResponse("risorse", risorse));
  } catch (error) {
    console.error("[api_backend] Error reading risorse:", error);

    return res.status(500).json({
      error: "Errore durante la lettura delle risorse"
    });
  }
});

/**
 * Restituisce una singola risorsa tramite il suo identificativo.
 *
 * Esempio:
 * GET /risorse/R-001
 */
app.get("/risorse/:id", async (req, res) => {
  try {
    // Recupera l'identificativo dalla URL.
    const idRisorsa = req.params.id;

    // Cerca una risorsa con id_risorsa uguale al valore richiesto.
    const risorsa = await db.collection("risorse").findOne({
      id_risorsa: idRisorsa
    });

    // Se la risorsa non esiste, restituisce 404.
    if (!risorsa) {
      return res.status(404).json({
        service: "api_backend",
        source: "mongodb",
        collection: "risorse",
        error: "Risorsa non trovata",
        id_risorsa: idRisorsa
      });
    }

    // Se la risorsa esiste, restituisce il documento trovato.
    return res.json({
      service: "api_backend",
      source: "mongodb",
      collection: "risorse",
      count: 1,
      data: risorsa
    });
  } catch (error) {
    console.error("[api_backend] Error reading risorsa by id:", error);

    return res.status(500).json({
      error: "Errore durante la lettura della risorsa richiesta"
    });
  }
});

/**
 * Restituisce tutti i dispositivi presenti in MongoDB.
 */
app.get("/dispositivi", async (req, res) => {
  try {
    // Legge tutti i documenti della collezione dispositivi.
    const dispositivi = await db
      .collection("dispositivi")
      .find({})
      .toArray();

    // Restituisce i dati nel formato standard del backend.
    return res.json(buildResponse("dispositivi", dispositivi));
  } catch (error) {
    console.error("[api_backend] Error reading dispositivi:", error);

    return res.status(500).json({
      error: "Errore durante la lettura dei dispositivi"
    });
  }
});

/**
 * Restituisce contemporaneamente utenti, risorse e dispositivi.
 */
app.get("/all", async (req, res) => {
  try {
    // Esegue le tre letture contemporaneamente.
    const [utenti, risorse, dispositivi] = await Promise.all([
      db.collection("utenti").find({}).toArray(),
      db.collection("risorse").find({}).toArray(),
      db.collection("dispositivi").find({}).toArray()
    ]);

    // Restituisce tutti i dati in un'unica risposta.
    return res.json({
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

    return res.status(500).json({
      error: "Errore durante la lettura dei dati"
    });
  }
});

/**
 * Avvia il backend solamente dopo aver stabilito
 * correttamente la connessione iniziale con MongoDB.
 */
connectMongo()
  .then(() => {
    // Espone il server su tutte le interfacce del container.
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`[api_backend] Server listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    // Se MongoDB non è raggiungibile all'avvio,
    // il backend termina con codice di errore.
    console.error("[api_backend] MongoDB connection failed:", error);

    process.exit(1);
  });