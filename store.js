// Stockage des données Bless Protect.
//
// Deux modes, choisis automatiquement :
//  - EN LIGNE (hébergement) : si les variables UPSTASH_REDIS_REST_URL et
//    UPSTASH_REDIS_REST_TOKEN existent, toute la base est enregistrée dans une
//    base de données Redis en ligne (Upstash, gratuit) → rien n'est perdu même
//    quand le serveur redémarre.
//  - LOCAL (sur un PC, pour tester) : la base est enregistrée dans data/db.json.
//
// L'interface (db, save, flush, pushCapped, …) reste identique dans les deux cas.
const fs = require("fs");
const path = require("path");

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const CONTACTS_DIR = path.join(DATA_DIR, "contacts");
const EVIDENCE_DIR = path.join(DATA_DIR, "evidence");
const PHOTOS_DIR = path.join(DATA_DIR, "photos");

fs.mkdirSync(CONTACTS_DIR, { recursive: true });
fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
fs.mkdirSync(PHOTOS_DIR, { recursive: true });

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const USE_REDIS = !!(REDIS_URL && REDIS_TOKEN);
const REDIS_KEY = process.env.REDIS_KEY || "blessprotect:db";

const empty = () => ({
  users: [],
  sessions: [],
  devices: [],
  locations: {},
  events: {},
  commands: {},
  evidence: {},
  photos: {},
});

let db = empty();

async function redisCommand(cmd) {
  const res = await fetch(REDIS_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${REDIS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(cmd),
  });
  if (!res.ok) throw new Error("Redis HTTP " + res.status);
  const j = await res.json();
  return j.result;
}

// Chargement initial. `ready` est résolu quand la base est prête (le serveur
// attend `ready` avant d'accepter des requêtes).
let ready;
if (USE_REDIS) {
  ready = (async () => {
    try {
      const val = await redisCommand(["GET", REDIS_KEY]);
      if (val) db = { ...empty(), ...JSON.parse(val) };
      console.log(`Base chargée depuis Redis (${val ? "existante" : "nouvelle"}).`);
    } catch (e) {
      console.error("Lecture Redis impossible, démarrage à vide :", e.message);
    }
  })();
} else {
  if (fs.existsSync(DB_FILE)) {
    try {
      db = { ...empty(), ...JSON.parse(fs.readFileSync(DB_FILE, "utf8")) };
    } catch (e) {
      console.error("Base illisible, démarrage à vide :", e.message);
    }
  }
  ready = Promise.resolve();
}

// Écriture, regroupée pour ne pas solliciter la base à chaque changement.
let saveTimer = null;
let saving = false;
let dirtyAgain = false;

function persist() {
  if (USE_REDIS) {
    saving = true;
    redisCommand(["SET", REDIS_KEY, JSON.stringify(db)])
      .catch((e) => console.error("Écriture Redis échouée :", e.message))
      .finally(() => {
        saving = false;
        if (dirtyAgain) {
          dirtyAgain = false;
          save();
        }
      });
  } else {
    const tmp = DB_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
  }
}

function save() {
  if (saving) {
    dirtyAgain = true;
    return;
  }
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    persist();
  }, USE_REDIS ? 2000 : 200);
}

function flush() {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  if (USE_REDIS) {
    persist();
  } else {
    fs.writeFileSync(DB_FILE, JSON.stringify(db));
  }
}

function pushCapped(map, key, item, max) {
  const list = (map[key] = map[key] || []);
  list.push(item);
  if (list.length > max) list.splice(0, list.length - max);
}

module.exports = {
  ready,
  usingRedis: USE_REDIS,
  get db() {
    return db;
  },
  save,
  flush,
  pushCapped,
  contactsFile: (deviceId) => path.join(CONTACTS_DIR, `${deviceId}.vcf`),
  evidenceFile: (deviceId, photoId) => {
    const dir = path.join(EVIDENCE_DIR, deviceId);
    fs.mkdirSync(dir, { recursive: true });
    return path.join(dir, `${photoId}.jpg`);
  },
  photoFile: (deviceId, photoId) => {
    const dir = path.join(PHOTOS_DIR, deviceId);
    fs.mkdirSync(dir, { recursive: true });
    const safe = String(photoId).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
    return path.join(dir, `${safe}.jpg`);
  },
  reset() {
    db = empty();
    flush();
  },
};
