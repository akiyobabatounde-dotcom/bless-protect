// Serveur Bless Protect (prototype)
//  - API pour l'application Android : inscription, positions, alertes, commandes, contacts
//  - API pour le site de suivi : connexion, appareils, carte, commandes à distance
//  - Vérification publique d'un IMEI (registre)
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const store = require("./store");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

const SESSION_DAYS = 30;
const COMMAND_TYPES = ["LOCATE", "ALARM", "LOCK", "VOL", "STOP"];
const PHOTO_LIMIT = 100; // nombre de photos conservées par appareil (coffre « + »)

// ---------- Utilitaires ----------

const id = () => crypto.randomBytes(9).toString("base64url");
const token = () => crypto.randomBytes(32).toString("base64url");
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function checkPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.passHash, "hex"));
}

const normEmail = (e) => String(e || "").trim().toLowerCase();
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const normPhone = (p) => String(p || "").replace(/[^\d+]/g, "");
const validImei = (i) => /^\d{15}$/.test(i) && luhn(i);

function luhn(num) {
  let sum = 0;
  for (let i = 0; i < num.length; i++) {
    let d = Number(num[num.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

function bad(res, status, message) {
  return res.status(status).json({ error: message });
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

// Limitation simple des tentatives de connexion (par IP + e-mail)
const attempts = new Map();
function tooManyAttempts(key) {
  const now = Date.now();
  const entry = attempts.get(key) || { count: 0, since: now };
  if (now - entry.since > 15 * 60_000) {
    entry.count = 0;
    entry.since = now;
  }
  entry.count++;
  attempts.set(key, entry);
  return entry.count > 10;
}

function publicDevice(d) {
  const db = store.db;
  const pending = (db.commands[d.id] || []).filter((c) => !c.deliveredAt).length;
  return {
    id: d.id,
    name: d.name,
    model: d.model,
    imei: d.imei,
    createdAt: d.createdAt,
    lastSeen: d.lastSeen,
    theft: d.theft,
    battery: d.battery,
    sim: d.sim,
    lastLocation: d.lastLocation,
    hasContacts: fs.existsSync(store.contactsFile(d.id)),
    contactsCount: d.contactsCount || 0,
    contactsAt: d.contactsAt || null,
    evidenceCount: (db.evidence[d.id] || []).length,
    photoCount: (db.photos[d.id] || []).length,
    pendingCommands: pending,
  };
}

// ---------- Authentification ----------

function requireUser(req, res, next) {
  const raw = parseCookies(req).bp_session || (req.headers.authorization || "").replace(/^Bearer /, "");
  if (!raw) return bad(res, 401, "Connectez-vous pour continuer.");
  const db = store.db;
  const session = db.sessions.find((s) => s.tokenHash === sha(raw) && s.expires > Date.now());
  if (!session) return bad(res, 401, "Votre session a expiré. Reconnectez-vous.");
  req.user = db.users.find((u) => u.id === session.userId);
  if (!req.user) return bad(res, 401, "Compte introuvable.");
  next();
}

function requireDevice(req, res, next) {
  const raw = (req.headers.authorization || "").replace(/^Device /, "");
  if (!raw) return bad(res, 401, "Appareil non authentifié.");
  const device = store.db.devices.find((d) => d.tokenHash === sha(raw));
  if (!device) return bad(res, 401, "Appareil inconnu.");
  req.device = device;
  device.lastSeen = Date.now();
  next();
}

function openSession(res, userId) {
  const raw = token();
  store.db.sessions.push({ tokenHash: sha(raw), userId, expires: Date.now() + SESSION_DAYS * 86400_000 });
  store.db.sessions = store.db.sessions.filter((s) => s.expires > Date.now());
  store.save();
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `bp_session=${raw}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${secure}`
  );
  return raw;
}

// ---------- API Application Android ----------

// Inscription (ou reconnexion) depuis le téléphone : crée le compte si besoin et enregistre l'appareil.
app.post("/api/device/register", (req, res) => {
  const email = normEmail(req.body.email);
  const phone = normPhone(req.body.phone);
  const password = String(req.body.password || "");
  const imei = String(req.body.imei || "").trim();
  const db = store.db;

  if (!validEmail(email)) return bad(res, 400, "Adresse e-mail invalide.");
  if (phone.replace(/\D/g, "").length < 8) return bad(res, 400, "Numéro de téléphone invalide.");
  if (password.length < 8) return bad(res, 400, "Le mot de passe doit contenir au moins 8 caractères.");
  if (imei && !validImei(imei)) return bad(res, 400, "IMEI invalide (15 chiffres, affichés avec *#06#).");

  let user = db.users.find((u) => u.email === email);
  if (user) {
    if (tooManyAttempts(`${req.ip}|${email}`)) return bad(res, 429, "Trop de tentatives. Réessayez dans 15 minutes.");
    if (!checkPassword(password, user)) return bad(res, 403, "Ce compte existe déjà et le mot de passe est incorrect.");
  } else {
    const { salt, hash } = hashPassword(password);
    user = { id: id(), email, phone, salt, passHash: hash, createdAt: Date.now() };
    db.users.push(user);
  }

  if (imei) {
    const taken = db.devices.find((d) => d.imei === imei && d.userId !== user.id);
    if (taken) return bad(res, 409, "Cet IMEI est déjà enregistré sur un autre compte.");
  }

  const rawToken = token();
  let device = imei ? db.devices.find((d) => d.imei === imei && d.userId === user.id) : null;
  if (device) {
    device.tokenHash = sha(rawToken); // réinstallation : nouveau jeton, ancien invalidé
  } else {
    device = {
      id: id(),
      userId: user.id,
      name: String(req.body.name || "Mon téléphone").slice(0, 60),
      model: String(req.body.model || "").slice(0, 60),
      imei: imei || null,
      tokenHash: sha(rawToken),
      createdAt: Date.now(),
      lastSeen: Date.now(),
      theft: false,
      battery: null,
      sim: null,
      lastLocation: null,
    };
    db.devices.push(device);
  }
  store.save();
  res.json({ deviceId: device.id, deviceToken: rawToken });
});

// Rapport du téléphone : position, batterie, mode vol, SIM, événement éventuel.
// Réponse : commandes en attente (le téléphone les exécute puis les confirme).
app.post("/api/device/report", requireDevice, (req, res) => {
  const d = req.device;
  const db = store.db;
  const b = req.body || {};

  if (typeof b.battery === "number") d.battery = Math.max(0, Math.min(100, Math.round(b.battery)));
  if (typeof b.theft === "boolean") d.theft = b.theft;
  if (typeof b.sim === "string") d.sim = b.sim.slice(0, 200);

  const lat = Number(b.lat), lng = Number(b.lng);
  if (Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180) {
    const loc = {
      lat,
      lng,
      accuracy: Number.isFinite(Number(b.accuracy)) ? Math.round(Number(b.accuracy)) : null,
      time: Number(b.time) || Date.now(),
    };
    d.lastLocation = loc;
    store.pushCapped(db.locations, d.id, loc, 1000);
  }

  if (b.event) {
    store.pushCapped(db.events, d.id, { type: String(b.event).slice(0, 40), detail: String(b.detail || "").slice(0, 300), time: Date.now() }, 300);
  }

  const now = Date.now();
  const pending = (db.commands[d.id] || []).filter((c) => !c.deliveredAt);
  pending.forEach((c) => (c.deliveredAt = now));
  store.save();
  res.json({ commands: pending.map((c) => ({ id: c.id, type: c.type })) });
});

// Confirmation d'exécution d'une commande
app.post("/api/device/commands/:cid/done", requireDevice, (req, res) => {
  const cmd = (store.db.commands[req.device.id] || []).find((c) => c.id === req.params.cid);
  if (!cmd) return bad(res, 404, "Commande inconnue.");
  cmd.doneAt = Date.now();
  cmd.result = String((req.body && req.body.result) || "ok").slice(0, 200);
  store.save();
  res.json({ ok: true });
});

// Sauvegarde des contacts (fichier vCard envoyé tel quel, 5 Mo max)
app.post("/api/device/contacts", requireDevice, express.text({ type: "*/*", limit: "5mb" }), (req, res) => {
  const body = typeof req.body === "string" ? req.body : "";
  if (!body.includes("BEGIN:VCARD")) return bad(res, 400, "Fichier de contacts invalide.");
  fs.writeFileSync(store.contactsFile(req.device.id), body);
  req.device.contactsCount = (body.match(/BEGIN:VCARD/g) || []).length;
  req.device.contactsAt = Date.now();
  store.save();
  res.json({ ok: true, count: req.device.contactsCount });
});

// Photo de preuve (JPEG brut, 3 Mo max) : visage du voleur (caméra avant) ou lieu (arrière).
app.post("/api/device/evidence", requireDevice, express.raw({ type: () => true, limit: "3mb" }), (req, res) => {
  const buf = Buffer.isBuffer(req.body) ? req.body : null;
  if (!buf || buf.length < 100) return bad(res, 400, "Image manquante.");
  const facing = req.headers["x-facing"] === "back" ? "back" : "front";
  const event = String(req.headers["x-event"] || "").slice(0, 40);
  let detail = "";
  try {
    detail = decodeURIComponent(String(req.headers["x-detail"] || "")).slice(0, 300);
  } catch (e) {
    detail = "";
  }
  const photoId = id();
  fs.writeFileSync(store.evidenceFile(req.device.id, photoId), buf);
  store.pushCapped(store.db.evidence, req.device.id, { id: photoId, facing, event, detail, time: Date.now() }, 50);
  store.pushCapped(
    store.db.events,
    req.device.id,
    { type: "PHOTO", detail: `Photo ${facing === "front" ? "caméra avant" : "caméra arrière"} (${event})`, time: Date.now() },
    300
  );
  store.save();
  res.json({ ok: true, id: photoId });
});

// Coffre photos (JPEG brut, 8 Mo max) : sauvegarde des photos récentes de la galerie.
app.post("/api/device/photos", requireDevice, express.raw({ type: () => true, limit: "8mb" }), (req, res) => {
  const buf = Buffer.isBuffer(req.body) ? req.body : null;
  if (!buf || buf.length < 100) return bad(res, 400, "Image manquante.");
  const photoId = String(req.headers["x-photo-id"] || "").slice(0, 64) || id();
  const taken = Number(req.headers["x-taken"]) || Date.now();
  const list = (store.db.photos[req.device.id] = store.db.photos[req.device.id] || []);

  fs.writeFileSync(store.photoFile(req.device.id, photoId), buf);
  const existing = list.find((p) => p.id === photoId);
  if (existing) {
    existing.taken = taken;
    existing.time = Date.now();
  } else {
    list.push({ id: photoId, taken, time: Date.now() });
  }
  // Plafond : on garde les plus récentes (par date de prise), on supprime le reste.
  if (list.length > PHOTO_LIMIT) {
    list.sort((a, b) => b.taken - a.taken);
    const dropped = list.splice(PHOTO_LIMIT);
    dropped.forEach((p) => {
      try {
        fs.unlinkSync(store.photoFile(req.device.id, p.id));
      } catch (e) {
        /* fichier déjà absent */
      }
    });
  }
  store.save();
  res.json({ ok: true, id: photoId, count: list.length });
});

// ---------- API Site de suivi ----------

app.post("/api/login", (req, res) => {
  const email = normEmail(req.body.email);
  if (tooManyAttempts(`${req.ip}|${email}`)) return bad(res, 429, "Trop de tentatives. Réessayez dans 15 minutes.");
  const user = store.db.users.find((u) => u.email === email);
  if (!user || !checkPassword(String(req.body.password || ""), user)) {
    return bad(res, 401, "E-mail ou mot de passe incorrect.");
  }
  openSession(res, user.id);
  res.json({ ok: true, email: user.email });
});

app.post("/api/logout", (req, res) => {
  const raw = parseCookies(req).bp_session;
  if (raw) store.db.sessions = store.db.sessions.filter((s) => s.tokenHash !== sha(raw));
  store.save();
  res.setHeader("Set-Cookie", "bp_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/me", requireUser, (req, res) => {
  const devices = store.db.devices.filter((d) => d.userId === req.user.id).map(publicDevice);
  res.json({ email: req.user.email, phone: req.user.phone, devices });
});

function ownDevice(req, res) {
  const d = store.db.devices.find((x) => x.id === req.params.id && x.userId === req.user.id);
  if (!d) bad(res, 404, "Appareil introuvable.");
  return d;
}

app.get("/api/devices/:id/history", requireUser, (req, res) => {
  const d = ownDevice(req, res);
  if (!d) return;
  const db = store.db;
  res.json({
    device: publicDevice(d),
    locations: (db.locations[d.id] || []).slice(-200),
    events: (db.events[d.id] || []).slice(-50).reverse(),
    commands: (db.commands[d.id] || []).slice(-20).reverse(),
    evidence: (db.evidence[d.id] || []).slice(-30).reverse(),
    photos: (db.photos[d.id] || []).slice().sort((a, b) => b.taken - a.taken),
  });
});

app.get("/api/devices/:id/evidence/:pid.jpg", requireUser, (req, res) => {
  const d = ownDevice(req, res);
  if (!d) return;
  const pid = String(req.params.pid);
  const meta = (store.db.evidence[d.id] || []).find((e) => e.id === pid);
  const file = store.evidenceFile(d.id, pid);
  if (!meta || !fs.existsSync(file)) return bad(res, 404, "Photo introuvable.");
  res.setHeader("Content-Type", "image/jpeg");
  res.setHeader("Cache-Control", "private, max-age=86400");
  res.send(fs.readFileSync(file));
});

// Coffre photos : liste et téléchargement, réservés au propriétaire.
app.get("/api/devices/:id/photos", requireUser, (req, res) => {
  const d = ownDevice(req, res);
  if (!d) return;
  const list = (store.db.photos[d.id] || []).slice().sort((a, b) => b.taken - a.taken);
  res.json({ count: list.length, limit: PHOTO_LIMIT, photos: list });
});

app.get("/api/devices/:id/photos/:pid.jpg", requireUser, (req, res) => {
  const d = ownDevice(req, res);
  if (!d) return;
  const pid = String(req.params.pid);
  const meta = (store.db.photos[d.id] || []).find((p) => p.id === pid);
  const file = store.photoFile(d.id, pid);
  if (!meta || !fs.existsSync(file)) return bad(res, 404, "Photo introuvable.");
  if (req.query.dl) {
    res.setHeader("Content-Disposition", `attachment; filename="bless-${pid}.jpg"`);
  }
  res.setHeader("Content-Type", "image/jpeg");
  res.setHeader("Cache-Control", "private, max-age=86400");
  res.send(fs.readFileSync(file));
});

app.post("/api/devices/:id/command", requireUser, (req, res) => {
  const d = ownDevice(req, res);
  if (!d) return;
  const type = String(req.body.type || "").toUpperCase();
  if (!COMMAND_TYPES.includes(type)) return bad(res, 400, "Commande inconnue.");
  const cmd = { id: id(), type, createdAt: Date.now(), deliveredAt: null, doneAt: null, result: null };
  store.pushCapped(store.db.commands, d.id, cmd, 100);
  // Le mode vol est visible tout de suite sur le site (et dans le registre IMEI)
  if (type === "VOL") d.theft = true;
  if (type === "STOP") d.theft = false;
  store.save();
  res.json({ ok: true, command: cmd });
});

app.get("/api/devices/:id/contacts.vcf", requireUser, (req, res) => {
  const d = ownDevice(req, res);
  if (!d) return;
  const file = store.contactsFile(d.id);
  if (!fs.existsSync(file)) return bad(res, 404, "Aucune sauvegarde de contacts pour cet appareil.");
  res.setHeader("Content-Type", "text/vcard; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="contacts-bless-protect.vcf"');
  res.send(fs.readFileSync(file));
});

// ---------- Registre IMEI public ----------

app.get("/api/imei/:imei", (req, res) => {
  const imei = String(req.params.imei).trim();
  if (!validImei(imei)) return bad(res, 400, "IMEI invalide : il doit contenir 15 chiffres (composez *#06#).");
  const d = store.db.devices.find((x) => x.imei === imei);
  if (!d) return res.json({ status: "unknown", message: "Cet IMEI n'est pas enregistré chez Bless Protect." });
  res.json(
    d.theft
      ? { status: "stolen", message: "Ce téléphone est DÉCLARÉ VOLÉ. Ne l'achetez pas et contactez la police." }
      : { status: "ok", message: "Ce téléphone est enregistré et n'est pas déclaré volé." }
  );
});

// ---------- Site ----------

app.use("/vendor/leaflet", express.static(path.join(__dirname, "node_modules", "leaflet", "dist")));
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("/health", (req, res) => res.json({ ok: true }));

function lanAddresses() {
  const nets = require("os").networkInterfaces();
  const out = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) out.push(net.address);
    }
  }
  return out;
}

function startListening() {
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, "0.0.0.0", () => {
    const ips = lanAddresses();
    const urls = ips.map((ip) => `http://${ip}:${port}`);
    console.log("====================================================");
    console.log(" Bless Protect - serveur demarre");
    console.log("----------------------------------------------------");
    console.log(` Sur ce PC        : http://localhost:${port}`);
    urls.forEach((u) => console.log(` Depuis le telephone : ${u}`));
    console.log("----------------------------------------------------");
    console.log(" Mettez l'adresse 'Depuis le telephone' dans l'app,");
    console.log(" champ 'Adresse du serveur'. Gardez cette fenetre ouverte.");
    console.log("====================================================");
    try {
      require("fs").writeFileSync(
        require("path").join(__dirname, "adresse-serveur.txt"),
        `Adresse a mettre dans l'application (champ 'Adresse du serveur') :\r\n\r\n` +
          (urls.length ? urls.join("\r\n") : `(aucune adresse Wi-Fi detectee) http://localhost:${port}`) +
          `\r\n\r\nLe PC et le telephone doivent etre sur le MEME Wi-Fi.\r\nGardez la fenetre du serveur ouverte.\r\n`
      );
    } catch (e) {
      /* pas bloquant */
    }
  });
  const stop = () => {
    store.flush();
    setTimeout(() => process.exit(0), 300);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

if (require.main === module) {
  // On attend que la base soit chargée (depuis Redis en ligne, ou le fichier local)
  // avant d'accepter des connexions.
  store.ready.then(startListening);
}

module.exports = app;
