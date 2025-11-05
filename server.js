import express from "express";
import QRCode from "qrcode";
import pino from "pino";
import jwt from "jsonwebtoken";
import {
  makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
} from "@whiskeysockets/baileys";
import fs from "fs";
import path from "path";

// ----------------- CONFIG -----------------
const app = express();
app.use(express.json());

// CORS simples (ajuste o domínio se quiser)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const log = pino({ level: process.env.LOG_LEVEL || "info" });
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || "/data";
const JWT_SECRET = process.env.JWT_SECRET || ""; // se vazio, auth desabilitada

fs.mkdirSync(DATA_DIR, { recursive: true });

// ----------------- AUTH -----------------
function requireAuth(req, res, next) {
  if (!JWT_SECRET) return next(); // desabilita se não houver segredo definido

  const authHeader = req.headers.authorization || "";
  const tokenFromHeader = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : null;

  const tokenFromQuery = req.query?.token;
  const tokenFromBody = req.body?.token;

  const token = tokenFromHeader || tokenFromQuery || tokenFromBody;

  if (!token) {
    console.warn("[Auth] ❌ missing_token");
    return res.status(401).json({ error: "missing_token" });
  }
  try {
    jwt.verify(token, JWT_SECRET);
    console.log("[Auth] ✅ Token verificado");
    next();
  } catch (e) {
    console.error("[Auth] ❌ invalid_token:", e.message);
    return res.status(401).json({ error: "invalid_token" });
  }
}

// ----------------- SESSÕES -----------------
// ===== Sessões e trava de inicialização =====
const sessions = new Map();     // sessionId -> meta
const sessionLocks = new Set(); // evita corrida ao criar a mesma sessão

async function getOrCreateSession(sessionId) {
  // já existe?
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  // outra chamada já está criando?
  while (sessionLocks.has(sessionId)) {
    await new Promise(r => setTimeout(r, 150));
  }
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  // trava
  sessionLocks.add(sessionId);
  try {
    const authDir = path.join(DATA_DIR, sessionId);
    fs.mkdirSync(authDir, { recursive: true });

    const { state, saveCreds } = await useMultiFileAuthState(authDir);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: false,
      logger: log,
    });

    const meta = {
      sock,
      status: "starting",
      lastQr: null,
      lastQrDataUrl: null,
      connectedAt: null,
    };
    sessions.set(sessionId, meta);

    sock.ev.on("creds.update", saveCreds);

    sock.ev.on("connection.update", async (u) => {
      const { connection, lastDisconnect, qr } = u || {};

      if (qr) {
        meta.lastQr = qr;
        try {
          // gera o PNG UMA VEZ por QR e guarda em memória
          meta.lastQrDataUrl = await QRCode.toDataURL(qr);
        } catch (e) {
          log.error(e, "QR encode error");
        }
        meta.status = "waiting_for_scan";
      }

      if (connection === "open") {
        meta.status = "connected";
        meta.connectedAt = Date.now();
        meta.lastQr = null;
        meta.lastQrDataUrl = null;
        log.info({ sessionId }, "Connected");
      }

      if (connection === "close") {
        const code = lastDisconnect?.error?.output?.statusCode;
        const shouldReconnect = code !== DisconnectReason.loggedOut;
        if (shouldReconnect) {
          meta.status = "reconnecting";
          setTimeout(() => getOrCreateSession(sessionId), 3000);
        } else {
          sessions.delete(sessionId);
          log.warn({ sessionId }, "Logged out, session cleared");
        }
      }
    });

    return meta;
  } finally {
    sessionLocks.delete(sessionId);
  }
}


// ----------------- HEALTH & INFO -----------------
app.get("/healthz", (req, res) => res.json({ ok: true, t: Date.now() }));
app.get("/version", (req, res) => {
  res.json({
    ok: true,
    port: PORT,
    dataDir: DATA_DIR,
    auth: !!JWT_SECRET,
    note: "Se auth=true, o token pode vir via header Authorization, query ?token= ou body.token",
  });
});

// ----------------- ROTAS PROTEGIDAS -----------------
app.get("/sessions/:id/status", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  res.json({
    status: meta.status,
    connected: meta.status === "connected",
    connectedAt: meta.connectedAt ?? null,
  });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);

  if (meta.status === "connected") {
    return res.json({ status: "connected" });
  }

  if (!meta.lastQrDataUrl) {
    // ainda não temos QR atual para mostrar
    return res.status(202).json({ status: meta.status || "starting" });
  }

  // devolve sempre o MESMO dataURL até o Baileys emitir outro
  res.json({
    status: meta.status || "waiting_for_scan",
    qr: meta.lastQrDataUrl,
  });
});


// ----------------- START -----------------
app.listen(PORT, () => {
  log.info(`Baileys API listening on :${PORT}`);
});
