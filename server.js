import express from "express";
import QRCode from "qrcode";
import pino from "pino";
import jwt from "jsonwebtoken";
import { makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion, DisconnectReason } from "@whiskeysockets/baileys";
import fs from "fs";
import path from "path";

// ----- Config -----
const app = express();
app.use(express.json());

// Basic CORS (adjust for your domain if needed)
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
const JWT_SECRET = process.env.JWT_SECRET || ""; // optional but recommended

fs.mkdirSync(DATA_DIR, { recursive: true });

// ----- Auth middleware (optional via JWT_SECRET) -----
function requireAuth(req, res, next) {
  if (!JWT_SECRET) return next(); // disabled if secret not set
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing_token" });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid_token" });
  }
}

// ----- Baileys session manager -----
const sessions = new Map(); // sessionId -> meta

async function getOrCreateSession(sessionId) {
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  const authDir = path.join(DATA_DIR, sessionId);
  fs.mkdirSync(authDir, { recursive: true });
  const { state, saveCreds } = await useMultiFileAuthState(authDir);
  const { version } = await fetchLatestBaileysVersion();
  const sock = makeWASocket({ version, auth: state, printQRInTerminal: false });

  const meta = { sock, status: "starting", lastQr: null, connectedAt: null };
  sessions.set(sessionId, meta);

  sock.ev.on("creds.update", saveCreds);
  sock.ev.on("connection.update", (u) => {
    const { connection, lastDisconnect, qr } = u || {};
    if (qr) { meta.lastQr = qr; meta.status = "qr"; log.info({ sessionId }, "QR updated"); }
    if (connection === "open") {
      meta.status = "connected"; meta.connectedAt = Date.now(); meta.lastQr = null;
      log.info({ sessionId }, "Session connected");
    }
    if (connection === "close") {
      const code = lastDisconnect?.error?.output?.statusCode;
      const shouldReconnect = code !== DisconnectReason.loggedOut;
      if (shouldReconnect) {
        meta.status = "reconnecting";
        log.warn({ sessionId, code }, "Reconnecting...");
        setTimeout(() => getOrCreateSession(sessionId), 1500);
      } else {
        log.warn({ sessionId, code }, "Logged out, cleaning session");
        sessions.delete(sessionId);
      }
    }
  });

  return meta;
}

// ----- Health -----
app.get("/healthz", (req, res) => res.json({ ok: true, t: Date.now() }));

// ----- Protected routes -----
app.get("/sessions/:id/status", requireAuth, (req, res) => {
  const meta = sessions.get(req.params.id);
  res.json({ status: meta?.status ?? "not_initialized", connectedAt: meta?.connectedAt ?? null });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  if (meta.status === "connected") return res.json({ status: "connected" });
  if (!meta.lastQr) return res.status(202).json({ status: meta.status ?? "starting" });
  const dataUrl = await QRCode.toDataURL(meta.lastQr);
  res.json({ status: meta.status, dataUrl });
});

app.post("/sessions/:id/messages", requireAuth, async (req, res) => {
  const { to, text } = req.body || {};
  const meta = sessions.get(req.params.id);
  if (!meta || meta.status !== "connected") return res.status(409).json({ error: "session_not_connected" });
  const jid = `${String(to).replace(/\D/g, "")}@s.whatsapp.net`;
  await meta.sock.sendMessage(jid, { text: text || "" });
  res.json({ ok: true });
});

app.post("/sessions/:id/disconnect", requireAuth, async (req, res) => {
  const meta = sessions.get(req.params.id);
  if (meta?.sock) await meta.sock.logout();
  sessions.delete(req.params.id);
  res.json({ ok: true });
});

app.listen(PORT, () => log.info(`Baileys API listening on :${PORT}`));
