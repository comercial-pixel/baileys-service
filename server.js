// server.js — Baileys API (ESM) com persistência e tratamento de device_removed

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
import { fileURLToPath } from "url";

// ----------------------------------------------------
// CONFIG BÁSICA
// ----------------------------------------------------
const app = express();
app.use(express.json());

// CORS simples
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const log = pino({ level: process.env.LOG_LEVEL || "info" });
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || "/data"; // monte um Disk no Render em /data
const JWT_SECRET = process.env.JWT_SECRET || "";  // se vazio, autenticação desabilitada

// Suporte __dirname em ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Garante diretório persistente
fs.mkdirSync(DATA_DIR, { recursive: true });

// ----------------------------------------------------
// AUTENTICAÇÃO (JWT no header Authorization, ?token= ou body.token)
// ----------------------------------------------------
function requireAuth(req, res, next) {
  if (!JWT_SECRET) return next(); // auth desabilitada

  const authHeader = req.headers.authorization || "";
  const tokenFromHeader = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : null;

  const token = tokenFromHeader || req.query?.token || req.body?.token;
  if (!token) {
    log.warn({ path: req.path }, "[Auth] missing_token");
    return res.status(401).json({ error: "missing_token" });
  }
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    log.warn({ path: req.path, err: e.message }, "[Auth] invalid_token");
    return res.status(401).json({ error: "invalid_token" });
  }
}

// ----------------------------------------------------
// GERENCIAMENTO DE SESSÕES
// ----------------------------------------------------
const sessions = new Map();     // sessionId -> meta
const sessionLocks = new Set(); // evita corrida na criação

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getOrCreateSession(sessionId) {
  if (sessions.has(sessionId)) return sessions.get(sessionId);
  while (sessionLocks.has(sessionId)) await sleep(120);
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  sessionLocks.add(sessionId);
  try {
    const authDir = path.join(DATA_DIR, sessionId);
    fs.mkdirSync(authDir, { recursive: true });

    const { state, saveCreds } = await useMultiFileAuthState(authDir);

    // versão do WA Web
    let version;
    try {
      ({ version } = await fetchLatestBaileysVersion());
    } catch (e) {
      log.warn({ sessionId, err: e?.message }, "fetchLatestBaileysVersion failed, fallback");
      version = [2, 3000, 1027934701]; // fallback
    }

    const sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: false,
      logger: log,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      connectTimeoutMs: 60_000,
      keepAliveIntervalMs: 15_000,
    });

    const meta = {
      sock,
      status: "starting",
      lastQrText: null,        // QR como texto
      lastQrDataUrl: null,     // QR como dataURL png (para frontend)
      connectedAt: null,
      reconnectAttempts: 0,
    };
    sessions.set(sessionId, meta);

    // persistência de credenciais
    sock.ev.on("creds.update", async () => {
      try { await saveCreds(); } catch (e) {
        log.error({ sessionId, err: e?.message }, "saveCreds failed");
      }
    });

    // eventos de conexão
    sock.ev.on("connection.update", async (update) => {
      const { connection, lastDisconnect, qr } = update || {};

      if (qr) {
        meta.lastQrText = qr;
        try {
          meta.lastQrDataUrl = await QRCode.toDataURL(qr);
        } catch (e) {
          meta.lastQrDataUrl = null;
          log.error({ sessionId, err: e?.message }, "QR encode error");
        }
        meta.status = "waiting_for_scan";
        meta.reconnectAttempts = 0;
        log.info({ sessionId }, "QR updated");
      }

      if (connection === "open") {
        meta.status = "connected";
        meta.connectedAt = Date.now();
        meta.lastQrText = null;
        meta.lastQrDataUrl = null;
        meta.reconnectAttempts = 0;
        log.info({ sessionId }, "Session connected");
      }

      if (connection === "close") {
        // status/erro
        const errObj = lastDisconnect?.error;
        const code =
          errObj?.output?.statusCode ??
          errObj?.statusCode ??
          errObj?.data?.statusCode ??
          errObj?.cause?.statusCode;

        const raw = JSON.stringify(errObj ?? {});
        const isRestartRequired =
          code === DisconnectReason.restartRequired || String(errObj?.message || "").toLowerCase().includes("restart required") || code === 515;

        const isConflictDeviceRemoved =
          (code === 401 && (raw.includes("device_removed") || raw.toLowerCase().includes("conflict"))) ||
          String(errObj?.message || "").toLowerCase().includes("device_removed");

        const isLoggedOut =
          code === DisconnectReason.loggedOut || code === DisconnectReason.badSession || (code === 401 && !isRestartRequired);

        log.warn({ sessionId, code, msg: String(errObj?.message || errObj) }, "connection closed");

        // 1) Conflito / device_removed → apaga sessão e pede novo QR
        if (isConflictDeviceRemoved) {
          try { await sock.logout?.(); } catch {}
          try { fs.rmSync(authDir, { recursive: true, force: true }); } catch {}
          sessions.delete(sessionId);
          log.warn({ sessionId }, "Sessão removida pelo WhatsApp (device_removed). Gere um novo QR.");
          return; // cliente deve chamar /qr para novo pareamento
        }

        // 2) Logout/badSession → apaga sessão e pede novo QR
        if (isLoggedOut) {
          try { await sock.logout?.(); } catch {}
          try { fs.rmSync(authDir, { recursive: true, force: true }); } catch {}
          sessions.delete(sessionId);
          log.warn({ sessionId, code }, "Logged out/bad session. Gere um novo QR.");
          return;
        }

        // 3) 515 restart required → reconexão controlada
        meta.status = "reconnecting";
        meta.reconnectAttempts = (meta.reconnectAttempts || 0) + 1;
        const backoff = isRestartRequired ? 1500 : Math.min(30000, 2000 * meta.reconnectAttempts);
        log.info({ sessionId, attempt: meta.reconnectAttempts, backoff }, "scheduling reconnect");

        // encerra instância antiga
        try { sock.ev.removeAllListeners(); } catch {}
        try { if (typeof sock.end === "function") sock.end(); } catch {}
        try { if (sock.ws && typeof sock.ws.close === "function") sock.ws.close(); } catch {}

        setTimeout(async () => {
          sessions.delete(sessionId);
          try {
            await getOrCreateSession(sessionId);
          } catch (e) {
            log.error({ sessionId, err: e?.message }, "reconnect failed");
          }
        }, backoff);
      }
    });

    // (opcional) log mínimo de mensagens recebidas
    sock.ev.on("messages.upsert", (m) => {
      const msg = m?.messages?.[0];
      if (!msg || msg.key.fromMe) return;
      log.info({ from: msg.key.remoteJid, type: Object.keys(msg.message || {})[0] }, "message.in");
    });

    return meta;
  } finally {
    sessionLocks.delete(sessionId);
  }
}

// ----------------------------------------------------
// HEALTH / INFO
// ----------------------------------------------------
app.get("/", (_req, res) => res.send("Baileys service up"));
app.get("/healthz", (_req, res) => res.json({ ok: true, t: Date.now() }));
app.get("/version", (_req, res) => {
  res.json({
    ok: true,
    port: PORT,
    dataDir: DATA_DIR,
    auth: Boolean(JWT_SECRET),
    note: "Se auth=true, o token pode vir via header Authorization, query ?token= ou body.token",
  });
});

// ----------------------------------------------------
// ROTAS PROTEGIDAS (status, qr, reset, send)
// ----------------------------------------------------
app.get("/sessions/:id/status", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  res.json({
    status: meta.status,
    connected: meta.status === "connected",
    connectedAt: meta.connectedAt ?? null,
    hint: meta.status === "waiting_for_scan" ? "call /qr" : "no-qr",
  });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  if (meta.status === "connected") return res.json({ status: "connected" });
  if (!meta.lastQrDataUrl) return res.status(202).json({ status: meta.status || "starting" }); // ainda sem QR
  return res.json({ status: meta.status || "waiting_for_scan", qr: meta.lastQrDataUrl });
});

// Enviar mensagem
app.post("/sessions/:id/send", requireAuth, async (req, res) => {
  try {
    const { to, text } = req.body || {};
    if (!to || !text) return res.status(400).json({ ok: false, error: "Campos 'to' e 'text' são obrigatórios" });
    const meta = await getOrCreateSession(req.params.id);
    if (meta.status !== "connected") return res.status(409).json({ ok: false, error: "not_connected" });

    // normaliza JID
    const jid = /@s\.whatsapp\.net$|@g\.us$/.test(to) ? to : `${String(to).replace(/[^\d]/g, "")}@s.whatsapp.net`;
    const r = await meta.sock.sendMessage(jid, { text });
    return res.json({ ok: true, id: r?.key?.id || null });
  } catch (e) {
    log.error({ err: e?.message }, "send error");
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// Alias legado: /messages -> /send (evita 404 HTML no front)
app.post("/sessions/:id/messages", requireAuth, (req, res) => {
  req.url = `/sessions/${req.params.id}/send`;
  app._router.handle(req, res);
});

// Reset manual (apaga credenciais e recomeça)
app.post("/sessions/:id/reset", requireAuth, async (req, res) => {
  const sessionId = req.params.id;
  try {
    const meta = sessions.get(sessionId);
    if (meta?.sock) { try { await meta.sock.logout(); } catch {} }
    sessions.delete(sessionId);
    const authDir = path.join(DATA_DIR, sessionId);
    try { fs.rmSync(authDir, { recursive: true, force: true }); } catch {}
    await sleep(300);
    const fresh = await getOrCreateSession(sessionId);
    return res.json({ ok: true, status: fresh.status || "starting" });
  } catch (e) {
    log.error({ err: e?.message }, "reset error");
    return res.status(500).json({ ok: false, error: e?.message });
  }
});

// Desconectar sem apagar credenciais
app.post("/sessions/:id/disconnect", requireAuth, async (req, res) => {
  const sessionId = req.params.id;
  const meta = sessions.get(sessionId);
  if (meta?.sock) { try { await meta.sock.logout(); } catch {} }
  sessions.delete(sessionId);
  return res.json({ ok: true });
});

// 404 JSON (evita “Unexpected token '<' …” no front)
app.use((req, res) => res.status(404).json({ ok: false, error: "Not Found", path: req.originalUrl }));

// START
app.listen(PORT, () => {
  log.info(`Baileys API listening on :${PORT}`);
});
