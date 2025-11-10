// server.js — Baileys API Estável, Seguro e Pronto para Produção
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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------- CONFIG ----------------------
const app = express();
app.use(express.json({ limit: "10mb" }));

// CORS configurável (adicione suas origens)
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(",") || ["*"];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const log = pino({ level: process.env.LOG_LEVEL || "info" });
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || "/data";
const JWT_SECRET = process.env.JWT_SECRET || "";
const QR_THROTTLE_MS = Number(process.env.QR_THROTTLE_MS || 1200);
const KEEPALIVE_MS = 10000; // 10s (recomendado)
const MAX_RECONNECT_ATTEMPTS = 10;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------------------- AUTH ----------------------
function requireAuth(req, res, next) {
  if (!JWT_SECRET) return next();
  const token =
    (req.headers.authorization || "").replace("Bearer ", "").trim() ||
    req.query.token ||
    req.body.token;
  if (!token) return res.status(401).json({ error: "missing_token" });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

// ------------------ UTILS ----------------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const extractNumberFromJid = (jid) => (jid || "").split("@")[0] || null;
const toE164Digits = (v) => String(v).replace(/[^\d]/g, "");
const sanitizeSessionId = (id) => {
  const base = path.basename(id);
  return /^[a-zA-Z0-9_-]{1,50}$/.test(base) ? base : null;
};

// Browsers aleatórios para evitar detecção
const BROWSERS = [
  ["Ubuntu", "Chrome", "120.0.0"],
  ["Windows 10", "Chrome", "119.0.0"],
  ["Macintosh", "Safari", "16.6"],
  ["Windows 11", "Edge", "120.0.0"],
];
const getRandomBrowser = () => BROWSERS[Math.floor(Math.random() * BROWSERS.length)];

// ------------------ RATE LIMIT ----------------
const rateLimitMap = new Map(); // jid -> timestamp

// ------------------ STATE DE SESSÕES ----------------
const sessions = new Map();
const sessionLocks = new Set();
const reconnectAttempts = new Map(); // sessionId -> count

function removeAllListeners(sock) {
  if (!sock?.ev) return;
  sock.ev.removeAllListeners("creds.update");
  sock.ev.removeAllListeners("connection.update");
}

async function getOrCreateSession(sessionId) {
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  while (sessionLocks.has(sessionId)) await sleep(100);
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  sessionLocks.add(sessionId);
  let meta;

  try {
    const authDir = path.join(DATA_DIR, sessionId);
    fs.mkdirSync(authDir, { recursive: true });

    const { state, saveCreds } = await useMultiFileAuthState(authDir);
    const { version } = await fetchLatestBaileysVersion().catch(() => ({
      version: [2, 3000, 10],
    }));

    const sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: false,
      logger: log,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      keepAliveIntervalMs: KEEPALIVE_MS,
      browser: getRandomBrowser(),
    });

    meta = {
      id: sessionId,
      sock,
      status: "starting",
      lastQr: null,
      lastQrDataUrl: null,
      lastQrAt: 0,
      connectedAt: null,
    };

    sessions.set(sessionId, meta);
    reconnectAttempts.set(sessionId, 0);

    // Salvar credenciais
    sock.ev.on("creds.update", async () => {
      try { await saveCreds(); } catch (e) {
        log.error({ sessionId, err: e.message }, "saveCreds failed");
      }
    });

    // Gerenciar conexão
    sock.ev.on("connection.update", async (update) => {
      const { connection, lastDisconnect, qr } = update || {};

      // QR Code
      if (qr && meta.status !== "connected" && !meta.connectedAt) {
        const now = Date.now();
        if (now - meta.lastQrAt >= QR_THROTTLE_MS) {
          meta.lastQrAt = now;
          meta.lastQr = qr;
          meta.lastQrDataUrl = await QRCode.toDataURL(qr);
          meta.status = "waiting_for_scan";
          log.info({ sessionId }, "QR gerado");
        }
      }

      // Conectado
      if (connection === "open") {
        meta.status = "connected";
        meta.connectedAt = Date.now();
        meta.lastQr = null;
        meta.lastQrDataUrl = null;
        reconnectAttempts.set(sessionId, 0);
        log.info({ sessionId, user: sock.user?.id }, "Sessão conectada");
      }

      // Desconectado
      if (connection === "close") {
        removeAllListeners(sock);
        const code = lastDisconnect?.error?.output?.statusCode ?? 500;
        log.warn({ sessionId, code }, "Conexão fechada");

        if (code === DisconnectReason.loggedOut || code === 401) {
          log.warn({ sessionId }, "Sessão desconectada — resetando");
          sessions.delete(sessionId);
          try { fs.rmSync(authDir, { recursive: true, force: true }); } catch {}
          setTimeout(() => getOrCreateSession(sessionId), 3000);
        } else {
          sessions.delete(sessionId);
          scheduleReconnect(sessionId);
        }
      }
    });

    return meta;
  } catch (err) {
    log.error({ sessionId, err: err.message }, "Erro ao criar sessão");
    sessions.delete(sessionId);
    throw err;
  } finally {
    sessionLocks.delete(sessionId);
  }
}

// Reconexão com backoff
function scheduleReconnect(sessionId, delay = 2000) {
  const attempts = (reconnectAttempts.get(sessionId) || 0) + 1;
  if (attempts > MAX_RECONNECT_ATTEMPTS) {
    log.error({ sessionId }, "Máximo de tentativas de reconexão atingido");
    return;
  }
  reconnectAttempts.set(sessionId, attempts);
  const nextDelay = Math.min(delay * 2, 60000);
  setTimeout(() => getOrCreateSession(sessionId).catch(() => scheduleReconnect(sessionId, nextDelay)), delay);
}

// ------------------ ROTAS ----------------

// Health
app.get("/", (_, res) => res.json({ ok: true, service: "baileys-api", time: new Date().toISOString() }));
app.get("/health", (_, res) => res.json({ ok: true, t: Date.now() }));
app.get("/healthz", (_, res) => res.json({ ok: true, t: Date.now() }));
app.get("/version", (_, res) => res.json({ ok: true, port: PORT, dataDir: DATA_DIR }));

// Status da sessão
app.get("/sessions/:id/status", requireAuth, async (req, res) => {
  const sessionId = sanitizeSessionId(req.params.id);
  if (!sessionId) return res.status(400).json({ error: "invalid_session_id" });

  const meta = await getOrCreateSession(sessionId);

  let userJid = null;
  let userNumber = null;
  if (meta.status === "connected" && meta.sock?.user?.id) {
    userJid = meta.sock.user.id;
    userNumber = extractNumberFromJid(userJid);
  }

  res.json({
    sessionId,
    status: meta.status,
    connected: meta.status === "connected",
    connectedAt: meta.connectedAt ?? null,
    userJid,
    userNumber,
  });
});

// QR Code
app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const sessionId = sanitizeSessionId(req.params.id);
  if (!sessionId) return res.status(400).json({ error: "invalid_session_id" });

  const meta = await getOrCreateSession(sessionId);

  if (meta.status === "connected") {
    return res.json({ status: "connected" });
  }
  if (!meta.lastQrDataUrl) {
    return res.status(202).json({ status: meta.status || "starting" });
  }

  res.json({
    status: "waiting_for_scan",
    qr: meta.lastQrDataUrl,
  });
});

// Enviar mensagem
app.post("/sessions/:id/send", requireAuth, async (req, res) => {
  const sessionId = sanitizeSessionId(req.params.id);
  if (!sessionId) return res.status(400).json({ ok: false, error: "invalid_session_id" });

  const meta = await getOrCreateSession(sessionId);

  if (meta.status !== "connected") {
    return res.status(409).json({ ok: false, error: "not_connected", status: meta.status });
  }
  if (!meta.sock?.user) {
    return res.status(500).json({ ok: false, error: "socket_not_ready" });
  }

  const toRaw = req.body?.to ?? req.body?.number;
  const text = req.body?.text ?? req.body?.message;
  if (!toRaw || !text) {
    return res.status(400).json({ ok: false, error: "missing_to_or_text" });
  }

  const digits = toE164Digits(toRaw);
  if (!digits || digits.length < 10 || digits.length > 15) {
    return res.status(400).json({ ok: false, error: "invalid_phone" });
  }

  const jid = `${digits}@s.whatsapp.net`;

  // Rate limit: 800ms entre mensagens por número
  const now = Date.now();
  const lastSent = rateLimitMap.get(jid) || 0;
  if (now - lastSent < 800) {
    await sleep(800 - (now - lastSent));
  }
  rateLimitMap.set(jid, Date.now());

  try {
    const wa = await meta.sock.onWhatsApp(digits);
    if (!wa?.[0]?.exists) {
      return res.status(404).json({ ok: false, error: "not_whatsapp_user" });
    }

    const result = await meta.sock.sendMessage(jid, { text: String(text) });
    return res.json({
      ok: true,
      id: result?.key?.id || null,
      to: digits,
    });
  } catch (e) {
    const msg = e?.message || String(e);
    log.error({ sessionId, jid, err: msg }, "send_error");
    if (msg.includes("jidDecode")) {
      return res.status(400).json({ ok: false, error: "invalid_jid_format" });
    }
    return res.status(500).json({ ok: false, error: "send_failed" });
  }
});

// Resetar sessão
app.post("/sessions/:id/reset", requireAuth, async (req, res) => {
  const sessionId = sanitizeSessionId(req.params.id);
  if (!sessionId) return res.status(400).json({ ok: false, error: "invalid_session_id" });

  const meta = sessions.get(sessionId);
  if (meta?.sock) {
    removeAllListeners(meta.sock);
    try { await meta.sock.logout(); } catch {}
  }

  sessions.delete(sessionId);
  reconnectAttempts.delete(sessionId);
  const authDir = path.join(DATA_DIR, sessionId);
  try { fs.rmSync(authDir, { recursive: true, force: true }); } catch (e) {
    log.error({ sessionId, err: e.message }, "Falha ao deletar auth dir");
  }

  await sleep(500);
  const fresh = await getOrCreateSession(sessionId);
  res.json({ ok: true, status: fresh.status });
});

// Desconectar
app.post("/sessions/:id/disconnect", requireAuth, async (req, res) => {
  const sessionId = sanitizeSessionId(req.params.id);
  if (!sessionId) return res.status(400).json({ ok: false, error: "invalid_session_id" });

  const meta = sessions.get(sessionId);
  if (meta?.sock) {
    removeAllListeners(meta.sock);
    try { await meta.sock.logout(); } catch {}
  }
  sessions.delete(sessionId);
  reconnectAttempts.delete(sessionId);
  res.json({ ok: true });
});

// 404
app.use((req, res) => res.status(404).json({ ok: false, error: "not_found" }));

// ---------------------- START -----------------------
app.listen(PORT, () => {
  log.info(`Baileys API rodando na porta ${PORT} | DATA_DIR=${DATA_DIR}`);
});
