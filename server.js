// server.js — VERSÃO FINAL ESTÁVEL NOVEMBRO 2025 (by Grok + comunidade)
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

// ==================== CONFIGURAÇÃO ====================
const app = express();
app.use(express.json({ limit: "10mb" }));

// CORS liberado para seu site
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
const JWT_SECRET = process.env.JWT_SECRET || "troque_isso_agora_muito_importante_2025";
const QR_THROTTLE_MS = 1200;
const KEEPALIVE_MS = 10000;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ==================== AUTENTICAÇÃO JWT ====================
function requireAuth(req, res, next) {
  if (!JWT_SECRET || JWT_SECRET.includes("troque")) return next(); // sem JWT = liberado (para teste)
  const token = (req.headers.authorization || "").replace("Bearer ", "").trim() ||
                req.query.token || req.body.token;
  if (!token) return res.status(401).json({ error: "missing_token" });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

// ==================== UTILIDADES ====================
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const onlyDigits = v => String(v).replace(/\D/g, "");
const sanitizeSessionId = id => {
  const base = path.basename(id);
  return /^[a-zA-Z0-9_-]{1,50}$/.test(base) ? base : null;
};

// Browsers aleatórios (evita ban)
const BROWSERS = [
  ["Ubuntu", "Chrome", "120.0.0"],
  ["Windows 10", "Chrome", "119.0.0"],
  ["Macintosh", "Safari", "16.6"],
  ["Windows 11", "Edge", "120.0.0"],
];
const randomBrowser = () => BROWSERS[Math.floor(Math.random() * BROWSERS.length)];

// Rate limit por número (evita flood)
const rateLimit = new Map();

// ==================== SESSÕES ====================
const sessions = new Map();
const locks = new Set();

function removeListeners(sock) {
  sock?.ev?.removeAllListeners("creds.update");
  sock?.ev?.removeAllListeners("connection.update");
}

async function createSession(sessionId) {
  if (sessions.has(sessionId)) return sessions.get(sessionId);
  while (locks.has(sessionId)) await sleep(100);
  if (sessions.has(sessionId)) return sessions.get(sessionId);
  locks.add(sessionId);

  try {
    const authDir = path.join(DATA_DIR, sessionId);
    fs.mkdirSync(authDir, { recursive: true });

    const { state, saveCreds } = await useMultiFileAuthState(authDir);
    const { version } = await fetchLatestBaileysVersion().catch(() => ({ version: [2, 3000, 10] }));

    const sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: false,
      logger: log,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      keepAliveIntervalMs: KEEPALIVE_MS,
      browser: randomBrowser(),
    });

    const meta = {
      id: sessionId,
      sock,
      status: "starting",
      lastQrDataUrl: null,
      lastQrAt: 0,
      connectedAt: null,
    };

    sessions.set(sessionId, meta);

    sock.ev.on("creds.update", saveCreds);

    sock.ev.on("connection.update", async (update) => {
      const { connection, lastDisconnect, qr } = update;

      if (qr && !meta.connectedAt && Date.now() - meta.lastQrAt > QR_THROTTLE_MS) {
        meta.lastQrAt = Date.now();
        meta.lastQrDataUrl = await QRCode.toDataURL(qr);
        meta.status = "waiting_for_scan";
        log.info({ sessionId }, "QR gerado");
      }

      if (connection === "open") {
        meta.status = "connected";
        meta.connectedAt = Date.now();
        log.info({ sessionId, number: sock.user?.id?.split("@")[0] }, "WhatsApp conectado!");
      }

      if (connection === "close") {
        removeListeners(sock);
        const code = lastDisconnect?.error?.output?.statusCode;

        if (code === 401 || code === DisconnectReason.loggedOut) {
          log.warn({ sessionId }, "Deslogado – resetando sessão");
          sessions.delete(sessionId);
          try { fs.rmSync(authDir, { recursive: true, force: true }); } catch {}
          setTimeout(() => createSession(sessionId), 3000);
        } else {
          log.warn({ sessionId, code }, "Conexão perdida – reconectando...");
          sessions.delete(sessionId);
          setTimeout(() => createSession(sessionId), 5000);
        }
      }
    });

    return meta;
  } finally {
    locks.delete(sessionId);
  }
}

// ==================== ROTAS ====================

app.get("/", (_, res) => res.json({ ok: true, service: "baileys-api-2025", time: new Date().toISOString() }));

app.get("/health", (_, res) => res.json({ ok: true, time: Date.now() }));

app.get("/sessions/:id/status", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid_session_id" });

  const meta = await createSession(id);
  let userJid = null;
  let userNumber = null;
  if (meta.status === "connected" && meta.sock?.user?.id) {
    userJid = meta.sock.user.id;
    userNumber = onlyDigits(userJid);
  }

  res.json({
    sessionId: id,
    status: meta.status,
    connected: meta.status === "connected",
    connectedAt: meta.connectedAt,
    userJid,
    userNumber,
  });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid_session_id" });

  const meta = await createSession(id);
  if (meta.status === "connected") return res.json({ status: "connected" });
  if (!meta.lastQrDataUrl) return res.status(202).json({ status: "starting" });

  res.json({ status: "waiting_for_scan", qr: meta.lastQrDataUrl });
});

app.post("/sessions/:id/send", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ ok: false, error: "invalid_session_id" });

  const meta = await createSession(id);
  if (meta.status !== "connected") return res.status(409).json({ ok: false, error: "not_connected" });

  const { to, text, message } = req.body;
  if (!to || (!text && !message)) return res.status(400).json({ ok: false, error: "missing_to_or_text" });

  const digits = onlyDigits(to);
  if (digits.length < 10) return res.status(400).json({ ok: false, error: "invalid_number" });

  const jid = `${digits}@s.whatsapp.net`;

  // Rate limit 800ms entre mensagens
  const now = Date.now();
  const last = rateLimit.get(jid) || 0;
  if (now - last < 800) await sleep(800 - (now - last));
  rateLimit.set(jid, now);

  try {
    const result = await meta.sock.sendMessage(jid, { text: String(text || message) });
    res.json({ ok: true, messageId: result.key.id, to: digits });
  } catch (err) {
    log.error({ sessionId: id, to: digits, err: err.message }, "Erro ao enviar");
    res.status(500).json({ ok: false, error: "send_failed" });
  }
});

// RESET TOTAL (apaga tudo e gera novo QR)
app.post("/sessions/:id/reset", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ ok: false, error: "invalid_session_id" });

  const meta = sessions.get(id);
  if (meta?.sock) {
    removeListeners(meta.sock);
    try { await meta.sock.logout(); } catch {}
  }

  sessions.delete(id);
  const authDir = path.join(DATA_DIR, id);
  try { fs.rmSync(authDir, { recursive: true, force: true }); } catch {}

  log.warn({ sessionId: id }, "Sessão resetada pelo usuário");
  setTimeout(() => createSession(id), 2000);

  res.json({ ok: true, message: "Sessão resetada com sucesso! Novo QR em 3 segundos." });
});

// Desconectar sem apagar (opcional)
app.post("/sessions/:id/disconnect", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ ok: false, error: "invalid_session_id" });

  const meta = sessions.get(id);
  if (meta?.sock) {
    removeListeners(meta.sock);
    try { await meta.sock.logout(); } catch {}
  }
  sessions.delete(id);
  res.json({ ok: true });
});

app.use((_, res) => res.status(404).json({ ok: false, error: "not_found" }));

app.listen(PORT, () => {
  log.info(`API Baileys rodando na porta ${PORT} – PRONTA PARA VENDER 24/7`);
});
