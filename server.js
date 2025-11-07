// server.js — Baileys QR Service (ESM)
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

// ----------------- BOOT -----------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
const PORT = Number(process.env.PORT || 3000);
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
    log.warn({ ip: req.ip }, "[Auth] missing_token");
    return res.status(401).json({ error: "missing_token" });
  }
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    log.warn({ ip: req.ip, err: e.message }, "[Auth] invalid_token");
    return res.status(401).json({ error: "invalid_token" });
  }
}

// ----------------- SESSÕES -----------------
/**
 * Estrutura:
 * sessions: Map(sessionId => {
 *   sock,
 *   status: 'starting' | 'waiting_for_scan' | 'connected' | 'reconnecting',
 *   lastQr: string|null,
 *   lastQrDataUrl: string|null,
 *   lastQrAt: number|null,
 *   connectedAt: number|null
 * })
 */
const sessions = new Map();
const sessionLocks = new Set();

async function getOrCreateSession(sessionId) {
  // sessão já criada?
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  // outra chamada já está criando?
  while (sessionLocks.has(sessionId)) {
    await new Promise((r) => setTimeout(r, 120));
  }
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  // trava criação
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
      lastQrAt: null,
      connectedAt: null,
    };
    sessions.set(sessionId, meta);

    sock.ev.on("creds.update", saveCreds);

    sock.ev.on("connection.update", async (u) => {
      const { connection, lastDisconnect, qr } = u || {};

      // Baileys vai trocando o QR sozinho quando expira (~20s).
      if (qr) {
        meta.status = "waiting_for_scan";
        meta.lastQr = qr;
        meta.lastQrAt = Date.now();
        try {
          // gera e guarda o dataURL uma única vez por QR
          meta.lastQrDataUrl = await QRCode.toDataURL(qr);
        } catch (e) {
          log.error({ sessionId, err: e.message }, "QR encode error");
          meta.lastQrDataUrl = null;
        }
        log.info({ sessionId }, "QR updated");
      }

      if (connection === "open") {
        meta.status = "connected";
        meta.connectedAt = Date.now();
        meta.lastQr = null;
        meta.lastQrDataUrl = null;
        meta.lastQrAt = null;
        log.info({ sessionId }, "Session connected");
      }

      if (connection === "close") {
        const code =
          lastDisconnect?.error?.output?.statusCode ??
          lastDisconnect?.error?.cause?.output?.statusCode;

        // se não for "loggedOut", tentamos reconectar
        const shouldReconnect = code !== DisconnectReason.loggedOut;
        if (shouldReconnect) {
          meta.status = "reconnecting";
          log.warn({ sessionId, code }, "Connection closed, reconnecting...");
          setTimeout(() => getOrCreateSession(sessionId), 2500);
        } else {
          log.warn({ sessionId, code }, "Logged out, clearing session");
          try {
            // limpa diretório da sessão para exigir novo pareamento
            const authDir = path.join(DATA_DIR, sessionId);
            fs.rmSync(authDir, { recursive: true, force: true });
          } catch {}
          sessions.delete(sessionId);
        }
      }
    });

    return meta;
  } finally {
    sessionLocks.delete(sessionId);
  }
}

async function destroySession(sessionId) {
  const meta = sessions.get(sessionId);
  if (meta?.sock) {
    try {
      await meta.sock.logout().catch(() => {});
    } catch {}
  }
  sessions.delete(sessionId);
  try {
    const authDir = path.join(DATA_DIR, sessionId);
    fs.rmSync(authDir, { recursive: true, force: true });
  } catch {}
}

// ----------------- HEALTH & INFO -----------------
app.get("/healthz", (req, res) => res.json({ ok: true, t: Date.now() }));
app.get("/version", (req, res) => {
  res.json({
    ok: true,
    port: PORT,
    dataDir: DATA_DIR,
    auth: !!JWT_SECRET,
    note:
      "Se auth=true, o token pode vir via header Authorization: Bearer <token>, query ?token= ou body.token",
  });
});

// ----------------- ROTAS PROTEGIDAS -----------------
app.get("/sessions/:id/status", requireAuth, async (req, res) => {
  const sessionId = String(req.params.id);
  const meta = await getOrCreateSession(sessionId);
  res.json({
    status: meta.status,
    connected: meta.status === "connected",
    connectedAt: meta.connectedAt ?? null,
    lastQrAt: meta.lastQrAt ?? null,
  });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const sessionId = String(req.params.id);
  const meta = await getOrCreateSession(sessionId);

  if (meta.status === "connected") {
    return res.json({ status: "connected" });
  }
  if (!meta.lastQrDataUrl) {
    // ainda não temos QR atual; cliente deve tentar de novo em alguns segundos
    return res.status(202).json({ status: meta.status || "starting" });
    // dica: faça polling de /status a cada 5s e só chame /qr quando status = waiting_for_scan
  }
  return res.json({
    status: meta.status || "waiting_for_scan",
    qr: meta.lastQrDataUrl,
    lastQrAt: meta.lastQrAt,
  });
});

// Envio de mensagem simples (teste) — opcional
app.post("/sessions/:id/messages", requireAuth, async (req, res) => {
  const sessionId = String(req.params.id);
  const { to, text } = req.body || {};
  if (!to || !text) {
    return res
      .status(400)
      .json({ error: "missing_params", detail: "to e text são obrigatórios" });
  }
  const meta = sessions.get(sessionId);
  if (!meta || meta.status !== "connected") {
    return res.status(409).json({ error: "session_not_connected" });
  }
  const jid = `${String(to).replace(/\D/g, "")}@s.whatsapp.net`;
  try {
    await meta.sock.sendMessage(jid, { text: String(text) });
    return res.json({ ok: true });
  } catch (e) {
    log.error({ sessionId, err: e.message }, "sendMessage error");
    return res.status(500).json({ error: "send_failed", detail: e.message });
  }
});

// Reset manual: logout + apaga credenciais (obriga novo pareamento)
app.post("/sessions/:id/reset", requireAuth, async (req, res) => {
  const sessionId = String(req.params.id);
  try {
    await destroySession(sessionId);
    // Nova sessão será criada na próxima chamada a /status ou /qr
    return res.json({ ok: true, reset: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// Desconectar sem apagar as credenciais (opcional)
app.post("/sessions/:id/disconnect", requireAuth, async (req, res) => {
  const sessionId = String(req.params.id);
  const meta = sessions.get(sessionId);
  try {
    if (meta?.sock) await meta.sock.logout();
    return res.json({ ok: true, disconnected: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ----------------- START -----------------
app.listen(PORT, () => {
  log.info(`Baileys API listening on :${PORT}`);
});
