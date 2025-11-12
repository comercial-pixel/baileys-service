// server.js — VERSÃO FINAL 100% AUTOMÁTICA (NOVEMBRO 2025)
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

const app = express();
app.use(express.json({ limit: "10mb" }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const log = pino({ level: "info" });
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || "/data";

// MUDE AQUI: COLOQUE O NOME DO SEU APP NO BASE44
const BASE44_WEBHOOK_URL = "https://connect-flow-71c06c9b.base44.app/api/functions/saveInboundWebhook";
// EXEMPLO: https://whatsapp-felipe.base44.app/api/functions/saveInboundWebhook

fs.mkdirSync(DATA_DIR, { recursive: true });

const sessions = new Map();
const locks = new Set();

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "").trim();
  if (!token) return res.status(401).json({ error: "token_required" });
  next();
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const onlyDigits = v => String(v).replace(/\D/g, "");
const sanitizeSessionId = id => /^[a-zA-Z0-9_-]{1,50}$/.test(id) ? id : null;

async function createSession(sessionId) {
  if (sessions.has(sessionId)) return sessions.get(sessionId);
  while (locks.has(sessionId)) await sleep(100);
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  locks.add(sessionId);
  try {
    const authDir = path.join(DATA_DIR, sessionId);
    fs.mkdirSync(authDir, { recursive: true });
    const { state, saveCreds } = await useMultiFileAuthState(authDir);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: false,
      logger: log.child({ sessionId }),
      browser: ["Chrome (Linux)", "", ""],
      markOnlineOnConnect: true,
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

      if (qr && Date.now() - meta.lastQrAt > 1500) {
        meta.lastQrAt = Date.now();
        meta.lastQrDataUrl = await QRCode.toDataURL(qr);
        meta.status = "waiting_for_scan";
        log.info({ sessionId }, "QR gerado");
      }

      if (connection === "open") {
        meta.status = "connected";
        meta.connectedAt = Date.now();
        log.info({ sessionId }, "WhatsApp conectado!");
      }

      if (connection === "close") {
        const shouldReset = [DisconnectReason.loggedOut, 401].includes(lastDisconnect?.error?.output?.statusCode);
        log.warn({ sessionId }, "Conexão fechada");
        removeListeners(sock);
        sessions.delete(sessionId);
        if (shouldReset) fs.rmSync(authDir, { recursive: true, force: true });
        setTimeout(() => createSession(sessionId), shouldReset ? 3000 : 7000);
      }
    });

    // WEBHOOK AUTOMÁTICO: MENSAGENS RECEBIDAS → INBOX
    sock.ev.on("messages.upsert", async (m) => {
      const msg = m.messages[0];
      if (!msg.key || msg.key.fromMe || !msg.message) return;

      const from = msg.key.remoteJid.replace("@s.whatsapp.net", "");
      const text = 
        msg.message.conversation ||
        msg.message.extendedTextMessage?.text ||
        msg.message.imageMessage?.caption ||
        "[Mídia]";

      try {
        await fetch(BASE44_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tenantSlug: sessionId,
            phoneE164: from,
            text: text,
            timestamp: new Date(msg.messageTimestamp * 1000).toISOString(),
          }),
        });
        log.info({ from, sessionId }, "Mensagem recebida → inbox");
      } catch (err) {
        log.error({ err: err.message }, "Falha no webhook");
      }
    });

    return meta;
  } finally {
    locks.delete(sessionId);
  }
}

function removeListeners(sock) {
  sock?.ev?.removeAllListeners();
}

// ROTAS
app.get("/health", (_, res) => res.json({ ok: true }));

app.get("/sessions/:id/status", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid_id" });
  const meta = await createSession(id);
  res.json({
    connected: meta.status === "connected",
    status: meta.status,
    phone: meta.sock?.user?.id?.split(":")[0] || null,
  });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid_id" });
  const meta = await createSession(id);
  if (meta.status === "connected") return res.json({ connected: true });
  if (!meta.lastQrDataUrl) return res.json({ waiting: true });
  res.json({ qr: meta.lastQrDataUrl });
});

app.post("/sessions/:id/send", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid_id" });
  const meta = await createSession(id);
  if (meta.status !== "connected") return res.status(400).json({ error: "not_connected" });

  const { to, text } = req.body;
  if (!to || !text) return res.status(400).json({ error: "missing_data" });

  const jid = `${onlyDigits(to)}@s.whatsapp.net`;

  try {
    const result = await meta.sock.sendMessage(jid, { text: String(text) });
    res.json({ success: true, messageId: result.key.id });
  } catch (err) {
    res.status(500).json({ error: "send_failed" });
  }
});

app.post("/sessions/:id/reset", requireAuth, async (req, res) => {
  const id = sanitizeSessionId(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid_id" });

  const meta = sessions.get(id);
  if (meta?.sock) {
    removeListeners(meta.sock);
    try { await meta.sock.logout(); } catch {}
  }

  const authDir = path.join(DATA_DIR, id);
  fs.rmSync(authDir, { recursive: true, force: true });
  sessions.delete(id);

  setTimeout(() => createSession(id), 2000);
  res.json({ success: true });
});

app.listen(PORT, () => {
  log.info(`SERVIÇO RODANDO NA PORTA ${PORT}`);
  log.info(`WEBHOOK → ${BASE44_WEBHOOK_URL}`);
});
