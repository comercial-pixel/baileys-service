// server.js — Baileys API (ESM) com:
// - QR “congelado” quando conecta (não regera à toa)
// - Notificação automática via WhatsApp do estado da sessão
// - Keep-alive, fila de notificações e endpoint de envio de mensagens
// - /health (além de /healthz)

import express from "express";
import QRCode from "qrcode";
import pino from "pino";
import jwt from "jsonwebtoken";
import {
  makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
  jidNormalizedUser,
} from "@whiskeysockets/baileys";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// ---------------------- CONFIG ----------------------
const app = express();
app.use(express.json());

// CORS simples
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const log = pino({ level: process.env.LOG_LEVEL || "info" });
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || "/data";

// se vazio, auth desabilitada
const JWT_SECRET = process.env.JWT_SECRET || "";

// E.164 para receber alertas de status (ex.: +5519999999999)
// se não setar, só loga no console
const ADMIN_NOTIFY_TO = process.env.ADMIN_NOTIFY_TO || "";

// throttling de QR para UI (ms)
const QR_THROTTLE_MS = Number(process.env.QR_THROTTLE_MS || 1200);

// ping periódico para manter sessão ativa (ms)
const KEEPALIVE_MS = Number(process.env.KEEPALIVE_MS || 30000);

// ----------------------------------------------
// __dirname (ESM)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------------------- AUTH ----------------------
function requireAuth(req, res, next) {
  if (!JWT_SECRET) return next();
  const authHeader = req.headers.authorization || "";
  const tokenFromHeader = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : null;
  const token = tokenFromHeader || req.query?.token || req.body?.token;
  if (!token) return res.status(401).json({ error: "missing_token" });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid_token" });
  }
}

// ------------------ STATE DE SESSÕES ----------------
const sessions = new Map();     // id -> meta
const sessionLocks = new Set();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function notifyAdmin(meta, text) {
  try {
    meta.pendingNotices = meta.pendingNotices || [];
    if (!ADMIN_NOTIFY_TO) {
      log.info({ sessionId: meta.id, text }, "[notify] (sem ADMIN_NOTIFY_TO)");
      return;
    }
    // se não está conectado, enfileira
    if (meta.status !== "connected") {
      meta.pendingNotices.push(text);
      return;
    }
    await meta.sock.sendMessage(jidNormalizedUser(ADMIN_NOTIFY_TO), {
      text,
    });
  } catch (e) {
    log.warn({ sessionId: meta.id, err: e?.message }, "notify failed; enqueue");
    (meta.pendingNotices = meta.pendingNotices || []).push(text);
  }
}

async function flushNotices(meta) {
  if (!ADMIN_NOTIFY_TO || !meta?.sock) return;
  if (!meta?.pendingNotices || !meta.pendingNotices.length) return;
  if (meta.status !== "connected") return;
  const to = jidNormalizedUser(ADMIN_NOTIFY_TO);
  for (const msg of meta.pendingNotices.splice(0)) {
    try {
      await meta.sock.sendMessage(to, { text: msg });
    } catch (e) {
      // se falhar, re-enfileira e para
      meta.pendingNotices.unshift(msg);
      break;
    }
  }
}

async function getOrCreateSession(sessionId) {
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  while (sessionLocks.has(sessionId)) await sleep(150);
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  sessionLocks.add(sessionId);
  try {
    const authDir = path.join(DATA_DIR, sessionId);
    fs.mkdirSync(authDir, { recursive: true });

    const { state, saveCreds } = await useMultiFileAuthState(authDir);

    // versão
    let version;
    try {
      ({ version } = await fetchLatestBaileysVersion());
    } catch {
      version = [2, 2310, 10];
    }

    const sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: false,
      logger: log,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      // ajuda a manter o socket “vivo”
      keepAliveIntervalMs: KEEPALIVE_MS,
      browser: ["Ubuntu", "Chrome", "22.04.4"],
    });

    const meta = {
      id: sessionId,
      sock,
      status: "starting",
      lastQr: null,
      lastQrDataUrl: null,
      lastQrAt: 0,
      connectedAt: null,
      reconnectAttempts: 0,
      pendingNotices: [],
      keepaliveTimer: null,
    };
    sessions.set(sessionId, meta);

    // persistir credenciais
    sock.ev.on("creds.update", async () => {
      try {
        await saveCreds();
      } catch (e) {
        log.error({ sessionId, err: e?.message }, "saveCreds failed");
      }
    });

    // keepalive “extra”: ping via presence (opcional)
    const startKeepAlive = () => {
      if (meta.keepaliveTimer) clearInterval(meta.keepaliveTimer);
      meta.keepaliveTimer = setInterval(async () => {
        try {
          if (meta.status === "connected") {
            await sock.presenceSubscribe(sock?.user?.id || "status@broadcast").catch(() => {});
          }
        } catch {}
      }, KEEPALIVE_MS);
    };
    startKeepAlive();

    sock.ev.on("connection.update", async (update) => {
      const { connection, lastDisconnect, qr } = update || {};

      // QR: só atualiza se AINDA NÃO estiver conectado e com throttle
      if (qr && meta.status !== "connected") {
        const now = Date.now();
        if (now - meta.lastQrAt >= QR_THROTTLE_MS) {
          meta.lastQrAt = now;
          meta.lastQr = qr;
          try {
            meta.lastQrDataUrl = await QRCode.toDataURL(qr);
          } catch (e) {
            log.error({ sessionId, err: e?.message }, "QR encode error");
            meta.lastQrDataUrl = null;
          }
          meta.status = "waiting_for_scan";
          meta.reconnectAttempts = 0;
          log.info({ sessionId }, "QR updated");
          await notifyAdmin(meta, `🟡 [${sessionId}] Aguardando scan do QR code.`);
        }
      }

      if (connection === "open") {
        meta.status = "connected";
        meta.connectedAt = Date.now();
        meta.lastQr = null;
        meta.lastQrDataUrl = null;
        meta.reconnectAttempts = 0;

        log.info({ sessionId }, "Session connected");
        await notifyAdmin(
          meta,
          `🟢 [${sessionId}] Conectado como ${sock?.user?.name || "bot"} (${sock?.user?.id || "?"}).`
        );
        await flushNotices(meta);
      }

      if (connection === "close") {
        const code =
          lastDisconnect?.error?.output?.statusCode ??
          lastDisconnect?.error?.statusCode ??
          lastDisconnect?.statusCode;
        const errObj = lastDisconnect?.error;
        log.warn(
          { sessionId, code, err: String(errObj?.message || errObj) },
          "connection closed"
        );

        // mensagens específicas
        if (code === DisconnectReason.loggedOut || code === 401) {
          await notifyAdmin(meta, `🔴 [${sessionId}] Sessão removida pelo WhatsApp (loggedOut/device_removed). Gere novo QR.`);
          try { await sock.logout(); } catch {}
          sessions.delete(sessionId);
          return;
        }
        if (code === DisconnectReason.restartRequired || code === 515) {
          // 515 é esperado após pairing; reconectar
          await notifyAdmin(meta, `🟠 [${sessionId}] Reinício do socket (restartRequired/515).`);
        }

        // cleanup
        try { sock.ev.removeAllListeners(); } catch {}
        try { if (typeof sock.end === "function") sock.end(); } catch {}
        try { if (sock.ws && typeof sock.ws.close === "function") sock.ws.close(); } catch {}

        meta.status = "reconnecting";
        meta.reconnectAttempts = (meta.reconnectAttempts || 0) + 1;
        const backoff = Math.min(30000, 2000 * meta.reconnectAttempts);
        log.info({ sessionId, attempt: meta.reconnectAttempts, backoff }, "scheduling reconnect");

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

    return meta;
  } finally {
    sessionLocks.delete(sessionId);
  }
}

// ------------------ HEALTH / INFO -------------------
app.get("/", (_req, res) => res.json({ ok: true, service: "baileys-api" }));
app.get("/healthz", (_req, res) => res.json({ ok: true, t: Date.now() }));
app.get("/health", (_req, res) => res.json({ ok: true, t: Date.now() }));

app.get("/version", (_req, res) => {
  res.json({
    ok: true,
    port: PORT,
    dataDir: DATA_DIR,
    auth: Boolean(JWT_SECRET),
    adminNotifyTo: ADMIN_NOTIFY_TO || null,
  });
});

// ------------------- ROTAS PROTEGIDAS ----------------
app.get("/sessions/:id/status", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  res.json({
    sessionId: meta.id,
    status: meta.status,
    connected: meta.status === "connected",
    connectedAt: meta.connectedAt ?? null,
    user: meta.sock?.user || null,
    hint: meta.status === "waiting_for_scan" ? "call /qr" : "no-qr",
  });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  if (meta.status === "connected") return res.json({ status: "connected" });
  if (!meta.lastQrDataUrl)
    return res.status(202).json({ status: meta.status || "starting" });

  return res.json({
    status: meta.status || "waiting_for_scan",
    qr: meta.lastQrDataUrl,
  });
});

// enviar mensagem
app.post("/sessions/:id/send", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  const { to, text } = req.body || {};
  if (!to || !text) return res.status(400).json({ error: "to and text are required" });
  if (meta.status !== "connected") return res.status(409).json({ error: "not_connected" });

  try {
    const jid = jidNormalizedUser(to);
    const r = await meta.sock.sendMessage(jid, { text });
    return res.json({ ok: true, id: r?.key?.id || null });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message });
  }
});

// reset total (apaga credenciais)
app.post("/sessions/:id/reset", requireAuth, async (req, res) => {
  const sessionId = req.params.id;
  try {
    const meta = sessions.get(sessionId);
    if (meta?.sock) try { await meta.sock.logout(); } catch {}
    sessions.delete(sessionId);
    const authDir = path.join(DATA_DIR, sessionId);
    try { fs.rmSync(authDir, { recursive: true, force: true }); } catch {}
    await sleep(300);
    const fresh = await getOrCreateSession(sessionId);
    return res.json({ ok: true, status: fresh.status || "starting" });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message });
  }
});

// desconectar sem apagar credenciais
app.post("/sessions/:id/disconnect", requireAuth, async (req, res) => {
  const sessionId = req.params.id;
  const meta = sessions.get(sessionId);
  if (meta?.sock) try { await meta.sock.logout(); } catch {}
  sessions.delete(sessionId);
  return res.json({ ok: true });
});

// ---------------------- START -----------------------
app.listen(PORT, () => {
  log.info(`Baileys API listening on :${PORT}`);
});
