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
const JWT_SECRET = process.env.JWT_SECRET || ""; // se vazio, auth off
const ADMIN_NOTIFY_TO = process.env.ADMIN_NOTIFY_TO || ""; // E.164
const QR_THROTTLE_MS = Number(process.env.QR_THROTTLE_MS || 1200);
const KEEPALIVE_MS = Number(process.env.KEEPALIVE_MS || 30000);

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
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

// ------------------ UTILS ----------------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function extractNumberFromJid(jid) {
  // ex.: "5511999999999@s.whatsapp.net" -> "5511999999999"
  const m = (jid || "").match(/^(\d{6,})@/);
  return m ? m[1] : null;
}

function toE164Digits(input) {
  // aceita "+55 11 999...","5511999...", "55-11-999..."
  if (!input) return null;
  const digits = String(input).replace(/[^\d]/g, "");
  return digits.length >= 6 ? digits : null;
}

// ------------------ STATE DE SESSÕES ----------------
const sessions = new Map();     // id -> meta
const sessionLocks = new Set();

async function notifyAdmin(meta, text) {
  try {
    meta.pendingNotices = meta.pendingNotices || [];
    if (!ADMIN_NOTIFY_TO) {
      log.info({ sessionId: meta.id, text }, "[notify] sem ADMIN_NOTIFY_TO");
      return;
    }
    if (meta.status !== "connected") {
      meta.pendingNotices.push(text);
      return;
    }
    await meta.sock.sendMessage(jidNormalizedUser(ADMIN_NOTIFY_TO), { text });
  } catch (e) {
    log.warn({ sessionId: meta.id, err: e?.message }, "notify failed");
    (meta.pendingNotices = meta.pendingNotices || []).push(text);
  }
}

async function flushNotices(meta) {
  if (!ADMIN_NOTIFY_TO || !meta?.sock) return;
  if (!meta.pendingNotices?.length || meta.status !== "connected") return;
  const to = jidNormalizedUser(ADMIN_NOTIFY_TO);
  for (const msg of meta.pendingNotices.splice(0)) {
    try {
      await meta.sock.sendMessage(to, { text: msg });
    } catch {
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

    sock.ev.on("creds.update", async () => {
      try { await saveCreds(); } catch (e) {
        log.error({ sessionId, err: e?.message }, "saveCreds failed");
      }
    });

    // keepalive adicional via presence
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

      // QR throttling e “congelar” após conectar
      if (qr && meta.status !== "connected") {
        const now = Date.now();
        if (now - meta.lastQrAt >= QR_THROTTLE_MS) {
          meta.lastQrAt = now;
          meta.lastQr = qr;
          try {
            meta.lastQrDataUrl = await QRCode.toDataURL(qr);
          } catch {
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
        const userJid = meta.sock?.user?.id || null;
        await notifyAdmin(meta, `🟢 [${sessionId}] Conectado como ${userJid || "?"}`);
        await flushNotices(meta);
      }

      if (connection === "close") {
        const code =
          lastDisconnect?.error?.output?.statusCode ??
          lastDisconnect?.error?.statusCode ??
          lastDisconnect?.statusCode;
        const errObj = lastDisconnect?.error;
        log.warn({ sessionId, code, err: String(errObj?.message || errObj) }, "connection closed");

        if (code === DisconnectReason.loggedOut || code === 401) {
          await notifyAdmin(meta, `🔴 [${sessionId}] Sessão removida (device_removed/loggedOut). Gere novo QR.`);
          try { await sock.logout(); } catch {}
          sessions.delete(sessionId);
          return;
        }

        if (code === DisconnectReason.restartRequired || code === 515) {
          await notifyAdmin(meta, `🟠 [${sessionId}] Reinício do socket (restartRequired/515).`);
        }

        try { sock.ev.removeAllListeners(); } catch {}
        try { sock.end?.(); } catch {}
        try { sock.ws?.close?.(); } catch {}

        meta.status = "reconnecting";
        meta.reconnectAttempts = (meta.reconnectAttempts || 0) + 1;
        const backoff = Math.min(30000, 2000 * meta.reconnectAttempts);
        log.info({ sessionId, backoff }, "scheduling reconnect");

        setTimeout(async () => {
          sessions.delete(sessionId);
          try { await getOrCreateSession(sessionId); } catch (e) {
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
  const userJid = meta.sock?.user?.id || null;
  res.json({
    sessionId: meta.id,
    status: meta.status,
    connected: meta.status === "connected",
    connectedAt: meta.connectedAt ?? null,
    userJid,
    userNumber: extractNumberFromJid(userJid), // <- front usa esse campo!
    hint: meta.status === "waiting_for_scan" ? "call /qr" : "no-qr",
  });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  if (meta.status === "connected") return res.json({ status: "connected" });
  if (!meta.lastQrDataUrl) return res.status(202).json({ status: meta.status || "starting" });
  return res.json({ status: meta.status || "waiting_for_scan", qr: meta.lastQrDataUrl });
});

// ------- ENVIO: aceita {to,text} ou {number,message} -------
app.post("/sessions/:id/send", requireAuth, async (req, res) => {
  const meta = await getOrCreateSession(req.params.id);
  if (meta.status !== "connected") return res.status(409).json({ error: "not_connected" });

  // compatibilidade:
  const toRaw = req.body?.to ?? req.body?.number;
  const text = req.body?.text ?? req.body?.message;

  if (!toRaw || !text) {
    return res.status(400).json({ error: "to/number and text/message are required" });
  }

  const digits = toE164Digits(toRaw);
  if (!digits) return res.status(400).json({ error: "invalid_phone" });

  try {
    const jid = jidNormalizedUser(digits);
    const r = await meta.sock.sendMessage(jid, { text });
    return res.json({ ok: true, id: r?.key?.id || null, to: digits });
  } catch (e) {
    log.error({ err: e?.message }, "send_error");
    return res.status(500).json({ ok: false, error: e?.message });
  }
});

// alias compatível: /messages (front antigo)
app.post("/sessions/:id/messages", requireAuth, async (req, res) => {
  req.url = req.url.replace("/messages", "/send");
  return app._router.handle(req, res);
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
  const meta = sessions.get(req.params.id);
  if (meta?.sock) try { await meta.sock.logout(); } catch {}
  sessions.delete(req.params.id);
  res.json({ ok: true });
});

// 404 handler p/ debug
app.use((req, res) => {
  log.warn({ method: req.method, url: req.originalUrl }, "route_not_found_404");
  res.status(404).json({ ok: false, error: "not_found" });
});

// ---------------------- START -----------------------
app.listen(PORT, () => {
  log.info(`✅ Baileys API listening on :${PORT}`);
});
