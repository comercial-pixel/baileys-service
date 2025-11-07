// server.js — Baileys API (ESM)

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

// CORS simples (ajuste o domínio se desejar)
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
const JWT_SECRET = process.env.JWT_SECRET || ""; // se vazio, autenticação desabilitada

// Suporte __dirname em ESM (se precisar para logs/paths)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

fs.mkdirSync(DATA_DIR, { recursive: true });

// ----------------------------------------------------
// AUTENTICAÇÃO (JWT no header Authorization, ?token= ou body.token)
// ----------------------------------------------------
function requireAuth(req, res, next) {
  if (!JWT_SECRET) return next(); // auth desabilitada se não houver segredo

  const authHeader = req.headers.authorization || "";
  const tokenFromHeader = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : null;

  const tokenFromQuery = req.query?.token;
  const tokenFromBody = req.body?.token;

  const token = tokenFromHeader || tokenFromQuery || tokenFromBody;

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
// GERENCIAMENTO DE SESSÕES (cache de QR + trava anti corrida)
// ----------------------------------------------------
const sessions = new Map();     // sessionId -> meta
const sessionLocks = new Set(); // evita corrida na criação simultânea

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function getOrCreateSession(sessionId) {
  // Retorna se já existir
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  // Espera se outra chamada estiver criando
  while (sessionLocks.has(sessionId)) {
    await sleep(150);
  }
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  // Criação com lock
  sessionLocks.add(sessionId);
  try {
    const authDir = path.join(DATA_DIR, sessionId);
    fs.mkdirSync(authDir, { recursive: true });

    const { state, saveCreds } = await useMultiFileAuthState(authDir);

    // Busca versão do baileys com fallback
    let version;
    try {
      ({ version } = await fetchLatestBaileysVersion());
    } catch (e) {
      log.warn({ sessionId, err: e?.message }, "fetchLatestBaileysVersion failed, using fallback");
      // fallback razoável (ajuste se desejar)
      version = [2, 2310, 10];
    }

    const sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: false,
      logger: log,
      // keepAliveIntervalMs: 30000, // opcional
    });

    const meta = {
      sock,
      status: "starting",
      lastQr: null,        // QR “puro” vindo do Baileys
      lastQrDataUrl: null, // DataURL PNG cacheado
      connectedAt: null,
      reconnectAttempts: 0,
    };
    sessions.set(sessionId, meta);

    // Garantir persistência segura de credenciais
    sock.ev.on("creds.update", async () => {
      try {
        await saveCreds();
      } catch (e) {
        log.error({ sessionId, err: e?.message }, "saveCreds failed");
      }
    });

    sock.ev.on("connection.update", async (update) => {
      const { connection, lastDisconnect, qr } = update || {};

      if (qr) {
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
      }

      if (connection === "open") {
        meta.status = "connected";
        meta.connectedAt = Date.now();
        meta.lastQr = null;
        meta.lastQrDataUrl = null;
        meta.reconnectAttempts = 0;
        log.info({ sessionId }, "Session connected");
      }

      if (connection === "close") {
        const code = lastDisconnect?.error?.output?.statusCode ?? lastDisconnect?.error?.statusCode;
        const errObj = lastDisconnect?.error;
        log.warn({ sessionId, code, err: String(errObj?.message || errObj) }, "connection closed");

        // Decide se reconectar
        const shouldReconnect = code !== DisconnectReason.loggedOut &&
                                code !== DisconnectReason.badSession &&
                                code !== DisconnectReason.restartRequired;

        // Se for logout explícito ou bad session, limpamos
        if (code === DisconnectReason.loggedOut || code === DisconnectReason.badSession) {
          try { await sock.logout(); } catch {}
          sessions.delete(sessionId);
          log.warn({ sessionId, code }, "Logged out or bad session, session cleared");
          return;
        }

        // Preparar reconexão controlada
        meta.status = "reconnecting";
        meta.reconnectAttempts = (meta.reconnectAttempts || 0) + 1;
        const backoff = Math.min(30000, 2000 * meta.reconnectAttempts);
        log.info({ sessionId, attempt: meta.reconnectAttempts, backoff }, "scheduling reconnect");

        // cleanup da instância antiga: remove listeners e fecha conexões subjacentes
        try {
          sock.ev.removeAllListeners();
        } catch (e) {
          log.debug({ sessionId, err: e?.message }, "removeAllListeners failed");
        }
        try {
          // Alguns sockets expõem end/close/ws; usamos try/catch para tolerância
          if (typeof sock.end === "function") sock.end();
          if (sock.ws && typeof sock.ws.close === "function") sock.ws.close();
        } catch (e) {
          log.debug({ sessionId, err: e?.message }, "socket close/end failed");
        }

        // Delay antes de recriar; garanta que a sessão antiga foi removida do mapa
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

// ----------------------------------------------------
// HEALTH / INFO
// ----------------------------------------------------
app.get("/healthz", (_req, res) => res.json({ ok: true, t: Date.now() }));

app.get("/version", (_req, res) => {
  res.json({
    ok: true,
    port: PORT,
    dataDir: DATA_DIR,
    auth: Boolean(JWT_SECRET),
    note:
      "Se auth=true, o token pode vir via header Authorization, query ?token= ou body.token",
  });
});

// ----------------------------------------------------
// ROTAS PROTEGIDAS (status, qr, reset)
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

  if (meta.status === "connected") {
    return res.json({ status: "connected" });
  }

  if (!meta.lastQrDataUrl) {
    return res.status(202).json({ status: meta.status || "starting" });
  }

  return res.json({
    status: meta.status || "waiting_for_scan",
    qr: meta.lastQrDataUrl,
  });
});

// Reset manual da sessão (apaga credenciais e recomeça do zero)
app.post("/sessions/:id/reset", requireAuth, async (req, res) => {
  const sessionId = req.params.id;
  try {
    const meta = sessions.get(sessionId);
    if (meta?.sock) {
      try {
        await meta.sock.logout();
      } catch {}
    }
    sessions.delete(sessionId);

    // Apaga diretório de credenciais
    const authDir = path.join(DATA_DIR, sessionId);
    try {
      fs.rmSync(authDir, { recursive: true, force: true });
    } catch {}

    // Reabre a sessão do zero
    await sleep(300);
    const fresh = await getOrCreateSession(sessionId);
    return res.json({ ok: true, status: fresh.status || "starting" });
  } catch (e) {
    log.error({ err: e?.message }, "reset error");
    return res.status(500).json({ ok: false, error: e?.message });
  }
});

// (Opcional) Desconectar sem apagar credenciais
app.post("/sessions/:id/disconnect", requireAuth, async (req, res) => {
  const sessionId = req.params.id;
  const meta = sessions.get(sessionId);
  if (meta?.sock) {
    try {
      await meta.sock.logout();
    } catch {}
  }
  sessions.delete(sessionId);
  return res.json({ ok: true });
});

// ----------------------------------------------------
// START
// ----------------------------------------------------
app.listen(PORT, () => {
  log.info(`Baileys API listening on :${PORT}`);
});
