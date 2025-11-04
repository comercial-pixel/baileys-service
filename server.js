// server.js
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

// =====================
// Configuração básica
// =====================
const app = express();
app.use(express.json({ limit: "2mb" }));

// CORS simples (ajuste o domínio se quiser limitar)
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

try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (e) {
  // em alguns ambientes /data já existe e é somente leitura
  log.warn({ err: e?.message }, "Não foi possível garantir DATA_DIR");
}

// =====================
// Autenticação flexível
//   - aceita segredo simples OU JWT
//   - lê de Authorization, query ?token= ou body.token
// =====================
function looksLikeJwt(str) {
  return typeof str === "string" && str.split(".").length === 3;
}

function requireAuth(req, res, next) {
  if (!JWT_SECRET) return next(); // se não houver segredo, desliga auth

  const hdr = req.headers.authorization || "";
  const tokenFromHeader = hdr.startsWith("Bearer ")
    ? hdr.slice(7).trim()
    : null;
  const tokenFromQuery = req.query.token;
  const tokenFromBody = req.body?.token;
  const token = tokenFromHeader || tokenFromQuery || tokenFromBody;

  if (!token) {
    log.warn("[Auth] ❌ missing_token");
    return res.status(401).json({ error: "missing_token" });
  }

  try {
    if (looksLikeJwt(token)) {
      jwt.verify(token, JWT_SECRET);
    } else {
      if (token !== JWT_SECRET) throw new Error("secret_mismatch");
    }
    log.info("[Auth] ✅ token OK");
    next();
  } catch (e) {
    log.error({ err: e?.message }, "[Auth] ❌ invalid_token");
    return res.status(401).json({ error: "invalid_token" });
  }
}

// =====================
// Gerenciamento de sessões Baileys
// =====================
const sessions = new Map(); // sessionId -> meta { sock, status, lastQr, connectedAt }

async function getOrCreateSession(sessionId) {
  if (sessions.has(sessionId)) return sessions.get(sessionId);

  const authDir = path.join(DATA_DIR, sessionId);
  fs.mkdirSync(authDir, { recursive: true });

  const { state, saveCreds } = await useMultiFileAuthState(authDir);
  const { version } = await fetchLatestBaileysVersion();

  const sock = makeWASocket({
    version,
    auth: state,
    printQRInTerminal: false,
    logger: pino({ level: "warn" }),
  });

  const meta = { sock, status: "starting", lastQr: null, connectedAt: null };
  sessions.set(sessionId, meta);

  sock.ev.on("creds.update", saveCreds);

  sock.ev.on("connection.update", (u) => {
    const { connection, lastDisconnect, qr } = u || {};

    if (qr) {
      meta.lastQr = qr;
      meta.status = "qr";
      log.info({ sessionId }, "QR atualizado");
    }

    if (connection === "open") {
      meta.status = "connected";
      meta.connectedAt = Date.now();
      meta.lastQr = null;
      log.info({ sessionId }, "Sessão conectada");
    }

    if (connection === "close") {
      const code = lastDisconnect?.error?.output?.statusCode;
      const shouldReconnect = code !== DisconnectReason.loggedOut;
      if (shouldReconnect) {
        meta.status = "reconnecting";
        log.warn({ sessionId, code }, "Conexão fechada, tentando reconectar...");
        setTimeout(() => getOrCreateSession(sessionId).catch(() => {}), 1500);
      } else {
        log.warn({ sessionId, code }, "Sessão deslogada, limpando credenciais");
        try {
          fs.rmSync(authDir, { recursive: true, force: true });
        } catch {}
        sessions.delete(sessionId);
      }
    }
  });

  return meta;
}

// =====================
// Rotas
// =====================
app.get("/healthz", (req, res) => res.json({ ok: true, t: Date.now() }));

app.get("/sessions/:id/status", requireAuth, (req, res) => {
  const meta = sessions.get(req.params.id);
  res.json({
    status: meta?.status ?? "not_initialized",
    connectedAt: meta?.connectedAt ?? null,
  });
});

app.get("/sessions/:id/qr", requireAuth, async (req, res) => {
  log.info({ path: req.path, id: req.params.id }, "GET QR");
  const meta = await getOrCreateSession(req.params.id);

  if (meta.status === "connected") {
    return res.json({ status: "connected" });
  }
  if (!meta.lastQr) {
    return res.status(202).json({ status: meta.status ?? "starting" });
  }
  const dataUrl = await QRCode.toDataURL(meta.lastQr);
  res.json({ status: meta.status, dataUrl });
});

app.post("/sessions/:id/messages", requireAuth, async (req, res) => {
  const { to, text } = req.body || {};
  const meta = sessions.get(req.params.id);
  if (!meta || meta.status !== "connected") {
    return res.status(409).json({ error: "session_not_connected" });
  }
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

// =====================
// Inicialização
// =====================
process.on("uncaughtException", (e) => log.error(e, "uncaughtException"));
process.on("unhandledRejection", (e) => log.error(e, "unhandledRejection"));

app.listen(PORT, () => {
  log.info({
    PORT,
    DATA_DIR,
    AUTH_ENABLED: !!JWT_SECRET,
  }, "Baileys API listening");
});
