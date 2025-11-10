// server.js — Baileys API (ESM)
// - QR “congelado” quando conecta (não regera à toa)
// - Notificação automática via WhatsApp do estado da sessão
// - Keep-alive e fila de notificações
// - Endpoint /send e alias /messages
// - Health checks (/health e /healthz)

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
const JWT_SECRET = process.env.JWT_SECRET || ""; // se vazio, desativa auth
const ADMIN_NOTIFY_TO = process.env.ADMIN_NOTIFY_TO || "";
const QR_THROTTLE_MS = Number(process.env.QR_THROTTLE_MS || 1200);
const KEEPALIVE_MS = Number(process.env.KEEPALIVE_MS || 30000);

// Suporte a __dirname em ESM
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
    if (meta.status !== "connected") {
      meta.pendingNotices.push(text);
      return;
    }
    await meta.sock.sendMessage(jidNormalizedUser(ADMIN_NOTIFY_TO), { text });
  } catch (e) {
    log.warn({ sessionId: meta.id, err: e?.message }, "notify failed; enqueue");
    (meta.pendingNotices = meta.pendingNotices || []).push(text);
  }
}

async function flushNotices(meta) {
  if (!ADMIN_NOTIFY_TO || !meta?.sock) return;
  if (!meta?.pendingNotices?.length || meta.status !== "connected") return
