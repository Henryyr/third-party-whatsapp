/* eslint-disable no-console */
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const STARSENDER_BASE = "https://api.starsender.online";
const WEBHOOK_TOKEN = process.env.WEBHOOK_TOKEN || "";
const WABLAS_BASE = process.env.WABLAS_BASE || "https://jkt.wablas.com";
const WABLAS_PHONE_BASE =
  process.env.WABLAS_PHONE_BASE || "https://phone.wablas.com";
const TELEGRAM_BASE =
  process.env.TELEGRAM_BASE || "https://telecore.mywifi.web.id/api/telegram";

function parseArgs(argv) {
  const args = {
    host: "127.0.0.1",
    port: 3000,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--help" || a === "-h" || a === "--usage") {
      args.help = true;
      continue;
    }
    if (a === "--host") {
      args.host = argv[i + 1] || args.host;
      i += 1;
      continue;
    }
    if (a === "--port" || a === "-p") {
      const v = Number.parseInt(argv[i + 1] || "", 10);
      if (Number.isFinite(v) && v > 0) args.port = v;
      i += 1;
      continue;
    }
  }

  return args;
}

function printUsage() {
  console.log("Usage:");
  console.log("  node main.js --port 3000");
  console.log("  node main.js --host 0.0.0.0 --port 3000");
  console.log("");
  console.log("Options:");
  console.log("  --port, -p   Port (default 3000)");
  console.log("  --host       Host (default 127.0.0.1)");
  console.log("  --help       Show this help");
}

function contentTypeFor(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".html") return "text/html; charset=utf-8";
  if (ext === ".css") return "text/css; charset=utf-8";
  if (ext === ".js") return "text/javascript; charset=utf-8";
  if (ext === ".json") return "application/json; charset=utf-8";
  return "application/octet-stream";
}

function sendJson(res, statusCode, payload, extraHeaders) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...(extraHeaders || {}),
  });
  res.end(body);
}

function setCors(req, res) {
  const origin = req.headers.origin;
  res.setHeader("Access-Control-Allow-Origin", origin || "*");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Vendor, X-API-KEY, X-API-SECRET, Authorization",
  );
  res.setHeader("Access-Control-Max-Age", "600");
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function safeJsonParse(text) {
  const raw = String(text || "").trim();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function wablasAuthHint(apiKey, secretKey) {
  const token = String(apiKey || "").trim();
  const secret = String(secretKey || "").trim();
  if (!token) return "API Key harus diisi token device (tanpa titik).";
  if (token.includes(".")) {
    return "API Key untuk Wablas harus token saja (jangan token.secret). Isi Secret Key terpisah.";
  }
  if (!secret)
    return "Secret Key harus diisi (hasil generate secret key di device settings).";
  if (secret.includes(".")) {
    return "Secret Key harus secret saja (tanpa token.).";
  }
  return null;
}

function isWablasCredsError(parsedBody, upstreamStatus) {
  const body = parsedBody && typeof parsedBody === "object" ? parsedBody : null;
  const msg = body && typeof body.message === "string" ? body.message : "";
  const normalized = msg.toLowerCase();
  if (upstreamStatus === 401 || upstreamStatus === 403) return true;
  if (!msg) return false;
  if (normalized.includes("secret key invalid")) return true;
  if (normalized.includes("token invalid")) return true;
  if (normalized.includes("invalid token")) return true;
  if (normalized.includes("unauthorized")) return true;
  return false;
}

function getVendor(req, body) {
  const fromHeader = String(req.headers["x-vendor"] || "").trim();
  const fromBody =
    body && typeof body === "object" ? String(body.vendor || "") : "";
  const vendor = (fromHeader || fromBody || "").toLowerCase();
  if (!vendor) return "";
  if (vendor === "starseeder") return "starsender";
  if (vendor === "starsender") return "starsender";
  if (vendor === "telegram") return "telegram";
  return vendor;
}

function getApiKey(req, body) {
  const headerKey = String(req.headers["x-api-key"] || "").trim();
  const auth = String(req.headers.authorization || "").trim();
  const bodyKey =
    body && typeof body === "object"
      ? String(body.apiKey || body.api_key || "")
      : "";
  return (
    headerKey ||
    (auth.startsWith("Bearer ") ? auth.slice(7) : auth) ||
    bodyKey ||
    ""
  );
}

function getApiSecret(req, body) {
  const headerSecret = String(req.headers["x-api-secret"] || "").trim();
  const rootSecret =
    body && typeof body === "object"
      ? String(body.secretKey || body.secret_key || "").trim()
      : "";
  const payloadSecret =
    body &&
    typeof body === "object" &&
    body.payload &&
    typeof body.payload === "object"
      ? String(body.payload.secretKey || body.payload.secret_key || "").trim()
      : "";
  return headerSecret || payloadSecret || rootSecret || "";
}

function normalizeStarsenderNumber(raw) {
  const text = String(raw || "").trim();
  if (!text) return "";
  const cleaned = text.replace(/[^\d+]/g, "");
  const withoutPlus = cleaned.startsWith("+") ? cleaned.slice(1) : cleaned;
  const digits = withoutPlus.replace(/\D/g, "");
  return digits;
}

function normalizeIndoMsisdnDigits(raw) {
  const digits = normalizeStarsenderNumber(raw);
  if (!digits) return "";
  if (digits.startsWith("62")) return digits;
  if (digits.startsWith("0")) return `62${digits.slice(1)}`;
  if (digits.startsWith("8")) return `62${digits}`;
  return digits;
}

function parseTelegramTarget(raw) {
  const text = String(raw || "").trim();
  if (!text) return null;

  if (text.startsWith("@")) {
    const username = text.slice(1).trim();
    if (!username) return null;
    return { kind: "username", value: username };
  }

  if (/^-?\d{6,}$/.test(text) && text.startsWith("-")) {
    return { kind: "chatId", value: text };
  }

  if (/^[A-Za-z][A-Za-z0-9_]{3,}$/.test(text)) {
    return { kind: "username", value: text };
  }

  if (/^[+\d][\d+\s().-]*$/.test(text)) {
    const phone = normalizeIndoMsisdnDigits(text);
    if (!phone) return null;
    return { kind: "phone", value: phone };
  }

  if (/^-?\d+$/.test(text)) {
    return text.startsWith("-")
      ? { kind: "chatId", value: text }
      : { kind: "phone", value: normalizeIndoMsisdnDigits(text) };
  }

  return null;
}

function pickFirstString(obj, keys) {
  if (!obj || typeof obj !== "object") return "";
  for (const k of keys) {
    if (typeof obj[k] === "string" && obj[k].trim()) return obj[k].trim();
  }
  return "";
}

function extractInbound(body) {
  const root = body && typeof body === "object" ? body : {};
  const data = root.data && typeof root.data === "object" ? root.data : {};

  const message =
    pickFirstString(root, ["message", "text", "body", "caption"]) ||
    pickFirstString(data, ["message", "text", "body", "caption"]);

  const fromRaw =
    pickFirstString(root, [
      "from",
      "sender",
      "number",
      "phone",
      "remoteJid",
      "chatId",
    ]) ||
    pickFirstString(data, [
      "from",
      "sender",
      "number",
      "phone",
      "remoteJid",
      "chatId",
    ]);

  return { message, fromRaw };
}

function extractWablasInbound(body) {
  const root = body && typeof body === "object" ? body : {};
  const message = pickFirstString(root, ["message", "text", "body", "caption"]);
  // Wablas webhook: `phone` = sender/customer, `sender` = device number.
  const fromRaw = pickFirstString(root, ["phone", "from", "number"]);
  return { message, fromRaw };
}

function parseConfirmReply(text) {
  const t = String(text || "").trim();
  // Accept "YA" only (no code), and also accept legacy "YA KODE".
  const ok = t.match(/^(YA|YES|Y)\b(?:\s+([A-Z0-9]{4,12}))?/i);
  if (ok) return { action: "confirm", code: ok[2] ? ok[2].toUpperCase() : "" };
  const no = t.match(/^(TIDAK|NO|N|BATAL|CANCEL)\b(?:\s+([A-Z0-9]{4,12}))?/i);
  if (no) return { action: "cancel", code: no[2] ? no[2].toUpperCase() : "" };
  return null;
}

async function starsenderCheckNumber(apiKey, number) {
  const url = `${STARSENDER_BASE}/api/check-number`;
  const payload = { number };
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: apiKey,
    },
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text };
}

async function starsenderSend(apiKey, to, bodyText, scheduleMs) {
  const url = `${STARSENDER_BASE}/api/send`;
  const payload = {
    messageType: "text",
    to,
    body: bodyText,
  };
  if (Number.isFinite(scheduleMs)) payload.schedule = scheduleMs;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: apiKey,
    },
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text };
}

async function wablasCheckPhone(token, phones) {
  const url = `${WABLAS_PHONE_BASE}/check-phone-number?phones=${encodeURIComponent(phones)}`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: token,
      url: WABLAS_BASE,
    },
  });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text };
}

async function wablasDeviceInfo(token) {
  const url = `${WABLAS_BASE}/api/device/info?token=${encodeURIComponent(token)}`;
  const res = await fetch(url, { method: "GET" });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text };
}

async function wablasListServer(token, secretKey) {
  const auth = wablasAuthHeader(token, secretKey);
  const url = `${WABLAS_BASE}/api/list-server?token=${encodeURIComponent(auth)}`;
  const res = await fetch(url, { method: "GET" });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text };
}

function wablasAuthHeader(token, secretKey) {
  const t = String(token || "").trim();
  const s = String(secretKey || "").trim();
  return `${t}.${s}`;
}

async function wablasSendText(token, secretKey, phone62Digits, message) {
  const url = `${WABLAS_BASE}/api/v2/send-message`;
  const payload = {
    data: [
      {
        phone: phone62Digits,
        message: String(message || ""),
      },
    ],
  };
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: wablasAuthHeader(token, secretKey),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text };
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function formatWablasScheduledAtFromLocal(local) {
  const v = String(local || "").trim();
  const m = v.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})$/);
  if (!m) return "";
  return `${m[1]} ${m[2]}:00`;
}

function formatWablasScheduledAtFromMs(epochMs) {
  const d = new Date(Number(epochMs));
  if (!Number.isFinite(d.getTime())) return "";
  const yyyy = d.getFullYear();
  const mm = pad2(d.getMonth() + 1);
  const dd = pad2(d.getDate());
  const hh = pad2(d.getHours());
  const mi = pad2(d.getMinutes());
  const ss = pad2(d.getSeconds());
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

async function wablasScheduleText(
  token,
  secretKey,
  phone62Digits,
  message,
  scheduledAt,
) {
  const url = `${WABLAS_BASE}/api/v2/schedule`;
  const payload = {
    data: [
      {
        category: "text",
        phone: phone62Digits,
        scheduled_at: scheduledAt,
        text: String(message || ""),
      },
    ],
  };
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: wablasAuthHeader(token, secretKey),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text };
}

async function telegramSendText(apiToken, sessionId, recipient, message) {
  const token = String(apiToken || "").trim();
  const sid = String(sessionId || "").trim();
  if (!token) throw new Error("missing x-api-token");
  if (!sid) throw new Error("missing sessionId");
  if (!recipient || !recipient.kind || !recipient.value) {
    throw new Error("invalid telegram recipient");
  }

  const endpoint =
    recipient.kind === "chatId" ? "/messages/send" : "/messages/send-to-phone";
  const body =
    recipient.kind === "chatId"
      ? {
          sessionId: sid,
          chatId: recipient.value,
          text: String(message || ""),
        }
      : {
          sessionId: sid,
          text: String(message || ""),
          ...(recipient.kind === "username"
            ? { username: recipient.value }
            : { phone: recipient.value }),
        };

  const res = await fetch(`${TELEGRAM_BASE}${endpoint}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-token": token,
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text };
}

const LIMITS = {
  minIntervalMs: Number.parseInt(process.env.MIN_INTERVAL_MS || "1500", 10),
  maxPerMinute: Number.parseInt(process.env.MAX_PER_MINUTE || "15", 10),
  perRecipientCooldownMs: Number.parseInt(
    process.env.PER_RECIPIENT_COOLDOWN_MS || "60000",
    10,
  ),
};

const rateState = new Map();

function getRateBucket(apiKey) {
  let bucket = rateState.get(apiKey);
  if (!bucket) {
    bucket = {
      windowStartMs: Date.now(),
      windowCount: 0,
      lastSentAtMs: 0,
      recipientLastSent: new Map(),
    };
    rateState.set(apiKey, bucket);
  }
  return bucket;
}

function rateLimitCheck(apiKey, recipientKey) {
  const now = Date.now();
  const bucket = getRateBucket(apiKey);

  if (now - bucket.windowStartMs >= 60_000) {
    bucket.windowStartMs = now;
    bucket.windowCount = 0;
  }

  if (bucket.lastSentAtMs && now - bucket.lastSentAtMs < LIMITS.minIntervalMs) {
    return {
      ok: false,
      kind: "min_interval",
      retryAfterMs: LIMITS.minIntervalMs - (now - bucket.lastSentAtMs),
    };
  }

  if (bucket.windowCount >= LIMITS.maxPerMinute) {
    return {
      ok: false,
      kind: "per_minute",
      retryAfterMs: 60_000 - (now - bucket.windowStartMs),
    };
  }

  if (recipientKey) {
    const last = bucket.recipientLastSent.get(recipientKey) || 0;
    if (last && now - last < LIMITS.perRecipientCooldownMs) {
      return {
        ok: false,
        kind: "per_recipient",
        retryAfterMs: LIMITS.perRecipientCooldownMs - (now - last),
      };
    }
  }

  return { ok: true };
}

function rateLimitCommit(apiKey, recipientKey) {
  const now = Date.now();
  const bucket = getRateBucket(apiKey);
  bucket.lastSentAtMs = now;
  bucket.windowCount += 1;
  if (recipientKey) bucket.recipientLastSent.set(recipientKey, now);
}

const STORE_PATH = path.join(__dirname, "tpwa-store.json");

function loadStore() {
  try {
    const raw = fs.readFileSync(STORE_PATH, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") {
      return { pending: [], scheduled: [] };
    }
    return {
      pending: Array.isArray(parsed.pending) ? parsed.pending : [],
      scheduled: Array.isArray(parsed.scheduled) ? parsed.scheduled : [],
    };
  } catch {
    return { pending: [], scheduled: [] };
  }
}

function saveStore(store) {
  try {
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
    return true;
  } catch {
    return false;
  }
}

function generateId() {
  return crypto.randomBytes(12).toString("hex");
}

function generateCode() {
  // Easy to type in WhatsApp.
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  const bytes = crypto.randomBytes(6);
  for (let i = 0; i < bytes.length; i += 1) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

function normalizeDigits(raw) {
  const digits = String(raw || "").replace(/\D/g, "");
  return digits;
}

function findPending(store, vendor, toDigits, code) {
  const now = Date.now();
  for (const item of store.pending) {
    if (!item || typeof item !== "object") continue;
    if (vendor && item.vendor !== vendor) continue;
    if (item.status !== "pending") continue;
    if (code && item.code !== code) continue;
    if (item.toDigits !== toDigits) continue;
    if (Number.isFinite(item.expiresAtMs) && now > item.expiresAtMs) {
      item.status = "expired";
      item.expiredAtMs = now;
      continue;
    }
    return item;
  }
  return null;
}

function findLatestPending(store, vendor, toDigits) {
  const now = Date.now();
  let best = null;
  for (const item of store.pending) {
    if (!item || typeof item !== "object") continue;
    if (vendor && item.vendor !== vendor) continue;
    if (item.status !== "pending") continue;
    if (item.toDigits !== toDigits) continue;
    if (Number.isFinite(item.expiresAtMs) && now > item.expiresAtMs) {
      item.status = "expired";
      item.expiredAtMs = now;
      continue;
    }
    if (!best) {
      best = item;
      continue;
    }
    const a = Number(item.createdAtMs || 0);
    const b = Number(best.createdAtMs || 0);
    if (a > b) best = item;
  }
  return best;
}

function serveFile(res, filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    res.writeHead(200, {
      "Content-Type": contentTypeFor(filePath),
      "Cache-Control": "no-store",
    });
    res.end(buf);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
}

function getScheduleMs(body) {
  const scheduleAt = body && typeof body === "object" ? body.scheduleAt : null;
  if (
    scheduleAt &&
    typeof scheduleAt === "object" &&
    Number.isFinite(scheduleAt.epochMs)
  ) {
    return Number(scheduleAt.epochMs);
  }
  if (Number.isFinite(scheduleAt)) return Number(scheduleAt);
  return null;
}

const args = parseArgs(process.argv);
if (args.help) {
  printUsage();
  process.exit(0);
}

const store = loadStore();

const ROOT = __dirname;
const PATH_INDEX = path.join(ROOT, "index.html");
const PATH_CSS = path.join(ROOT, "style.css");
const PATH_APP = path.join(ROOT, "app.js");

function maskSecret(value) {
  const v = String(value || "");
  if (!v) return "";
  if (v.length <= 6) return "*".repeat(v.length);
  return `${v.slice(0, 3)}***${v.slice(-3)}`;
}

function redactPendingForApi(item) {
  if (!item || typeof item !== "object") return item;
  const out = { ...item };
  if ("apiKey" in out) out.apiKey = maskSecret(out.apiKey);
  if ("secretKey" in out) out.secretKey = maskSecret(out.secretKey);
  return out;
}

function redactScheduledForApi(item) {
  if (!item || typeof item !== "object") return item;
  const out = { ...item };
  if ("apiKey" in out) out.apiKey = maskSecret(out.apiKey);
  if ("secretKey" in out) out.secretKey = maskSecret(out.secretKey);
  return out;
}

const telegramTimers = new Map();

async function executeTelegramScheduledJob(jobId) {
  const job = store.scheduled.find((x) => x && x.id === jobId);
  if (!job) return;
  if (job.status !== "queued") return;

  const recipient = job.recipient || null;
  if (!recipient || !recipient.kind || !recipient.value) {
    job.status = "error";
    job.error = "invalid recipient";
    job.updatedAtMs = Date.now();
    saveStore(store);
    return;
  }

  const rl = rateLimitCheck(job.apiKey || "", recipient.value);
  if (!rl.ok) {
    const retryAfterMs = Math.max(250, Number(rl.retryAfterMs || 1000));
    const when = Date.now() + retryAfterMs;
    job.scheduleMs = when;
    job.updatedAtMs = Date.now();
    saveStore(store);
    armTelegramTimer(job);
    return;
  }

  try {
    const upstream = await telegramSendText(
      job.apiKey || "",
      job.secretKey || "",
      recipient,
      job.message || "",
    );
    const parsed = safeJsonParse(upstream.text) || upstream.text;
    if (upstream.ok) rateLimitCommit(job.apiKey || "", recipient.value);
    job.status = upstream.ok ? "sent" : "error";
    job.updatedAtMs = Date.now();
    job.upstream = { status: upstream.status, body: parsed };
  } catch (err) {
    job.status = "error";
    job.updatedAtMs = Date.now();
    job.error = String(err && err.message ? err.message : err);
  }
  saveStore(store);
}

function armTelegramTimer(job) {
  if (!job || job.vendor !== "telegram" || job.status !== "queued") return;
  const existing = telegramTimers.get(job.id);
  if (existing) clearTimeout(existing);

  const delayMs = Math.max(0, Number(job.scheduleMs || 0) - Date.now());
  const timer = setTimeout(async () => {
    telegramTimers.delete(job.id);
    await executeTelegramScheduledJob(job.id);
  }, delayMs);
  telegramTimers.set(job.id, timer);
}

function restoreTelegramTimers() {
  const now = Date.now();
  for (const item of store.scheduled) {
    if (!item || item.vendor !== "telegram") continue;
    if (item.status !== "queued") continue;
    if (!Number.isFinite(item.scheduleMs)) continue;
    if (item.scheduleMs < now - 24 * 60 * 60 * 1000) {
      item.status = "expired";
      item.updatedAtMs = now;
      continue;
    }
    armTelegramTimer(item);
  }
  saveStore(store);
}

const server = http.createServer(async (req, res) => {
  setCors(req, res);

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(
    req.url || "/",
    `http://${req.headers.host || "localhost"}`,
  );

  if (
    req.method === "GET" &&
    (url.pathname === "/" || url.pathname === "/index.html")
  ) {
    serveFile(res, PATH_INDEX);
    return;
  }
  if (req.method === "GET" && url.pathname === "/style.css") {
    serveFile(res, PATH_CSS);
    return;
  }
  if (req.method === "GET" && url.pathname === "/app.js") {
    serveFile(res, PATH_APP);
    return;
  }
  if (req.method === "GET" && url.pathname === "/health") {
    sendJson(res, 200, {
      ok: true,
      service: "tpwa",
      vendors: ["starsender", "wablas", "telegram"],
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/pending") {
    const debug = url.searchParams.get("debug") === "1";
    sendJson(res, 200, {
      ok: true,
      debug,
      pending: debug
        ? store.pending
        : store.pending.map((x) => redactPendingForApi(x)),
      scheduled: debug
        ? store.scheduled
        : store.scheduled.map((x) => redactScheduledForApi(x)),
    });
    return;
  }

  if (req.method !== "POST") {
    sendJson(res, 405, { ok: false, error: "Method not allowed" });
    return;
  }

  if (
    url.pathname !== "/api/test" &&
    url.pathname !== "/api/send" &&
    url.pathname !== "/webhook/starsender" &&
    url.pathname !== "/webhook/wablas"
  ) {
    sendJson(res, 404, { ok: false, error: "Not found" });
    return;
  }

  const body = await readJson(req);
  if (body === null) {
    sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
    return;
  }

  if (
    url.pathname === "/webhook/starsender" ||
    url.pathname === "/webhook/wablas"
  ) {
    if (WEBHOOK_TOKEN) {
      const token = url.searchParams.get("token") || "";
      if (token !== WEBHOOK_TOKEN) {
        sendJson(res, 401, { ok: false, error: "Unauthorized" });
        return;
      }
    }

    const webhookVendor =
      url.pathname === "/webhook/wablas" ? "wablas" : "starsender";
    const { message, fromRaw } =
      webhookVendor === "wablas"
        ? extractWablasInbound(body)
        : extractInbound(body);
    const fromDigits = normalizeIndoMsisdnDigits(fromRaw || "");
    const parsed = parseConfirmReply(message);

    console.log(
      "[webhook:%s] from=%s msg=%s",
      webhookVendor,
      fromDigits || "(none)",
      String(message || "").slice(0, 120),
    );

    if (!fromDigits || !message) {
      sendJson(res, 200, {
        ok: true,
        ignored: true,
        reason: "missing from/message",
      });
      return;
    }

    if (!parsed) {
      sendJson(res, 200, {
        ok: true,
        ignored: true,
        reason: "not a confirm/cancel reply",
      });
      return;
    }

    let pending = parsed.code
      ? findPending(store, webhookVendor, fromDigits, parsed.code)
      : findLatestPending(store, webhookVendor, fromDigits);
    // If user replies with a code but we didn't issue codes, fall back to latest.
    if (!pending && parsed.code) {
      pending = findLatestPending(store, webhookVendor, fromDigits);
    }
    if (!pending) {
      sendJson(res, 200, {
        ok: true,
        ignored: true,
        reason: "no matching pending",
        parsed,
      });
      saveStore(store);
      return;
    }

    const now = Date.now();
    if (parsed.action === "cancel") {
      pending.status = "canceled";
      pending.canceledAtMs = now;
      saveStore(store);
      try {
        if (webhookVendor === "starsender") {
          await starsenderSend(
            pending.apiKey || "",
            pending.toDigits,
            "OK, permintaan dijadwalkan dibatalkan.",
            null,
          );
        } else {
          await wablasSendText(
            pending.apiKey || "",
            pending.secretKey || "",
            pending.toDigits,
            "OK, permintaan dijadwalkan dibatalkan.",
          );
        }
      } catch {
        // ignore
      }
      sendJson(res, 200, { ok: true, action: "canceled", id: pending.id });
      return;
    }

    pending.status = "confirmed";
    pending.confirmedAtMs = now;
    saveStore(store);

    const apiKey = pending.apiKey || "";
    const secretKey = pending.secretKey || "";
    if (!apiKey) {
      pending.status = "error";
      pending.error = "missing apiKey for scheduling";
      saveStore(store);
      sendJson(res, 500, { ok: false, error: "missing apiKey for scheduling" });
      return;
    }
    if (webhookVendor === "wablas" && !secretKey) {
      pending.status = "error";
      pending.error = "missing secretKey for scheduling";
      saveStore(store);
      sendJson(res, 500, {
        ok: false,
        error: "missing secretKey for scheduling",
      });
      return;
    }

    const scheduleMs =
      Number.isFinite(pending.scheduleMs) &&
      pending.scheduleMs > Date.now() + 1000
        ? pending.scheduleMs
        : null;

    const rl = rateLimitCheck(apiKey, pending.toDigits);
    if (!rl.ok) {
      const retryAfterMs = Math.max(250, Number(rl.retryAfterMs || 1000));
      pending.status = "rate_limited";
      pending.rateLimit = { kind: rl.kind, retryAfterMs, atMs: now };
      saveStore(store);
      sendJson(res, 429, { ok: false, error: "Rate limited", retryAfterMs });
      return;
    }

    try {
      const upstream =
        webhookVendor === "starsender"
          ? await starsenderSend(
              apiKey,
              pending.toDigits,
              pending.finalMessage || "",
              scheduleMs,
            )
          : await wablasScheduleText(
              apiKey,
              secretKey,
              pending.toDigits,
              pending.finalMessage || "",
              formatWablasScheduledAtFromLocal(pending.scheduleAtLocal) ||
                formatWablasScheduledAtFromMs(pending.scheduleMs),
            );
      const upstreamBody = safeJsonParse(upstream.text) || upstream.text;
      if (upstream.ok) rateLimitCommit(apiKey, pending.toDigits);

      pending.status = upstream.ok ? "scheduled" : "error";
      pending.scheduledAtMs = Date.now();
      pending.upstreamSchedule = {
        status: upstream.status,
        body: upstreamBody,
      };
      saveStore(store);

      try {
        const when = pending.scheduleAtLocal || "sesuai jadwal";
        const ack = upstream.ok
          ? `Terima kasih. Konfirmasi diterima, pesan akan dikirim ${when}.`
          : "Konfirmasi diterima, tapi penjadwalan gagal. Silakan hubungi admin.";
        if (webhookVendor === "starsender") {
          await starsenderSend(apiKey, pending.toDigits, ack, null);
        } else {
          await wablasSendText(apiKey, secretKey, pending.toDigits, ack);
        }
      } catch {
        // ignore
      }

      sendJson(res, upstream.ok ? 200 : 502, {
        ok: upstream.ok,
        action: "scheduled",
        id: pending.id,
        upstream: { status: upstream.status, body: upstreamBody },
      });
    } catch (err) {
      pending.status = "error";
      pending.error = String(err && err.message ? err.message : err);
      saveStore(store);
      sendJson(res, 502, {
        ok: false,
        error: "Upstream request failed",
        details: pending.error,
      });
    }
    return;
  }

  const vendor = getVendor(req, body);
  if (!vendor) {
    sendJson(res, 400, {
      ok: false,
      error: "Missing vendor (X-Vendor or body.vendor)",
    });
    return;
  }

  if (vendor !== "starsender" && vendor !== "wablas" && vendor !== "telegram") {
    sendJson(res, 400, { ok: false, vendor, error: "Unsupported vendor" });
    return;
  }

  const payload =
    body.payload && typeof body.payload === "object" ? body.payload : body;
  const apiKey = getApiKey(req, body);
  const secretKey = getApiSecret(req, body);

  if (!apiKey) {
    sendJson(res, 400, { ok: false, vendor, error: "Missing API key" });
    return;
  }

  if (
    (vendor === "wablas" || vendor === "telegram") &&
    url.pathname !== "/api/test" &&
    !secretKey
  ) {
    sendJson(res, 400, {
      ok: false,
      vendor,
      error: "Missing secret key",
      hint:
        vendor === "telegram"
          ? "Telegram butuh sessionId/device_tag di Secret Key."
          : "Wablas butuh Authorization header format token.secret_key.",
    });
    return;
  }

  if (url.pathname === "/api/test") {
    const listCandidate =
      Array.isArray(body.toList) && body.toList.length
        ? String(body.toList[0])
        : "";
    const payloadListCandidate =
      body.payload &&
      Array.isArray(body.payload.toList) &&
      body.payload.toList.length
        ? String(body.payload.toList[0])
        : "";
    const candidate =
      body.number ||
      listCandidate ||
      body.to ||
      (body.payload && body.payload.to) ||
      payloadListCandidate ||
      body.testNumber ||
      "";

    if (vendor === "starsender") {
      const number = normalizeIndoMsisdnDigits(candidate);
      if (!number) {
        sendJson(res, 200, {
          ok: true,
          vendor,
          tested: false,
          message: "Isi field To dulu untuk test via check-number.",
        });
        return;
      }

      try {
        const upstream = await starsenderCheckNumber(apiKey, number);
        const parsed = safeJsonParse(upstream.text);
        sendJson(res, upstream.ok ? 200 : 502, {
          ok: upstream.ok,
          vendor,
          action: "check-number",
          request: { number },
          upstream: { status: upstream.status, body: parsed || upstream.text },
        });
      } catch (err) {
        sendJson(res, 502, {
          ok: false,
          vendor,
          error: "Upstream request failed",
          details: String(err && err.message ? err.message : err),
        });
      }
      return;
    }

    if (vendor === "telegram") {
      const target = parseTelegramTarget(candidate);
      if (!secretKey) {
        sendJson(res, 200, {
          ok: true,
          vendor,
          tested: false,
          action: "config-check",
          note: "Isi Secret Key dengan sessionId/device_tag aktif Telegram.",
          config: {
            apiToken: Boolean(apiKey),
            sessionId: false,
          },
        });
        return;
      }

      if (!candidate) {
        sendJson(res, 200, {
          ok: true,
          vendor,
          tested: false,
          action: "config-check",
          note: "Isi field To untuk validasi target (nomor/@username/chatId).",
          config: {
            apiToken: Boolean(apiKey),
            sessionId: Boolean(secretKey),
          },
        });
        return;
      }

      if (!target) {
        sendJson(res, 400, {
          ok: false,
          vendor,
          tested: false,
          error: "Target Telegram tidak valid",
          hint: "Gunakan nomor, @username, atau chatId.",
        });
        return;
      }

      sendJson(res, 200, {
        ok: true,
        vendor,
        tested: true,
        action: "config-check",
        config: {
          apiToken: Boolean(apiKey),
          sessionId: Boolean(secretKey),
        },
        request: { target },
        note: "Test Telegram melakukan validasi konfigurasi lokal tanpa mengirim pesan.",
      });
      return;
    }

    // wablas
    const phone = normalizeIndoMsisdnDigits(candidate);
    let deviceInfo = null;
    try {
      const di = await wablasDeviceInfo(apiKey);
      deviceInfo = {
        status: di.status,
        ok: di.ok,
        body: safeJsonParse(di.text) || di.text,
      };
    } catch (err) {
      deviceInfo = {
        status: 0,
        ok: false,
        body: String(err && err.message ? err.message : err),
      };
    }

    let listServer = null;
    if (secretKey) {
      try {
        const ls = await wablasListServer(apiKey, secretKey);
        listServer = {
          status: ls.status,
          ok: ls.ok,
          body: safeJsonParse(ls.text) || ls.text,
        };
      } catch (err) {
        listServer = {
          status: 0,
          ok: false,
          body: String(err && err.message ? err.message : err),
        };
      }
    }

    if (!phone) {
      sendJson(res, 200, {
        ok: Boolean(deviceInfo && deviceInfo.ok),
        vendor,
        tested: Boolean(deviceInfo && deviceInfo.ok),
        action: "device-info",
        note: "Field To kosong, jadi hanya test koneksi/token via device-info (bukan check-phone-number).",
        upstream: deviceInfo,
        listServer,
        authHint: wablasAuthHint(apiKey, secretKey),
      });
      return;
    }

    try {
      const upstream = await wablasCheckPhone(apiKey, phone);
      const parsed = safeJsonParse(upstream.text);
      const ok = upstream.ok;
      // phone.wablas.com kadang 502 dari Cloudflare; tetap tampilkan device-info biar jelas token/koneksi.
      sendJson(res, ok ? 200 : 502, {
        ok,
        vendor,
        action: "check-phone-number",
        request: { phones: phone },
        upstream: { status: upstream.status, body: parsed || upstream.text },
        deviceInfo,
        listServer,
        authHint: wablasAuthHint(apiKey, secretKey),
        hint:
          upstream.status === 502
            ? "Wablas phone check lagi 502 (Cloudflare). Coba lagi nanti, atau test kirim pesan langsung."
            : null,
      });
    } catch (err) {
      sendJson(res, 502, {
        ok: false,
        vendor,
        error: "Upstream request failed",
        details: String(err && err.message ? err.message : err),
        deviceInfo,
        listServer,
        authHint: wablasAuthHint(apiKey, secretKey),
      });
    }
    return;
  }

  // /api/send
  const requireConfirm = Boolean(payload.requireConfirm);
  const scheduleMs = getScheduleMs(payload) || null;

  const toListRaw = Array.isArray(payload.toList) ? payload.toList : [];
  const toRaw = payload.to || "";
  const message = payload.message || payload.body || "";
  const text = String(message || "");

  if (!text.trim()) {
    sendJson(res, 400, { ok: false, vendor, error: "Missing message" });
    return;
  }

  if (requireConfirm) {
    if (vendor === "telegram") {
      sendJson(res, 400, {
        ok: false,
        vendor,
        error: "requireConfirm belum didukung untuk Telegram",
      });
      return;
    }

    if (!Number.isFinite(scheduleMs)) {
      sendJson(res, 400, {
        ok: false,
        vendor,
        error: "requireConfirm membutuhkan scheduleAt",
      });
      return;
    }

    const recipients = toListRaw
      .map((x) => normalizeIndoMsisdnDigits(x))
      .filter(Boolean);

    if (recipients.length === 0) {
      sendJson(res, 400, {
        ok: false,
        vendor,
        error: "Missing recipients (toList)",
      });
      return;
    }

    const whenText =
      (payload.scheduleAt && payload.scheduleAt.local) ||
      new Date(Number(scheduleMs)).toISOString();

    const confirmWindowMinutesRaw = Number.parseInt(
      payload.confirmWindowMinutes || "1440",
      10,
    );
    const confirmWindowMinutes =
      Number.isFinite(confirmWindowMinutesRaw) && confirmWindowMinutesRaw > 0
        ? confirmWindowMinutesRaw
        : 1440;
    const windowMs = confirmWindowMinutes * 60_000;

    const results = [];
    for (const toDigits of recipients) {
      const rl = rateLimitCheck(apiKey, toDigits);
      if (!rl.ok) {
        const retryAfterMs = Math.max(250, Number(rl.retryAfterMs || 1000));
        results.push({
          to: toDigits,
          ok: false,
          error: "rate_limited",
          retryAfterMs,
        });
        continue;
      }

      const id = generateId();

      // Expire earlier than schedule, and always give at least 5 minutes.
      const expiresAtMs = Math.max(
        Date.now() + 5 * 60_000,
        Math.min(Date.now() + windowMs, Number(scheduleMs) - 60_000),
      );

      const confirmMessage =
        `Konfirmasi: balas YA untuk mengizinkan pesan terjadwal dikirim pada ${whenText}. ` +
        `Jika tidak setuju, abaikan pesan ini.`;

      try {
        const upstream =
          vendor === "starsender"
            ? await starsenderSend(apiKey, toDigits, confirmMessage, null)
            : await wablasSendText(apiKey, secretKey, toDigits, confirmMessage);
        const upstreamBody = safeJsonParse(upstream.text) || upstream.text;
        if (upstream.ok) rateLimitCommit(apiKey, toDigits);

        store.pending.push({
          id,
          vendor,
          toDigits,
          code: "",
          scheduleMs: Number(scheduleMs),
          scheduleAtLocal: whenText,
          finalMessage: text,
          status: upstream.ok ? "pending" : "confirm_failed",
          createdAtMs: Date.now(),
          expiresAtMs,
          apiKey, // NOTE: stored in plain text for local dev.
          ...(vendor === "wablas" ? { secretKey } : {}),
          upstreamConfirm: { status: upstream.status, body: upstreamBody },
        });
        saveStore(store);

        results.push({
          to: toDigits,
          ok: upstream.ok,
          id,
          expiresAtMs,
          upstream: { status: upstream.status, body: upstreamBody },
        });
      } catch (err) {
        results.push({
          to: toDigits,
          ok: false,
          error: "upstream_failed",
          details: String(err && err.message ? err.message : err),
        });
      }
    }

    sendJson(res, 200, {
      ok: true,
      vendor,
      action: "confirm_requested",
      scheduleMs,
      results,
      webhook: {
        path: vendor === "wablas" ? "/webhook/wablas" : "/webhook/starsender",
        tokenParam: WEBHOOK_TOKEN ? "token=..." : null,
        note:
          vendor === "wablas"
            ? "Set webhook inbound Wablas ke endpoint ini agar balasan YA bisa diproses."
            : "Set webhook inbound StarSender ke endpoint ini agar balasan YA bisa diproses.",
      },
    });
    return;
  }

  if (vendor === "telegram") {
    const recipient = parseTelegramTarget(toRaw);
    if (!recipient) {
      sendJson(res, 400, { ok: false, vendor, error: "Missing/invalid to" });
      return;
    }

    const recipientKey = `${recipient.kind}:${recipient.value}`;

    if (Number.isFinite(scheduleMs)) {
      const id = generateId();
      const job = {
        id,
        vendor: "telegram",
        recipient,
        message: text,
        scheduleMs: Number(scheduleMs),
        status: "queued",
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
        apiKey,
        secretKey,
      };
      store.scheduled.push(job);
      saveStore(store);
      armTelegramTimer(job);
      sendJson(res, 200, {
        ok: true,
        vendor,
        action: "queued_schedule",
        id,
        request: {
          to: recipient,
          schedule: scheduleMs,
        },
      });
      return;
    }

    const rl = rateLimitCheck(apiKey, recipientKey);
    if (!rl.ok) {
      const retryAfterMs = Math.max(250, Number(rl.retryAfterMs || 1000));
      sendJson(
        res,
        429,
        {
          ok: false,
          vendor,
          error: "Rate limited",
          details: { kind: rl.kind, retryAfterMs, limits: LIMITS },
        },
        { "Retry-After": String(Math.ceil(retryAfterMs / 1000)) },
      );
      return;
    }

    try {
      const upstream = await telegramSendText(
        apiKey,
        secretKey,
        recipient,
        text,
      );
      const parsed = safeJsonParse(upstream.text);
      if (upstream.ok) rateLimitCommit(apiKey, recipientKey);
      sendJson(res, upstream.ok ? 200 : 502, {
        ok: upstream.ok,
        vendor,
        action: "send",
        request: {
          messageType: "text",
          to: recipient,
          schedule: scheduleMs,
        },
        upstream: { status: upstream.status, body: parsed || upstream.text },
      });
    } catch (err) {
      sendJson(res, 502, {
        ok: false,
        vendor,
        error: "Upstream request failed",
        details: String(err && err.message ? err.message : err),
      });
    }
    return;
  }

  const to = normalizeIndoMsisdnDigits(toRaw);
  if (!to) {
    sendJson(res, 400, { ok: false, vendor, error: "Missing/invalid to" });
    return;
  }

  const rl = rateLimitCheck(apiKey, to);
  if (!rl.ok) {
    const retryAfterMs = Math.max(250, Number(rl.retryAfterMs || 1000));
    sendJson(
      res,
      429,
      {
        ok: false,
        vendor,
        error: "Rate limited",
        details: { kind: rl.kind, retryAfterMs, limits: LIMITS },
      },
      { "Retry-After": String(Math.ceil(retryAfterMs / 1000)) },
    );
    return;
  }

  try {
    const upstream =
      vendor === "starsender"
        ? await starsenderSend(apiKey, to, text, scheduleMs)
        : Number.isFinite(scheduleMs)
          ? await wablasScheduleText(
              apiKey,
              secretKey,
              to,
              text,
              formatWablasScheduledAtFromLocal(
                payload.scheduleAt && payload.scheduleAt.local,
              ) || formatWablasScheduledAtFromMs(scheduleMs),
            )
          : await wablasSendText(apiKey, secretKey, to, text);
    const parsed = safeJsonParse(upstream.text);
    if (upstream.ok) rateLimitCommit(apiKey, to);

    if (vendor === "wablas" && !upstream.ok) {
      const hint = wablasAuthHint(apiKey, secretKey);
      if (isWablasCredsError(parsed, upstream.status)) {
        sendJson(res, 401, {
          ok: false,
          vendor,
          action: "send",
          error: "Wablas credential error",
          hint,
          request: {
            to,
            schedule: scheduleMs,
          },
          upstream: { status: upstream.status, body: parsed || upstream.text },
        });
        return;
      }
    }

    sendJson(res, upstream.ok ? 200 : 502, {
      ok: upstream.ok,
      vendor,
      action: "send",
      request: {
        messageType: "text",
        to,
        schedule: scheduleMs,
      },
      upstream: { status: upstream.status, body: parsed || upstream.text },
    });
  } catch (err) {
    sendJson(res, 502, {
      ok: false,
      vendor,
      error: "Upstream request failed",
      details: String(err && err.message ? err.message : err),
    });
  }
});

restoreTelegramTimers();

server.listen(args.port, args.host, () => {
  console.log(`Server: http://${args.host}:${args.port}`);
  console.log("UI:");
  console.log("  GET  /");
  console.log("API:");
  console.log("  GET  /health");
  console.log("  POST /api/test");
  console.log("  POST /api/send");
});
