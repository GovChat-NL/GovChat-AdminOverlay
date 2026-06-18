const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3002;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const DATA_DIR = process.env.DATA_DIR || "/data";
const PUBLISH_DIR = process.env.PUBLISH_DIR || "/publish";
const SESSION_SECRET = crypto.randomBytes(32).toString("hex");

// Active sessions (in-memory, resets on restart)
const sessions = new Map();

// ── Middleware ──────────────────────────────────────────────────────
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS for public API endpoints
app.use("/api/config", (req, res, next) => {
  res.set("Access-Control-Allow-Origin", CORS_ORIGIN);
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ── Data helpers ───────────────────────────────────────────────────
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function initDefaults() {
  ensureDataDir();
  const jsonDefaults = ["help-content.json", "apps.json"];
  for (const file of jsonDefaults) {
    const target = path.join(DATA_DIR, file);
    if (!fs.existsSync(target)) {
      const source = path.join(__dirname, "defaults", file);
      if (fs.existsSync(source)) {
        fs.copyFileSync(source, target);
        console.log(`[init] Copied default ${file} to ${DATA_DIR}`);
      }
    }
  }

  // Keep apps.json synced with repository defaults to avoid stale webhook URL/token
  // from older volumes when n8n integration is enabled.
  const appsSource = path.join(__dirname, "defaults", "apps.json");
  const appsTarget = path.join(DATA_DIR, "apps.json");
  if (fs.existsSync(appsSource)) {
    fs.copyFileSync(appsSource, appsTarget);
    console.log(`[init] Synced runtime config apps.json to ${DATA_DIR}`);
  }

  // Keep runtime assets in sync with repository defaults on each start.
  // This prevents stale loader/custom.css from old named volumes.
  const runtimeAssets = ["loader.js", "custom.css"];
  for (const file of runtimeAssets) {
    const source = path.join(__dirname, "defaults", file);
    const target = path.join(DATA_DIR, file);
    if (fs.existsSync(source)) {
      fs.copyFileSync(source, target);
      console.log(`[init] Synced runtime asset ${file} to ${DATA_DIR}`);
    }
  }
}

function readJSON(filename) {
  const filepath = path.join(DATA_DIR, filename);
  if (!fs.existsSync(filepath)) return null;
  return JSON.parse(fs.readFileSync(filepath, "utf-8"));
}

function writeJSON(filename, data) {
  ensureDataDir();
  const filepath = path.join(DATA_DIR, filename);
  fs.writeFileSync(filepath, JSON.stringify(data, null, 2), "utf-8");
  // Also publish to shared static volume for Open WebUI
  publishFile(filename, data);
}

function publishFile(filename, data) {
  try {
    if (!fs.existsSync(PUBLISH_DIR)) {
      fs.mkdirSync(PUBLISH_DIR, { recursive: true });
    }
    const target = path.join(PUBLISH_DIR, filename);
    fs.writeFileSync(target, JSON.stringify(data, null, 2), "utf-8");
    console.log(`[publish] ${filename} → ${PUBLISH_DIR}`);
  } catch (err) {
    console.warn(`[publish] Failed to publish ${filename}: ${err.message}`);
  }
}

function publishFileRaw(filename) {
  try {
    if (!fs.existsSync(PUBLISH_DIR)) {
      fs.mkdirSync(PUBLISH_DIR, { recursive: true });
    }
    const source = path.join(DATA_DIR, filename);
    if (!fs.existsSync(source)) return;
    const target = path.join(PUBLISH_DIR, filename);
    fs.copyFileSync(source, target);
    console.log(`[publish] ${filename} → ${PUBLISH_DIR}`);
  } catch (err) {
    console.warn(`[publish] Failed to publish ${filename}: ${err.message}`);
  }
}

function publishAll() {
  const jsonFiles = ["help-content.json", "apps.json"];
  for (const file of jsonFiles) {
    const data = readJSON(file);
    if (data) publishFile(file, data);
  }
  const rawFiles = ["loader.js", "custom.css"];
  for (const file of rawFiles) {
    publishFileRaw(file);
  }
}

// ── Auth helpers ───────────────────────────────────────────────────
function createSession() {
  const id = crypto.randomBytes(24).toString("hex");
  sessions.set(id, { created: Date.now() });
  return id;
}

function isAuthenticated(req) {
  const sid = req.cookies?.session;
  return sid && sessions.has(sid);
}

function requireAuth(req, res, next) {
  if (isAuthenticated(req)) return next();
  res.redirect("/login");
}

// ── View helper ────────────────────────────────────────────────────
function sendView(res, name, vars = {}) {
  const filepath = path.join(__dirname, "views", name);
  let html = fs.readFileSync(filepath, "utf-8");
  for (const [key, value] of Object.entries(vars)) {
    html = html.replaceAll(`{{${key}}}`, value);
  }
  res.type("html").send(html);
}

// ── Public API endpoints (no auth) ────────────────────────────────
app.get("/api/config/help-content", (req, res) => {
  const data = readJSON("help-content.json");
  if (!data) return res.status(404).json({ error: "Not found" });
  res.json(data);
});

app.get("/api/config/apps", (req, res) => {
  const data = readJSON("apps.json");
  if (!data) return res.status(404).json({ error: "Not found" });
  res.json(data);
});

// ── Login ──────────────────────────────────────────────────────────
app.get("/login", (req, res) => {
  if (isAuthenticated(req)) return res.redirect("/dashboard");
  sendView(res, "login.html", { error: "" });
});

app.post("/login", (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    const sid = createSession();
    res.cookie("session", sid, {
      httpOnly: true,
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });
    return res.redirect("/dashboard");
  }
  sendView(res, "login.html", {
    error: '<p class="error">Onjuist wachtwoord. Probeer het opnieuw.</p>',
  });
});

app.get("/logout", (req, res) => {
  const sid = req.cookies?.session;
  if (sid) sessions.delete(sid);
  res.clearCookie("session");
  res.redirect("/login");
});

// ── Admin pages (auth required) ────────────────────────────────────
app.get("/", (req, res) => {
  if (isAuthenticated(req)) return res.redirect("/dashboard");
  res.redirect("/login");
});

app.get("/dashboard", requireAuth, (req, res) => {
  const helpData = readJSON("help-content.json");
  const appsData = readJSON("apps.json");
  const helpSections = helpData?.sections?.length || 0;
  const appCount = appsData?.apps?.length || 0;
  sendView(res, "dashboard.html", {
    helpSections: String(helpSections),
    appCount: String(appCount),
    helpTitle: helpData?.title || "(niet ingesteld)",
    appsTitle: appsData?.title || "(niet ingesteld)",
  });
});

app.get("/help-editor", requireAuth, (req, res) => {
  const data = readJSON("help-content.json") || { title: "", subtitle: "", sections: [] };
  sendView(res, "help-editor.html", {
    jsonData: JSON.stringify(data),
  });
});

app.get("/apps-editor", requireAuth, (req, res) => {
  const data = readJSON("apps.json") || { title: "App Launcher", apps: [] };
  sendView(res, "apps-editor.html", {
    jsonData: JSON.stringify(data),
  });
});

// ── Admin API endpoints (auth required) ────────────────────────────
app.post("/api/config/help-content", requireAuth, (req, res) => {
  try {
    writeJSON("help-content.json", req.body);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/config/apps", requireAuth, (req, res) => {
  try {
    writeJSON("apps.json", req.body);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start ──────────────────────────────────────────────────────────
initDefaults();

// Wait a bit for Open WebUI to finish its startup copy, then publish admin data
setTimeout(() => {
  publishAll();
  console.log(`[govchat-admin] Published config to ${PUBLISH_DIR}`);
}, 15000);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[govchat-admin] Running on http://0.0.0.0:${PORT}`);
  console.log(`[govchat-admin] Data directory: ${DATA_DIR}`);
  console.log(`[govchat-admin] Publish directory: ${PUBLISH_DIR}`);
});
