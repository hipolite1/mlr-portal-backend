// index.js — Render-friendly version using better-sqlite3
require("dotenv").config();

const express = require("express");
const path = require("path");
const Stripe = require("stripe");
const crypto = require("crypto");
const Database = require("better-sqlite3");

// ✅ NEW: Twilio + Cron for reminders
const twilio = require("twilio");
const cron = require("node-cron");

const app = express();
app.use(express.json());

// ---------------------------
// Stripe (fail-fast)
// ---------------------------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
if (!STRIPE_SECRET_KEY) {
  console.error(
    "\n❌ STRIPE_SECRET_KEY missing in environment (.env locally / Render env vars)\n"
  );
  process.exit(1);
}
const stripe = new Stripe(STRIPE_SECRET_KEY);

// ---------------------------
// Database (better-sqlite3)
// ---------------------------
const db = new Database("./users.db");

// Create required tables (MVP)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    loginId TEXT UNIQUE,
    password TEXT,
    phone TEXT UNIQUE,
    subscription_status TEXT DEFAULT 'inactive',
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS pickups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    customer_name TEXT,
    customer_phone TEXT NOT NULL,
    due_date TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// =========================
// SAFE MIGRATION: add last_sent_on to pickups (once-per-day control)
// =========================
try {
  const cols = db.prepare(`PRAGMA table_info(pickups)`).all().map((c) => c.name);
  if (!cols.includes("last_sent_on")) {
    db.prepare(`ALTER TABLE pickups ADD COLUMN last_sent_on TEXT`).run();
    console.log("✅ Migration: Added pickups.last_sent_on");
  }
} catch (e) {
  console.error("Migration error (last_sent_on):", e?.message || e);
}

// ---------------------------
// Helpers: password hashing (no bcrypt needed)
// ---------------------------
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`${salt}:${derivedKey.toString("hex")}`);
    });
  });
}

function verifyPassword(password, stored) {
  return new Promise((resolve) => {
    try {
      if (!stored || !stored.includes(":")) return resolve(false);
      const [salt, key] = stored.split(":");
      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) return resolve(false);
        resolve(derivedKey.toString("hex") === key);
      });
    } catch {
      resolve(false);
    }
  });
}

// ---------------------------
// Prevent stale HTML/CSS/JS after deploy (helps Render/CDN + browser cache)
// ---------------------------
app.use((req, res, next) => {
  if (req.method === "GET" && /\.(html|css|js)$/.test(req.path)) {
    res.setHeader("Cache-Control", "no-store");
  }
  next();
});

// =========================
// HEALTH CHECK
// =========================
app.get("/ping", (req, res) => res.status(200).send("ok"));

// ---------------------------
// Force-serve key pages FIRST (before express.static)
// ---------------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "login.html"));
});

app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "login.html"));
});

app.get("/welcome.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "welcome.html"));
});

app.get("/choose-plan.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "choose-plan.html"));
});

app.get("/dashboard.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "dashboard.html"));
});

app.get("/add-pickup.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "add-pickup.html"));
});

// ---------------------------
// Static frontend (CSS, images, etc.) — AFTER forced routes
// ---------------------------
app.use(express.static(path.join(__dirname, "frontend")));

// =====================================================
// ✅ JSON API: CREATE ACCOUNT
// =====================================================
app.post("/api/create-account", async (req, res) => {
  try {
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "").trim();

    if (!phone || !password) {
      return res
        .status(400)
        .json({ ok: false, error: "phone and password are required" });
    }
    if (password.length < 6) {
      return res
        .status(400)
        .json({ ok: false, error: "password must be at least 6 characters" });
    }

    const uniq = Date.now();
    const loginId = `MLR${String(uniq).slice(-8)}`;
    const hashed = await hashPassword(password);

    try {
      const stmt = db.prepare(`
        INSERT INTO users (loginId, password, phone, subscription_status)
        VALUES (?, ?, ?, 'inactive')
      `);

      const info = stmt.run(loginId, hashed, phone);

      return res.json({
        ok: true,
        ownerId: Number(info.lastInsertRowid),
        loginId,
      });
    } catch (err) {
      return res
        .status(400)
        .json({ ok: false, error: err.message || "Create failed" });
    }
  } catch (e) {
    console.error("Create account error:", e?.message || e);
    return res
      .status(500)
      .json({ ok: false, error: "Server error creating account" });
  }
});

// =====================================================
// ✅ JSON API: LOGIN
// =====================================================
app.post("/api/login", async (req, res) => {
  try {
    const loginId = String(req.body.loginId || "").trim();
    const password = String(req.body.password || "").trim();

    if (!loginId || !password) {
      return res
        .status(400)
        .json({ ok: false, error: "loginId and password are required" });
    }

    const row = db
      .prepare(
        `SELECT id, loginId, password, subscription_status FROM users WHERE loginId = ?`
      )
      .get(loginId);

    if (!row) return res.status(400).json({ ok: false, error: "Invalid login" });

    const ok = await verifyPassword(password, row.password);
    if (!ok) return res.status(400).json({ ok: false, error: "Invalid login" });

    return res.json({
      ok: true,
      ownerId: row.id,
      loginId: row.loginId,
      subscription_status: row.subscription_status,
    });
  } catch (e) {
    console.error("Login error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "Server error logging in" });
  }
});

// ---------------------------
// Existing checkout endpoint (DO NOT TOUCH)
// ---------------------------
app.post("/stripe/create-checkout-session", async (req, res) => {
  try {
    const { ownerId, plan } = req.body;

    if (!ownerId || !plan) {
      return res.status(400).json({ error: "Missing ownerId or plan" });
    }

    const priceId =
      plan === "single"
        ? process.env.STRIPE_PRICE_SINGLE
        : plan === "growth"
        ? process.env.STRIPE_PRICE_GROWTH
        : plan === "pro"
        ? process.env.STRIPE_PRICE_PRO
        : null;

    if (!priceId) {
      return res.status(400).json({ error: "Invalid plan" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.APP_BASE_URL}/welcome.html?success=1`,
      cancel_url: `${process.env.APP_BASE_URL}/choose-plan.html?canceled=1`,
      client_reference_id: String(ownerId),
      metadata: { owner_id: String(ownerId), plan },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("Checkout error:", err?.message || err);
    res.status(500).json({ error: "Checkout failed" });
  }
});

// =====================================================
// 🚀 SERVER-CREATED CHECKOUT (FOR MARKETING SITE)
// =====================================================
app.get("/stripe/checkout", (req, res) => {
  try {
    const planKey = String(req.query.plan || "").toLowerCase();

    const priceId =
      planKey === "single"
        ? process.env.STRIPE_PRICE_SINGLE
        : planKey === "growth"
        ? process.env.STRIPE_PRICE_GROWTH
        : planKey === "pro"
        ? process.env.STRIPE_PRICE_PRO
        : null;

    if (!priceId) {
      return res.status(400).send("Invalid plan (missing STRIPE_PRICE_ env)");
    }

    const baseUrl =
      process.env.APP_BASE_URL ||
      process.env.PUBLIC_URL ||
      "http://localhost:3000";

    const uniq = Date.now();
    const autoLoginId = `AUTO${uniq}`;
    const autoPass = `temp${uniq}`;
    const autoPhone = `+100000${String(uniq).slice(-6)}`;

    let ownerId;
    try {
      const info = db
        .prepare(
          `INSERT INTO users (loginId, password, phone, subscription_status)
           VALUES (?, ?, ?, 'inactive')`
        )
        .run(autoLoginId, autoPass, autoPhone);

      ownerId = Number(info.lastInsertRowid);
    } catch (err) {
      console.error("Owner create error:", err?.message || err);
      return res
        .status(500)
        .send(`Failed to create owner: ${err?.message || "unknown"}`);
    }

    stripe.checkout.sessions
      .create({
        mode: "subscription",
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: `${baseUrl}/login.html?paid=1&owner_id=${ownerId}`,
        cancel_url: `${baseUrl}/choose-plan.html?canceled=1`,
        client_reference_id: String(ownerId),
        metadata: { owner_id: String(ownerId), plan: planKey },
      })
      .then((session) => res.redirect(session.url))
      .catch((e) => {
        console.error("Stripe session create failed:", e?.message || e);
        res
          .status(500)
          .send(
            `Stripe checkout session failed: ${e?.message || "unknown error"}`
          );
      });
  } catch (e) {
    console.error("checkout route error:", e?.message || e);
    return res.status(500).send("Checkout error");
  }
});

// =========================
// REMINDER ENGINE (CRON)
// Once per day AFTER due_date has passed (never before)
// Respects RUN_REMINDERS + SEND_SMS flags
// Uses pickups.last_sent_on to prevent same-day duplicates
// =========================

const RUN_REMINDERS =
  String(process.env.RUN_REMINDERS || "false").toLowerCase() === "true";
const SEND_SMS =
  String(process.env.SEND_SMS || "false").toLowerCase() === "true";

const TWILIO_SID = process.env.TWILIO_SID;
const TWILIO_AUTH = process.env.TWILIO_AUTH;
const TWILIO_FROM = process.env.TWILIO_FROM;

// Create Twilio client only if creds exist
const twilioClient =
  TWILIO_SID && TWILIO_AUTH ? twilio(TWILIO_SID, TWILIO_AUTH) : null;

function todayKeyLocal() {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function normalizeDueDateKey(due_date) {
  if (!due_date) return null;

  if (typeof due_date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(due_date)) {
    return due_date;
  }

  const dt = new Date(due_date);
  if (!isNaN(dt.getTime())) {
    const yyyy = dt.getFullYear();
    const mm = String(dt.getMonth() + 1).padStart(2, "0");
    const dd = String(dt.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  }

  return null;
}

function runReminderJob() {
  if (!RUN_REMINDERS) return;

  const today = todayKeyLocal();

  const pending = db
    .prepare(
      `
      SELECT id, owner_id, customer_name, customer_phone, due_date, status, last_sent_on
      FROM pickups
      WHERE status = 'pending'
    `
    )
    .all();

  let overdueCount = 0;
  let sentCount = 0;
  let skippedSameDay = 0;
  let skippedNoTwilio = 0;

  for (const p of pending) {
    const dueKey = normalizeDueDateKey(p.due_date);
    if (!dueKey) continue;

    // ✅ ONLY after due date has passed (not before, not on due date)
    if (!(dueKey < today)) continue;

    overdueCount++;

    // ✅ once per day max
    if (p.last_sent_on === today) {
      skippedSameDay++;
      continue;
    }

    const name = (p.customer_name || "").trim();
    const smsBody =
      (name ? `Hello ${name}. ` : "Hello. ") +
      "Reminder: Your laundry pickup is overdue. Please pick up as soon as possible.";

    if (!SEND_SMS) {
      console.log(
        `🧪 (SEND_SMS=false) Would send to ${p.customer_phone}: ${smsBody}`
      );
      continue;
    }

    if (!twilioClient || !TWILIO_FROM) {
      skippedNoTwilio++;
      console.error(
        "❌ Twilio not configured. Set TWILIO_SID, TWILIO_AUTH, TWILIO_FROM."
      );
      continue;
    }

    try {
      // Send SMS
      twilioClient.messages
        .create({
          body: smsBody,
          from: TWILIO_FROM,
          to: p.customer_phone,
        })
        .then(() => {
          // Mark as sent today (prevents spam)
          db.prepare(`UPDATE pickups SET last_sent_on = ? WHERE id = ?`).run(
            today,
            p.id
          );
        })
        .catch((e) => {
          console.error(`❌ SMS failed for pickup ${p.id}:`, e?.message || e);
        });

      sentCount++;
    } catch (e) {
      console.error(`❌ SMS failed for pickup ${p.id}:`, e?.message || e);
    }
  }

  console.log(
    `🔔 Reminder job done. overdue=${overdueCount}, sent=${sentCount}, skippedSameDay=${skippedSameDay}, skippedNoTwilio=${skippedNoTwilio}`
  );
}

// Run daily at 10:00 AM server time
cron.schedule("0 10 * * *", () => runReminderJob());

// ---------------------------
// Start server
// ---------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MLR server running on port ${PORT}`));