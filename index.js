// index.js — Render-friendly version using better-sqlite3
require("dotenv").config();

const express = require("express");
const path = require("path");
const Stripe = require("stripe");
const crypto = require("crypto");
const Database = require("better-sqlite3");

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

// Create required table (MVP minimal)
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
// Static frontend
// ---------------------------
// (Optional but helpful) avoid stale cached HTML/CSS on deploy
app.use((req, res, next) => {
  if (req.method === "GET" && /\.(html|css|js)$/.test(req.path)) {
    res.setHeader("Cache-Control", "no-store");
  }
  next();
});

app.use(express.static(path.join(__dirname, "frontend")));

// =========================
// HEALTH CHECK
// =========================
app.get("/ping", (req, res) => res.status(200).send("ok"));

// ---------------------------
// Root route
// ---------------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "login.html"));
});

// Force-serve key pages (prevents 404)
app.get("/welcome.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "welcome.html"));
});

app.get("/choose-plan.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "choose-plan.html"));
});

app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "login.html"));
});

// ✅ Step 3: New pages for post-login funnel
app.get("/dashboard.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "dashboard.html"));
});

app.get("/add-pickup.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "add-pickup.html"));
});

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
      process.env.APP_BASE_URL || process.env.PUBLIC_URL || "http://localhost:3000";

    // Auto-create owner row (unique)
    const uniq = Date.now();
    const autoLoginId = `AUTO${uniq}`;
    const autoPass = `temp${uniq}`; // placeholder only
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
          .send(`Stripe checkout session failed: ${e?.message || "unknown error"}`);
      });
  } catch (e) {
    console.error("checkout route error:", e?.message || e);
    return res.status(500).send("Checkout error");
  }
});

// ---------------------------
// Start server
// ---------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MLR server running on port ${PORT}`));