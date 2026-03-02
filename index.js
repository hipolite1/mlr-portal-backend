// index.js — MLR CLEAN VERSION (Stripe + Auto-owner + Create Account + Login APIs)

require("dotenv").config();

const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const Stripe = require("stripe");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// ---------------------------
// Stripe (fail-fast if missing key)
// ---------------------------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
if (!STRIPE_SECRET_KEY) {
  console.error("\n❌ STRIPE_SECRET_KEY is missing in .env\n");
  process.exit(1);
}
const stripe = new Stripe(STRIPE_SECRET_KEY);

// ---------------------------
// Database
// ---------------------------
const db = new sqlite3.Database("./users.db");

// ---------------------------
// DB BOOTSTRAP (users table for MVP)
// ---------------------------
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      loginId TEXT UNIQUE,
      password TEXT,
      phone TEXT UNIQUE,
      subscription_status TEXT DEFAULT 'inactive',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.all(`PRAGMA table_info(users)`, (err, cols) => {
    if (err) return console.error("PRAGMA error:", err.message);
    const names = cols.map((c) => c.name);
    if (!names.includes("subscription_status")) {
      db.run(`ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT 'inactive'`);
    }
  });
});

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
    if (!stored || !stored.includes(":")) return resolve(false);
    const [salt, key] = stored.split(":");
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return resolve(false);
      resolve(derivedKey.toString("hex") === key);
    });
  });
}

// ---------------------------
// Static frontend
// ---------------------------
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

// Force-serve key pages
app.get("/welcome.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "welcome.html"));
});
app.get("/choose-plan.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "choose-plan.html"));
});
app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "login.html"));
});

// =====================================================
// ✅ NEW: CREATE ACCOUNT (JSON API)
// =====================================================
app.post("/api/create-account", async (req, res) => {
  try {
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "").trim();

    if (!phone || !password) {
      return res.status(400).json({ error: "phone and password are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "password must be at least 6 characters" });
    }

    const uniq = Date.now();
    const loginId = `MLR${String(uniq).slice(-8)}`;

    const hashed = await hashPassword(password);

    db.run(
      `INSERT INTO users (loginId, password, phone, subscription_status)
       VALUES (?, ?, ?, 'inactive')`,
      [loginId, hashed, phone],
      function (err) {
        if (err) {
          const msg = err.message || "Create failed";
          // common: UNIQUE constraint failed: users.phone
          return res.status(400).json({ error: msg });
        }
        return res.json({ ok: true, ownerId: this.lastID, loginId });
      }
    );
  } catch (e) {
    console.error("Create account error:", e?.message || e);
    return res.status(500).json({ error: "Server error creating account" });
  }
});

// =====================================================
// ✅ NEW: LOGIN (JSON API)
// =====================================================
app.post("/api/login", (req, res) => {
  try {
    const loginId = String(req.body.loginId || "").trim();
    const password = String(req.body.password || "").trim();

    if (!loginId || !password) {
      return res.status(400).json({ error: "loginId and password are required" });
    }

    db.get(
      `SELECT id, loginId, password, subscription_status FROM users WHERE loginId = ?`,
      [loginId],
      async (err, row) => {
        if (err) return res.status(500).json({ error: "DB error" });
        if (!row) return res.status(400).json({ error: "Invalid login" });

        const ok = await verifyPassword(password, row.password);
        if (!ok) return res.status(400).json({ error: "Invalid login" });

        // MVP: return ownerId + subscription status
        return res.json({
          ok: true,
          ownerId: row.id,
          loginId: row.loginId,
          subscription_status: row.subscription_status,
        });
      }
    );
  } catch (e) {
    console.error("Login error:", e?.message || e);
    return res.status(500).json({ error: "Server error logging in" });
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
    console.error("Checkout error:", err);
    res.status(500).json({ error: "Checkout failed" });
  }
});

// =====================================================
// 🚀 SERVER-CREATED CHECKOUT (FOR MARKETING SITE)
// =====================================================
app.get("/stripe/checkout", (req, res) => {
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

  // Auto-create owner record (unique values)
  const uniq = Date.now();
  const autoLoginId = `AUTO${uniq}`;
  const autoPass = `temp${uniq}`;
  const autoPhone = `+100000${String(uniq).slice(-6)}`;

  db.run(
    `INSERT INTO users (loginId, password, phone, subscription_status)
     VALUES (?, ?, ?, 'inactive')`,
    [autoLoginId, autoPass, autoPhone],
    function (err) {
      if (err) {
        console.error("Owner create error:", err.message);
        return res.status(500).send(`Failed to create owner: ${err.message}`);
      }

      const ownerId = this.lastID;

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
          res.status(500).send(`Stripe checkout session failed: ${e?.message || "unknown"}`);
        });
    }
  );
});

// ---------------------------
// Start server
// ---------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MLR server running on port ${PORT}`));