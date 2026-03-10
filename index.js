require("dotenv").config();

const express = require("express");
const path = require("path");
const Stripe = require("stripe");
const crypto = require("crypto");
const fs = require("fs");
const Database = require("better-sqlite3");
const cron = require("node-cron");
const twilio = require("twilio");

const app = express();

// =========================
// ADMIN KEY (protect dangerous routes)
// =========================
const ADMIN_KEY = String(process.env.ADMIN_KEY || "").trim();
console.log(
  `🔐 ADMIN_KEY loaded: ${ADMIN_KEY ? "set" : "missing"} (len=${ADMIN_KEY.length})`
);

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) {
    return res.status(500).json({ ok: false, error: "ADMIN_KEY not set on server" });
  }

  const provided =
    String(req.get("x-admin-key") || "").trim() ||
    String(req.query.admin_key || "").trim();

  if (!provided || provided !== ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized (admin key required)" });
  }

  return next();
}

// ---------------------------
// Stripe (fail-fast)
// ---------------------------
const STRIPE_SECRET_KEY = String(process.env.STRIPE_SECRET_KEY || "").trim();
if (!STRIPE_SECRET_KEY) {
  console.error("\n❌ STRIPE_SECRET_KEY missing in environment (.env locally / Render env vars)\n");
  process.exit(1);
}
const stripe = new Stripe(STRIPE_SECRET_KEY);

// Webhook secret: remove ANY whitespace (Render paste can include newline)
const STRIPE_WEBHOOK_SECRET_RAW = String(process.env.STRIPE_WEBHOOK_SECRET || "");
const STRIPE_WEBHOOK_SECRET = STRIPE_WEBHOOK_SECRET_RAW.replace(/\s+/g, "");
console.log(
  `🔔 Webhook secret loaded: ${STRIPE_WEBHOOK_SECRET ? "set" : "missing"} (len=${STRIPE_WEBHOOK_SECRET.length}, hadWhitespace=${/\s/.test(STRIPE_WEBHOOK_SECRET_RAW)})`
);

// ---------------------------
// Database (Render Disk ready)
// ---------------------------
const DB_PATH = process.env.DB_PATH || "./users.db";
const db = new Database(DB_PATH);

// ---------------------------
// Generic table helpers
// ---------------------------
function tableExists(name) {
  return !!db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
    .get(name);
}

function tableCols(table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
}

function addColIfMissing(table, colDefSql) {
  const colName = colDefSql.split(/\s+/)[0];
  const cols = tableCols(table);
  if (!cols.includes(colName)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${colDefSql}`);
    console.log(`✅ Added column ${table}.${colName}`);
  }
}

// ---------------------------
// Users table (bootstrapping)
// ---------------------------
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

addColIfMissing("users", "stripe_customer_id TEXT");
addColIfMissing("users", "stripe_subscription_id TEXT");
addColIfMissing("users", "stripe_checkout_session_id TEXT");
addColIfMissing("users", "stripe_price_id TEXT");
addColIfMissing("users", "plan_name TEXT");
addColIfMissing("users", "subscription_current_period_end INTEGER");
addColIfMissing("users", "activatedAt DATETIME");
addColIfMissing("users", "updatedAt DATETIME");

// =====================================================
// ✅ Pickups table: canonical + migrations
// =====================================================
function backfillIfExists(table, targetCol, candidates) {
  const cols = tableCols(table);
  const src = candidates.find((c) => cols.includes(c));
  if (!src) return;

  db.exec(`
    UPDATE ${table}
    SET ${targetCol} = ${src}
    WHERE (${targetCol} IS NULL OR ${targetCol} = '')
      AND ${src} IS NOT NULL
      AND ${src} <> ''
  `);
  console.log(`✅ Backfilled ${table}.${targetCol} from ${src}`);
}

function createCanonicalPickupsTable() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS pickups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      customer_name TEXT NOT NULL,
      customer_phone TEXT NOT NULL,
      due_date TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      last_reminder_sent TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function coalesceExpr(cols, candidates, fallbackLiteral) {
  const existing = candidates.filter((c) => cols.includes(c));
  if (existing.length === 0) return fallbackLiteral;
  return `COALESCE(${existing.join(", ")}, ${fallbackLiteral})`;
}

function ensureCanonicalPickups() {
  if (!tableExists("pickups")) {
    createCanonicalPickupsTable();
    console.log("✅ Created canonical pickups table.");
    return;
  }

  const cols = tableCols("pickups");

  // Legacy schema contains customer_id (NOT NULL) -> rebuild table
  if (cols.includes("customer_id")) {
    const legacyName = `pickups_legacy_${Date.now()}`;
    db.exec(`ALTER TABLE pickups RENAME TO ${legacyName};`);
    createCanonicalPickupsTable();
    console.log(`✅ Renamed legacy pickups -> ${legacyName} and created canonical pickups table.`);

    try {
      const legacyCols = tableCols(legacyName);

      const ownerExpr = legacyCols.includes("owner_id") ? "owner_id" : "NULL";
      const nameExpr = coalesceExpr(legacyCols, ["customer_name", "name", "customerName"], "''");
      const phoneExpr = coalesceExpr(legacyCols, ["customer_phone", "phone", "customerPhone"], "''");
      const dueExpr = coalesceExpr(legacyCols, ["due_date", "dueDate", "due"], "''");
      const statusExpr = legacyCols.includes("status") ? "COALESCE(status,'pending')" : "'pending'";
      const createdExpr = legacyCols.includes("createdAt")
        ? "createdAt"
        : legacyCols.includes("created_at")
        ? "created_at"
        : "CURRENT_TIMESTAMP";

      const sql = `
        INSERT INTO pickups (owner_id, customer_name, customer_phone, due_date, status, createdAt)
        SELECT ${ownerExpr},
               ${nameExpr},
               ${phoneExpr},
               ${dueExpr},
               ${statusExpr},
               ${createdExpr}
        FROM ${legacyName}
        WHERE ${ownerExpr} IS NOT NULL
          AND ${nameExpr} <> ''
          AND ${phoneExpr} <> ''
          AND ${dueExpr} <> ''
      `;
      db.exec(sql);
      console.log("✅ Migrated usable legacy pickups into canonical table (best-effort).");
    } catch (e) {
      console.log("🟡 Legacy pickup migration skipped:", e.message);
    }
    return;
  }

  addColIfMissing("pickups", "customer_name TEXT");
  addColIfMissing("pickups", "customer_phone TEXT");
  addColIfMissing("pickups", "due_date TEXT");
  addColIfMissing("pickups", "status TEXT DEFAULT 'pending'");
  addColIfMissing("pickups", "last_reminder_sent TEXT");
  addColIfMissing("pickups", "createdAt DATETIME DEFAULT CURRENT_TIMESTAMP");

  backfillIfExists("pickups", "customer_name", ["name", "customerName"]);
  backfillIfExists("pickups", "customer_phone", ["phone", "customerPhone"]);
  backfillIfExists("pickups", "due_date", ["dueDate", "due", "due_date_old"]);
  backfillIfExists("pickups", "createdAt", ["created_at"]);

  console.log("✅ Pickups schema is canonical-ready.");
}

ensureCanonicalPickups();

// ---------------------------
// Stripe helpers
// ---------------------------
function mapStripeSubscriptionStatus(stripeStatus) {
  const s = String(stripeStatus || "").toLowerCase();
  const known = new Set([
    "trialing",
    "active",
    "past_due",
    "canceled",
    "incomplete",
    "incomplete_expired",
    "unpaid",
    "paused",
  ]);
  if (known.has(s)) return s;
  return "inactive";
}

function planToPriceId(planKey) {
  const plan = String(planKey || "").toLowerCase();
  if (plan === "single") return process.env.STRIPE_PRICE_SINGLE || null;
  if (plan === "growth") return process.env.STRIPE_PRICE_GROWTH || null;
  if (plan === "pro") return process.env.STRIPE_PRICE_PRO || null;
  return null;
}

function updateUserStripeCheckoutSuccess({
  ownerId,
  customerId = null,
  subscriptionId = null,
  checkoutSessionId = null,
  priceId = null,
  planName = null,
  subscriptionStatus = "active",
  currentPeriodEnd = null,
}) {
  if (!ownerId) return;

  const info = db
    .prepare(
      `
    UPDATE users
    SET subscription_status = ?,
        stripe_customer_id = COALESCE(?, stripe_customer_id),
        stripe_subscription_id = COALESCE(?, stripe_subscription_id),
        stripe_checkout_session_id = COALESCE(?, stripe_checkout_session_id),
        stripe_price_id = COALESCE(?, stripe_price_id),
        plan_name = COALESCE(?, plan_name),
        subscription_current_period_end = COALESCE(?, subscription_current_period_end),
        activatedAt = COALESCE(activatedAt, CURRENT_TIMESTAMP),
        updatedAt = CURRENT_TIMESTAMP
    WHERE id = ?
  `
    )
    .run(
      subscriptionStatus,
      customerId,
      subscriptionId,
      checkoutSessionId,
      priceId,
      planName,
      currentPeriodEnd,
      Number(ownerId)
    );

  if (info.changes === 0) {
    console.log(`🟡 Webhook update skipped: owner ${ownerId} not found.`);
  } else {
    console.log(`✅ Webhook updated owner ${ownerId} -> ${subscriptionStatus}`);
  }
}

function updateUserStripeSubscriptionStatus({
  ownerId = null,
  subscriptionId = null,
  customerId = null,
  stripeStatus = null,
  priceId = null,
  planName = null,
  currentPeriodEnd = null,
}) {
  const appStatus = mapStripeSubscriptionStatus(stripeStatus);

  const info = db
    .prepare(
      `
      UPDATE users
      SET subscription_status = ?,
          stripe_subscription_id = COALESCE(?, stripe_subscription_id),
          stripe_customer_id = COALESCE(?, stripe_customer_id),
          stripe_price_id = COALESCE(?, stripe_price_id),
          plan_name = COALESCE(?, plan_name),
          subscription_current_period_end = COALESCE(?, subscription_current_period_end),
          updatedAt = CURRENT_TIMESTAMP
      WHERE stripe_subscription_id = ?
         OR stripe_customer_id = ?
         OR id = ?
    `
    )
    .run(
      appStatus,
      subscriptionId,
      customerId,
      priceId,
      planName,
      currentPeriodEnd,
      subscriptionId,
      customerId,
      ownerId ? Number(ownerId) : null
    );

  console.log(
    `✅ Subscription sync -> ${appStatus} (sub=${subscriptionId || "n/a"} cust=${customerId || "n/a"} owner=${
      ownerId || "n/a"
    } period_end=${currentPeriodEnd ?? "null"} changes=${info.changes})`
  );
}

// =====================================================
// ✅ STRIPE WEBHOOK (raw body)
// =====================================================
app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    if (!STRIPE_WEBHOOK_SECRET) {
      console.error("❌ STRIPE_WEBHOOK_SECRET missing");
      return res.status(500).send("Webhook secret not configured");
    }

    const signature = req.headers["stripe-signature"];
    if (!signature) return res.status(400).send("Missing Stripe-Signature header");

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error("❌ Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        case "checkout.session.completed": {
          const session = event.data.object;

          const ownerId = Number(session?.metadata?.owner_id || session?.client_reference_id || 0);
          const customerId =
            typeof session.customer === "string" ? session.customer : session.customer?.id || null;
          const subscriptionId =
            typeof session.subscription === "string"
              ? session.subscription
              : session.subscription?.id || null;

          const priceId = session?.metadata?.price_id || null;
          const planName = session?.metadata?.plan || null;

          let appStatus = "active";
          let periodEnd = null;

          if (subscriptionId) {
            try {
              const subscription = await stripe.subscriptions.retrieve(subscriptionId);
              appStatus = mapStripeSubscriptionStatus(subscription.status);
              periodEnd =
                subscription.current_period_end != null ? Number(subscription.current_period_end) : null;

              const subPriceId = subscription?.items?.data?.[0]?.price?.id || null;

              updateUserStripeCheckoutSuccess({
                ownerId,
                customerId,
                subscriptionId,
                checkoutSessionId: session.id,
                priceId: subPriceId || priceId,
                planName,
                subscriptionStatus: appStatus,
                currentPeriodEnd: periodEnd,
              });
            } catch (subErr) {
              console.log("🟡 Subscription retrieve failed:", subErr.message);
              updateUserStripeCheckoutSuccess({
                ownerId,
                customerId,
                subscriptionId,
                checkoutSessionId: session.id,
                priceId,
                planName,
                subscriptionStatus: appStatus,
                currentPeriodEnd: periodEnd,
              });
            }
          } else {
            updateUserStripeCheckoutSuccess({
              ownerId,
              customerId,
              subscriptionId,
              checkoutSessionId: session.id,
              priceId,
              planName,
              subscriptionStatus: appStatus,
              currentPeriodEnd: periodEnd,
            });
          }
          break;
        }

        case "customer.subscription.updated":
        case "customer.subscription.deleted": {
          const sub = event.data.object;

          const ownerId = Number(sub?.metadata?.owner_id || 0);
          const customerId =
            typeof sub.customer === "string" ? sub.customer : sub.customer?.id || null;

          const subscriptionId = String(sub.id);
          const stripeStatus = String(sub.status || "");
          const priceId = sub?.items?.data?.[0]?.price?.id || null;
          const planName = sub?.metadata?.plan || null;
          const periodEnd = sub.current_period_end != null ? Number(sub.current_period_end) : null;

          updateUserStripeSubscriptionStatus({
            ownerId,
            subscriptionId,
            customerId,
            stripeStatus,
            priceId,
            planName,
            currentPeriodEnd: periodEnd,
          });
          break;
        }

        case "invoice.payment_failed": {
          const invoice = event.data.object;

          const subscriptionId =
            typeof invoice.subscription === "string"
              ? invoice.subscription
              : invoice.subscription?.id || null;

          const customerId =
            typeof invoice.customer === "string" ? invoice.customer : invoice.customer?.id || null;

          if (subscriptionId) {
            db.prepare(
              `
              UPDATE users
              SET subscription_status = 'past_due',
                  stripe_customer_id = COALESCE(?, stripe_customer_id),
                  updatedAt = CURRENT_TIMESTAMP
              WHERE stripe_subscription_id = ?
            `
            ).run(customerId, subscriptionId);

            console.log(`🟡 Invoice payment failed -> marked past_due for subscription ${subscriptionId}`);
          }
          break;
        }

        default:
          console.log(`ℹ️ Unhandled Stripe event: ${event.type}`);
      }

      return res.json({ received: true });
    } catch (err) {
      console.error("❌ Webhook handler error:", err.message);
      return res.status(500).send("Webhook handler failed");
    }
  }
);

// ✅ JSON for everything EXCEPT Stripe webhook (webhook needs raw body)
app.use((req, res, next) => {
  if (req.originalUrl === "/stripe/webhook") return next();
  return express.json()(req, res, next);
});

// ---------------------------
// Helpers: password hashing
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

// =====================================================
// ✅ BACKEND GATING
// =====================================================
function getSubStatus(ownerId) {
  const row = db.prepare(`SELECT subscription_status FROM users WHERE id=?`).get(Number(ownerId));
  return row?.subscription_status || "inactive";
}
function isAllowedStatus(status) {
  return status === "trialing" || status === "active";
}
function requireActiveFromOwnerId(ownerId, res) {
  if (!ownerId) {
    res.status(400).json({ ok: false, error: "ownerId required" });
    return false;
  }
  const status = getSubStatus(ownerId);
  if (!isAllowedStatus(status)) {
    res.status(403).json({ ok: false, error: `Access denied: subscription_status=${status}` });
    return false;
  }
  return true;
}
function requireActive(req, res, next) {
  try {
    const ownerId = Number(req.query?.ownerId ?? req.body?.ownerId);
    if (!requireActiveFromOwnerId(ownerId, res)) return;
    return next();
  } catch (e) {
    console.error("requireActive error:", e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
}

// ---------------------------
// Static frontend
// ---------------------------
// ✅ IMPORTANT: URL params must NOT unlock access.
// ✅ Unlock happens only after Stripe confirms (webhook updates subscription_status).
app.use((req, res, next) => next());

app.use(express.static(path.join(__dirname, "frontend")));

// =========================
// HEALTH CHECK
// =========================
app.get("/ping", (req, res) => res.status(200).send("ok"));

// Pages
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "frontend", "login.html")));
app.get("/welcome.html", (req, res) => res.sendFile(path.join(__dirname, "frontend", "welcome.html")));
app.get("/choose-plan.html", (req, res) =>
  res.sendFile(path.join(__dirname, "frontend", "choose-plan.html"))
);
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "frontend", "login.html")));
app.get("/dashboard.html", (req, res) =>
  res.sendFile(path.join(__dirname, "frontend", "dashboard.html"))
);
app.get("/add-pickup.html", (req, res) =>
  res.sendFile(path.join(__dirname, "frontend", "add-pickup.html"))
);

// =====================================================
// ✅ Manual unlock for testing (ADMIN ONLY; remove before launch)
// =====================================================
app.get("/api/mark-trial", requireAdmin, (req, res) => {
  try {
    const ownerId = Number(req.query.ownerId);
    if (!ownerId) return res.status(400).json({ ok: false, error: "ownerId required" });

    const info = db
      .prepare(
        `UPDATE users SET subscription_status='trialing', updatedAt=CURRENT_TIMESTAMP WHERE id=?`
      )
      .run(ownerId);

    if (info.changes === 0) {
      return res
        .status(404)
        .json({ ok: false, error: `Owner ${ownerId} not found (no rows updated)` });
    }

    const row = db
      .prepare(
        `
      SELECT id, loginId, phone, subscription_status,
             stripe_customer_id, stripe_subscription_id, plan_name,
             subscription_current_period_end
      FROM users
      WHERE id=?
    `
      )
      .get(ownerId);

    return res.json({
      ok: true,
      ownerId: row.id,
      loginId: row.loginId,
      phone: row.phone,
      subscription_status: row.subscription_status,
      stripe_customer_id: row.stripe_customer_id,
      stripe_subscription_id: row.stripe_subscription_id,
      plan_name: row.plan_name,
      subscription_current_period_end: row.subscription_current_period_end,
    });
  } catch (e) {
    console.error("GET /api/mark-trial error:", e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// =====================================================
// ✅ ADMIN: cleanup users incorrectly marked trialing without Stripe IDs
// (Fixes cases like owner 8: trialing but all stripe_* fields null)
// =====================================================
app.post("/api/admin/cleanup-trialing-no-stripe", requireAdmin, (req, res) => {
  try {
    const info = db
      .prepare(
        `
      UPDATE users
      SET subscription_status = 'inactive',
          updatedAt = CURRENT_TIMESTAMP
      WHERE subscription_status = 'trialing'
        AND (stripe_subscription_id IS NULL OR stripe_subscription_id = '')
        AND (stripe_checkout_session_id IS NULL OR stripe_checkout_session_id = '')
        AND (stripe_customer_id IS NULL OR stripe_customer_id = '')
    `
      )
      .run();

    return res.json({ ok: true, cleaned: info.changes });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});
// =====================================================
// ✅ Debug (ADMIN ONLY)
// =====================================================
app.get("/api/debug/user-status", requireAdmin, (req, res) => {
  try {
    const ownerId = Number(req.query.ownerId);
    if (!ownerId) return res.status(400).json({ ok: false, error: "ownerId required" });

    const row = db
      .prepare(
        `
      SELECT id, loginId, phone, subscription_status,
             stripe_customer_id, stripe_subscription_id,
             stripe_checkout_session_id, stripe_price_id, plan_name,
             subscription_current_period_end,
             activatedAt, updatedAt
      FROM users
      WHERE id=?
    `
      )
      .get(ownerId);

    if (!row) return res.json({ ok: true, exists: false, ownerId });
    return res.json({ ok: true, exists: true, ...row });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/debug/pickups-schema", requireAdmin, (req, res) => {
  try {
    if (!tableExists("pickups")) return res.json({ ok: true, exists: false });
    return res.json({ ok: true, exists: true, cols: tableCols("pickups") });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ✅ Debug: show which SQLite file is actually in use (ADMIN ONLY)
app.get("/api/debug/db-info", requireAdmin, (req, res) => {
  try {
    const envDbPath = String(process.env.DB_PATH || "./users.db");
    const fileExists = fs.existsSync(envDbPath);

    const dbList = db.prepare("PRAGMA database_list").all();

    return res.json({
      ok: true,
      env_DB_PATH: envDbPath,
      file_exists: fileExists,
      database_list: dbList,
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ✅ Debug: confirm server is reading ADMIN_KEY (safe fingerprint) — ADMIN ONLY
app.get("/api/debug/admin-key", requireAdmin, (req, res) => {
  try {
    const v = String(ADMIN_KEY || "");
    const masked = v ? `${v.slice(0, 6)}...${v.slice(-4)} (len=${v.length})` : "(missing)";
    return res.json({ ok: true, admin_key: masked });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// =====================================================
// ✅ CREATE ACCOUNT
// =====================================================
app.post("/api/create-account", async (req, res) => {
  try {
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "").trim();
    const ownerId = Number(req.body.ownerId || req.query.ownerId || 0);

    if (!phone || !password)
      return res.status(400).json({ ok: false, error: "phone and password are required" });
    if (password.length < 6)
      return res.status(400).json({ ok: false, error: "password must be at least 6 characters" });

    const uniq = Date.now();
    const loginId = `MLR${String(uniq).slice(-8)}`;
    const hashed = await hashPassword(password);

    if (ownerId) {
      const exists = db.prepare(`SELECT id FROM users WHERE id=?`).get(ownerId);
      if (!exists) return res.status(400).json({ ok: false, error: "ownerId not found" });

      db.prepare(
        `UPDATE users SET loginId=?, password=?, phone=?, updatedAt=CURRENT_TIMESTAMP WHERE id=?`
      ).run(loginId, hashed, phone, ownerId);

      return res.json({ ok: true, ownerId, loginId });
    }

    const info = db
      .prepare(
        `INSERT INTO users (loginId, password, phone, subscription_status, updatedAt)
         VALUES (?, ?, ?, 'inactive', CURRENT_TIMESTAMP)`
      )
      .run(loginId, hashed, phone);

    return res.json({ ok: true, ownerId: Number(info.lastInsertRowid), loginId });
  } catch (e) {
    console.error("POST /api/create-account error:", e.message);
    return res.status(400).json({ ok: false, error: e.message || "Create failed" });
  }
});

// =====================================================
// ✅ LOGIN
// =====================================================
app.post("/api/login", async (req, res) => {
  try {
    const loginId = String(req.body.loginId || "").trim();
    const password = String(req.body.password || "").trim();
    if (!loginId || !password)
      return res.status(400).json({ ok: false, error: "loginId and password are required" });

    const row = db
      .prepare(
        `
      SELECT id, loginId, password, subscription_status,
             stripe_customer_id, stripe_subscription_id, plan_name
      FROM users
      WHERE loginId = ?
    `
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
      stripe_customer_id: row.stripe_customer_id,
      stripe_subscription_id: row.stripe_subscription_id,
      plan_name: row.plan_name,
    });
  } catch (e) {
    console.error("POST /api/login error:", e.message);
    return res.status(500).json({ ok: false, error: "Server error logging in" });
  }
});

// =====================================================
// ✅ PICKUPS API
// =====================================================
app.post("/api/pickups", requireActive, (req, res) => {
  try {
    const ownerId = Number(req.body.ownerId);
    const name = String(req.body.name || "").trim();
    const phone = String(req.body.phone || "").trim();
    const dueDate = String(req.body.dueDate || "").trim();

    if (!ownerId || !name || !phone || !dueDate) {
      return res.status(400).json({ ok: false, error: "ownerId, name, phone, dueDate are required" });
    }

    const info = db
      .prepare(
        `
      INSERT INTO pickups (owner_id, customer_name, customer_phone, due_date, status)
      VALUES (?, ?, ?, ?, 'pending')
    `
      )
      .run(ownerId, name, phone, dueDate);

    return res.json({ ok: true, id: Number(info.lastInsertRowid) });
  } catch (e) {
    console.error("POST /api/pickups error:", e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/pickups", requireActive, (req, res) => {
  try {
    const ownerId = Number(req.query.ownerId);

    const rows = db
      .prepare(
        `
      SELECT id,
             owner_id as ownerId,
             customer_name as name,
             customer_phone as phone,
             due_date as dueDate,
             status,
             createdAt,
             last_reminder_sent as lastReminderSent
      FROM pickups
      WHERE owner_id = ?
      ORDER BY id DESC
    `
      )
      .all(ownerId);

    return res.json({ ok: true, pickups: rows });
  } catch (e) {
    console.error("GET /api/pickups error:", e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.patch("/api/pickups/:id/status", (req, res) => {
  try {
    const pickupId = Number(req.params.id);
    const status = String(req.body.status || "").trim();

    if (!pickupId) return res.status(400).json({ ok: false, error: "Invalid pickup id" });
    if (!["pending", "picked_up"].includes(status)) {
      return res.status(400).json({ ok: false, error: "status must be pending or picked_up" });
    }

    const row = db.prepare(`SELECT owner_id FROM pickups WHERE id=?`).get(pickupId);
    if (!row) return res.status(404).json({ ok: false, error: "Pickup not found" });

    if (!requireActiveFromOwnerId(row.owner_id, res)) return;

    db.prepare(`UPDATE pickups SET status = ? WHERE id = ?`).run(status, pickupId);
    return res.json({ ok: true });
  } catch (e) {
    console.error("PATCH /api/pickups/:id/status error:", e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// =====================================================
// ✅ REMINDER ENGINE
// =====================================================
const RUN_REMINDERS = String(process.env.RUN_REMINDERS || "").toLowerCase() === "true";
const SEND_SMS = String(process.env.SEND_SMS || "").toLowerCase() === "true";

const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || process.env.accountSid;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || process.env.authToken;
const TWILIO_NUMBER = process.env.TWILIO_NUMBER;

const twilioClient =
  TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;

function todayUTC() {
  return new Date().toISOString().slice(0, 10);
}

function buildReminderMessage(pickup) {
  const nm = pickup.customer_name || "there";
  return `MyLaundryReminder: Hi ${nm}, your items are ready for pickup. Due date: ${pickup.due_date}. Please pick up today.`;
}

async function sendReminderSms(to, body) {
  if (!SEND_SMS) {
    console.log("🟡 SEND_SMS=false — would send to:", to, "msg:", body);
    return { skipped: true };
  }
  if (!to || !String(to).trim()) throw new Error('Required parameter "to" missing (customer_phone).');
  if (!twilioClient || !TWILIO_NUMBER) {
    throw new Error("Twilio not configured (TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_NUMBER)");
  }
  const msg = await twilioClient.messages.create({ from: TWILIO_NUMBER, to, body });
  return { sid: msg.sid };
}

async function runRemindersOnce() {
  if (!RUN_REMINDERS) {
    console.log("🟡 RUN_REMINDERS=false — reminder job not running.");
    return;
  }

  const today = todayUTC();

  const rows = db
    .prepare(
      `
    SELECT p.id, p.owner_id, p.customer_name, p.customer_phone, p.due_date, p.status, p.last_reminder_sent
    FROM pickups p
    JOIN users u ON u.id = p.owner_id
    WHERE u.subscription_status IN ('trialing','active')
      AND p.status = 'pending'
      AND p.due_date <= ?
      AND (p.last_reminder_sent IS NULL OR p.last_reminder_sent <> ?)
      AND p.customer_phone IS NOT NULL AND p.customer_phone <> ''
      AND p.customer_name  IS NOT NULL AND p.customer_name  <> ''
    ORDER BY p.id ASC
    LIMIT 50
  `
    )
    .all(today, today);

  if (rows.length === 0) {
    console.log(`✅ Reminder job: no pickups to remind (today=${today}).`);
    return;
  }

  console.log(`🚀 Reminder job: ${rows.length} pickup(s) eligible (today=${today}).`);

  for (const p of rows) {
    try {
      const body = buildReminderMessage(p);
      await sendReminderSms(p.customer_phone, body);
      db.prepare(`UPDATE pickups SET last_reminder_sent = ? WHERE id = ?`).run(today, p.id);
      console.log(`✅ Reminded pickup #${p.id} -> ${p.customer_phone}`, SEND_SMS ? "" : "(skipped)");
    } catch (e) {
      console.error(`❌ Reminder failed for pickup #${p.id}:`, e.message);
    }
  }
}

if (RUN_REMINDERS) {
  const CRON_EXPR = process.env.REMINDER_CRON || "*/10 * * * *";
  cron.schedule(CRON_EXPR, () => runRemindersOnce());
  console.log(`⏱️ Reminder cron enabled: "${CRON_EXPR}" (RUN_REMINDERS=true)`);
} else {
  console.log("🟡 Reminder cron disabled (RUN_REMINDERS=false)");
}

// ✅ LOCKED: require ADMIN_KEY now
app.post("/api/reminders/run-now", requireAdmin, async (req, res) => {
  try {
    await runRemindersOnce();
    res.json({ ok: true });
  } catch (e) {
    console.error("POST /api/reminders/run-now error:", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------------------------
// Stripe checkout endpoints
// ---------------------------
app.post("/stripe/create-checkout-session", async (req, res) => {
  try {
    const { ownerId, plan } = req.body;
    if (!ownerId || !plan) return res.status(400).json({ error: "Missing ownerId or plan" });

    const priceId = planToPriceId(plan);
    if (!priceId) return res.status(400).json({ error: "Invalid plan" });

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.APP_BASE_URL}/welcome.html?success=1`,
      cancel_url: `${process.env.APP_BASE_URL}/choose-plan.html?canceled=1`,
      client_reference_id: String(ownerId),
      metadata: { owner_id: String(ownerId), plan: String(plan), price_id: String(priceId) },

      // ✅ 30-day free trial
      subscription_data: {
        trial_period_days: 30,
        metadata: { owner_id: String(ownerId), plan: String(plan) },
      },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("Checkout error:", err?.message || err);
    res.status(500).json({ error: "Checkout failed" });
  }
});

app.get("/stripe/checkout", (req, res) => {
  try {
    const planKey = String(req.query.plan || "").toLowerCase();
    const priceId = planToPriceId(planKey);

    if (!priceId) return res.status(400).send("Invalid plan (missing STRIPE_PRICE_ env)");

    const baseUrl = process.env.APP_BASE_URL || process.env.PUBLIC_URL || "http://localhost:3000";

    const uniq = Date.now();
    const autoLoginId = `AUTO${uniq}`;
    const autoPass = `temp${uniq}`;
    const autoPhone = `+100000${String(uniq).slice(-6)}`;

    let ownerId;
    try {
      const info = db
        .prepare(
          `INSERT INTO users (loginId, password, phone, subscription_status, updatedAt)
           VALUES (?, ?, ?, 'inactive', CURRENT_TIMESTAMP)`
        )
        .run(autoLoginId, autoPass, autoPhone);
      ownerId = Number(info.lastInsertRowid);
    } catch (err) {
      console.error("Owner create error:", err?.message || err);
      return res.status(500).send(`Failed to create owner: ${err?.message || "unknown"}`);
    }

    stripe.checkout.sessions
      .create({
        mode: "subscription",
        line_items: [{ price: priceId, quantity: 1 }],
        // ✅ include session_id so we can verify later if needed
        success_url: `${baseUrl}/login.html?paid=1&owner_id=${ownerId}&session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${baseUrl}/choose-plan.html?canceled=1`,
        client_reference_id: String(ownerId),
        metadata: { owner_id: String(ownerId), plan: planKey, price_id: String(priceId) },

        // ✅ 30-day free trial
        subscription_data: {
          trial_period_days: 30,
          metadata: { owner_id: String(ownerId), plan: planKey },
        },
      })
      .then((session) => res.redirect(session.url))
      .catch((e) => {
        console.error("Stripe session create failed:", e?.message || e);
        res.status(500).send(`Stripe checkout session failed: ${e?.message || "unknown error"}`);
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

// Pretty URL redirects
app.get("/welcome", (req, res) => res.redirect("/welcome.html"));
app.get("/add-pickup", (req, res) => res.redirect("/add-pickup.html"));
app.get("/dashboard", (req, res) => res.redirect("/dashboard.html"));
app.get("/login", (req, res) => res.redirect("/login.html"));
app.get("/choose-plan", (req, res) => res.redirect("/choose-plan.html"));

app.listen(PORT, () => console.log(`MLR server running on port ${PORT}`));