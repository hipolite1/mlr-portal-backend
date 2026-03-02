const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'users.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error('DB connection error:', err.message);
  else console.log('Connected to SQLite:', DB_PATH);
});

// Helpers
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function columnExists(table, column) {
  const rows = await all(`PRAGMA table_info(${table})`);
  return rows.some(r => r.name === column);
}

async function initDb() {
  // Your current "users" table = owners/operators
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      loginId TEXT UNIQUE,
      password TEXT,
      phone TEXT UNIQUE,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Add subscription fields safely (won't break if already present)
  if (!(await columnExists('users', 'stripe_customer_id'))) {
    await run(`ALTER TABLE users ADD COLUMN stripe_customer_id TEXT`);
  }
  if (!(await columnExists('users', 'stripe_subscription_id'))) {
    await run(`ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT`);
  }
  if (!(await columnExists('users', 'subscription_status'))) {
    await run(`ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT 'inactive'`);
  }

  // Customers (belongs to an owner/operator)
  await run(`
    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    )
  `);

  // Pickups (belongs to owner + customer)
  await run(`
    CREATE TABLE IF NOT EXISTS pickups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      customer_id INTEGER NOT NULL,
      due_date TEXT NOT NULL,              -- YYYY-MM-DD
      status TEXT DEFAULT 'pending',       -- pending | picked_up
      last_reminder_sent TEXT,             -- YYYY-MM-DD (so we only send once/day)
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_id) REFERENCES users(id),
      FOREIGN KEY(customer_id) REFERENCES customers(id)
    )
  `);

  console.log('DB schema ready: users + customers + pickups (+ subscription fields)');
}

module.exports = { db, run, get, all, initDb };
