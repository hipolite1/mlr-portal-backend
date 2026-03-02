const express = require('express');
const router = express.Router();
const { run, all } = require('../db');

// MVP auth: pass ownerId from frontend (later we can switch to sessions/JWT)
router.post('/add', async (req, res) => {
  try {
    const { ownerId, name, phone } = req.body;
    if (!ownerId || !name || !phone) {
      return res.status(400).json({ error: 'ownerId, name, phone are required' });
    }

    const r = await run(
      `INSERT INTO customers (owner_id, name, phone) VALUES (?, ?, ?)`,
      [ownerId, name.trim(), phone.trim()]
    );

    res.json({ success: true, customerId: r.lastID });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/list', async (req, res) => {
  try {
    const ownerId = req.query.ownerId;
    if (!ownerId) return res.status(400).json({ error: 'ownerId is required' });

    const rows = await all(
      `SELECT id, name, phone, createdAt FROM customers WHERE owner_id = ? ORDER BY id DESC`,
      [ownerId]
    );

    res.json({ success: true, customers: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
