const express = require('express');
const router = express.Router();
const { run, all, get } = require('../db');

// Create pickup (staff enters customer + due date)
router.post('/add', async (req, res) => {
  try {
    const { ownerId, customerId, dueDate } = req.body; // dueDate = YYYY-MM-DD
    if (!ownerId || !customerId || !dueDate) {
      return res.status(400).json({ error: 'ownerId, customerId, dueDate are required' });
    }

    const r = await run(
      `INSERT INTO pickups (owner_id, customer_id, due_date) VALUES (?, ?, ?)`,
      [ownerId, customerId, dueDate]
    );

    res.json({ success: true, pickupId: r.lastID });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// List pickups for an owner (optionally filter by status)
router.get('/list', async (req, res) => {
  try {
    const { ownerId, status } = req.query;
    if (!ownerId) return res.status(400).json({ error: 'ownerId is required' });

    const whereStatus = status ? `AND p.status = ?` : '';
    const params = status ? [ownerId, status] : [ownerId];

    const rows = await all(
      `
      SELECT
        p.id,
        p.due_date,
        p.status,
        p.last_reminder_sent,
        c.name AS customer_name,
        c.phone AS customer_phone
      FROM pickups p
      JOIN customers c ON c.id = p.customer_id
      WHERE p.owner_id = ?
      ${whereStatus}
      ORDER BY p.id DESC
      `,
      params
    );

    res.json({ success: true, pickups: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Mark pickup as picked up (this stops reminders)
router.post('/mark-picked-up', async (req, res) => {
  try {
    const { ownerId, pickupId } = req.body;
    if (!ownerId || !pickupId) {
      return res.status(400).json({ error: 'ownerId and pickupId are required' });
    }

    // extra safety: ensure pickup belongs to owner
    const row = await get(`SELECT id FROM pickups WHERE id = ? AND owner_id = ?`, [pickupId, ownerId]);
    if (!row) return res.status(404).json({ error: 'Pickup not found for this owner' });

    await run(`UPDATE pickups SET status = 'picked_up' WHERE id = ?`, [pickupId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
