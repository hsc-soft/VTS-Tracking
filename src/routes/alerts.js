const express = require('express');
const router  = express.Router();
const db      = require('../db');
const auth    = require('../middleware/auth');

// ── GET ALL ALERTS ────────────────────────────────
router.get('/', auth, async (req, res) => {
  const { unread, limit = 50 } = req.query;
  try {
    let query = `
      SELECT a.*, v.registration, v.driver_name, g.name as geofence_name
      FROM alerts a
      JOIN vehicles v ON a.vehicle_id = v.id
      LEFT JOIN geofences g ON a.geofence_id = g.id
      WHERE v.account_id = $1
    `;
    const params = [req.user.account_id];

    if (unread === 'true') {
      query += ` AND a.is_read = false`;
    }

    query += ` ORDER BY a.triggered_at DESC LIMIT $2`;
    params.push(parseInt(limit));

    const result = await db.query(query, params);
    res.json({ alerts: result.rows, total: result.rows.length });

  } catch (err) {
    console.error('Get alerts error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── MARK ALERT AS READ ────────────────────────────
router.put('/:id/read', auth, async (req, res) => {
  try {
    await db.query(
      `UPDATE alerts SET is_read = true
       WHERE id = $1
         AND vehicle_id IN (
           SELECT id FROM vehicles WHERE account_id = $2
         )`,
      [req.params.id, req.user.account_id]
    );
    res.json({ message: 'Alert marked as read.' });
  } catch (err) {
    console.error('Mark read error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── MARK ALL AS READ ──────────────────────────────
router.put('/read/all', auth, async (req, res) => {
  try {
    await db.query(
      `UPDATE alerts SET is_read = true
       WHERE vehicle_id IN (
         SELECT id FROM vehicles WHERE account_id = $1
       ) AND is_read = false`,
      [req.user.account_id]
    );
    res.json({ message: 'All alerts marked as read.' });
  } catch (err) {
    console.error('Mark all read error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;