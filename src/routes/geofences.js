const express = require('express');
const router  = express.Router();
const db      = require('../db');
const redis   = require('../redis');
const auth    = require('../middleware/auth');

// Invalidate the per-account geofence cache so gpsServer picks up changes immediately
async function bustCache(account_id) {
  try { await redis.del(`geofences:${account_id}`); } catch (_) {}
}

// ── LIST GEOFENCES ────────────────────────────────
router.get('/', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, name, geofence_type, center_lat, center_lng, radius_m,
              coordinates, speed_limit, trigger_on, color, is_active, created_at
       FROM geofences
       WHERE account_id = $1
       ORDER BY created_at DESC`,
      [req.user.account_id]
    );
    res.json({ geofences: result.rows });
  } catch (err) {
    console.error('List geofences error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── GET SINGLE GEOFENCE ───────────────────────────
router.get('/:id', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM geofences WHERE id = $1 AND account_id = $2`,
      [req.params.id, req.user.account_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Geofence not found.' });
    res.json({ geofence: result.rows[0] });
  } catch (err) {
    console.error('Get geofence error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── CREATE GEOFENCE ───────────────────────────────
// Circle:  { name, shape:"circle",  center_lat, center_lng, radius_m }
// Polygon: { name, shape:"polygon", polygon:[{lat,lng},...] }
router.post('/', auth, async (req, res) => {
  const { name, shape, center_lat, center_lng, radius_m, polygon } = req.body;

  if (!name || !shape) {
    return res.status(400).json({ error: 'name and shape are required.' });
  }
  if (shape === 'circle' && (!center_lat || !center_lng || !radius_m)) {
    return res.status(400).json({ error: 'Circle requires center_lat, center_lng, radius_m.' });
  }
  if (shape === 'polygon' && (!Array.isArray(polygon) || polygon.length < 3)) {
    return res.status(400).json({ error: 'Polygon requires at least 3 points.' });
  }

  try {
    const result = await db.query(
      `INSERT INTO geofences
         (account_id, name, shape, center_lat, center_lng, radius_m, polygon)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [req.user.account_id, name, shape,
       center_lat || null, center_lng || null, radius_m || null,
       polygon ? JSON.stringify(polygon) : null]
    );

    await bustCache(req.user.account_id);

    res.status(201).json({ message: 'Geofence created.', geofence: result.rows[0] });
  } catch (err) {
    console.error('Create geofence error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── UPDATE GEOFENCE ───────────────────────────────
router.put('/:id', auth, async (req, res) => {
  const { name, shape, center_lat, center_lng, radius_m, polygon, is_active } = req.body;

  try {
    const result = await db.query(
      `UPDATE geofences
       SET name       = COALESCE($1, name),
           shape      = COALESCE($2, shape),
           center_lat = COALESCE($3, center_lat),
           center_lng = COALESCE($4, center_lng),
           radius_m   = COALESCE($5, radius_m),
           polygon    = COALESCE($6, polygon),
           is_active  = COALESCE($7, is_active)
       WHERE id = $8 AND account_id = $9
       RETURNING *`,
      [name, shape, center_lat, center_lng, radius_m,
       polygon ? JSON.stringify(polygon) : null,
       is_active, req.params.id, req.user.account_id]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Geofence not found.' });

    await bustCache(req.user.account_id);

    res.json({ message: 'Geofence updated.', geofence: result.rows[0] });
  } catch (err) {
    console.error('Update geofence error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── DELETE GEOFENCE ───────────────────────────────
router.delete('/:id', auth, async (req, res) => {
  try {
    const result = await db.query(
      `DELETE FROM geofences WHERE id = $1 AND account_id = $2 RETURNING id`,
      [req.params.id, req.user.account_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Geofence not found.' });

    await bustCache(req.user.account_id);

    res.json({ message: 'Geofence deleted.' });
  } catch (err) {
    console.error('Delete geofence error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── GET GEOFENCE EVENTS ───────────────────────────
// Query params: vehicle_id, event_type, from, to, limit
router.get('/:id/events', auth, async (req, res) => {
  const { vehicle_id, event_type, from, to, limit = 100 } = req.query;
  try {
    // Verify geofence belongs to account
    const gf = await db.query(
      `SELECT id FROM geofences WHERE id = $1 AND account_id = $2`,
      [req.params.id, req.user.account_id]
    );
    if (gf.rows.length === 0) return res.status(404).json({ error: 'Geofence not found.' });

    const conditions = ['e.geofence_id = $1'];
    const params     = [req.params.id];
    let   p          = 2;

    if (vehicle_id)  { conditions.push(`e.vehicle_id = $${p++}`);  params.push(vehicle_id); }
    if (event_type)  { conditions.push(`e.event_type = $${p++}`);  params.push(event_type); }
    if (from)        { conditions.push(`e.occurred_at >= $${p++}`); params.push(from); }
    if (to)          { conditions.push(`e.occurred_at <= $${p++}`); params.push(to); }

    params.push(Math.min(parseInt(limit) || 100, 1000));

    const result = await db.query(
      `SELECT e.*, v.registration
       FROM geofence_events e
       JOIN vehicles v ON e.vehicle_id = v.id
       WHERE ${conditions.join(' AND ')}
       ORDER BY e.occurred_at DESC
       LIMIT $${p}`,
      params
    );

    res.json({ events: result.rows, total: result.rows.length });
  } catch (err) {
    console.error('Geofence events error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
