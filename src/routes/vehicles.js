const express = require('express');
const router  = express.Router();
const db      = require('../db');
const redis   = require('../redis');
const auth    = require('../middleware/auth');

// ── GET ALL VEHICLES (with live position from Redis) ──
router.get('/', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT v.*, d.imei, d.model as device_model, d.is_active as device_active
       FROM vehicles v
       LEFT JOIN devices d ON v.device_id = d.id
       WHERE v.account_id = $1
       ORDER BY v.created_at DESC`,
      [req.user.account_id]
    );

    // Attach live position from Redis for each vehicle
    const vehicles = await Promise.all(result.rows.map(async (v) => {
      if (v.imei) {
        const liveData = await redis.get(`device:${v.imei}`);
        if (liveData) {
          v.live = JSON.parse(liveData);
        }
      }
      return v;
    }));

    res.json({ vehicles, total: vehicles.length });

  } catch (err) {
    console.error('Get vehicles error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── GET SINGLE VEHICLE ────────────────────────────
router.get('/:id', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT v.*, d.imei, d.model as device_model, d.protocol
       FROM vehicles v
       LEFT JOIN devices d ON v.device_id = d.id
       WHERE v.id = $1 AND v.account_id = $2`,
      [req.params.id, req.user.account_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Vehicle not found.' });
    }

    const vehicle = result.rows[0];

    // Get live position from Redis
    if (vehicle.imei) {
      const liveData = await redis.get(`device:${vehicle.imei}`);
      if (liveData) vehicle.live = JSON.parse(liveData);
    }

    res.json({ vehicle });

  } catch (err) {
    console.error('Get vehicle error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── ADD VEHICLE ───────────────────────────────────
router.post('/', auth, async (req, res) => {
  const { registration, make, model, year, vehicle_type,
          color, driver_name, driver_phone, imei } = req.body;

  if (!registration) {
    return res.status(400).json({ error: 'Registration number is required.' });
  }

  try {
    let device_id = null;

    // If IMEI provided, find or create device
    if (imei) {
      const deviceResult = await db.query(
        `INSERT INTO devices (account_id, imei)
         VALUES ($1, $2)
         ON CONFLICT (imei) DO UPDATE SET account_id = $1
         RETURNING id`,
        [req.user.account_id, imei]
      );
      device_id = deviceResult.rows[0].id;
    }

    const result = await db.query(
      `INSERT INTO vehicles
         (account_id, device_id, registration, make, model, year,
          vehicle_type, color, driver_name, driver_phone)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING *`,
      [req.user.account_id, device_id, registration, make, model,
       year, vehicle_type || 'car', color, driver_name, driver_phone]
    );

    res.status(201).json({
      message: 'Vehicle added successfully!',
      vehicle: result.rows[0]
    });

  } catch (err) {
    console.error('Add vehicle error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── UPDATE VEHICLE ────────────────────────────────
router.put('/:id', auth, async (req, res) => {
  const { registration, make, model, year, vehicle_type,
          color, driver_name, driver_phone } = req.body;
  try {
    const result = await db.query(
      `UPDATE vehicles SET
         registration=$1, make=$2, model=$3, year=$4,
         vehicle_type=$5, color=$6, driver_name=$7, driver_phone=$8
       WHERE id=$9 AND account_id=$10 RETURNING *`,
      [registration, make, model, year, vehicle_type,
       color, driver_name, driver_phone,
       req.params.id, req.user.account_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Vehicle not found.' });
    }

    res.json({ message: 'Vehicle updated!', vehicle: result.rows[0] });

  } catch (err) {
    console.error('Update vehicle error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── DELETE VEHICLE ────────────────────────────────
router.delete('/:id', auth, async (req, res) => {
  try {
    await db.query(
      `DELETE FROM vehicles WHERE id=$1 AND account_id=$2`,
      [req.params.id, req.user.account_id]
    );
    res.json({ message: 'Vehicle deleted.' });
  } catch (err) {
    console.error('Delete vehicle error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── GET VEHICLE GPS HISTORY ───────────────────────
router.get('/:id/history', auth, async (req, res) => {
  const { from, to } = req.query;
  try {
    const vehicle = await db.query(
      `SELECT device_id FROM vehicles WHERE id=$1 AND account_id=$2`,
      [req.params.id, req.user.account_id]
    );

    if (vehicle.rows.length === 0) {
      return res.status(404).json({ error: 'Vehicle not found.' });
    }

    const result = await db.query(
      `SELECT ts, latitude, longitude, speed_kmh, heading, ignition
       FROM gps_pings
       WHERE device_id = $1
         AND ts BETWEEN $2 AND $3
       ORDER BY ts ASC
       LIMIT 5000`,
      [vehicle.rows[0].device_id,
       from || new Date(Date.now() - 86400000).toISOString(),
       to   || new Date().toISOString()]
    );

    res.json({ pings: result.rows, total: result.rows.length });

  } catch (err) {
    console.error('History error:', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;