const net   = require('net');
const db    = require('./db');
const redis = require('./redis');

// ── PARSE GT06 GPS PACKET ─────────────────────────
// Basic GT06/GT02 protocol parser (most common budget trackers)
function parseGT06(buffer) {
  try {
    const hex = buffer.toString('hex');

    // GT06 packets start with 7878 or 7979
    if (!hex.startsWith('7878') && !hex.startsWith('7979')) {
      return null;
    }

    // Try to extract basic GPS data
    // This is a simplified parser — production needs full GT06 spec
    const data = {
      protocol: 'gt06',
      raw: hex,
      ts: new Date().toISOString()
    };

    return data;
  } catch (err) {
    return null;
  }
}

// ── PARSE PLAIN TEXT / OSMAND FORMAT ─────────────
// Format: id=IMEI&lat=xx&lon=xx&speed=xx&heading=xx&ignition=1
function parseTextPacket(text) {
  try {
    const params = new URLSearchParams(text.trim());
    const imei     = params.get('id')       || params.get('imei');
    const latitude = parseFloat(params.get('lat')  || params.get('latitude')  || 0);
    const longitude= parseFloat(params.get('lon')  || params.get('longitude') || 0);
    const speed    = parseFloat(params.get('speed') || 0);
    const heading  = parseFloat(params.get('heading') || params.get('bearing') || 0);
    const ignition = params.get('ignition') === '1' || params.get('ignition') === 'true';
    const battery  = parseFloat(params.get('batt') || params.get('battery') || 0);

    if (!imei || !latitude || !longitude) return null;

    return { imei, latitude, longitude, speed_kmh: speed,
             heading, ignition, battery_v: battery,
             ts: new Date().toISOString(), protocol: 'text' };
  } catch {
    return null;
  }
}

// ── SAVE GPS PING TO DATABASE + REDIS ─────────────
async function savePing(data) {
  try {
    // 1. Find device by IMEI
    const deviceResult = await db.query(
      `SELECT id FROM devices WHERE imei = $1 AND is_active = true`,
      [data.imei]
    );

    if (deviceResult.rows.length === 0) {
      console.log(`⚠️  Unknown device IMEI: ${data.imei}`);
      return;
    }

    const device_id = deviceResult.rows[0].id;

    // 2. Save to PostgreSQL (gps_pings table)
    await db.query(
      `INSERT INTO gps_pings
         (device_id, ts, latitude, longitude, speed_kmh,
          heading, ignition, battery_v, is_valid)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [device_id, data.ts, data.latitude, data.longitude,
       data.speed_kmh || 0, data.heading || 0,
       data.ignition || false, data.battery_v || null, true]
    );

    // 3. Update live position in Redis (5 minute TTL)
    const liveData = {
      lat:      data.latitude,
      lng:      data.longitude,
      speed:    data.speed_kmh || 0,
      heading:  data.heading   || 0,
      ignition: data.ignition  || false,
      battery:  data.battery_v || null,
      ts:       data.ts
    };
    await redis.setex(`device:${data.imei}`, 300, JSON.stringify(liveData));

    // 4. Check overspeed alert (>80 km/h)
    if (data.speed_kmh > 80) {
      await triggerAlert(device_id, 'overspeed', 'warning', data.speed_kmh,
                         data.latitude, data.longitude);
    }

    console.log(`📍 Ping saved — IMEI: ${data.imei} | Speed: ${data.speed_kmh} km/h | ` +
                `Ignition: ${data.ignition ? 'ON' : 'OFF'}`);

  } catch (err) {
    console.error('❌ Save ping error:', err.message);
  }
}

// ── TRIGGER ALERT ─────────────────────────────────
async function triggerAlert(device_id, alert_type, severity, value, lat, lng) {
  try {
    // Get vehicle_id from device
    const v = await db.query(
      `SELECT id FROM vehicles WHERE device_id = $1`, [device_id]
    );
    if (v.rows.length === 0) return;

    const vehicle_id = v.rows[0].id;

    // Check if same alert already exists in last 5 mins (avoid spam)
    const existing = await db.query(
      `SELECT id FROM alerts
       WHERE vehicle_id = $1 AND alert_type = $2
         AND triggered_at > NOW() - INTERVAL '5 minutes'`,
      [vehicle_id, alert_type]
    );
    if (existing.rows.length > 0) return;

    // Insert alert
    await db.query(
      `INSERT INTO alerts
         (vehicle_id, alert_type, severity, value, latitude, longitude)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [vehicle_id, alert_type, severity, value, lat, lng]
    );

    // Publish to Redis for real-time dashboard
    await redis.publish(`alerts:${vehicle_id}`, JSON.stringify({
      alert_type, severity, value, lat, lng,
      ts: new Date().toISOString()
    }));

    console.log(`🔔 Alert: ${alert_type} | Vehicle: ${vehicle_id} | Value: ${value}`);

  } catch (err) {
    console.error('❌ Alert error:', err.message);
  }
}

// ── START TCP SERVER ──────────────────────────────
function startGPSServer(port) {
  const server = net.createServer((socket) => {
    const clientIP = socket.remoteAddress;
    console.log(`📡 Device connected: ${clientIP}`);

    socket.on('data', async (buffer) => {
      const text = buffer.toString('utf8').trim();

      let parsed = null;

      // Try text/OsmAnd format first
      if (text.includes('lat=') || text.includes('id=')) {
        parsed = parseTextPacket(text);
      }
      // Try GT06 binary format
      else {
        const gt06 = parseGT06(buffer);
        if (gt06) {
          // For demo: log raw GT06 — full decoder needed for production
          console.log(`📦 GT06 packet from ${clientIP}:`, gt06.raw.substring(0, 40));
          return;
        }
      }

      if (parsed) {
        await savePing(parsed);
        // Send ACK back to device
        socket.write('OK\r\n');
      } else {
        console.log(`⚠️  Unknown packet from ${clientIP}:`, text.substring(0, 50));
      }
    });

    socket.on('error', (err) => {
      console.error(`❌ Socket error (${clientIP}):`, err.message);
    });

    socket.on('close', () => {
      console.log(`📴 Device disconnected: ${clientIP}`);
    });

    // Keep connection alive
    socket.setKeepAlive(true, 30000);
  });

  server.listen(port, () => {
    console.log(`🛰️  GPS TCP Server running on port ${port}`);
  });

  server.on('error', (err) => {
    console.error('❌ GPS Server error:', err.message);
  });

  return server;
}

module.exports = { startGPSServer };