const net   = require('net');
const db    = require('./db');
const redis = require('./redis');

// ── CRC-16/IBM (a.k.a. CRC-16/ARC) ──────────────────────────────
// Teltonika spec: Poly=0x8005, Init=0x0000, RefIn=true, RefOut=true
function crc16ibm(buf) {
  let crc = 0x0000;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc & 1) ? ((crc >>> 1) ^ 0xA001) : (crc >>> 1);
    }
  }
  return crc & 0xFFFF;
}

// ── PARSE TELTONIKA CODEC 8 EXTENDED AVL PACKET ──────────────────
// Returns { numRecords, records } or null on failure/bad CRC.
function parseCodec8Extended(buffer, imei) {
  try {
    let off = 0;

    if (buffer.length < 12) return null;

    // Preamble: 4 zero bytes
    if (buffer.readUInt32BE(off) !== 0) return null;
    off += 4;

    // Data Field Length — covers Codec ID → Number of Data 2
    const dataLen = buffer.readUInt32BE(off);
    off += 4;

    if (buffer.length < 8 + dataLen + 4) return null; // incomplete

    // CRC is over the slice: Codec ID … Number of Data 2
    const crcSlice = buffer.subarray(8, 8 + dataLen);

    // Codec ID must be 0x8E for Codec 8 Extended
    const codecId = buffer.readUInt8(off); off += 1;
    if (codecId !== 0x8E) return null;

    const numData1 = buffer.readUInt8(off); off += 1;

    const records = [];

    for (let r = 0; r < numData1; r++) {
      // ── Timestamp (8 bytes, ms since Unix epoch) ──────────────
      const tsBig = buffer.readBigUInt64BE(off); off += 8;

      // ── Priority (1 byte: 0=Low, 1=High, 2=Panic) ────────────
      const priority = buffer.readUInt8(off); off += 1;

      // ── GPS Element (15 bytes) ────────────────────────────────
      const lonRaw   = buffer.readInt32BE(off);  off += 4;
      const latRaw   = buffer.readInt32BE(off);  off += 4;
      const altitude = buffer.readUInt16BE(off); off += 2;
      const angle    = buffer.readUInt16BE(off); off += 2;
      const sats     = buffer.readUInt8(off);    off += 1;
      const speed    = buffer.readUInt16BE(off); off += 2;

      // Coordinates are signed integers × 10^-7
      const longitude = lonRaw / 10_000_000;
      const latitude  = latRaw / 10_000_000;

      // ── IO Element ───────────────────────────────────────────
      off += 2; // Event IO ID (skip — not stored)
      /* const nTotal = */ buffer.readUInt16BE(off); off += 2;

      const io = {};

      // N1 — 1-byte values
      const n1 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n1; i++) {
        const id = buffer.readUInt16BE(off); off += 2;
        io[id]   = buffer.readUInt8(off);   off += 1;
      }

      // N2 — 2-byte values
      const n2 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n2; i++) {
        const id = buffer.readUInt16BE(off);  off += 2;
        io[id]   = buffer.readUInt16BE(off);  off += 2;
      }

      // N4 — 4-byte values
      const n4 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n4; i++) {
        const id = buffer.readUInt16BE(off);  off += 2;
        io[id]   = buffer.readUInt32BE(off);  off += 4;
      }

      // N8 — 8-byte values
      const n8 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n8; i++) {
        const id = buffer.readUInt16BE(off);           off += 2;
        io[id]   = Number(buffer.readBigUInt64BE(off)); off += 8;
      }

      // NX — variable-length values
      const nx = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < nx; i++) {
        const id  = buffer.readUInt16BE(off); off += 2;
        const len = buffer.readUInt16BE(off); off += 2;
        io[id]    = buffer.subarray(off, off + len).toString('hex');
        off += len;
      }

      // AVL ID 239 = Ignition, 66 = External Voltage (mV), 67 = Battery Voltage (mV)
      records.push({
        imei,
        ts:         new Date(Number(tsBig)).toISOString(),
        latitude,
        longitude,
        altitude,
        heading:    angle,
        satellites: sats,
        speed_kmh:  speed,
        priority,
        ignition:   io[239] === 1,
        battery_v:  io[67] != null ? io[67]  / 1000 : null,
        ext_v:      io[66] != null ? io[66]  / 1000 : null,
        protocol:   'codec8ext',
        io
      });
    }

    const numData2 = buffer.readUInt8(off); off += 1;
    if (numData1 !== numData2) {
      console.warn(`[Teltonika] numData1=${numData1} ≠ numData2=${numData2}`);
    }

    const receivedCrc = buffer.readUInt32BE(off);
    const calcCrc     = crc16ibm(crcSlice);
    if (calcCrc !== (receivedCrc & 0xFFFF)) {
      console.warn(
        `[Teltonika] CRC mismatch — calc: 0x${calcCrc.toString(16).padStart(4,'0')}` +
        ` recv: 0x${(receivedCrc & 0xFFFF).toString(16).padStart(4,'0')}`
      );
      return null;
    }

    return { numRecords: numData1, records };

  } catch (err) {
    console.error('[Teltonika] Parse error:', err.message);
    return null;
  }
}

// ── PARSE PLAIN TEXT / OSMAND FORMAT ─────────────────────────────
function parseTextPacket(text) {
  try {
    const params    = new URLSearchParams(text.trim());
    const imei      = params.get('id')       || params.get('imei');
    const latitude  = parseFloat(params.get('lat')  || params.get('latitude')  || 0);
    const longitude = parseFloat(params.get('lon')  || params.get('longitude') || 0);
    const speed     = parseFloat(params.get('speed') || 0);
    const heading   = parseFloat(params.get('heading') || params.get('bearing') || 0);
    const ignition  = params.get('ignition') === '1' || params.get('ignition') === 'true';
    const battery   = parseFloat(params.get('batt') || params.get('battery') || 0);

    if (!imei || !latitude || !longitude) return null;

    return { imei, latitude, longitude, speed_kmh: speed,
             heading, ignition, battery_v: battery,
             ts: new Date().toISOString(), protocol: 'text' };
  } catch {
    return null;
  }
}

// ── HAVERSINE DISTANCE (km) ───────────────────────────────────────
function haversineKm(lat1, lon1, lat2, lon2) {
  const R    = 6371;
  const toRad = d => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a    = Math.sin(dLat / 2) ** 2 +
               Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ── TRIP DETECTION ────────────────────────────────────────────────
//
// State machine (persisted in Redis as `trip:active:{device_id}`):
//   no key      → vehicle is stopped / no active trip
//   key present → trip in progress (trip row already written to DB)
//
// Transitions:
//   ignition OFF → ON   : start trip
//   ignition ON  → ON   : accumulate stats
//   ignition ON  → OFF  : close trip
//   ignition unknown    : fall back to speed threshold (TRIP_MIN_SPEED)
//
// GPS-glitch guard: jumps > 2 km between consecutive pings are ignored.

const TRIP_MIN_SPEED        = 3;    // km/h — idle threshold / fallback start signal
const TRIP_MAX_JUMP_KM      = 2;    // km   — GPS glitch guard
const OVERSPEED_THRESHOLD   = 60;   // km/h — threshold for counting an overspeed event
const HARSH_BRAKE_THRESHOLD = 25;   // km/h drop between consecutive pings = harsh braking
const FUEL_L_PER_KM         = 0.10; // L/km while moving  (≈ 10 L / 100 km default)
const FUEL_IDLE_L_PER_HOUR  = 0.50; // L/h  while idling

async function processTripDetection(device_id, vehicle_id, data) {
  if (!vehicle_id) return;

  const stateKey = `trip:active:${device_id}`;

  const raw       = await redis.get(stateKey);
  const tripState = raw ? JSON.parse(raw) : null;

  const ignitionAvailable = data.ignition !== undefined && data.ignition !== null;
  const isMoving          = data.speed_kmh >= TRIP_MIN_SPEED;
  const tripShouldStart   = ignitionAvailable ? data.ignition === true  : isMoving;
  const tripShouldEnd     = ignitionAvailable ? data.ignition === false : !isMoving;

  // ── START ─────────────────────────────────────────────────────
  if (tripShouldStart && !tripState) {
    const result = await db.query(
      `INSERT INTO trips
         (vehicle_id, device_id, started_at, start_lat, start_lng,
          distance_km, max_speed_kmh, avg_speed_kmh,
          idle_minutes, harsh_braking, overspeeds, fuel_used_l)
       VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 0, 0, 0, 0)
       RETURNING id`,
      [vehicle_id, device_id, data.ts, data.latitude, data.longitude]
    );

    const newState = {
      trip_id:      result.rows[0].id,
      start_ts:     data.ts,
      last_lat:     data.latitude,
      last_lng:     data.longitude,
      last_ts:      data.ts,
      distance_km:  0,
      max_speed:    data.speed_kmh,
      idle_seconds: 0,
      harsh_braking: 0,
      overspeeds:   0,
      in_overspeed: data.speed_kmh > OVERSPEED_THRESHOLD,
      prev_speed:   data.speed_kmh
    };
    await redis.set(stateKey, JSON.stringify(newState));

    console.log(`🚗 Trip STARTED — Vehicle: ${vehicle_id} | Trip ID: ${newState.trip_id}`);
    return;
  }

  // ── UPDATE ────────────────────────────────────────────────────
  if (tripShouldStart && tripState) {
    // Time elapsed since last ping (seconds)
    const segSec = Math.max(
      0,
      (new Date(data.ts) - new Date(tripState.last_ts)) / 1000
    );

    // Distance — ignore GPS glitches
    const seg = haversineKm(
      tripState.last_lat, tripState.last_lng,
      data.latitude,      data.longitude
    );
    if (seg <= TRIP_MAX_JUMP_KM) {
      tripState.distance_km += seg;
    }

    // Max speed
    if (data.speed_kmh > tripState.max_speed) {
      tripState.max_speed = data.speed_kmh;
    }

    // Idle: engine on but vehicle not moving
    if (data.speed_kmh < TRIP_MIN_SPEED) {
      tripState.idle_seconds += segSec;
    }

    // Harsh braking: speed drops ≥ threshold between consecutive pings
    const speedDrop = tripState.prev_speed - data.speed_kmh;
    if (speedDrop >= HARSH_BRAKE_THRESHOLD && tripState.prev_speed > 10) {
      tripState.harsh_braking++;
    }

    // Overspeed: count each transition from normal → over-speed
    if (data.speed_kmh > OVERSPEED_THRESHOLD) {
      if (!tripState.in_overspeed) {
        tripState.overspeeds++;
        tripState.in_overspeed = true;
      }
    } else {
      tripState.in_overspeed = false;
    }

    tripState.prev_speed = data.speed_kmh;
    tripState.last_lat   = data.latitude;
    tripState.last_lng   = data.longitude;
    tripState.last_ts    = data.ts;

    await redis.set(stateKey, JSON.stringify(tripState));
    return;
  }

  // ── END ───────────────────────────────────────────────────────
  if (tripShouldEnd && tripState) {
    const duration_sec = Math.max(
      0,
      Math.round((new Date(data.ts) - new Date(tripState.start_ts)) / 1000)
    );

    const avg_speed_kmh = duration_sec > 0
      ? parseFloat((tripState.distance_km / (duration_sec / 3600)).toFixed(2))
      : 0;

    const idle_minutes = parseFloat((tripState.idle_seconds / 60).toFixed(2));

    const fuel_used_l = parseFloat((
      tripState.distance_km  * FUEL_L_PER_KM +
      (tripState.idle_seconds / 3600) * FUEL_IDLE_L_PER_HOUR
    ).toFixed(3));

    await db.query(
      `UPDATE trips
       SET ended_at      = $1,
           end_lat       = $2,
           end_lng       = $3,
           distance_km   = $4,
           max_speed_kmh = $5,
           avg_speed_kmh = $6,
           duration_sec  = $7,
           idle_minutes  = $8,
           harsh_braking = $9,
           overspeeds    = $10,
           fuel_used_l   = $11,
           is_complete   = true
       WHERE id = $12`,
      [
        data.ts,
        data.latitude,
        data.longitude,
        parseFloat(tripState.distance_km.toFixed(3)),
        tripState.max_speed,
        avg_speed_kmh,
        duration_sec,
        idle_minutes,
        tripState.harsh_braking,
        tripState.overspeeds,
        fuel_used_l,
        tripState.trip_id
      ]
    );

    await redis.del(stateKey);

    console.log(
      `🏁 Trip ENDED — Vehicle: ${vehicle_id} | Trip ID: ${tripState.trip_id} | ` +
      `${tripState.distance_km.toFixed(2)} km | ${Math.round(duration_sec / 60)} min | ` +
      `Avg: ${avg_speed_kmh} km/h | Idle: ${idle_minutes} min | ` +
      `Harsh brakes: ${tripState.harsh_braking} | Overspeeds: ${tripState.overspeeds} | ` +
      `Fuel: ${fuel_used_l} L`
    );
  }
}

// ── SAVE GPS PING TO DATABASE + REDIS ────────────────────────────
async function savePing(data) {
  try {
    // Fetch device + linked vehicle in one query
    const deviceResult = await db.query(
      `SELECT d.id AS device_id, v.id AS vehicle_id
       FROM devices d
       LEFT JOIN vehicles v ON v.device_id = d.id
       WHERE d.imei = $1 AND d.is_active = true`,
      [data.imei]
    );

    if (deviceResult.rows.length === 0) {
      console.log(`⚠️  Unknown device IMEI: ${data.imei}`);
      return;
    }

    const { device_id, vehicle_id } = deviceResult.rows[0];

    await db.query(
      `INSERT INTO gps_pings
         (device_id, ts, latitude, longitude, speed_kmh,
          heading, ignition, battery_v, is_valid)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [device_id, data.ts, data.latitude, data.longitude,
       data.speed_kmh || 0, data.heading || 0,
       data.ignition  || false, data.battery_v || null, true]
    );

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

    if (data.speed_kmh > 60) {
      await triggerAlert(device_id, 'overspeed', 'warning', data.speed_kmh,
                         data.latitude, data.longitude);
    }

    // Trip detection runs after every ping
    await processTripDetection(device_id, vehicle_id, data);

    console.log(
      `📍 Ping — IMEI: ${data.imei} | ` +
      `${data.latitude.toFixed(6)},${data.longitude.toFixed(6)} | ` +
      `Speed: ${data.speed_kmh} km/h | Ignition: ${data.ignition ? 'ON' : 'OFF'} | ` +
      `Proto: ${data.protocol}`
    );

  } catch (err) {
    console.error('❌ Save ping error:', err.message);
  }
}

// ── TRIGGER ALERT ─────────────────────────────────────────────────
async function triggerAlert(device_id, alert_type, severity, value, lat, lng) {
  try {
    const v = await db.query(
      `SELECT id FROM vehicles WHERE device_id = $1`, [device_id]
    );
    if (v.rows.length === 0) return;

    const vehicle_id = v.rows[0].id;

    const existing = await db.query(
      `SELECT id FROM alerts
       WHERE vehicle_id = $1 AND alert_type = $2
         AND triggered_at > NOW() - INTERVAL '5 minutes'`,
      [vehicle_id, alert_type]
    );
    if (existing.rows.length > 0) return;

    await db.query(
      `INSERT INTO alerts
         (vehicle_id, alert_type, severity, value, latitude, longitude)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [vehicle_id, alert_type, severity, value, lat, lng]
    );

    await redis.publish(`alerts:${vehicle_id}`, JSON.stringify({
      alert_type, severity, value, lat, lng,
      ts: new Date().toISOString()
    }));

    console.log(`🔔 Alert: ${alert_type} | Vehicle: ${vehicle_id} | Value: ${value}`);

  } catch (err) {
    console.error('❌ Alert error:', err.message);
  }
}

// ── START TCP SERVER ──────────────────────────────────────────────
function startGPSServer(port) {
  const server = net.createServer((socket) => {
    const clientIP = socket.remoteAddress;
    console.log(`📡 Device connected: ${clientIP}`);

    let imei     = null;
    let buf      = Buffer.alloc(0);
    let textMode = false;

    socket.on('data', async (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      // ── Text / OsmAnd detection ───────────────────────────────
      if (!imei && !textMode) {
        const preview = buf.toString('utf8');
        if (preview.includes('lat=') || preview.includes('id=')) {
          textMode = true;
        }
      }

      if (textMode) {
        const parsed = parseTextPacket(buf.toString('utf8'));
        if (parsed) {
          await savePing(parsed);
          socket.write('OK\r\n');
        }
        buf = Buffer.alloc(0);
        return;
      }

      // ── Teltonika IMEI handshake ──────────────────────────────
      if (!imei) {
        if (buf.length < 2) return;

        const imeiLen = buf.readUInt16BE(0);
        if (buf.length < 2 + imeiLen) return;

        const candidate = buf.subarray(2, 2 + imeiLen).toString('ascii');
        if (imeiLen >= 10 && imeiLen <= 20 && /^\d+$/.test(candidate)) {
          imei = candidate;
          buf  = buf.subarray(2 + imeiLen);
          console.log(`🔑 Teltonika IMEI accepted: ${imei} from ${clientIP}`);
          socket.write(Buffer.from([0x01]));
        } else {
          console.warn(`[Teltonika] Invalid IMEI from ${clientIP} — rejecting`);
          socket.write(Buffer.from([0x00]));
          socket.destroy();
          return;
        }

        if (buf.length === 0) return;
      }

      // ── Codec 8 Extended AVL packets ─────────────────────────
      while (buf.length >= 8) {
        if (buf.readUInt32BE(0) !== 0) {
          console.warn(`[Teltonika] Bad preamble from ${imei} — dropping 1 byte`);
          buf = buf.subarray(1);
          continue;
        }

        const dataLen       = buf.readUInt32BE(4);
        const totalExpected = 8 + dataLen + 4;

        if (buf.length < totalExpected) break;

        const packet = buf.subarray(0, totalExpected);
        buf          = buf.subarray(totalExpected);

        const result = parseCodec8Extended(packet, imei);
        if (result) {
          for (const record of result.records) {
            await savePing(record);
          }
          const ack = Buffer.allocUnsafe(4);
          ack.writeUInt32BE(result.numRecords);
          socket.write(ack);
          console.log(`✅ ACK ${result.numRecords} record(s) — IMEI: ${imei}`);
        } else {
          console.warn(`⚠️  Invalid Codec8Ext packet from ${imei || clientIP}`);
        }
      }
    });

    socket.on('error', (err) => {
      console.error(`❌ Socket error (${imei || clientIP}):`, err.message);
    });

    socket.on('close', () => {
      console.log(`📴 Device disconnected: ${imei || clientIP}`);
    });

    socket.setKeepAlive(true, 30000);
  });

  server.listen(port, () => {
    console.log(`🛰️  GPS TCP Server running on port ${port} [Teltonika Codec 8 Extended]`);
  });

  server.on('error', (err) => {
    console.error('❌ GPS Server error:', err.message);
  });

  return server;
}

module.exports = { startGPSServer };
