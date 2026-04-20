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
      /* const nTotal = */ buffer.readUInt16BE(off); off += 2; // N of Total IO

      const io = {}; // { avlId: value }

      // N1 — 1-byte values
      const n1 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n1; i++) {
        const id  = buffer.readUInt16BE(off); off += 2;
        io[id]    = buffer.readUInt8(off);    off += 1;
      }

      // N2 — 2-byte values
      const n2 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n2; i++) {
        const id  = buffer.readUInt16BE(off);  off += 2;
        io[id]    = buffer.readUInt16BE(off);  off += 2;
      }

      // N4 — 4-byte values
      const n4 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n4; i++) {
        const id  = buffer.readUInt16BE(off);  off += 2;
        io[id]    = buffer.readUInt32BE(off);  off += 4;
      }

      // N8 — 8-byte values
      const n8 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n8; i++) {
        const id  = buffer.readUInt16BE(off);          off += 2;
        io[id]    = Number(buffer.readBigUInt64BE(off)); off += 8;
      }

      // NX — variable-length values
      const nx = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < nx; i++) {
        const id  = buffer.readUInt16BE(off); off += 2;
        const len = buffer.readUInt16BE(off); off += 2;
        io[id]    = buffer.subarray(off, off + len).toString('hex');
        off += len;
      }

      // ── Well-known AVL IDs ────────────────────────────────────
      // 239 (0xEF) = Ignition          (0/1)
      //  66        = External Voltage  (mV → V)
      //  67        = Battery Voltage   (mV → V)
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

    // Number of Data 2 (must equal Number of Data 1)
    const numData2 = buffer.readUInt8(off); off += 1;
    if (numData1 !== numData2) {
      console.warn(`[Teltonika] numData1=${numData1} ≠ numData2=${numData2}`);
    }

    // CRC-16 stored in the last 4 bytes (only the lower 16 bits matter)
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
// Format: id=IMEI&lat=xx&lon=xx&speed=xx&heading=xx&ignition=1
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

// ── SAVE GPS PING TO DATABASE + REDIS ────────────────────────────
async function savePing(data) {
  try {
    const deviceResult = await db.query(
      `SELECT id FROM devices WHERE imei = $1 AND is_active = true`,
      [data.imei]
    );

    if (deviceResult.rows.length === 0) {
      console.log(`⚠️  Unknown device IMEI: ${data.imei}`);
      return;
    }

    const device_id = deviceResult.rows[0].id;

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

    if (data.speed_kmh > 80) {
      await triggerAlert(device_id, 'overspeed', 'warning', data.speed_kmh,
                         data.latitude, data.longitude);
    }

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

    // Per-socket state
    let imei      = null;          // set after IMEI handshake
    let buf       = Buffer.alloc(0); // TCP stream reassembly buffer
    let textMode  = false;          // true once we identify a text-format device

    socket.on('data', async (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      // ── Text / OsmAnd detection ───────────────────────────────
      // Check before IMEI handshake — text devices never send binary IMEI
      if (!imei && !textMode) {
        const preview = buf.toString('utf8');
        if (preview.includes('lat=') || preview.includes('id=')) {
          textMode = true;
        }
      }

      if (textMode) {
        const text   = buf.toString('utf8');
        const parsed = parseTextPacket(text);
        if (parsed) {
          await savePing(parsed);
          socket.write('OK\r\n');
        }
        buf = Buffer.alloc(0);
        return;
      }

      // ── Teltonika IMEI handshake ──────────────────────────────
      // Packet: [2-byte length][IMEI ASCII bytes]
      if (!imei) {
        if (buf.length < 2) return; // wait for more bytes

        const imeiLen = buf.readUInt16BE(0);
        if (buf.length < 2 + imeiLen) return; // wait for full IMEI

        const candidate = buf.subarray(2, 2 + imeiLen).toString('ascii');
        if (imeiLen >= 10 && imeiLen <= 20 && /^\d+$/.test(candidate)) {
          imei = candidate;
          buf  = buf.subarray(2 + imeiLen);
          console.log(`🔑 Teltonika IMEI accepted: ${imei} from ${clientIP}`);
          socket.write(Buffer.from([0x01])); // accept
        } else {
          console.warn(`[Teltonika] Invalid IMEI from ${clientIP} — rejecting`);
          socket.write(Buffer.from([0x00])); // reject
          socket.destroy();
          return;
        }

        if (buf.length === 0) return; // typical: AVL data arrives in next packet
      }

      // ── Codec 8 Extended AVL packets ─────────────────────────
      // Loop to consume multiple full packets that may have arrived together
      while (buf.length >= 8) {
        // Expect 4-byte zero preamble
        if (buf.readUInt32BE(0) !== 0) {
          console.warn(`[Teltonika] Bad preamble from ${imei} — dropping 1 byte`);
          buf = buf.subarray(1);
          continue;
        }

        const dataLen       = buf.readUInt32BE(4);
        const totalExpected = 8 + dataLen + 4; // preamble(4) + lenField(4) + data + CRC(4)

        if (buf.length < totalExpected) break; // incomplete packet — wait for more

        const packet = buf.subarray(0, totalExpected);
        buf          = buf.subarray(totalExpected);

        const result = parseCodec8Extended(packet, imei);
        if (result) {
          for (const record of result.records) {
            await savePing(record);
          }
          // ACK: 4-byte big-endian number of accepted records
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
