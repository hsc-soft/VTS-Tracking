const net = require('net');
const db = require('./db');
const redis = require('./redis');
const clients = new Map();

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
function parseCodec8Extended(buffer, imei) {
  try {
    let off = 0;

    if (buffer.length < 12) return null;

    if (buffer.readUInt32BE(off) !== 0) return null;
    off += 4;

    const dataLen = buffer.readUInt32BE(off);
    off += 4;

    if (buffer.length < 8 + dataLen + 4) return null;

    const crcSlice = buffer.subarray(8, 8 + dataLen);

    const codecId = buffer.readUInt8(off); off += 1;
    if (codecId !== 0x8E) return null;

    const numData1 = buffer.readUInt8(off); off += 1;

    const records = [];

    for (let r = 0; r < numData1; r++) {
      const tsBig = buffer.readBigUInt64BE(off); off += 8;
      const priority = buffer.readUInt8(off); off += 1;

      const lonRaw = buffer.readInt32BE(off); off += 4;
      const latRaw = buffer.readInt32BE(off); off += 4;
      const altitude = buffer.readUInt16BE(off); off += 2;
      const angle = buffer.readUInt16BE(off); off += 2;
      const sats = buffer.readUInt8(off); off += 1;
      const speed = buffer.readUInt16BE(off); off += 2;

      const longitude = lonRaw / 10_000_000;
      const latitude = latRaw / 10_000_000;

      off += 2; // Event IO ID
      off += 2; // N of Total IO (redundant — N1/N2/N4/N8/NX counts cover it)

      const io = {};

      const n1 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n1; i++) {
        const id = buffer.readUInt16BE(off); off += 2;
        io[id] = buffer.readUInt8(off); off += 1;
      }

      const n2 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n2; i++) {
        const id = buffer.readUInt16BE(off); off += 2;
        io[id] = buffer.readUInt16BE(off); off += 2;
      }

      const n4 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n4; i++) {
        const id = buffer.readUInt16BE(off); off += 2;
        io[id] = buffer.readUInt32BE(off); off += 4;
      }

      const n8 = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < n8; i++) {
        const id = buffer.readUInt16BE(off); off += 2;
        io[id] = Number(buffer.readBigUInt64BE(off)); off += 8;
      }

      const nx = buffer.readUInt16BE(off); off += 2;
      for (let i = 0; i < nx; i++) {
        const id = buffer.readUInt16BE(off); off += 2;
        const len = buffer.readUInt16BE(off); off += 2;
        io[id] = buffer.subarray(off, off + len).toString('hex');
        off += len;
      }

      records.push({
        imei,
        ts: new Date(Number(tsBig)).toISOString(),
        latitude,
        longitude,
        altitude,
        heading: angle,
        satellites: sats,
        speed_kmh: speed,
        priority,
        ignition: io[239] != null ? io[239] === 1 : null,
        battery_v: io[67] != null ? io[67] / 1000 : null,
        ext_v: io[66] != null ? io[66] / 1000 : null,
        protocol: 'codec8ext',
        io
      });
    }

    const numData2 = buffer.readUInt8(off); off += 1;
    if (numData1 !== numData2) {
      console.warn(`[Teltonika] numData1=${numData1} ≠ numData2=${numData2}`);
    }

    const receivedCrc = buffer.readUInt32BE(off);
    const calcCrc = crc16ibm(crcSlice);
    if (calcCrc !== (receivedCrc & 0xFFFF)) {
      console.warn(
        `[Teltonika] CRC mismatch — calc: 0x${calcCrc.toString(16).padStart(4, '0')}` +
        ` recv: 0x${(receivedCrc & 0xFFFF).toString(16).padStart(4, '0')}`
      );
      return null;
    }

    return { numRecords: numData1, records };

  } catch (err) {
    console.error('[Teltonika] Parse error:', err.message);
    return null;
  }
}

// ── GT06N PROTOCOL ────────────────────────────────────────────────
// CRC-ITU: lookup table, init=0xFFFF, final=~fcs (as per SK05S protocol doc)
const GT06_CRC_TABLE = [
  0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
  0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
  0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
  0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
  0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
  0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
  0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
  0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
  0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
  0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
  0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
  0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
  0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
  0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
  0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
  0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
  0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
  0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
  0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
  0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
  0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
  0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
  0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
  0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
  0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
  0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
];
function crc16GT06(buf) {
  let fcs = 0xFFFF;
  for (let i = 0; i < buf.length; i++) {
    fcs = (fcs >> 8) ^ GT06_CRC_TABLE[(fcs ^ buf[i]) & 0xFF];
  }
  return (~fcs) & 0xFFFF;
}

function decodeGT06IMEI(buf) {
  let s = '';
  for (let i = 0; i < 8; i++) {
    s += ((buf[i] >> 4) & 0x0F).toString();
    s += (buf[i] & 0x0F).toString();
  }
  // First nibble is padding (0), real 15-digit IMEI starts at position 1
  return s.replace(/[fF]$/, '').slice(1, 16);
}
function buildGT06ACK(proto, serial) {
  // 1. सीरियल नंबर को सुरक्षित रूप से हैंडल करें
  const sH = (serial >> 8) & 0xFF;
  const sL = serial & 0xFF;

  // 2. डेटा का वह हिस्सा जिसका CRC निकालना है (Length + Proto + Serial)
  const crcPayload = Buffer.from([0x05, proto, sH, sL]);

  // 3. CRC कैलकुलेट करें
  const crc = crc16GT06(crcPayload);
  const crcH = (crc >> 8) & 0xFF;
  const crcL = crc & 0xFF;

  // 4. पूरा 10-byte का वैध पैकेट बनाकर भेजें
  return Buffer.from([
    0x78, 0x78, // Start
    0x05,       // Length
    proto,      // Protocol
    sH, sL,     // Serial
    crcH, crcL, // CRC
    0x0D, 0x0A  // Stop
  ]);
}


function buildGT06ExtACK(proto, serial) {
  // 79 79 00 05 [proto] [serialH] [serialL] [crcH] [crcL] 0D 0A
  const pkt = Buffer.allocUnsafe(11);
  pkt[0] = 0x79; pkt[1] = 0x79;
  pkt[2] = 0x00; pkt[3] = 0x05;
  pkt[4] = proto;
  pkt[5] = (serial >> 8) & 0xFF;
  pkt[6] = serial & 0xFF;
  const crc = crc16GT06(pkt.subarray(2, 7));
  pkt[7] = (crc >> 8) & 0xFF; pkt[8] = crc & 0xFF;
  pkt[9] = 0x0D; pkt[10] = 0x0A;
  return pkt;
}

function parseGT06GPS(content, imei) {
  if (content.length < 18) return null;
  let off = 0;

  const yy = content[off++], mm = content[off++], dd = content[off++];
  const hh = content[off++], mi = content[off++], ss = content[off++];
  const ts = new Date(Date.UTC(2000 + yy, mm - 1, dd, hh, mi, ss)).toISOString();

  // Satellite byte: high nibble = GPS data length, low nibble = satellite count
  const satByte = content[off++];
  const satellites = satByte & 0x0F;

  if (content.length < off + 10) return null;
  const latRaw = content.readUInt32BE(off); off += 4;
  const lngRaw = content.readUInt32BE(off); off += 4;

  let latitude = latRaw / 1800000.0;
  let longitude = lngRaw / 1800000.0;

  const speed_kmh = content[off++];
  const statusByte = content[off++]; // bit6=ACC, bit4=GPS fix, bit3=West, bit2=North
  const headingLow = content.length > off ? content[off++] : 0;

  const heading = ((statusByte & 0x03) << 8) | headingLow;
  const ignition = !!(statusByte & 0x40); // bit 6 = ACC (ignition)
  const isWest = !!(statusByte & 0x08); // bit 3
  const isNorth = !!(statusByte & 0x04); // bit 2 (1=North, 0=South)

  if (!isNorth) latitude = -latitude;
  if (isWest) longitude = -longitude;

  return {
    imei, ts, latitude, longitude,
    altitude: 0, heading, satellites, speed_kmh,
    ignition, battery_v: null, ext_v: null,
    protocol: 'gt06', io: {}
  };
}

// ── PARSE PLAIN TEXT / OSMAND FORMAT ─────────────────────────────
function parseTextPacket(text) {
  try {
    const params = new URLSearchParams(text.trim());
    const imei = params.get('id') || params.get('imei');
    const latitude = parseFloat(params.get('lat') || params.get('latitude') || 0);
    const longitude = parseFloat(params.get('lon') || params.get('longitude') || 0);
    const speed = parseFloat(params.get('speed') || 0);
    const heading = parseFloat(params.get('heading') || params.get('bearing') || 0);
    const ignition = params.get('ignition') === '1' || params.get('ignition') === 'true';
    const battery = parseFloat(params.get('batt') || params.get('battery') || 0);

    if (!imei || !latitude || !longitude) return null;

    return {
      imei, latitude, longitude, speed_kmh: speed,
      heading, ignition, battery_v: battery,
      ts: new Date().toISOString(), protocol: 'text'
    };
  } catch {
    return null;
  }
}

// ── HAVERSINE DISTANCE (km) ───────────────────────────────────────
function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const toRad = d => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ── GPS VALIDITY CHECK ────────────────────────────────────────────
// Returns false for pings the device sends when it has no satellite fix.
// Per Teltonika spec: no-fix records have satellites=0 and speed=0;
// coordinates may be (0,0) or the last known position — both unreliable.
function isValidGPS(lat, lng, satellites, hdop = null) {
  if (lat === 0 && lng === 0) return false;            // null island
  if (Math.abs(lat) > 90 || Math.abs(lng) > 180) return false; // out of range
  if (satellites === 0) return false;                  // no satellite fix
  if (hdop != null && hdop > 50) return false;         // IO 182: HDOP×10 > 50 means HDOP > 5.0
  return true;
}

// ── GEOMETRY HELPERS ─────────────────────────────────────────────

function isInsideCircle(lat, lng, cLat, cLng, radiusM) {
  return haversineKm(lat, lng, cLat, cLng) * 1000 <= radiusM;
}

// Ray-casting algorithm for point-in-polygon
function isInsidePolygon(lat, lng, polygon) {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const xi = polygon[i].lng, yi = polygon[i].lat;
    const xj = polygon[j].lng, yj = polygon[j].lat;
    if (((yi > lat) !== (yj > lat)) &&
      (lng < (xj - xi) * (lat - yi) / (yj - yi) + xi)) {
      inside = !inside;
    }
  }
  return inside;
}

// Load active geofences for an account, cached in Redis for 60 s
async function loadGeofences(account_id) {
  const cacheKey = `geofences:${account_id}`;
  const cached = await redis.get(cacheKey);
  if (cached) return typeof cached === 'string' ? JSON.parse(cached) : cached;

  const result = await db.query(
    `SELECT id, name, geofence_type, center_lat, center_lng, radius_m,
            coordinates, trigger_on, speed_limit, color
     FROM geofences
     WHERE account_id = $1 AND is_active = true`,
    [account_id]
  );
  await redis.set(cacheKey, JSON.stringify(result.rows), { ex: 60 });
  return result.rows;
}

// ── GEOFENCE DETECTION ────────────────────────────────────────────
//
// Redis key `gf:state:{vehicle_id}` stores a map of { geofence_id: true/false }
// (true = currently inside). On first-ever ping the state is established without
// firing any event, so we don't get a spurious ENTER for a vehicle that has been
// parked inside a zone all along.

async function processGeofenceDetection(vehicle_id, account_id, data) {
  if (!vehicle_id || !account_id) return;

  const geofences = await loadGeofences(account_id);
  if (geofences.length === 0) return;

  const stateKey = `gf:state:${vehicle_id}`;
  const rawState = await redis.get(stateKey);
  const prevState = rawState
    ? (typeof rawState === 'string' ? JSON.parse(rawState) : rawState)
    : null; // null = first ping ever

  const newState = {};

  for (const gf of geofences) {
    let inside = false;
    const coords = typeof gf.coordinates === 'string'
      ? JSON.parse(gf.coordinates)
      : gf.coordinates;

    if (gf.geofence_type === 'circle') {
      inside = isInsideCircle(
        data.latitude, data.longitude,
        gf.center_lat, gf.center_lng, gf.radius_m
      );
    } else if (Array.isArray(coords) && coords.length >= 3) {
      inside = isInsidePolygon(data.latitude, data.longitude, coords);
    }

    newState[gf.id] = inside;

    if (prevState === null) continue; // first ping — just record state, no event

    const wasInside = prevState[gf.id] ?? false;
    const triggerOn = gf.trigger_on || 'both'; // 'enter', 'exit', or 'both'

    if (!wasInside && inside && (triggerOn === 'enter' || triggerOn === 'both')) {
      await fireGeofenceEvent(gf, vehicle_id, 'enter', data);
    } else if (wasInside && !inside && (triggerOn === 'exit' || triggerOn === 'both')) {
      await fireGeofenceEvent(gf, vehicle_id, 'exit', data);
    }
  }

  await redis.set(stateKey, JSON.stringify(newState), { ex: 86400 });
}

async function fireGeofenceEvent(gf, vehicle_id, event_type, data) {
  await db.query(
    `INSERT INTO geofence_events
       (geofence_id, vehicle_id, event_type, lat, lng, occurred_at)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [gf.id, vehicle_id, event_type, data.latitude, data.longitude, data.ts]
  );

  await triggerAlert(vehicle_id, `geofence_${event_type}`, 'info',
    gf.name, data.latitude, data.longitude);

  await redis.publish(`geofence:${vehicle_id}`, JSON.stringify({
    event_type, geofence_id: gf.id, geofence_name: gf.name,
    lat: data.latitude, lng: data.longitude, ts: data.ts
  }));

  console.log(`🔲 Geofence ${event_type.toUpperCase()} — Vehicle: ${vehicle_id} | Zone: "${gf.name}"`);
}

// ── TRIP DETECTION CONFIG ─────────────────────────────────────────
//
// Server-side defaults — used when the device does not send the
// corresponding IO element in its AVL packet.
const DEFAULTS = {
  tripMinSpeed: 3,    // km/h — movement threshold & idle detection
  tripMaxJumpKm: 2,    // km   — GPS glitch guard (never device-overridden)
  overspeedThreshold: 60,   // km/h — overspeed alert & counter
  harshBrakeThreshold: 25,   // km/h drop between consecutive pings
  fuelLPerKm: 0.10, // L/km while moving
  fuelIdleLPerHour: 0.50, // L/h  while idling
  excessiveIdleMinutes: 5,    // minutes of continuous idle before alert fires
  tripEndDebounceSec: 180,  // seconds ignition-off must hold before trip closes
};

// Map each setting to the Teltonika AVL IO ID that carries it.
// Set to null to always use the server default for that setting.
// Update these IDs to match your Teltonika Configurator setup.
const IO_CONFIG_IDS = {
  // AVL 183 is the current speed reading, NOT a speed-limit threshold — leave null
  // To override, set this to the IO ID your device uses for configured speed limit
  overspeedThreshold: null,
  harshBrakeThreshold: null,
  tripMinSpeed: null,
  fuelLPerKm: null,
  fuelIdleLPerHour: null,
  excessiveIdleMinutes: null,
  tripEndDebounceSec: null,
};

// Merge device IO values with server defaults.
// data.io is the IO element map from the parsed AVL packet.
function resolveConfig(io = {}) {
  const pick = (id, fallback) =>
    (id != null && io[id] != null) ? Number(io[id]) : fallback;

  return {
    tripMinSpeed: pick(IO_CONFIG_IDS.tripMinSpeed, DEFAULTS.tripMinSpeed),
    tripMaxJumpKm: DEFAULTS.tripMaxJumpKm,
    overspeedThreshold: pick(IO_CONFIG_IDS.overspeedThreshold, DEFAULTS.overspeedThreshold),
    harshBrakeThreshold: pick(IO_CONFIG_IDS.harshBrakeThreshold, DEFAULTS.harshBrakeThreshold),
    fuelLPerKm: pick(IO_CONFIG_IDS.fuelLPerKm, DEFAULTS.fuelLPerKm),
    fuelIdleLPerHour: pick(IO_CONFIG_IDS.fuelIdleLPerHour, DEFAULTS.fuelIdleLPerHour),
    excessiveIdleMinutes: pick(IO_CONFIG_IDS.excessiveIdleMinutes, DEFAULTS.excessiveIdleMinutes),
    tripEndDebounceSec: pick(IO_CONFIG_IDS.tripEndDebounceSec, DEFAULTS.tripEndDebounceSec),
  };
}

async function processTripDetection(device_id, vehicle_id, data, cfg) {
  if (!vehicle_id) return;

  const stateKey = `trip:active:${device_id}`;

  const raw = await redis.get(stateKey);
  const tripState = raw
    ? (typeof raw === 'string' ? JSON.parse(raw) : raw)
    : null;

  // null means AVL 239 was not present in this packet — don't treat as OFF
  const ignitionKnown = data.ignition === true || data.ignition === false;
  const isMoving = data.speed_kmh >= cfg.tripMinSpeed;
  const wantsStart = ignitionKnown ? data.ignition === true : isMoving;
  const wantsEnd = ignitionKnown ? data.ignition === false : !isMoving;

  // ── START ─────────────────────────────────────────────────────
  if (wantsStart && !tripState) {
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
      trip_id: result.rows[0].id,
      start_ts: data.ts,
      last_lat: data.latitude,
      last_lng: data.longitude,
      last_ts: data.ts,
      distance_km: 0,
      max_speed: data.speed_kmh,
      idle_seconds: 0,
      harsh_braking: 0,
      overspeeds: 0,
      in_overspeed: data.speed_kmh > cfg.overspeedThreshold,
      prev_speed: data.speed_kmh,
      idle_start_ts: null,
      idle_alerted: false,
      end_candidate_ts: null,  // set when ignition-off debounce begins
    };

    await redis.set(stateKey, JSON.stringify(newState), { ex: 86400 });
    console.log(`🚗 Trip STARTED — Vehicle: ${vehicle_id} | Trip ID: ${newState.trip_id}`);
    return;
  }

  // ── UPDATE / DEBOUNCE-END ────────────────────────────────────
  if (tripState) {
    // Skip out-of-order records (device buffer uploads arriving late)
    if (new Date(data.ts) < new Date(tripState.last_ts)) {
      return;
    }

    // Vehicle resumed (ignition on or moving) — cancel any pending end
    if (wantsStart && tripState.end_candidate_ts) {
      tripState.end_candidate_ts = null;
    }

    // Ignition off / stopped — start debounce window if not already started
    if (wantsEnd && !tripState.end_candidate_ts) {
      tripState.end_candidate_ts = data.ts;
    }

    // Accumulate stats regardless of debounce state
    const segSec = Math.max(0, (new Date(data.ts) - new Date(tripState.last_ts)) / 1000);

    const seg = haversineKm(
      tripState.last_lat, tripState.last_lng,
      data.latitude, data.longitude
    );
    if (seg <= cfg.tripMaxJumpKm) {
      tripState.distance_km += seg;
    }

    if (data.speed_kmh > tripState.max_speed) {
      tripState.max_speed = data.speed_kmh;
    }

    if (data.speed_kmh < cfg.tripMinSpeed) {
      tripState.idle_seconds += segSec;

      if (!tripState.idle_start_ts) {
        tripState.idle_start_ts = data.ts;
        tripState.idle_alerted = false;
      }

      const continuousIdleSec =
        (new Date(data.ts) - new Date(tripState.idle_start_ts)) / 1000;

      if (continuousIdleSec >= cfg.excessiveIdleMinutes * 60 && !tripState.idle_alerted) {
        await triggerAlert(
          vehicle_id, 'excessive_idle', 'warning',
          parseFloat((continuousIdleSec / 60).toFixed(1)),
          data.latitude, data.longitude
        );
        tripState.idle_alerted = true;
        console.log(
          `⏸️  Excessive idle — Vehicle: ${vehicle_id} | ` +
          `${(continuousIdleSec / 60).toFixed(1)} min at ` +
          `${data.latitude.toFixed(5)},${data.longitude.toFixed(5)}`
        );
      }
    } else {
      tripState.idle_start_ts = null;
      tripState.idle_alerted = false;
    }

    const speedDrop = tripState.prev_speed - data.speed_kmh;
    if (speedDrop >= cfg.harshBrakeThreshold && tripState.prev_speed > 10) {
      tripState.harsh_braking++;
    }

    if (data.speed_kmh > cfg.overspeedThreshold) {
      if (!tripState.in_overspeed) {
        tripState.overspeeds++;
        tripState.in_overspeed = true;
      }
    } else {
      tripState.in_overspeed = false;
    }

    tripState.prev_speed = data.speed_kmh;
    tripState.last_lat = data.latitude;
    tripState.last_lng = data.longitude;
    tripState.last_ts = data.ts;

    // Check whether the debounce window has expired → close trip
    if (tripState.end_candidate_ts) {
      const debounceElapsed =
        (new Date(data.ts) - new Date(tripState.end_candidate_ts)) / 1000;

      if (debounceElapsed >= cfg.tripEndDebounceSec) {
        const duration_sec = Math.max(
          0,
          Math.round((new Date(data.ts) - new Date(tripState.start_ts)) / 1000)
        );

        const avg_speed_kmh = duration_sec > 0
          ? parseFloat((tripState.distance_km / (duration_sec / 3600)).toFixed(2))
          : 0;

        const idle_minutes = parseFloat((tripState.idle_seconds / 60).toFixed(2));

        const fuel_used_l = parseFloat((
          tripState.distance_km * cfg.fuelLPerKm +
          (tripState.idle_seconds / 3600) * cfg.fuelIdleLPerHour
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
        return;
      }
    }

    await redis.set(stateKey, JSON.stringify(tripState), { ex: 86400 });
  }
}

// ── SAVE GPS PING TO DATABASE + REDIS ────────────────────────────
async function savePing(data) {
  try {
    const deviceResult = await db.query(
      `SELECT d.id AS device_id, v.id AS vehicle_id, v.account_id
       FROM devices d
       LEFT JOIN vehicles v ON v.device_id = d.id
       WHERE d.imei = $1 AND d.is_active = true`,
      [data.imei]
    );

    if (deviceResult.rows.length === 0) {
      console.log(`⚠️  Unknown device IMEI: ${data.imei}`);
      return;
    }

    const { device_id, vehicle_id, account_id } = deviceResult.rows[0];

    // Resolve per-ping config from device IO values, falling back to server defaults
    const cfg = resolveConfig(data.io);


    const hdop = data.io[182] != null ? data.io[182] : null;
    const gpsValid = isValidGPS(data.latitude, data.longitude, data.satellites, hdop);

    await db.query(
      `INSERT INTO gps_pings
         (device_id, ts, latitude, longitude, speed_kmh,
          heading, ignition, battery_v, satellites, is_valid)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [device_id, data.ts, data.latitude, data.longitude,
        data.speed_kmh || 0, data.heading || 0,
        data.ignition || false, data.battery_v || null,
        data.satellites ?? null, gpsValid]
    );

    if (!gpsValid) {
      console.log(`📵 No-fix ping saved (invalid) — IMEI: ${data.imei} | Sats: ${data.satellites ?? '?'}`);
      return;
    }

    // Store last known valid position for GT06N heartbeat-based trip/idle detection
    // Only update if this ping is newer than what's stored (skip out-of-order records)
    const rawExistingPos = await redis.get(`device:lastpos:${data.imei}`);
    const existingPos = rawExistingPos
      ? (typeof rawExistingPos === 'string' ? JSON.parse(rawExistingPos) : rawExistingPos)
      : null;
    if (!existingPos || new Date(data.ts) >= new Date(existingPos.ts)) {
      await redis.set(`device:lastpos:${data.imei}`, JSON.stringify({
        lat: data.latitude,
        lng: data.longitude,
        ts: data.ts,
        speed: data.speed_kmh
      }), { ex: 86400 });
    }

    await redis.set(`device:lastping:${data.imei}`, Date.now().toString(), { ex: 7200 });
    await redis.set(`device:acc:${data.imei}`, data.ignition ? 'on' : 'off', { ex: 86400 });

    // GPS jump detection: implied speed > 200 km/h between two valid pings = spoof or jump
    if (existingPos && vehicle_id) {
      const timeDiffMin = (new Date(data.ts) - new Date(existingPos.ts)) / 60000;
      if (timeDiffMin > 0 && timeDiffMin < 10) {
        const distKm = haversineKm(existingPos.lat, existingPos.lng, data.latitude, data.longitude);
        if ((distKm / (timeDiffMin / 60)) > 200) {
          await triggerAlert(vehicle_id, 'gps_jump', 'warning',
            Math.round(distKm / (timeDiffMin / 60)), data.latitude, data.longitude);
        }
      }
    }

    // Reset excessive idle alert when vehicle is moving again
    if (data.speed_kmh >= DEFAULTS.tripMinSpeed && vehicle_id) {
      await redis.del(`idle:alerted:${vehicle_id}`);
    }

    const liveData = {
      lat: data.latitude,
      lng: data.longitude,
      speed: data.speed_kmh || 0,
      heading: data.heading || 0,
      ignition: data.ignition || false,
      battery: data.battery_v || null,
      ts: data.ts
    };

    // Only update live position if this ping is newer than stored (skip out-of-order)
    if (!existingPos || new Date(data.ts) >= new Date(existingPos.ts)) {
      await redis.set(`device:${data.imei}`, JSON.stringify(liveData), { ex: 300 });
    }

    if (vehicle_id && data.speed_kmh > cfg.overspeedThreshold) {
      await triggerAlert(vehicle_id, 'overspeed', 'warning', data.speed_kmh,
        data.latitude, data.longitude);
    }

    // Tow detection: vehicle moving with ignition explicitly OFF
    if (vehicle_id && data.ignition === false && (data.speed_kmh || 0) >= 5) {
      await triggerAlert(vehicle_id, 'tow_alert', 'critical', data.speed_kmh || 0,
        data.latitude, data.longitude);
    }

    // Trip and geofence detection are non-critical — Redis failures must not prevent ping save
    try {
      await processTripDetection(device_id, vehicle_id, data, cfg);
    } catch (tripErr) {
      console.warn(`⚠️  Trip detection skipped for ${data.imei}:`, tripErr.message);
    }

    try {
      await processGeofenceDetection(vehicle_id, account_id, data);
    } catch (gfErr) {
      console.warn(`⚠️  Geofence detection skipped for ${data.imei}:`, gfErr.message);
    }

    console.log(
      `📍 Ping — IMEI: ${data.imei} | ` +
      `${data.latitude.toFixed(6)},${data.longitude.toFixed(6)} | ` +
      `Speed: ${data.speed_kmh} km/h | Ignition: ${data.ignition ? 'ON' : 'OFF'} | ` +
      `Proto: ${data.protocol} | ` +
      `Time: ${new Date(data.ts).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false })}`
    );

  } catch (err) {
    console.error('❌ Save ping error:', err.message, err.stack);
  }
}

// ── TRIGGER ALERT ─────────────────────────────────────────────────
async function triggerAlert(vehicle_id, alert_type, severity, value, lat, lng) {
  try {
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

    // सर्वर साइड टाइमआउट और कीप-अलाइव को एकदम परफेक्ट सेट करें
    socket.setTimeout(0);
    socket.setKeepAlive(true, 60000);
    socket.setNoDelay(true);

    let imei = null;
    let buf = Buffer.alloc(0);
    let textMode = false;
    let gt06Mode = false;
    const pktCount = { login: 0, gps: 0, hb: 0, alarm: 0, other: 0 };

    const MAX_BUF = 65_536; // 64 KB

    socket.on('data', async (chunk) => {
      try {
        buf = Buffer.concat([buf, chunk]);

        if (buf.length > MAX_BUF) {
          console.warn(`[GPS] Buffer overflow from ${imei || clientIP} — closing`);
          socket.destroy();
          return;
        }

        if (!imei && !textMode && !gt06Mode) {
          if (buf.length >= 2 && buf[0] === 0x78 && buf[1] === 0x78) {
            gt06Mode = true;
          } else {
            const preview = buf.toString('utf8');
            if (preview.includes('lat=') || preview.includes('id=')) {
              textMode = true;
            }
          }
        }

        if (gt06Mode) {
          while (buf.length >= 6) {

            // ── 1. Packet type detect ──────────────────────
            const isShort = buf[0] === 0x78 && buf[1] === 0x78;
            const isLong = buf[0] === 0x79 && buf[1] === 0x79;

            if (!isShort && !isLong) {
              buf = buf.subarray(1);
              continue;
            }

            // ── 2. Length calculate ────────────────────────
            let len, totalLen;
            if (isShort) {
              len = buf[2];
              totalLen = len + 5;
            } else {
              len = buf.readUInt16BE(2);
              totalLen = len + 6;
            }

            // ── 3. Full packet aaya? ───────────────────────
            if (buf.length < totalLen) break;

            // ── 4. Packet extract ──────────────────────────
            const pkt = buf.subarray(0, totalLen);
            buf = buf.subarray(totalLen);

            // ── 5. Fields parse ────────────────────────────
            let proto, content, crcCalc;
            if (isShort) {
              proto = pkt[3];
              content = pkt.subarray(4, pkt.length - 6);
              crcCalc = crc16GT06(pkt.subarray(2, pkt.length - 4));
            } else {
              proto = pkt[4];
              content = pkt.subarray(5, pkt.length - 6);
              crcCalc = crc16GT06(pkt.subarray(2, pkt.length - 4));
            }

            const serial = pkt.readUInt16BE(pkt.length - 6);
            const crcRecv = pkt.readUInt16BE(pkt.length - 4);

            // ── 6. CRC verify ─────────────────────────────
            if (crcCalc !== crcRecv) {
              console.warn(`[GT06] CRC fail — proto:0x${proto.toString(16).padStart(2, '0')} calc:${crcCalc.toString(16)} recv:${crcRecv.toString(16)}`);
              continue;
            }

            // ── 7. 🚀 ARCHITECTURAL COLLISION FIX (100% FIXED) ──────────────────
            const protoNum = Number(proto);

            // हमेशा कटे हुए सिंगल पैकेट 'pkt' का आकार जांचें, पूरे 'chunk' का नहीं
            if (pkt.length >= 10) {

              if ([0x01, 0x13, 19, 0x16, 0x22, 0x94, 148].includes(protoNum)) {

                // बिल्कुल सही पैकेट (pkt) के अंत से सीरियल और CRC काटें
                const serialH = pkt[pkt.length - 6];
                const serialL = pkt[pkt.length - 5];
                const crcH = pkt[pkt.length - 4];
                const crcL = pkt[pkt.length - 3];

                // प्रोटोकॉल नंबर को फिक्स करें
                let actualProto = protoNum;
                if (protoNum === 19) actualProto = 0x13;
                if (protoNum === 148) actualProto = 0x94;

                const dynamicAck = Buffer.from([
                  0x78, 0x78,
                  0x05,
                  actualProto,
                  serialH, serialL,
                  crcH, crcL,
                  0x0D, 0x0A
                ]);

                // बफ़र ओवरलैप को रोकने के लिए तुरंत फ्लश करें (कॉलबैक के साथ)
                socket.write(dynamicAck, 'binary', () => {
                  console.log(`[🟢 FLUSHED TO WIRE] ACK for 0x${actualProto.toString(16)} successfully sent.`);
                });
              }
              else if (isLong) {
                const extAck = buildGT06ExtACK(proto, serial);
                socket.write(extAck, 'binary', () => { });
              }

            }

            // ── इसके नीचे का कोड आपके Part 2 में आएगा ──────────────────
            // ── PART 2: PROTOCOL ROUTING & PARSING ───────────────────────────
            if (proto === 0x01) {
              pktCount.login++;
              imei = decodeGT06IMEI(content.subarray(0, 8));
              clients.set(imei, { socket, lastSeen: Date.now() });
              console.log(`🔑 Login — IMEI: ${imei} | IP: ${clientIP}`);

              // ── 0x12 / 0x22 GPS LOCATION PACKETS ──────────────────────────
            } else if (proto === 0x12 || proto === 0x22) {
              pktCount.gps++;

              const maybeCount = content[0];
              const isMultiRecord = proto === 0x22 ||
                (maybeCount >= 1 && maybeCount <= 20 && content.length === 1 + maybeCount * 18);

              if (isMultiRecord) {
                const recordCount = maybeCount;
                console.log(`📦 Buffered GPS — IMEI: ${imei} | Records: ${recordCount}`);

                for (let i = 0; i < recordCount; i++) {
                  const recordStart = 1 + i * 18;
                  if (recordStart + 18 > content.length) break;

                  const record = content.subarray(recordStart, recordStart + 18);

                  // पूरे पार्सिंग और डेटाबेस ऑपरेशन को मुख्य सॉकेट थ्रेड से अलग करें
                  try {
                    const data = parseGT06GPS(record, imei);
                    if (data) {
                      data.protocol = 'gt06_buffered';
                      const gpsTime = new Date(data.ts).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
                      console.log(`  ↳ Record ${i + 1}/${recordCount} | Time: ${gpsTime} | Lat: ${data.latitude} | Lng: ${data.longitude}`);

                      // setTimeout(..., 0) हैवी डेटाबेस टास्क को लूप ब्लॉक से मुक्त रखता है
                      setTimeout(async () => {
                        try { savePing(data); }
                        catch (err) { console.error('[Safe DB Catch] Buffered savePing Error:', err.message); }
                      }, 200);
                    } else {
                      console.warn(`[GT06] Buffered record ${i + 1} parse fail — hex: ${record.toString('hex')}`);
                    }
                  } catch (parseInnerErr) {
                    console.error(`[GT06 Exception Handled] Buffered loop bypass:`, parseInnerErr.message);
                  }
                }
              } else {
                // Single real-time record (रियल-टाइम लोकेशन)
                try {
                  const data = parseGT06GPS(content, imei);
                  if (data) {
                    const recvTime = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
                    const gpsTime = new Date(data.ts).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
                    const delayMin = ((Date.now() - new Date(data.ts).getTime()) / 60000).toFixed(1);

                    if (pktCount.gps === 1) {
                      console.log(`🚗 Movement — IMEI: ${imei} | GPS time: ${gpsTime} | Delay: ${delayMin} min`);
                    }
                    console.log(`📍 GPS record — IMEI: ${imei} | Time: ${recvTime} | Lat: ${data.latitude} | Lng: ${data.longitude}`);

                    // सॉकेट थ्रेड को फ्री रखने के लिए एसिंक्रोनस आइसोलेशन
                    setTimeout(async () => {
                      try { savePing(data); }
                      catch (err) { console.error('[Safe DB Catch] Realtime savePing Error:', err.message); }
                    }, 200);
                  } else {
                    console.warn(`[GT06] GPS parse fail — IMEI: ${imei} | hex: ${content.toString('hex')}`);
                  }
                } catch (realtimeParseErr) {
                  console.error('[GT06 Exception Handled] Realtime parse bypass:', realtimeParseErr.message);
                }
              }

              // ── इसके नीचे आपका अगला पार्ट (Heartbeat 0x13 और बाकी कंडीशंस) आएगा ──
              // ── PART 3: 0x13 HEARTBEAT PACKET ROUTING ────────────────────────
            } else if (proto === 0x13 || proto === 19) {
              pktCount.hb++;

              const termInfo = content[0] ?? 0;
              const gpsFix = !!(termInfo & 0x40);
              const acc = !!(termInfo & 0x02);
              const voltLevel = content[1] ?? '?';
              const signal = content[2] ?? '?';
              const hbTime = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });

              console.log(`💓 Heartbeat — IMEI: ${imei} | GPS: ${gpsFix ? 'Fix✅' : 'No Fix❌'} | ACC: ${acc ? 'ON' : 'OFF'} | Signal: ${signal} | Volt: ${voltLevel} | Time: ${hbTime}`);

              // ── डेटाबेस और रेडिस का भारी काम सुरक्षित थ्रेड में वापस शुरू (Uncommented & Secured) ──
              setTimeout(async () => {
                try {
                  if (!imei) return;

                  // 1. रेडिस पिंग अपडेट (सुरक्षित कैच के साथ)
                  await redis.set(`device:lastping:${imei}`, Date.now().toString(), { ex: 7200 }).catch(e => null);

                  const rawLastPos = await redis.get(`device:lastpos:${imei}`).catch(e => null);
                  if (!rawLastPos) {
                    console.log(`[HB] No lastpos for ${imei} — skipping DB operations safely`);
                    return;
                  }

                  const lastPos = typeof rawLastPos === 'string' ? JSON.parse(rawLastPos) : rawLastPos;

                  // 2. डेटाबेस क्वेरी
                  const devRes = await db.query(
                    `SELECT d.id AS device_id, v.id AS vehicle_id
                     FROM devices d LEFT JOIN vehicles v ON v.device_id = d.id
                     WHERE d.imei = $1 AND d.is_active = true`, [imei]
                  ).catch(e => { console.error('[HB DB Query Error]:', e.message); return { rows: [] }; });

                  if (!devRes || !devRes.rows || !devRes.rows.length) return;
                  const { device_id, vehicle_id } = devRes.rows[0];

                  // 3. Ignition State Change (इग्निशन स्थिति में बदलाव)
                  const prevAccRaw = await redis.get(`device:acc:${imei}`).catch(e => null);
                  const prevAcc = prevAccRaw === 'on';

                  if (acc !== prevAcc) {
                    await redis.set(`device:acc:${imei}`, acc ? 'on' : 'off', { ex: 86400 }).catch(e => null);

                    try {
                      await savePing({
                        imei, ts: new Date().toISOString(),
                        latitude: lastPos.lat, longitude: lastPos.lng,
                        speed_kmh: 0, heading: 0, ignition: acc,
                        battery_v: null, satellites: null, altitude: 0,
                        protocol: 'gt06_heartbeat', io: {}
                      });

                      if (vehicle_id) {
                        await db.query(
                          `INSERT INTO alerts (vehicle_id, alert_type, severity, value, latitude, longitude)
                           VALUES ($1,$2,$3,$4,$5,$6)`,
                          [vehicle_id, acc ? 'ignition_on' : 'ignition_off', 'info',
                            acc ? 1 : 0, lastPos.lat, lastPos.lng]
                        );
                        console.log(`🔑 Ignition ${acc ? 'ON' : 'OFF'} — IMEI: ${imei}`);
                      }
                    } catch (saveErr) {
                      console.error('[HB Internal Save Error]:', saveErr.message);
                    }
                  }

                  // 4. Trip Detection (ट्रिप डिटेक्शन)
                  const cfg = resolveConfig({});
                  const tripRaw = await redis.get(`trip:active:${device_id}`).catch(e => null);
                  if (tripRaw) {
                    const hbData = {
                      imei, ts: new Date().toISOString(),
                      latitude: lastPos.lat, longitude: lastPos.lng,
                      speed_kmh: 0, heading: 0, ignition: acc,
                      battery_v: null, satellites: null,
                      protocol: 'gt06_heartbeat', io: {}
                    };
                    try { await processTripDetection(device_id, vehicle_id, hbData, cfg); }
                    catch (e) { console.error('[HB] Trip detection error:', e.message); }
                  }

                  // 5. Excessive Idle (अत्यधिक आइडल चेतावनी)
                  if (acc && vehicle_id) {
                    const gapMin = (Date.now() - new Date(lastPos.ts).getTime()) / 60000;
                    if (gapMin >= cfg.excessiveIdleMinutes) {
                      const alertedKey = `idle:alerted:${vehicle_id}`;
                      const alreadyAlerted = await redis.get(alertedKey).catch(e => null);
                      if (!alreadyAlerted) {
                        try {
                          await triggerAlert(vehicle_id, 'excessive_idle', 'warning',
                            parseFloat(gapMin.toFixed(1)), lastPos.lat, lastPos.lng);
                          await redis.set(alertedKey, '1', { ex: 3600 }).catch(e => null);
                          console.log(`⏸️  Excessive idle — Vehicle: ${vehicle_id} | ${gapMin.toFixed(1)} min`);
                        } catch (alertErr) {
                          console.error('[HB Idle Alert Error]:', alertErr.message);
                        }
                      }
                    }
                  }

                  // 6. Live Position Update (लाइव पोजीशन अपडेट)
                  const gapFromLastGps = (Date.now() - new Date(lastPos.ts).getTime()) / 60000;
                  if (!acc || gapFromLastGps > 2) {
                    await redis.set(`device:${imei}`, JSON.stringify({
                      lat: lastPos.lat, lng: lastPos.lng,
                      speed: 0, heading: 0, ignition: acc,
                      battery: null, ts: new Date().toISOString()
                    }), { ex: 300 }).catch(e => null);
                  }

                } catch (err) {
                  console.error(`[HB Isolated Catch Error] IMEI: ${imei}:`, err.message);
                }
              }, 0);
            }
          } // while लूप का अंत
        } // gt06Mode का अंत
      } catch (globalSocketError) {
        console.error(`[Global Socket Parser Error]:`, globalSocketError.message);
      }
    }); // socket.on('data') का अंत

    // ── 💡 नेटवर्क एरर को म्यूट करें (खड़ी गाड़ी का नॉर्मल डिस्कनेक्शन इग्नोर करें) ──
    socket.on('error', (err) => {
      if (err.code === 'ECONNRESET') return; // स्क्रीन पर लाल रंग की एरर आना बंद हो जाएगी
      console.error(`[-] Real Socket Error from ${clientIP}:`, err.message);
    });

    socket.on('close', () => {
      console.log(`[-] Device disconnected: ${clientIP} | Logs:`, pktCount);
    });
  }); // net.createServer का अंत

  server.listen(port, () => {
    console.log(`🚀 GT06 GPS Service listening perfectly on port ${port}`);
  });
}



module.exports = { startGPSServer };