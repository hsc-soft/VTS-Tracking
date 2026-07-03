# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev       # Development (nodemon auto-restart)
npm start         # Production (node src/index.js)
pm2 restart aegistrack  # Restart on Ubuntu server (PM2 process name)
pm2 logs aegistrack     # Live logs on server
```

## Architecture

Single Node.js process runs two servers simultaneously:

- **HTTP API** (`src/index.js`) — Express 5 on port `$PORT` (default 8080)
- **GPS TCP Server** (`src/gpsServer.js`) — `net.createServer` on port `$GPS_TCP_PORT` (default 5023)

### Data Layer

- **PostgreSQL** — Supabase, accessed via `pg.Pool` (`src/db.js`). All persistent data: vehicles, devices, gps_pings, alerts, trips, geofences.
- **Redis** — Upstash REST client (`@upstash/redis`) in `src/redis.js`. **Important**: Upstash returns already-parsed objects, not JSON strings. Always use `typeof val === 'string' ? JSON.parse(val) : val` when reading stored JSON.

### Redis Key Schema

| Key | TTL | Purpose |
|-----|-----|---------|
| `device:{imei}` | 300s | Live map position (lat/lng/speed/heading/ignition/ts) |
| `device:lastpos:{imei}` | 86400s | Last valid GPS fix (used by heartbeat logic) |
| `device:lastping:{imei}` | 7200s | Last contact timestamp (unix ms string) |
| `device:acc:{imei}` | 86400s | ACC/ignition state (`'on'` or `'off'`) |
| `trip:active:{device_id}` | — | Active trip data |
| `gf:state:{vehicle_id}` | — | Geofence presence state |
| `idle:alerted:{vehicle_id}` | 3600s | Excessive idle alert dedup flag |

### GPS Server Protocol Handling (`src/gpsServer.js`)

Each TCP connection auto-detects protocol from the first packet:

**GT06N** (SK05S device) — binary framing:
- Short packet: `78 78 [L] [proto] [...content...] [serial 2B] [CRC 2B] 0D 0A`
- Extended packet: `79 79 [L_H][L_L] [proto] [...content...] [serial 2B] [CRC 2B] 0D 0A`
- CRC: CRC-ITU (lookup table, init=`0xFFFF`, final=`~fcs & 0xFFFF`)
- `79 79` packets get `buildGT06ExtACK` (11 bytes); `78 78` packets get `buildGT06ACK` (10 bytes)
- Protocol Rule: Login (0x01) and Heartbeat (0x13) MUST get ACK within 5 seconds or device disconnects

Key GT06N proto handlers:
- `0x01` Login — extracts 15-digit IMEI from 8-byte BCD content
- `0x12` / `0x22` GPS — single or multi-record; `parseGT06GPS()` decodes 18-byte GPS record
- `0x13` Heartbeat — terminal info byte: bit6=GPS fix, bit1=ACC; triggers ignition change detection, trip detection, excessive idle, live position update via `setImmediate`
- `0x16` Alarm — GPS data (same 18B as 0x12) + LBS + alarm type at `content[22 + lbsLen]` where `lbsLen = content[18]`
- `0x94` ICCID — extended (79 79) format only; protocol says server does NOT need to reply, but ExtACK is harmless

**Teltonika Codec8 Extended** — `parseCodec8Extended()`, CRC-16/IBM (poly=0x8005)

### savePing Flow

`savePing(data)` is the central function called by all GPS/alarm/heartbeat handlers:
1. Lookup `device_id` / `vehicle_id` / `account_id` from DB by IMEI
2. INSERT into `gps_pings` (marks `is_valid=false` if no GPS fix)
3. Update `device:lastpos:{imei}` and `device:lastping:{imei}` and `device:acc:{imei}` in Redis
4. GPS jump detection (implied speed >200 km/h between pings → `gps_jump` alert)
5. Update live position `device:{imei}` in Redis
6. Overspeed and tow alerts
7. Call `processTripDetection()` for trip start/end logic

### HTTP API Routes

All routes under `/api/` require JWT Bearer token (`src/middleware/auth.js`). JWT payload contains `account_id`.

- `POST /api/auth/register` / `POST /api/auth/login`
- `GET|POST|PUT|DELETE /api/vehicles`
- `GET /api/alerts`
- `GET|POST|PUT|DELETE /api/geofences`

### Device Configuration (SK05S)

Current device settings: `TIMER:10,60;SENDS:1;HBT:3,5`
- `TIMER:10,60` — upload every 10s when vehicle running; every 60s when vehicle stopped (NOT GPS record interval)
- `SENDS:1` — short-TCP mode: connect → login → GPS data → disconnect (ECONNRESET is normal, NOT a bug)
- `HBT:3,5` — heartbeat every 3 min when stationary; must get ACK within 5s or device reconnects
- `0x22` is NOT in the official SK05S protocol document; device uses it as firmware extension for stored/buffered GPS (same 18-byte format as 0x12)
- 32-minute GPS delay = documented behavior (protocol sec 5.2.2): device stores records when GSM signal is weak, uploads them all after vehicle stops
