require('dotenv').config();
const express = require('express');
const cors    = require('cors');

const { startGPSServer } = require('./gpsServer');

const authRoutes     = require('./routes/auth');
const vehicleRoutes  = require('./routes/vehicles');
const alertRoutes    = require('./routes/alerts');

const app = express();

// ── MIDDLEWARE ────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── ROUTES ────────────────────────────────────────
app.use('/api/auth',     authRoutes);
app.use('/api/vehicles', vehicleRoutes);
app.use('/api/alerts',   alertRoutes);

// ── HEALTH CHECK ──────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    name:    'AegisTrack API',
    status:  'running',
    version: '1.0.0',
    time:    new Date().toISOString()
  });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// ── 404 HANDLER ───────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found.' });
});

// ── START HTTP SERVER ─────────────────────────────
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 AegisTrack API running on http://localhost:${PORT}`);
});

// ── START GPS TCP SERVER ──────────────────────────
const GPS_PORT = process.env.GPS_TCP_PORT || 5023;
startGPSServer(parseInt(GPS_PORT));