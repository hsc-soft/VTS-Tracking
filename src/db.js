const { Pool } = require('pg');

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

db.connect()
  .then(() => console.log('✅ Supabase PostgreSQL connected!'))
  .catch(err => console.error('❌ Database connection error:', err.message));

module.exports = db;