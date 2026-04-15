const { Pool } = require('pg');

const db = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:Soniya@7597330400@db.tbuyphhjihmufrunxuon.supabase.co:5432/postgres',
  ssl: { rejectUnauthorized: false }
});

db.connect()
  .then(() => console.log('✅ Supabase PostgreSQL connected!'))
  .catch(err => console.error('❌ Database connection error:', err.message));

module.exports = db;