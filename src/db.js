const { Pool } = require('pg');

const db = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres.tbuyphhjihmufrunxuon:Soniya@7597330400@aws-1-ap-south-1.pooler.supabase.com:6543/postgres',
  ssl: { rejectUnauthorized: false }
});

db.connect()
  .then(() => console.log('✅ Supabase PostgreSQL connected!'))
  .catch(err => console.error('❌ Database connection error:', err.message));

module.exports = db;