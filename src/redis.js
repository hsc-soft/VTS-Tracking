const Redis = require('ioredis');
require('dotenv').config();

const redis = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  retryStrategy(times) {
    return Math.min(times * 100, 3000);
  },
  tls: {
    rejectUnauthorized: false
  }
});

redis.on('connect', () => console.log('✅ Upstash Redis connected!'));
redis.on('error', (err) => console.error('❌ Redis error:', err.message));

module.exports = redis;