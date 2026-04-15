const Redis = require('ioredis');
require('dotenv').config();

const redis = new Redis(process.env.REDIS_URL, {
  tls: {},
  maxRetriesPerRequest: 3,
  retryStrategy(times) {
    return Math.min(times * 100, 3000);
  }
});

redis.on('connect', () => console.log('✅ Upstash Redis connected!'));
redis.on('error',   (err) => console.error('❌ Redis error:', err.message));

module.exports = redis;