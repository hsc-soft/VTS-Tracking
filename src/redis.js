const { Redis } = require('@upstash/redis');

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL || 'https://logical-calf-68263.upstash.io',
  token: process.env.UPSTASH_REDIS_REST_TOKEN || 'gQAAAAAAAAQqnAAIncDI1MmE3MTJiMWJlMjk0MGQ5YjBmMmQzNDAzMTAyMWYxM3AyNjgyNjM',
});

module.exports = redis;