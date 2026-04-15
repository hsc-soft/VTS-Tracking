const { Redis } = require('@upstash/redis');
require('dotenv').config();

console.log('UPSTASH URL:', process.env.UPSTASH_REDIS_REST_URL);
console.log('UPSTASH TOKEN:', process.env.UPSTASH_REDIS_REST_TOKEN ? 'EXISTS' : 'MISSING');

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

console.log('✅ Upstash Redis initialized!');

module.exports = redis;