const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const db      = require('../db');

// ── REGISTER ─────────────────────────────────────
router.post('/register', async (req, res) => {
  const { company_name, email, phone, password } = req.body;

  if (!company_name || !email || !password) {
    return res.status(400).json({ error: 'company_name, email and password are required.' });
  }

  try {
    // Create account
    const accountResult = await db.query(
      `INSERT INTO accounts (company_name, email, phone)
       VALUES ($1, $2, $3) RETURNING id`,
      [company_name, email, phone]
    );
    const account_id = accountResult.rows[0].id;

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Create owner user
    const userResult = await db.query(
      `INSERT INTO users (account_id, name, email, password_hash, role)
       VALUES ($1, $2, $3, $4, 'owner') RETURNING id, name, email, role`,
      [account_id, company_name, email, password_hash]
    );

    const user = userResult.rows[0];
    const token = jwt.sign(
      { id: user.id, account_id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Account created successfully!',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });

  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Email already registered.' });
    }
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ── LOGIN ─────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const result = await db.query(
      `SELECT u.*, a.id as account_id, a.plan, a.is_active as account_active
       FROM users u
       JOIN accounts a ON u.account_id = a.id
       WHERE u.email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];

    if (!user.account_active) {
      return res.status(403).json({ error: 'Account is inactive. Contact support.' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Update last login
    await db.query(`UPDATE users SET last_login = NOW() WHERE id = $1`, [user.id]);

    const token = jwt.sign(
      { id: user.id, account_id: user.account_id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful!',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        plan: user.plan
      }
    });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

module.exports = router;