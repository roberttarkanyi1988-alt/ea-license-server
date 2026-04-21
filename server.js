const express = require('express');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());

// ─── Admin Panel ──────────────────────────────────────────────────────────────
const ADMIN_KEY = process.env.ADMIN_KEY || 'schimba-aceasta-cheie-secreta';

app.get('/admin-panel', (req, res) => {
  const k = req.query.key || req.headers['x-admin-key'];
  if (!k || k !== ADMIN_KEY) return res.status(401).send('Unauthorized');
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── Database Setup (Supabase PostgreSQL) ─────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      id          SERIAL PRIMARY KEY,
      account_id  TEXT NOT NULL UNIQUE,
      email       TEXT,
      plan        TEXT DEFAULT 'monthly',
      status      TEXT DEFAULT 'active',
      expires_at  TEXT NOT NULL,
      created_at  TEXT DEFAULT to_char(now(), 'YYYY-MM-DD HH24:MI:SS'),
      notes       TEXT
    );
    CREATE TABLE IF NOT EXISTS access_log (
      id          SERIAL PRIMARY KEY,
      account_id  TEXT,
      ip          TEXT,
      result      TEXT,
      checked_at  TEXT DEFAULT to_char(now(), 'YYYY-MM-DD HH24:MI:SS')
    );
  `);
  console.log('✅ Database initialized');
}

initDB().catch(console.error);

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: 'RATE_LIMITED'
});
app.use('/api/', limiter);

// ─── Middleware: Admin Auth ───────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ─── ENDPOINT: Verificare licență ────────────────────────────────────────────
app.get('/api/check', async (req, res) => {
  const { account } = req.query;
  const ip = req.ip;

  if (!account) {
    await logAccess(null, ip, 'MISSING_ACCOUNT');
    return res.status(400).send('INVALID');
  }

  const result = await pool.query('SELECT * FROM licenses WHERE account_id=$1', [account]);
  const row = result.rows[0];

  if (!row) {
    await logAccess(account, ip, 'NOT_FOUND');
    return res.send('INVALID');
  }

  if (row.status === 'suspended') {
    await logAccess(account, ip, 'SUSPENDED');
    return res.send('SUSPENDED');
  }

  const now = new Date();
  const expiry = new Date(row.expires_at);

  if (now > expiry) {
    await pool.query("UPDATE licenses SET status='expired' WHERE account_id=$1", [account]);
    await logAccess(account, ip, 'EXPIRED');
    return res.send('EXPIRED');
  }

  const daysLeft = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
  await logAccess(account, ip, 'VALID');
  return res.send(`VALID|${row.expires_at}|${daysLeft}`);
});

// ─── ADMIN: Adaugă / reînnoiește licență ─────────────────────────────────────
app.post('/admin/license', adminAuth, async (req, res) => {
  const { account_id, email, months = 1, plan = 'monthly', notes } = req.body;
  if (!account_id) return res.status(400).json({ error: 'account_id required' });

  const existing = await pool.query('SELECT * FROM licenses WHERE account_id=$1', [account_id]);
  const row = existing.rows[0];

  let expiresAt;
  if (row && row.status === 'active') {
    const base = new Date(row.expires_at);
    base.setMonth(base.getMonth() + parseInt(months));
    expiresAt = base.toISOString().split('T')[0];
  } else {
    const base = new Date();
    base.setMonth(base.getMonth() + parseInt(months));
    expiresAt = base.toISOString().split('T')[0];
  }

  await pool.query(`
    INSERT INTO licenses (account_id, email, plan, status, expires_at, notes)
    VALUES ($1,$2,$3,'active',$4,$5)
    ON CONFLICT(account_id) DO UPDATE SET
      email=excluded.email, plan=excluded.plan,
      status='active', expires_at=excluded.expires_at, notes=excluded.notes
  `, [account_id, email, plan, expiresAt, notes]);

  res.json({ success: true, account_id, expires_at: expiresAt, months_added: months });
});

// ─── ADMIN: Suspendă ──────────────────────────────────────────────────────────
app.patch('/admin/license/:account_id/suspend', adminAuth, async (req, res) => {
  const { account_id } = req.params;
  const r = await pool.query("UPDATE licenses SET status='suspended' WHERE account_id=$1", [account_id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true, account_id, status: 'suspended' });
});

// ─── ADMIN: Activează ─────────────────────────────────────────────────────────
app.patch('/admin/license/:account_id/activate', adminAuth, async (req, res) => {
  const { account_id } = req.params;
  await pool.query("UPDATE licenses SET status='active' WHERE account_id=$1", [account_id]);
  res.json({ success: true, account_id, status: 'active' });
});

// ─── ADMIN: Șterge ────────────────────────────────────────────────────────────
app.delete('/admin/license/:account_id', adminAuth, async (req, res) => {
  await pool.query('DELETE FROM licenses WHERE account_id=$1', [req.params.account_id]);
  res.json({ success: true });
});

// ─── ADMIN: Listare ───────────────────────────────────────────────────────────
app.get('/admin/licenses', adminAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM licenses ORDER BY expires_at ASC');
  res.json(result.rows);
});

// ─── ADMIN: Logs ──────────────────────────────────────────────────────────────
app.get('/admin/logs', adminAuth, async (req, res) => {
  const { account } = req.query;
  let result;
  if (account) {
    result = await pool.query('SELECT * FROM access_log WHERE account_id=$1 ORDER BY checked_at DESC LIMIT 100', [account]);
  } else {
    result = await pool.query('SELECT * FROM access_log ORDER BY checked_at DESC LIMIT 200');
  }
  res.json(result.rows);
});

// ─── Helper ───────────────────────────────────────────────────────────────────
async function logAccess(account, ip, result) {
  try {
    await pool.query('INSERT INTO access_log (account_id, ip, result) VALUES ($1,$2,$3)', [account, ip, result]);
  } catch (_) {}
}

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ License server running on port ${PORT}`));
