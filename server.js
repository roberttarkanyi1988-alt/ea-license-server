const express = require('express');
const sqlite3 = require('better-sqlite3');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const path = require('path');

const app = express();
app.use(express.json());

// ─── Admin Panel (HTML static) ────────────────────────────────────────────────
// Accesibil doar cu ADMIN_KEY în URL pentru protecție simplă
app.get('/admin-panel', (req, res) => {
  const k = req.query.key || req.headers['x-admin-key'];
  if (!k || k !== (process.env.ADMIN_KEY || 'schimba-aceasta-cheie-secreta')) {
    return res.status(401).send('Unauthorized');
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── Database Setup ───────────────────────────────────────────────────────────
const db = sqlite3('licenses.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  TEXT    NOT NULL UNIQUE,
    email       TEXT,
    plan        TEXT    DEFAULT 'monthly',
    status      TEXT    DEFAULT 'active',   -- active | suspended | expired
    expires_at  TEXT    NOT NULL,           -- ISO date string
    created_at  TEXT    DEFAULT (datetime('now')),
    notes       TEXT
  );

  CREATE TABLE IF NOT EXISTS access_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  TEXT,
    ip          TEXT,
    result      TEXT,
    checked_at  TEXT    DEFAULT (datetime('now'))
  );
`);

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minut
  max: 30,               // max 30 requesturi/minut per IP
  message: 'RATE_LIMITED'
});
app.use('/api/', limiter);

// ─── Middleware: Admin Auth ───────────────────────────────────────────────────
const ADMIN_KEY = process.env.ADMIN_KEY || 'schimba-aceasta-cheie-secreta';

function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── ENDPOINT: Verificare licență (apelat din EA) ─────────────────────────────
// GET /api/check?account=12345678&ea=MyEA
app.get('/api/check', (req, res) => {
  const { account, ea } = req.query;
  const ip = req.ip;

  if (!account) {
    logAccess(null, ip, 'MISSING_ACCOUNT');
    return res.status(400).send('INVALID');
  }

  const row = db.prepare(
    'SELECT * FROM licenses WHERE account_id = ?'
  ).get(account);

  if (!row) {
    logAccess(account, ip, 'NOT_FOUND');
    return res.send('INVALID');
  }

  if (row.status === 'suspended') {
    logAccess(account, ip, 'SUSPENDED');
    return res.send('SUSPENDED');
  }

  const now = new Date();
  const expiry = new Date(row.expires_at);

  if (now > expiry) {
    // Marchează automat ca expirat
    db.prepare("UPDATE licenses SET status='expired' WHERE account_id=?").run(account);
    logAccess(account, ip, 'EXPIRED');
    return res.send('EXPIRED');
  }

  // Returnează și data expirării pentru afișare în EA
  const daysLeft = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
  logAccess(account, ip, 'VALID');
  return res.send(`VALID|${row.expires_at}|${daysLeft}`);
});

// ─── ADMIN: Adaugă / reînnoiește licență ─────────────────────────────────────
// POST /admin/license
// Body: { account_id, email, months, plan, notes }
app.post('/admin/license', adminAuth, (req, res) => {
  const { account_id, email, months = 1, plan = 'monthly', notes } = req.body;

  if (!account_id) return res.status(400).json({ error: 'account_id required' });

  const existing = db.prepare('SELECT * FROM licenses WHERE account_id=?').get(account_id);

  let expiresAt;
  if (existing && existing.status === 'active') {
    // Extinde de la data curentă de expirare
    const base = new Date(existing.expires_at);
    base.setMonth(base.getMonth() + parseInt(months));
    expiresAt = base.toISOString().split('T')[0];
  } else {
    // Nouă sau reactivare — pornește de azi
    const base = new Date();
    base.setMonth(base.getMonth() + parseInt(months));
    expiresAt = base.toISOString().split('T')[0];
  }

  db.prepare(`
    INSERT INTO licenses (account_id, email, plan, status, expires_at, notes)
    VALUES (@account_id, @email, @plan, 'active', @expires_at, @notes)
    ON CONFLICT(account_id) DO UPDATE SET
      email      = excluded.email,
      plan       = excluded.plan,
      status     = 'active',
      expires_at = excluded.expires_at,
      notes      = excluded.notes
  `).run({ account_id, email, plan, expires_at: expiresAt, notes });

  res.json({ success: true, account_id, expires_at: expiresAt, months_added: months });
});

// ─── ADMIN: Suspendă licență (neplată) ───────────────────────────────────────
// PATCH /admin/license/:account_id/suspend
app.patch('/admin/license/:account_id/suspend', adminAuth, (req, res) => {
  const { account_id } = req.params;
  const info = db.prepare("UPDATE licenses SET status='suspended' WHERE account_id=?").run(account_id);
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true, account_id, status: 'suspended' });
});

// ─── ADMIN: Reactivează licență ───────────────────────────────────────────────
// PATCH /admin/license/:account_id/activate
app.patch('/admin/license/:account_id/activate', adminAuth, (req, res) => {
  const { account_id } = req.params;
  db.prepare("UPDATE licenses SET status='active' WHERE account_id=?").run(account_id);
  res.json({ success: true, account_id, status: 'active' });
});

// ─── ADMIN: Șterge licență ────────────────────────────────────────────────────
// DELETE /admin/license/:account_id
app.delete('/admin/license/:account_id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM licenses WHERE account_id=?').run(req.params.account_id);
  res.json({ success: true });
});

// ─── ADMIN: Listare licențe ───────────────────────────────────────────────────
// GET /admin/licenses
app.get('/admin/licenses', adminAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM licenses ORDER BY expires_at ASC').all();
  res.json(rows);
});

// ─── ADMIN: Log-uri acces ─────────────────────────────────────────────────────
// GET /admin/logs?account=12345 (opțional filtru)
app.get('/admin/logs', adminAuth, (req, res) => {
  const { account } = req.query;
  let rows;
  if (account) {
    rows = db.prepare('SELECT * FROM access_log WHERE account_id=? ORDER BY checked_at DESC LIMIT 100').all(account);
  } else {
    rows = db.prepare('SELECT * FROM access_log ORDER BY checked_at DESC LIMIT 200').all();
  }
  res.json(rows);
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function logAccess(account, ip, result) {
  try {
    db.prepare('INSERT INTO access_log (account_id, ip, result) VALUES (?,?,?)').run(account, ip, result);
  } catch (_) {}
}

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ License server running on port ${PORT}`);
});
