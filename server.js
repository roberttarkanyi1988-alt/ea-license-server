const express = require('express');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto'); // 🔐 NOU pentru HMAC
require('dotenv').config();
const { Client, GatewayIntentBits } = require('discord.js');

const app = express();

// ─── Stripe webhook needs raw body ───────────────────────────────────────────
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ─── Stripe Setup ─────────────────────────────────────────────────────────────
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// ─── Admin Key ────────────────────────────────────────────────────────────────
const ADMIN_KEY = process.env.ADMIN_KEY || 'schimba-aceasta-cheie-secreta';

// 🔐 NOU: HMAC Setup pentru securitate EA
const HMAC_SECRET = process.env.HMAC_SECRET || '';
const TIMESTAMP_WINDOW_SECONDS = 60;

if (!HMAC_SECRET) {
  console.warn('⚠️  HMAC_SECRET nu e setat! Mod backwards compat activ.');
} else {
  console.log('✅ HMAC_SECRET încărcat — securitate maximă activă');
}

function generateHMAC(payload) {
  if (!HMAC_SECRET) return '';
  return crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.redirect('/landing');
});

app.get('/landing', (req, res) => {
  res.sendFile(path.join(__dirname, 'landing.html'));
});

app.get('/client', (req, res) => {
  res.sendFile(path.join(__dirname, 'client.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin-panel', (req, res) => {
  const k = req.query.key || req.headers['x-admin-key'];
  if (!k || k !== ADMIN_KEY) return res.status(401).send('Unauthorized');
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── PWA Files ────────────────────────────────────────────────────────────────
app.get('/manifest.json', (req, res) => res.sendFile(path.join(__dirname, 'manifest.json')));
app.get('/sw.js', (req, res) => res.sendFile(path.join(__dirname, 'sw.js')));
app.get('/icon-512.svg', (req, res) => res.sendFile(path.join(__dirname, 'icon-512.svg')));
app.get('/icon-192.svg', (req, res) => res.sendFile(path.join(__dirname, 'icon-192.svg')));

// ─── Database Setup ───────────────────────────────────────────────────────────
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

// ─── Telegram ─────────────────────────────────────────────────────────────────
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

async function sendTelegram(message) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: message, parse_mode: 'HTML' })
    });
  } catch(e) {
    console.error('Telegram error:', e.message);
  }
}

// ─── DISCORD BOT ──────────────────────────────────────────────────────────────
const DISCORD_GUILD_ID = '1500420643290615918';
const DISCORD_ROLES = {
  basic: '1503110227438993469',
  pro:   '1503110421740257471',
  full:  '1503108475495125033'
};

const discordClient = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers]
});

discordClient.once('ready', () => {
  console.log(`✅ Discord bot conectat: ${discordClient.user.tag}`);
});

if (process.env.DISCORD_BOT_TOKEN) {
  discordClient.login(process.env.DISCORD_BOT_TOKEN).catch(err => {
    console.error('Discord login error:', err.message);
  });
}

function getRoleIdForPlan(plan) {
  if (!plan) return DISCORD_ROLES.basic;
  const p = plan.toLowerCase();
  if (p.includes('full')) return DISCORD_ROLES.full;
  if (p.includes('pro'))  return DISCORD_ROLES.pro;
  return DISCORD_ROLES.basic;
}

async function addDiscordRole(email, plan) {
  try {
    if (!discordClient.isReady()) return false;
    const guild = await discordClient.guilds.fetch(DISCORD_GUILD_ID);
    const members = await guild.members.fetch();
    const member = members.find(m =>
      m.user.username.toLowerCase().includes(email.split('@')[0].toLowerCase())
    );
    if (!member) { console.log(`Discord: ${email} negăsit`); return false; }
    const roleId = getRoleIdForPlan(plan);
    await member.roles.add(roleId);
    console.log(`✅ Discord: rol ${plan} adăugat pentru ${email}`);
    return true;
  } catch(e) {
    console.error('Discord addRole error:', e.message);
    return false;
  }
}

async function removeDiscordRole(email) {
  try {
    if (!discordClient.isReady()) return false;
    const guild = await discordClient.guilds.fetch(DISCORD_GUILD_ID);
    const members = await guild.members.fetch();
    const member = members.find(m =>
      m.user.username.toLowerCase().includes(email.split('@')[0].toLowerCase())
    );
    if (!member) { console.log(`Discord: ${email} negăsit`); return false; }
    for (const roleId of Object.values(DISCORD_ROLES)) {
      if (member.roles.cache.has(roleId)) await member.roles.remove(roleId);
    }
    console.log(`✅ Discord: roluri șterse pentru ${email}`);
    return true;
  } catch(e) {
    console.error('Discord removeRole error:', e.message);
    return false;
  }
}

// ─── Verificare zilnică ───────────────────────────────────────────────────────
async function checkExpiringLicenses() {
  try {
    const result = await pool.query(`
      SELECT * FROM licenses 
      WHERE status = 'active' 
      AND expires_at::date - CURRENT_DATE IN (7, 3, 1)
    `);
    for (const row of result.rows) {
      const daysLeft = Math.ceil((new Date(row.expires_at) - new Date()) / 86400000);
      await sendTelegram(
        `⚠️ <b>Abonament expiră în ${daysLeft} zile!</b>\n` +
        `👤 Cont: <b>#${row.account_id}</b>\n` +
        `📧 Email: ${row.email || 'nespecificat'}\n` +
        `📅 Expiră: ${row.expires_at}`
      );
    }
    const expired = await pool.query(`
      SELECT * FROM licenses WHERE status = 'active' AND expires_at::date < CURRENT_DATE
    `);
    for (const row of expired.rows) {
      if (row.email) await removeDiscordRole(row.email);
      await pool.query("UPDATE licenses SET status='expired' WHERE account_id=$1", [row.account_id]);
    }
  } catch(e) {
    console.error('Expiry check error:', e.message);
  }
}

setInterval(() => {
  const now = new Date();
  if (now.getHours() === 9 && now.getMinutes() === 0) checkExpiringLicenses();
}, 60000);

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const limiter = rateLimit({ windowMs: 60 * 1000, max: 30, message: 'RATE_LIMITED' });
app.use('/api/', limiter);

// ─── Admin Auth ───────────────────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ─── Verificare licență (cu HMAC + Timestamp + Multi-source) ──────────────────
// 🆕 SESIUNEA 4: Caută întâi în tabelele NOI (mt5_accounts + subscriptions),
//               apoi fallback la tabela veche `licenses` pentru backwards compat
app.get('/api/check', async (req, res) => {
  const { account, ts } = req.query;
  const ip = req.ip;
  if (!account) { await logAccess(null, ip, 'MISSING_ACCOUNT'); return res.status(400).send('INVALID'); }

  // 🔐 Verificare timestamp pentru anti-replay
  if (ts) {
    const clientTime = parseInt(ts, 10);
    const serverTime = Math.floor(Date.now() / 1000);
    const diff = Math.abs(serverTime - clientTime);
    if (diff > TIMESTAMP_WINDOW_SECONDS) {
      await logAccess(account, ip, 'TIMESTAMP_INVALID');
      await logAccessV2(null, account, null, ip, 'TIMESTAMP_INVALID', false, false);
      return res.send('INVALID');
    }
  }

  // Funcție helper pentru a forma răspunsul cu/fără HMAC
  const buildResponse = (baseResponse) => {
    if (ts && HMAC_SECRET) {
      const serverTs = Math.floor(Date.now() / 1000);
      const payload = `${baseResponse}|${serverTs}`;
      const hmac = generateHMAC(payload);
      return `${payload}|${hmac}`;
    }
    return baseResponse;
  };

  // 🆕 PRIORITATE 1: Caută în tabelele NOI (users + subscriptions + mt5_accounts)
  try {
    const newSystemQuery = await pool.query(`
      SELECT 
        u.id AS user_id,
        u.email,
        s.id AS subscription_id,
        s.plan,
        s.status AS sub_status,
        s.current_period_end,
        s.grace_period_until,
        m.account_number,
        m.is_active AS account_active
      FROM mt5_accounts m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN subscriptions s ON s.id = m.subscription_id
      WHERE m.account_number = $1 AND m.is_active = true
      LIMIT 1
    `, [account]);

    if (newSystemQuery.rows.length > 0) {
      const r = newSystemQuery.rows[0];
      const now = new Date();
      const expiry = r.current_period_end ? new Date(r.current_period_end) : null;

      // Verificări status
      if (r.sub_status === 'cancelled') {
        await logAccess(account, ip, 'CANCELLED');
        await logAccessV2(r.user_id, account, null, ip, 'CANCELLED', true, true);
        return res.send(buildResponse('SUSPENDED'));
      }
      if (r.sub_status === 'expired' || (expiry && now > expiry)) {
        await logAccess(account, ip, 'EXPIRED');
        await logAccessV2(r.user_id, account, null, ip, 'EXPIRED_NEW', true, true);
        return res.send(buildResponse('EXPIRED'));
      }
      if (r.sub_status !== 'active' && r.sub_status !== 'grace_period') {
        await logAccess(account, ip, 'INACTIVE');
        await logAccessV2(r.user_id, account, null, ip, 'INACTIVE', true, true);
        return res.send(buildResponse('SUSPENDED'));
      }

      // Tot OK — calculează zile rămase
      const expiryStr = expiry ? expiry.toISOString().split('T')[0] : '2099-12-31';
      const daysLeft = expiry ? Math.ceil((expiry - now) / (1000 * 60 * 60 * 24)) : 9999;
      await logAccess(account, ip, 'VALID_NEW');
      await logAccessV2(r.user_id, account, null, ip, 'VALID_NEW', true, true);
      return res.send(buildResponse(`VALID|${expiryStr}|${daysLeft}`));
    }
  } catch (e) {
    console.error('New system lookup error:', e.message);
    // Nu blocăm — încercăm fallback la tabela veche
  }

  // 🔁 PRIORITATE 2 (FALLBACK): Tabela veche `licenses` — backwards compat
  const result = await pool.query('SELECT * FROM licenses WHERE account_id=$1', [account]);
  const row = result.rows[0];

  if (!row) { 
    await logAccess(account, ip, 'NOT_FOUND'); 
    await logAccessV2(null, account, null, ip, 'NOT_FOUND', true, true);
    return res.send(buildResponse('INVALID')); 
  }
  if (row.status === 'suspended') { 
    await logAccess(account, ip, 'SUSPENDED'); 
    await logAccessV2(null, account, null, ip, 'SUSPENDED', true, true);
    return res.send(buildResponse('SUSPENDED')); 
  }

  const now = new Date();
  const expiry = new Date(row.expires_at);
  if (now > expiry) {
    await pool.query("UPDATE licenses SET status='expired' WHERE account_id=$1", [account]);
    if (row.email) await removeDiscordRole(row.email);
    await logAccess(account, ip, 'EXPIRED');
    await logAccessV2(null, account, null, ip, 'EXPIRED_OLD', true, true);
    return res.send(buildResponse('EXPIRED'));
  }

  const daysLeft = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
  await logAccess(account, ip, 'VALID_OLD');
  await logAccessV2(null, account, null, ip, 'VALID_OLD', true, true);
  return res.send(buildResponse(`VALID|${row.expires_at}|${daysLeft}`));
});

// 🔐 NOU: Endpoint test pentru a verifica HMAC e activ
app.get('/api/hmac-test', (req, res) => {
  res.json({
    hmac_enabled: !!HMAC_SECRET,
    secret_length: HMAC_SECRET.length,
    timestamp: Math.floor(Date.now() / 1000),
    test_signature: generateHMAC('test_payload')
  });
});

// ─── Stripe: Creare link plată ────────────────────────────────────────────────
// Acum acceptă și plan + eas din landing page
app.post('/api/create-payment', async (req, res) => {
  const { account_id, email, months = 1, plan = 'basic', eas = '' } = req.body;
  if (!account_id) return res.status(400).json({ error: 'account_id required' });
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      customer_email: email || undefined,
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: months }],
      metadata: {
        account_id,
        months: String(months),
        email: email || '',
        plan: plan,
        eas: eas
      },
      success_url: 'https://ea-license-server-lrsl.onrender.com/payment-success?session_id={CHECKOUT_SESSION_ID}',
      cancel_url:  'https://ea-license-server-lrsl.onrender.com/payment-cancel',
    });
    res.json({ url: session.url, session_id: session.id });
  } catch(e) {
    console.error('Stripe error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Stripe: Webhook ──────────────────────────────────────────────────────────
app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch(e) {
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { account_id, months, email, plan, eas } = session.metadata;
    const base = new Date();
    base.setDate(base.getDate() + (parseInt(months) * 30));
    const expiresAt = base.toISOString().split('T')[0];

    // Salvează planul și EA-urile in notes pentru referinta
    const notesText = eas
      ? `Plată Stripe | Plan: ${plan} | EA-uri: ${eas}`
      : `Plată Stripe automată | Plan: ${plan || 'basic'}`;

    await pool.query(`
      INSERT INTO licenses (account_id, email, plan, status, expires_at, notes)
      VALUES ($1,$2,$3,'active',$4,$5)
      ON CONFLICT(account_id) DO UPDATE SET
        email=excluded.email, plan=excluded.plan,
        status='active', expires_at=excluded.expires_at, notes=excluded.notes
    `, [account_id, email, plan || 'basic', expiresAt, notesText]);

    if (email) await addDiscordRole(email, plan || 'basic');

    // ─── Telegram cu toate detaliile pentru tine ─────────────────
    const easLine = eas
      ? `\n🤖 <b>EA-uri alese:</b> ${eas}`
      : '';
    const planLine = plan
      ? `\n📦 <b>Plan:</b> ${plan}`
      : '';

    await sendTelegram(
      `💳 <b>PLATĂ NOUĂ PRIMITĂ!</b>\n` +
      `👤 Cont MT5: <b>#${account_id}</b>\n` +
      `📧 Email: ${email || 'nespecificat'}` +
      planLine +
      easLine +
      `\n📅 Activ până: ${expiresAt}\n` +
      `\n⚡ <b>TODO: Compilează EA-urile de mai sus cu contul #${account_id} și trimite pe Discord!</b>`
    );
  }

  if (event.type === 'customer.subscription.deleted' || event.type === 'invoice.payment_failed') {
    const obj = event.data.object;
    const email = obj.customer_email || obj.metadata?.email;
    if (email) {
      await removeDiscordRole(email);
      await pool.query("UPDATE licenses SET status='expired' WHERE email=$1", [email]);
      await sendTelegram(`❌ <b>Abonament anulat!</b>\n📧 Email: ${email}`);
    }
  }

  res.json({ received: true });
});

// ─── Discord manual ───────────────────────────────────────────────────────────
app.post('/discord/add-role', adminAuth, async (req, res) => {
  const result = await addDiscordRole(req.body.email, req.body.plan);
  res.json({ success: result });
});

app.post('/discord/remove-role', adminAuth, async (req, res) => {
  const result = await removeDiscordRole(req.body.email);
  res.json({ success: result });
});

// ─── Pagini Stripe ────────────────────────────────────────────────────────────
app.get('/payment-success', (req, res) => {
  res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#0a0c0f;color:#e8eaf0;">
    <h1 style="color:#00e5a0;">✅ Plată reușită!</h1>
    <p>Abonamentul tău a fost activat. Vei primi EA-ul pe Discord în scurt timp.</p>
    <a href="/client" style="color:#00e5a0;">Mergi la portal →</a>
  </body></html>`);
});

app.get('/payment-cancel', (req, res) => {
  res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#0a0c0f;color:#e8eaf0;">
    <h1 style="color:#ff3d5a;">❌ Plată anulată</h1>
    <a href="/landing" style="color:#00e5a0;">Înapoi →</a>
  </body></html>`);
});

// ─── Check Status ─────────────────────────────────────────────────────────────
app.get('/check-status', async (req, res) => {
  const { account } = req.query;
  if (!account) {
    return res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#0a0c0f;color:#e8eaf0;">
      <h2>Verifică abonamentul tău</h2>
      <form method="GET" action="/check-status">
        <input name="account" placeholder="Număr cont MT5" style="padding:10px;font-size:16px;border-radius:8px;border:1px solid #1e2330;background:#161a22;color:#e8eaf0;width:250px;">
        <br><br>
        <button type="submit" style="padding:12px 24px;background:#00e5a0;color:#000;border:none;border-radius:8px;font-size:16px;font-weight:800;cursor:pointer;">Verifică</button>
      </form>
    </body></html>`);
  }
  const result = await pool.query('SELECT * FROM licenses WHERE account_id=$1', [account]);
  const row = result.rows[0];
  if (!row) return res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#0a0c0f;color:#e8eaf0;"><h1 style="color:#ff3d5a;">❌ Cont negăsit</h1><a href="/check-status" style="color:#00e5a0;">Încearcă din nou</a></body></html>`);
  const now = new Date();
  const expiry = new Date(row.expires_at);
  const daysLeft = Math.ceil((expiry - now) / 86400000);
  const statusColor = row.status === 'active' ? '#00e5a0' : '#ff3d5a';
  const statusText = row.status === 'active' ? '✅ Activ' : row.status === 'suspended' ? '⏸ Suspendat' : '❌ Expirat';
  res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#0a0c0f;color:#e8eaf0;">
    <h1 style="color:${statusColor};">${statusText}</h1>
    <div style="background:#161a22;border:1px solid #1e2330;border-radius:16px;padding:32px;max-width:400px;margin:0 auto;">
      <p><b>Cont MT5:</b> #${row.account_id}</p>
      <p><b>Expiră:</b> ${row.expires_at}</p>
      ${row.status === 'active' ? `<p><b>Zile rămase:</b> <span style="color:#00e5a0;font-size:24px;font-weight:800;">${daysLeft}</span></p>` : ''}
    </div>
    <br><a href="/check-status" style="color:#00e5a0;">Verifică alt cont</a>
  </body></html>`);
});

// ─── Admin Endpoints ──────────────────────────────────────────────────────────
app.post('/admin/license', adminAuth, async (req, res) => {
  const { account_id, email, months = 1, plan = 'monthly', notes } = req.body;
  if (!account_id) return res.status(400).json({ error: 'account_id required' });
  const existing = await pool.query('SELECT * FROM licenses WHERE account_id=$1', [account_id]);
  const row = existing.rows[0];
  let expiresAt;
  if (row && row.status === 'active') {
    const base = new Date(row.expires_at);
    base.setDate(base.getDate() + (parseInt(months) * 30));
    expiresAt = base.toISOString().split('T')[0];
  } else {
    const base = new Date();
    base.setDate(base.getDate() + (parseInt(months) * 30));
    expiresAt = base.toISOString().split('T')[0];
  }
  await pool.query(`
    INSERT INTO licenses (account_id, email, plan, status, expires_at, notes)
    VALUES ($1,$2,$3,'active',$4,$5)
    ON CONFLICT(account_id) DO UPDATE SET
      email=excluded.email, plan=excluded.plan,
      status='active', expires_at=excluded.expires_at, notes=excluded.notes
  `, [account_id, email, plan, expiresAt, notes]);
  await sendTelegram(`✅ <b>Licență adăugată manual!</b>\n👤 Cont: <b>#${account_id}</b>\n📧 Email: ${email || 'nespecificat'}\n📦 Plan: ${plan}\n📅 Expiră: ${expiresAt}`);
  res.json({ success: true, account_id, expires_at: expiresAt, months_added: months });
});

app.post('/admin/payment-link', adminAuth, async (req, res) => {
  const { account_id, email, months = 1 } = req.body;
  if (!account_id) return res.status(400).json({ error: 'account_id required' });
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      customer_email: email || undefined,
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: parseInt(months) }],
      metadata: { account_id, months: String(months), email: email || '' },
      success_url: 'https://ea-license-server-lrsl.onrender.com/payment-success',
      cancel_url:  'https://ea-license-server-lrsl.onrender.com/payment-cancel',
    });
    res.json({ url: session.url });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/admin/license/:account_id/suspend', adminAuth, async (req, res) => {
  const { account_id } = req.params;
  const r = await pool.query("UPDATE licenses SET status='suspended' WHERE account_id=$1", [account_id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
  await sendTelegram(`⏸ <b>Licență suspendată!</b>\n👤 Cont: <b>#${account_id}</b>`);
  res.json({ success: true, account_id, status: 'suspended' });
});

app.patch('/admin/license/:account_id/activate', adminAuth, async (req, res) => {
  const { account_id } = req.params;
  await pool.query("UPDATE licenses SET status='active' WHERE account_id=$1", [account_id]);
  await sendTelegram(`✅ <b>Licență reactivată!</b>\n👤 Cont: <b>#${account_id}</b>`);
  res.json({ success: true, account_id, status: 'active' });
});

app.delete('/admin/license/:account_id', adminAuth, async (req, res) => {
  await pool.query('DELETE FROM licenses WHERE account_id=$1', [req.params.account_id]);
  res.json({ success: true });
});

app.get('/admin/licenses', adminAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM licenses ORDER BY expires_at ASC');
  res.json(result.rows);
});

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

async function logAccess(account, ip, result) {
  try {
    await pool.query('INSERT INTO access_log (account_id, ip, result) VALUES ($1,$2,$3)', [account, ip, result]);
  } catch (_) {}
}

// 🆕 SESIUNEA 4: Logging extins în access_log_v2 cu detalii HMAC + user_id
async function logAccessV2(userId, account, eaName, ip, result, hmacValid, timestampValid) {
  try {
    await pool.query(
      'INSERT INTO access_log_v2 (user_id, account_number, ea_name, ip, result, hmac_valid, timestamp_valid) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [userId, account, eaName, ip, result, hmacValid, timestampValid]
    );
  } catch (_) {}
}

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ License server running on port ${PORT}`);
  sendTelegram('🚀 <b>EA Manager Server pornit!</b>');
});
