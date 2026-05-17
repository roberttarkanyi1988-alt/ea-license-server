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

// 🆕 SESIUNEA 8: Discord ID-ul OWNER-ului (Robert) — exclus de la kick/role removal
const DISCORD_OWNER_ID = '928628118149816330';

function getRoleIdForPlan(plan) {
  if (!plan) return DISCORD_ROLES.basic;
  const p = plan.toLowerCase();
  if (p.includes('full')) return DISCORD_ROLES.full;
  if (p.includes('pro'))  return DISCORD_ROLES.pro;
  return DISCORD_ROLES.basic;
}

// 🆕 SESIUNEA 8: Funcție unificată — caută user după email, ia discord_user_id din DB
async function getDiscordIdByEmail(email) {
  try {
    const r = await pool.query('SELECT discord_user_id, discord_username FROM users WHERE email=$1 LIMIT 1', [email]);
    if (r.rows[0] && r.rows[0].discord_user_id) return r.rows[0];
    return null;
  } catch (e) {
    console.error('getDiscordIdByEmail error:', e.message);
    return null;
  }
}

// 🆕 SESIUNEA 8: Adaugă rol folosind discord_user_id direct (mult mai sigur decât căutare după username)
async function addDiscordRole(email, plan) {
  try {
    if (!discordClient.isReady()) { console.log('Discord bot nu e gata'); return false; }
    
    const dRow = await getDiscordIdByEmail(email);
    if (!dRow) { console.log(`Discord: ${email} n-are discord_user_id în DB (clientul trebuie să conecteze Discord în portal)`); return false; }
    
    const guild = await discordClient.guilds.fetch(DISCORD_GUILD_ID);
    const member = await guild.members.fetch(dRow.discord_user_id).catch(() => null);
    if (!member) { console.log(`Discord: user ${dRow.discord_user_id} nu e pe server`); return false; }
    
    const roleId = getRoleIdForPlan(plan);
    await member.roles.add(roleId);
    console.log(`✅ Discord: rol ${plan} adăugat pentru ${email} (${dRow.discord_user_id})`);
    
    // Log în discord_events
    await pool.query(
      'INSERT INTO discord_events (user_id, discord_user_id, event_type, role_name, details) VALUES ((SELECT id FROM users WHERE email=$1), $2, $3, $4, $5)',
      [email, dRow.discord_user_id, 'role_added', plan, `Plan ${plan} activat`]
    );
    
    // DM bun venit
    try {
      await member.send(`🎉 Bine ai venit! Rolul **${plan.toUpperCase()}** a fost activat pe contul tău EA Strategies. Acces VIP deschis! 💎`);
      await pool.query(
        'INSERT INTO discord_events (user_id, discord_user_id, event_type, details) VALUES ((SELECT id FROM users WHERE email=$1), $2, $3, $4)',
        [email, dRow.discord_user_id, 'dm_sent', 'Welcome DM']
      );
    } catch (e) { console.log('DM bun venit eșuat (user are DM închise):', e.message); }
    
    return true;
  } catch(e) {
    console.error('Discord addRole error:', e.message);
    return false;
  }
}

// 🆕 SESIUNEA 8: Șterge TOATE rolurile + opțional DM de informare
async function removeDiscordRole(email, sendDM = false, reason = '') {
  try {
    if (!discordClient.isReady()) return false;
    
    const dRow = await getDiscordIdByEmail(email);
    if (!dRow) return false;
    
    // 🛡️ PROTECȚIE OWNER: nu șterge rolurile OWNER-ului niciodată
    if (dRow.discord_user_id === DISCORD_OWNER_ID) {
      console.log(`🛡️ Skip removeDiscordRole pentru OWNER (${email})`);
      return false;
    }
    
    const guild = await discordClient.guilds.fetch(DISCORD_GUILD_ID);
    const member = await guild.members.fetch(dRow.discord_user_id).catch(() => null);
    if (!member) return false;
    
    for (const roleId of Object.values(DISCORD_ROLES)) {
      if (member.roles.cache.has(roleId)) await member.roles.remove(roleId);
    }
    console.log(`✅ Discord: roluri șterse pentru ${email}`);
    
    await pool.query(
      'INSERT INTO discord_events (user_id, discord_user_id, event_type, details) VALUES ((SELECT id FROM users WHERE email=$1), $2, $3, $4)',
      [email, dRow.discord_user_id, 'role_removed', reason || 'Abonament expirat']
    );
    
    if (sendDM) {
      try {
        await member.send(`⚠️ Abonamentul EA Strategies a expirat. Ai **30 zile** să-l reînnoiești înainte să fii înlăturat de pe server. Reînnoiește aici: https://ea-license-server-lrsl.onrender.com/landing`);
        await pool.query(
          'INSERT INTO discord_events (user_id, discord_user_id, event_type, details) VALUES ((SELECT id FROM users WHERE email=$1), $2, $3, $4)',
          [email, dRow.discord_user_id, 'dm_sent', 'Expiry warning']
        );
      } catch (e) { console.log('DM expiry eșuat:', e.message); }
    }
    
    return true;
  } catch(e) {
    console.error('Discord removeRole error:', e.message);
    return false;
  }
}

// 🆕 SESIUNEA 8: Kick de pe server (după 30 zile grace period)
async function kickFromDiscord(email) {
  try {
    if (!discordClient.isReady()) return false;
    
    const dRow = await getDiscordIdByEmail(email);
    if (!dRow) return false;
    
    // 🛡️ PROTECȚIE OWNER: nu da NICIODATĂ kick OWNER-ului
    if (dRow.discord_user_id === DISCORD_OWNER_ID) {
      console.log(`🛡️ Skip kickFromDiscord pentru OWNER (${email})`);
      return false;
    }
    
    const guild = await discordClient.guilds.fetch(DISCORD_GUILD_ID);
    const member = await guild.members.fetch(dRow.discord_user_id).catch(() => null);
    if (!member) return false;
    
    // DM înainte de kick
    try {
      await member.send(`👋 Au trecut 30 zile de la expirarea abonamentului. Te-am scos de pe server. Te așteptăm înapoi oricând: https://ea-license-server-lrsl.onrender.com/landing`);
    } catch (e) { /* DM închise, dă mai departe */ }
    
    await member.kick('Subscription expired 30+ days');
    console.log(`✅ Discord: ${email} kicked după grace period`);
    
    await pool.query(
      'INSERT INTO discord_events (user_id, discord_user_id, event_type, details) VALUES ((SELECT id FROM users WHERE email=$1), $2, $3, $4)',
      [email, dRow.discord_user_id, 'kicked', '30 zile grace period expirate']
    );
    
    return true;
  } catch (e) {
    console.error('Discord kick error:', e.message);
    return false;
  }
}

// ─── 🆕 SESIUNEA 8: Verificare zilnică (3-tier: warn, expire+grace, kick) ──────
async function checkExpiringLicenses() {
  try {
    // 1. Avertismente: expiră în 7, 3, 1 zi → DOAR Telegram pentru tine
    const expiringWarn = await pool.query(`
      SELECT * FROM licenses 
      WHERE status = 'active' 
      AND expires_at::date - CURRENT_DATE IN (7, 3, 1)
    `);
    for (const row of expiringWarn.rows) {
      const daysLeft = Math.ceil((new Date(row.expires_at) - new Date()) / 86400000);
      await sendTelegram(
        `⚠️ <b>Abonament expiră în ${daysLeft} zile!</b>\n` +
        `👤 Cont: <b>#${row.account_id}</b>\n` +
        `📧 Email: ${row.email || 'nespecificat'}\n` +
        `📅 Expiră: ${row.expires_at}`
      );
    }
    
    // 2. Tocmai expirate → marchează expired, șterge rol, DM cu 30 zile grace
    const justExpired = await pool.query(`
      SELECT * FROM licenses WHERE status = 'active' AND expires_at::date < CURRENT_DATE
    `);
    for (const row of justExpired.rows) {
      if (row.email) await removeDiscordRole(row.email, true, 'Abonament expirat — grace 30 zile');
      await pool.query("UPDATE licenses SET status='expired' WHERE account_id=$1", [row.account_id]);
      await sendTelegram(`❌ <b>Abonament expirat!</b>\n👤 #${row.account_id}\n📧 ${row.email || '—'}\n⏰ Grace 30 zile activ`);
    }
    
    // 3. Grace period 30+ zile expirat → KICK
    const graceExpired = await pool.query(`
      SELECT * FROM licenses 
      WHERE status = 'expired' 
      AND expires_at::date < CURRENT_DATE - INTERVAL '30 days'
      AND email IS NOT NULL
    `);
    for (const row of graceExpired.rows) {
      const kicked = await kickFromDiscord(row.email);
      if (kicked) {
        await pool.query("UPDATE licenses SET status='kicked' WHERE account_id=$1", [row.account_id]);
        await sendTelegram(`👋 <b>Kick Discord:</b> ${row.email} (grace 30 zile expirat)`);
      }
    }
    
    // 4. Verifică și subscriptions noi (tabela mt5_accounts)
    const newExpired = await pool.query(`
      SELECT s.id, s.user_id, u.email, s.current_period_end
      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      WHERE s.status = 'active' AND s.current_period_end < NOW()
    `);
    for (const row of newExpired.rows) {
      await removeDiscordRole(row.email, true, 'Subscription expirat — grace 30 zile');
      await pool.query(
        "UPDATE subscriptions SET status='grace_period', grace_period_until=NOW() + INTERVAL '30 days' WHERE id=$1",
        [row.id]
      );
      await sendTelegram(`❌ <b>Subscription expirat (nou):</b>\n📧 ${row.email}\n⏰ Grace 30 zile`);
    }
    
    // 5. Grace period nou expirat → KICK + status expired
    const newKick = await pool.query(`
      SELECT s.id, s.user_id, u.email
      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      WHERE s.status = 'grace_period' AND s.grace_period_until < NOW()
    `);
    for (const row of newKick.rows) {
      const kicked = await kickFromDiscord(row.email);
      if (kicked) {
        await pool.query("UPDATE subscriptions SET status='expired' WHERE id=$1", [row.id]);
        await sendTelegram(`👋 <b>Kick Discord (nou):</b> ${row.email}`);
      }
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
        await logAccessV2(r.user_id, account, req.query.ea || null, ip, 'CANCELLED', true, true);
        return res.send(buildResponse('SUSPENDED'));
      }
      if (r.sub_status === 'expired' || (expiry && now > expiry)) {
        await logAccess(account, ip, 'EXPIRED');
        await logAccessV2(r.user_id, account, req.query.ea || null, ip, 'EXPIRED_NEW', true, true);
        return res.send(buildResponse('EXPIRED'));
      }
      if (r.sub_status !== 'active' && r.sub_status !== 'grace_period') {
        await logAccess(account, ip, 'INACTIVE');
        await logAccessV2(r.user_id, account, req.query.ea || null, ip, 'INACTIVE', true, true);
        return res.send(buildResponse('SUSPENDED'));
      }

      // 🆕 SESIUNEA 10: Verificare per EA — userul are licență pentru acest EA specific?
      if (req.query.ea) {
        const eaCheck = await pool.query(
          `SELECT id FROM ea_licenses WHERE user_id=$1 AND ea_name=$2 AND status='active' LIMIT 1`,
          [r.user_id, req.query.ea]
        );
        if (eaCheck.rows.length === 0) {
          await logAccess(account, ip, 'EA_NOT_LICENSED');
          await logAccessV2(r.user_id, account, req.query.ea, ip, 'EA_NOT_LICENSED', true, true);
          return res.send(buildResponse('INVALID'));
        }
      }

      // Tot OK — calculează zile rămase
      const expiryStr = expiry ? expiry.toISOString().split('T')[0] : '2099-12-31';
      const daysLeft = expiry ? Math.ceil((expiry - now) / (1000 * 60 * 60 * 24)) : 9999;
      await logAccess(account, ip, 'VALID_NEW');
      await logAccessV2(r.user_id, account, req.query.ea || null, ip, 'VALID_NEW', true, true);
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

// 🆕 SESIUNEA 8: Stripe Customer Portal — clientul gestionează singur abonamentul
app.post('/api/customer-portal', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  
  try {
    // Caut user-ul în DB
    const userResult = await pool.query('SELECT stripe_customer_id FROM users WHERE email=$1 LIMIT 1', [email]);
    let customerId = userResult.rows[0]?.stripe_customer_id;
    
    // Dacă nu avem stripe_customer_id salvat, îl găsim/creem
    if (!customerId) {
      const customers = await stripe.customers.list({ email, limit: 1 });
      if (customers.data.length > 0) {
        customerId = customers.data[0].id;
        await pool.query('UPDATE users SET stripe_customer_id=$1 WHERE email=$2', [customerId, email]);
      } else {
        return res.status(404).json({ error: 'No subscription found for this email' });
      }
    }
    
    // Creează sesiune Customer Portal
    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: 'https://ea-license-server-lrsl.onrender.com/client'
    });
    
    res.json({ url: session.url });
  } catch (e) {
    console.error('Customer portal error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// 🆕 SESIUNEA 11: Download EA file cu signed URL temporary (5 min)
const SUPABASE_URL = 'https://cxtbthwoffyeazlxzequ.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

// Inițializare Supabase client (pentru Storage signed URLs)
let supabaseClient = null;
try {
  const { createClient } = require('@supabase/supabase-js');
  if (SUPABASE_SERVICE_KEY) {
    supabaseClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
    console.log('✅ Supabase client inițializat pentru Storage');
  } else {
    console.warn('⚠️  SUPABASE_SERVICE_KEY lipsește');
  }
} catch (e) {
  console.error('Supabase init error:', e.message);
}

app.post('/api/download-ea', async (req, res) => {
  const { email, ea_name } = req.body;
  if (!email || !ea_name) return res.status(400).json({ error: 'Missing email or ea_name' });
  
  try {
    // 1. Verific licența activă
    const licCheck = await pool.query(`
      SELECT el.file_name, el.status, u.id AS user_id
      FROM ea_licenses el
      JOIN users u ON u.id = el.user_id
      WHERE u.email = $1 AND el.ea_name = $2 AND el.status = 'active'
      LIMIT 1
    `, [email, ea_name]);
    
    if (licCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Nu ai licență activă pentru acest EA' });
    }
    
    const fileName = licCheck.rows[0].file_name;
    if (!fileName) {
      return res.status(404).json({ error: 'Fișier indisponibil. Contactează suport.' });
    }
    
    if (!supabaseClient) {
      return res.status(500).json({ error: 'Supabase client neinițializat. SUPABASE_SERVICE_KEY lipsește.' });
    }
    
    // 2. Creez signed URL (5 minute) via Supabase JS client
    const { data, error } = await supabaseClient
      .storage
      .from('ea-files')
      .createSignedUrl(fileName, 300);
    
    if (error || !data || !data.signedUrl) {
      console.error('Signed URL error:', error);
      return res.status(500).json({ error: 'Nu am putut genera link de descărcare: ' + (error?.message || 'unknown') });
    }
    
    // Log download
    await logAccessV2(licCheck.rows[0].user_id, null, ea_name, req.ip, 'DOWNLOAD', true, true);
    
    res.json({ 
      url: data.signedUrl,
      file_name: fileName,
      expires_in: 300
    });
    
  } catch (e) {
    console.error('Download error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// 🆕 SESIUNEA 12: Endpoint admin pentru detectare abuzuri
app.get('/admin/abuse-report', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id AS user_id,
        u.email,
        u.full_name,
        u.created_at AS user_since,
        COUNT(m.id) AS total_accounts,
        COUNT(CASE WHEN m.is_active = true THEN 1 END) AS active_accounts,
        COUNT(CASE WHEN m.is_active = false THEN 1 END) AS removed_accounts,
        MAX(m.added_at) AS last_added,
        MAX(m.removed_at) AS last_removed,
        s.plan,
        s.max_mt5_accounts
      FROM users u
      LEFT JOIN mt5_accounts m ON m.user_id = u.id
      LEFT JOIN subscriptions s ON s.user_id = u.id AND s.status IN ('active', 'grace_period')
      GROUP BY u.id, u.email, u.full_name, u.created_at, s.plan, s.max_mt5_accounts
      HAVING COUNT(m.id) > 0
      ORDER BY removed_accounts DESC, total_accounts DESC
    `);
    
    // Calculez "risk score" pentru fiecare user
    const enriched = result.rows.map(r => {
      const removedCount = parseInt(r.removed_accounts);
      const totalCount = parseInt(r.total_accounts);
      const maxAllowed = parseInt(r.max_mt5_accounts) || 1;
      
      // Risc = câte conturi a folosit în total raportat la plan
      const ratio = totalCount / maxAllowed;
      let risk = 'low';
      if (ratio >= 3) risk = 'high';
      else if (ratio >= 2) risk = 'medium';
      
      return { ...r, risk_level: risk };
    });
    
    res.json(enriched);
  } catch (e) {
    console.error('Abuse report error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// 🆕 Endpoint detalii conturi MT5 per user (istoric complet)
app.get('/admin/user-accounts/:user_id', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT account_number, broker, is_active, added_at, removed_at
      FROM mt5_accounts
      WHERE user_id = $1
      ORDER BY added_at DESC
    `, [req.params.user_id]);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Discord OAuth ────────────────────────────────────────────────────────────
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;

app.get('/auth/discord', (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).send('Missing email — trebuie să fii logat în portal');
  
  const redirectUri = 'https://ea-license-server-lrsl.onrender.com/auth/discord/callback';
  const scope = 'identify email guilds.join';
  // Encode email-ul portal în state (base64) ca să-l recuperăm la callback
  const state = Buffer.from(email).toString('base64');
  const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scope)}&state=${state}`;
  res.redirect(authUrl);
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('Missing code');
  if (!state) return res.status(400).send('Missing state');

  // Decodez emailul portal din state
  let portalEmail;
  try {
    portalEmail = Buffer.from(state, 'base64').toString('utf-8');
  } catch (e) {
    return res.status(400).send('Invalid state');
  }

  try {
    // Exchange code for token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'https://ea-license-server-lrsl.onrender.com/auth/discord/callback'
      })
    });
    const tokenData = await tokenRes.json();

    if (!tokenData.access_token) {
      console.error('Discord OAuth error:', tokenData);
      return res.status(500).send('Failed to get access token');
    }

    // Get Discord user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();

    const discordUserId = userData.id;
    const discordUsername = userData.username + (userData.discriminator && userData.discriminator !== '0' ? `#${userData.discriminator}` : '');

    // 🆕 Folosim EMAILUL DIN PORTAL (din state), nu emailul Discord
    const upd = await pool.query(
      'UPDATE users SET discord_user_id=$1, discord_username=$2 WHERE email=$3 RETURNING id',
      [discordUserId, discordUsername, portalEmail]
    );
    console.log(`Discord OAuth: portal_email=${portalEmail} discord_id=${discordUserId} updated_rows=${upd.rowCount}`);

    if (upd.rowCount === 0) {
      return res.status(404).send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#0a0c0f;color:#e8eaf0;">
        <h1 style="color:#ff3d5a;">❌ Eroare</h1>
        <p>Nu am găsit user-ul cu emailul: ${portalEmail}</p>
        <a href="/client" style="color:#00e5a0;">Înapoi la portal →</a>
      </body></html>`);
    }

    // Redirect înapoi la portal
    res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#0a0c0f;color:#e8eaf0;">
      <h1 style="color:#00e5a0;">✅ Discord conectat!</h1>
      <p>Contul Discord <b>${discordUsername}</b> a fost conectat la <b>${portalEmail}</b></p>
      <a href="/client" style="color:#00e5a0;">Înapoi la portal →</a>
      <script>setTimeout(() => window.location.href='/client', 2500);</script>
    </body></html>`);

  } catch (err) {
    console.error('Discord OAuth error:', err);
    res.status(500).send('OAuth error');
  }
});

// 🆕 SESIUNEA 8: Endpoint test rol din browser (protejat cu admin key în URL)
app.get('/api/discord-give-role', async (req, res) => {
  const { key, email, plan } = req.query;
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'Wrong admin key' });
  if (!email || !plan) return res.status(400).json({ error: 'Missing email or plan' });
  
  const result = await addDiscordRole(email, plan);
  res.json({ success: result, email, plan });
});

// 🆕 SESIUNEA 8: Endpoint test bot Discord (verifică că botul răspunde + DB e ok)
app.get('/api/discord-test', async (req, res) => {
  try {
    const botReady = discordClient.isReady();
    const botTag = botReady ? discordClient.user.tag : null;
    
    // Verifică câți useri au discord_user_id setat
    const connected = await pool.query('SELECT COUNT(*) FROM users WHERE discord_user_id IS NOT NULL');
    
    // Ultimele 5 evenimente Discord
    const events = await pool.query('SELECT event_type, role_name, details, created_at FROM discord_events ORDER BY id DESC LIMIT 5');
    
    res.json({
      bot_ready: botReady,
      bot_tag: botTag,
      guild_id: DISCORD_GUILD_ID,
      roles: DISCORD_ROLES,
      users_with_discord: parseInt(connected.rows[0].count),
      recent_events: events.rows
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
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
    const planNormalized = (plan || 'basic').toLowerCase();
    const monthsInt = parseInt(months) || 1;
    const base = new Date();
    base.setDate(base.getDate() + (monthsInt * 30));
    const expiresAt = base.toISOString().split('T')[0];
    const expiresAtFull = base.toISOString();

    // Salvează planul și EA-urile in notes pentru referinta
    const notesText = eas
      ? `Plată Stripe | Plan: ${plan} | EA-uri: ${eas}`
      : `Plată Stripe automată | Plan: ${plan || 'basic'}`;

    // 1️⃣ SISTEM VECHI: licenses (backwards compat)
    await pool.query(`
      INSERT INTO licenses (account_id, email, plan, status, expires_at, notes)
      VALUES ($1,$2,$3,'active',$4,$5)
      ON CONFLICT(account_id) DO UPDATE SET
        email=excluded.email, plan=excluded.plan,
        status='active', expires_at=excluded.expires_at, notes=excluded.notes
    `, [account_id, email, planNormalized, expiresAt, notesText]);

    // 🆕 SESIUNEA 13: SISTEM NOU — users + subscriptions + mt5_accounts + ea_licenses
    if (email) {
      try {
        // Plan mapping pentru tabela subscriptions
        const planForSub = planNormalized === 'full' ? 'full_access' : planNormalized;
        const maxAccounts = planForSub === 'full_access' ? 3 : planForSub === 'pro' ? 2 : 1;
        
        // 1. Caut/creez user în tabela users
        let userResult = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
        let userId;
        if (userResult.rows.length === 0) {
          const newUser = await pool.query(
            'INSERT INTO users (email, stripe_customer_id) VALUES ($1, $2) RETURNING id',
            [email, session.customer || null]
          );
          userId = newUser.rows[0].id;
        } else {
          userId = userResult.rows[0].id;
          // Update stripe_customer_id dacă lipsește
          if (session.customer) {
            await pool.query(
              'UPDATE users SET stripe_customer_id=$1 WHERE id=$2 AND stripe_customer_id IS NULL',
              [session.customer, userId]
            );
          }
        }
        
        // 2. UPSERT subscription pentru acest user
        const existingSub = await pool.query('SELECT id FROM subscriptions WHERE user_id=$1', [userId]);
        let subId;
        if (existingSub.rows.length === 0) {
          const newSub = await pool.query(
            `INSERT INTO subscriptions (user_id, plan, max_mt5_accounts, status, current_period_end, stripe_subscription_id)
             VALUES ($1, $2, $3, 'active', $4, $5) RETURNING id`,
            [userId, planForSub, maxAccounts, expiresAtFull, session.subscription || null]
          );
          subId = newSub.rows[0].id;
        } else {
          subId = existingSub.rows[0].id;
          await pool.query(
            `UPDATE subscriptions SET plan=$1, max_mt5_accounts=$2, status='active', 
             current_period_end=$3, grace_period_until=NULL,
             stripe_subscription_id=COALESCE(stripe_subscription_id, $4)
             WHERE id=$5`,
            [planForSub, maxAccounts, expiresAtFull, session.subscription || null, subId]
          );
        }
        
        // 3. Adaug cont MT5 (dacă nu există deja activ)
        if (account_id) {
          const accCheck = await pool.query(
            'SELECT id FROM mt5_accounts WHERE user_id=$1 AND account_number=$2',
            [userId, account_id]
          );
          if (accCheck.rows.length === 0) {
            await pool.query(
              `INSERT INTO mt5_accounts (user_id, subscription_id, account_number, is_active, added_at)
               VALUES ($1, $2, $3, true, NOW())`,
              [userId, subId, account_id]
            );
          } else {
            // Reactivez dacă era inactiv
            await pool.query(
              'UPDATE mt5_accounts SET is_active=true, removed_at=NULL, subscription_id=$1 WHERE id=$2',
              [subId, accCheck.rows[0].id]
            );
          }
        }
        
        // 4. EA licenses — mapping nume frumos → fișier tehnic
        const EA_MAP = {
          'ZigZag Fibo EA': 'Fibo_Final_V3.ex5',
          'Killer Indices EA': 'Killer_Indices_RobertAbo_V3.ex5',
          'Meneger Stock EA': 'Meneger_Stock_MarketsABO_V3.ex5',
          'Range Breakout EA': 'Range_Breakout_Abo_V3.ex5',
          'Robert Long EA': 'Robert_Long_Indices_ABO_V3.ex5',
          'Simple BuyDay EA': 'Simple__BuyDay_EAABO_V3.ex5'
        };
        const ALL_EAS = Object.keys(EA_MAP);
        
        // Determin ce EA-uri primește acest plan
        let eaList = [];
        if (planForSub === 'full_access') {
          // Full = toate 6
          eaList = ALL_EAS;
        } else if (eas) {
          // EA-uri alese explicit (din metadata Stripe)
          eaList = eas.split(',').map(s => s.trim()).filter(s => ALL_EAS.includes(s));
          // Limită pe plan
          const maxEAs = planForSub === 'pro' ? 3 : 1;
          eaList = eaList.slice(0, maxEAs);
        }
        
        // Ștergem EA-urile vechi și punem cele noi
        if (eaList.length > 0) {
          await pool.query('DELETE FROM ea_licenses WHERE user_id=$1', [userId]);
          for (const eaName of eaList) {
            await pool.query(
              `INSERT INTO ea_licenses (user_id, subscription_id, ea_name, file_name, status, activated_at, expires_at)
               VALUES ($1, $2, $3, $4, 'active', NOW(), $5)`,
              [userId, subId, eaName, EA_MAP[eaName], expiresAtFull]
            );
          }
        }
        
        console.log(`✅ Webhook: user ${email} (id=${userId}) actualizat la ${planForSub}, ${eaList.length} EA-uri`);
      } catch (e) {
        console.error('Webhook NEW system error:', e.message);
        await sendTelegram(`⚠️ <b>Eroare sistem nou:</b>\n${e.message}\n📧 ${email}`);
      }
    }

    // 5. Discord rol automat (folosește planNormalized)
    if (email) await addDiscordRole(email, planNormalized);

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
      `\n✅ <b>Activare automată completă</b> — clientul are acces în portal acum.`
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
