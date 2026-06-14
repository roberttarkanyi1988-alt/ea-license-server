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

// 🆕 SESIUNEA 15-FIX v2 (Opțiunea B): Sincronizare TOATE facturile lipsă pentru un customer
// Aceasta abordare e ROBUSTĂ — nu pierdem niciodată facturi, indiferent ce eveniment Stripe primim
async function saveInvoiceFromStripe(invoiceIdOrNull, userId, subId, userEmail, stripeCustomerId = null) {
  try {
    // 1. Aflu stripe_customer_id dacă nu mi-a fost dat
    let customerId = stripeCustomerId;
    if (!customerId && userId) {
      const userQuery = await pool.query(
        'SELECT stripe_customer_id FROM users WHERE id = $1 LIMIT 1',
        [userId]
      );
      customerId = userQuery.rows[0]?.stripe_customer_id;
    }

    if (!customerId) {
      console.log('saveInvoice: nu am stripe_customer_id, sar peste');
      return false;
    }

    // 2. Cer Stripe TOATE facturile recente ale customer-ului (PLĂTITE)
    const stripeInvoices = await stripe.invoices.list({
      customer: customerId,
      status: 'paid',
      limit: 20  // ultimele 20 facturi plătite — suficient
    });

    if (!stripeInvoices.data || stripeInvoices.data.length === 0) {
      console.log(`saveInvoice: niciun invoice plătit pentru customer ${customerId}`);
      return false;
    }

    // 3. Verific care din ele NU sunt deja în Supabase
    const stripeInvoiceIds = stripeInvoices.data.map(inv => inv.id);
    const existingQuery = await pool.query(
      'SELECT stripe_invoice_id FROM invoices WHERE stripe_invoice_id = ANY($1::text[])',
      [stripeInvoiceIds]
    );
    const existingIds = new Set(existingQuery.rows.map(r => r.stripe_invoice_id));

    // 4. Salvez DOAR facturile noi (cele care nu există deja)
    let savedCount = 0;
    for (const inv of stripeInvoices.data) {
      if (existingIds.has(inv.id)) continue;  // Sărim peste cele deja salvate

      const amount = inv.amount_paid || inv.amount_due || 0;
      if (amount <= 0) continue;  // Sărim peste facturi cu sumă zero (proration credits)

      const pdfUrl = inv.invoice_pdf || inv.hosted_invoice_url || null;
      const status = inv.status || 'paid';
      const paidAt = inv.status_transitions?.paid_at
        ? new Date(inv.status_transitions.paid_at * 1000)
        : new Date();

      // Pentru fiecare factură, încerc să găsesc subscription_id corect (poate fi diferit)
      let invSubId = subId;
      if (inv.subscription) {
        const subQ = await pool.query(
          'SELECT id FROM subscriptions WHERE stripe_subscription_id = $1 LIMIT 1',
          [inv.subscription]
        );
        if (subQ.rows.length > 0) invSubId = subQ.rows[0].id;
      }

      await pool.query(`
        INSERT INTO invoices (
          user_id, subscription_id, stripe_invoice_id,
          amount_cents, currency, status, invoice_pdf_url, paid_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (stripe_invoice_id) DO NOTHING
      `, [
        userId,
        invSubId,
        inv.id,
        amount,
        (inv.currency || 'eur').toLowerCase(),
        status,
        pdfUrl,
        paidAt
      ]);

      savedCount++;
      console.log(`✅ Factură nouă salvată: ${inv.id} pentru ${userEmail}, €${(amount/100).toFixed(2)}`);

      // Telegram per factură nouă
      await sendTelegram(
        `🧾 <b>Factură nouă salvată</b>\n` +
        `📧 ${userEmail || 'N/A'}\n` +
        `💰 €${(amount/100).toFixed(2)}\n` +
        `📅 ${paidAt.toISOString().split('T')[0]}\n` +
        `📄 PDF: disponibil în portal client`
      );
    }

    if (savedCount === 0) {
      console.log(`ℹ️ Sync facturi pentru ${userEmail}: toate sunt deja salvate (${stripeInvoices.data.length} total)`);
    } else {
      console.log(`✅ Sync facturi pentru ${userEmail}: ${savedCount} facturi noi salvate`);
    }

    return true;
  } catch (e) {
    console.error('saveInvoiceFromStripe error:', e.message);
    return false;
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

    // 🆕 FIX: La schimbare de plan (upgrade/downgrade), scoate ÎNTÂI toate rolurile vechi
    // ca să nu se acumuleze (ex: Basic + Pro). Excepție: OWNER protejat.
    // 🆕 În același timp detectez planul vechi ca să trimit mesaj DM corect (schimbare vs prima dată)
    let oldPlanName = null;
    const PLAN_NAMES_BY_ROLE = {
      [DISCORD_ROLES.basic]: 'BASIC',
      [DISCORD_ROLES.pro]:   'PRO',
      [DISCORD_ROLES.full]:  'FULL ACCESS'
    };
    if (dRow.discord_user_id !== DISCORD_OWNER_ID) {
      for (const oldRoleId of Object.values(DISCORD_ROLES)) {
        if (oldRoleId !== roleId && member.roles.cache.has(oldRoleId)) {
          if (!oldPlanName) oldPlanName = PLAN_NAMES_BY_ROLE[oldRoleId] || null;
          await member.roles.remove(oldRoleId).catch(e => console.log('remove old role err:', e.message));
          console.log(`🧹 Discord: rol vechi șters (${oldRoleId}) pentru ${email}`);
          await pool.query(
            'INSERT INTO discord_events (user_id, discord_user_id, event_type, role_name, details) VALUES ((SELECT id FROM users WHERE email=$1), $2, $3, $4, $5)',
            [email, dRow.discord_user_id, 'role_removed', oldRoleId, `Schimbare plan → ${plan}`]
          );
        }
      }
    }

    await member.roles.add(roleId);
    console.log(`✅ Discord: rol ${plan} adăugat pentru ${email} (${dRow.discord_user_id})`);
    
    // Log în discord_events
    await pool.query(
      'INSERT INTO discord_events (user_id, discord_user_id, event_type, role_name, details) VALUES ((SELECT id FROM users WHERE email=$1), $2, $3, $4, $5)',
      [email, dRow.discord_user_id, 'role_added', plan, `Plan ${plan} activat`]
    );
    
    // 🆕 DM diferit: upgrade/downgrade (avea rol vechi) vs prima conectare
    const newPlanName = (plan || '').toUpperCase().replace('FULL_ACCESS', 'FULL ACCESS');
    let dmText;
    let dmType;
    if (oldPlanName && oldPlanName !== newPlanName) {
      dmText = `🔄 **Planul tău a fost schimbat!**\nDe la **${oldPlanName}** la **${newPlanName}**.\nBun venit la noul nivel — acces actualizat instant. 🚀`;
      dmType = 'Plan change DM';
    } else {
      dmText = `🎉 Bine ai venit! Rolul **${newPlanName}** a fost activat pe contul tău EA Strategies. Acces VIP deschis! 💎`;
      dmType = 'Welcome DM';
    }
    try {
      await member.send(dmText);
      await pool.query(
        'INSERT INTO discord_events (user_id, discord_user_id, event_type, details) VALUES ((SELECT id FROM users WHERE email=$1), $2, $3, $4)',
        [email, dRow.discord_user_id, 'dm_sent', dmType]
      );
    } catch (e) { console.log('DM eșuat (user are DM închise):', e.message); }
    
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

// 🆕 FAZA 3: Verificare zilnică pentru trial-uri care expiră curând
async function checkExpiringTrials() {
  try {
    // Trial-uri care expiră în 3 zile sau 1 zi → notificare Telegram + DM Discord
    const expiringTrials = await pool.query(`
      SELECT 
        s.id, s.user_id, s.plan, s.trial_source, s.current_period_end,
        u.email, u.discord_user_id, u.discord_username,
        EXTRACT(DAY FROM (s.current_period_end - NOW())) AS days_left
      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      WHERE s.is_trial = true 
        AND s.status = 'active'
        AND s.current_period_end > NOW()
        AND s.current_period_end::date - CURRENT_DATE IN (3, 1)
    `);

    for (const t of expiringTrials.rows) {
      const days = Math.ceil((new Date(t.current_period_end) - new Date()) / 86400000);
      // Telegram pentru tine
      await sendTelegram(
        `🎁 <b>Trial expiră în ${days} zile</b>\n` +
        `📧 ${t.email}\n` +
        `📦 Plan: ${t.plan} (${t.trial_source || 'unknown'})\n` +
        `📅 Expiră: ${new Date(t.current_period_end).toISOString().split('T')[0]}`
      );

      // DM Discord pentru client (dacă are Discord conectat)
      if (t.discord_user_id && discordClient.isReady()) {
        try {
          const guild = await discordClient.guilds.fetch(DISCORD_GUILD_ID);
          const member = await guild.members.fetch(t.discord_user_id).catch(() => null);
          if (member) {
            await member.send(
              `⏳ Hei! Trial-ul tău EA Strategies expiră în **${days} zile**. ` +
              `Dacă vrei să continui după expirare, contactează-mă pentru un abonament. 🚀`
            );
          }
        } catch (e) { /* DM eșuat, lăsăm */ }
      }
    }

    // Trial-uri tocmai expirate → marchez expired + remove rol Discord
    const justExpiredTrials = await pool.query(`
      SELECT s.id, s.user_id, u.email
      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      WHERE s.is_trial = true AND s.status = 'active' AND s.current_period_end < NOW()
    `);

    for (const t of justExpiredTrials.rows) {
      await pool.query("UPDATE subscriptions SET status='expired' WHERE id=$1", [t.id]);
      await pool.query("UPDATE ea_licenses SET status='expired' WHERE user_id=$1", [t.user_id]);
      if (t.email) await removeDiscordRole(t.email, true, 'Trial expirat');
      await sendTelegram(`❌ <b>Trial expirat:</b>\n📧 ${t.email}\n⏰ Acces blocat`);
    }
  } catch (e) {
    console.error('Trial expiry check error:', e.message);
  }
}

setInterval(() => {
  const now = new Date();
  if (now.getHours() === 9 && now.getMinutes() === 0) {
    checkExpiringLicenses();
    checkExpiringTrials();
  }
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

// 🆕 Rezolvare alias nume EA — pentru cazuri când .ex5 raportează un nume diferit de cel din ea_licenses
// Backwards compatible: dacă nu există alias, returnează numele original
async function resolveEaName(eaName) {
  if (!eaName) return eaName;
  try {
    const r = await pool.query(
      'SELECT canonical_name FROM ea_name_aliases WHERE alias_name = $1 LIMIT 1',
      [eaName]
    );
    return r.rows.length > 0 ? r.rows[0].canonical_name : eaName;
  } catch (e) {
    console.error('resolveEaName error (folosesc numele original):', e.message);
    return eaName;
  }
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

      // 🆕 FIX SECURITATE: Verifică dacă acest cont e ÎN LIMITA planului
      // Caz: client face downgrade Pro→Basic. Avea 2 conturi, acum permise 1.
      // Doar PRIMELE N conturi (în ordinea adăugării) sunt valide; restul → INVALID
      try {
        const maxAccountsQuery = await pool.query(
          'SELECT max_mt5_accounts FROM subscriptions WHERE id=$1 LIMIT 1',
          [r.subscription_id]
        );
        const maxAccounts = maxAccountsQuery.rows[0]?.max_mt5_accounts || 1;
        
        const accountRankQuery = await pool.query(`
          SELECT account_number, ROW_NUMBER() OVER (ORDER BY added_at ASC) AS rank
          FROM mt5_accounts
          WHERE user_id=$1 AND is_active=true
        `, [r.user_id]);
        
        const currentRank = accountRankQuery.rows.find(row => row.account_number === account)?.rank;
        
        if (currentRank && parseInt(currentRank) > maxAccounts) {
          await logAccess(account, ip, 'OVER_LIMIT');
          await logAccessV2(r.user_id, account, req.query.ea || null, ip, 'OVER_LIMIT', true, true);
          console.log(`🚫 Cont ${account} peste limita planului (rank ${currentRank}, max ${maxAccounts}) pentru ${r.email}`);
          return res.send(buildResponse('INVALID'));
        }
      } catch (e) {
        console.error('Limit check error:', e.message);
        // Pe orice eroare lăsăm să treacă (failsafe — nu blocăm clientul din greșeala mea)
      }

      // 🆕 SESIUNEA 10: Verificare per EA — userul are licență pentru acest EA specific?
      if (req.query.ea) {
        const canonicalEaName = await resolveEaName(req.query.ea);
        const eaCheck = await pool.query(
          `SELECT id FROM ea_licenses WHERE user_id=$1 AND ea_name=$2 AND status='active' LIMIT 1`,
          [r.user_id, canonicalEaName]
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

// 🆕 PORTAL INIT — verifică dacă userul (după email-ul Google) există în DB
// Folosit pe portal la login pentru a decide între: arată portal sau arată "Claim subscription"
app.get('/api/portal-init', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'email required' });

  try {
    const r = await pool.query(
      `SELECT u.id, u.email, u.discord_user_id, s.plan, s.status
       FROM users u
       LEFT JOIN subscriptions s ON s.user_id = u.id
       WHERE u.email = $1 LIMIT 1`,
      [email]
    );

    if (r.rows.length === 0) {
      return res.json({ exists: false });
    }

    const user = r.rows[0];
    return res.json({
      exists: true,
      user_id: user.id,
      email: user.email,
      plan: user.plan || null,
      subscription_status: user.status || null,
      discord_connected: !!user.discord_user_id
    });
  } catch (e) {
    console.error('portal-init error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// 🆕 CLAIM SUBSCRIPTION — leagă o plată Stripe (făcută cu alt email) la userul logat cu Google
// Caz tipic: client a plătit cu yahoo, apoi se loghează cu Google care are alt email
app.post('/api/claim-subscription', async (req, res) => {
  const { stripe_email, current_email } = req.body;
  if (!stripe_email || !current_email) {
    return res.status(400).json({ error: 'stripe_email și current_email sunt obligatorii' });
  }

  // Normalizare (Stripe păstrează email-urile cu majuscule cum a scris clientul)
  const stripeEmailNorm = stripe_email.trim().toLowerCase();
  const currentEmailNorm = current_email.trim().toLowerCase();

  if (stripeEmailNorm === currentEmailNorm) {
    return res.status(400).json({ error: 'Cele două email-uri sunt identice — nu e nevoie de claim' });
  }

  try {
    // 1. Verific dacă cumva există deja user cu email-ul curent (Google)
    //    Dacă da, ar fi o coliziune (2 conturi pentru același Google email)
    const existingCheck = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1',
      [currentEmailNorm]
    );
    if (existingCheck.rows.length > 0) {
      return res.status(409).json({ 
        error: 'Există deja un cont cu acest email Google. Contactează suportul.',
        contact: 'discord'
      });
    }

    // 2. Caut user-ul cu email-ul Stripe + subscription activ
    const userQuery = await pool.query(
      `SELECT u.id, u.email, s.status, s.plan
       FROM users u
       LEFT JOIN subscriptions s ON s.user_id = u.id
       WHERE LOWER(u.email) = $1 LIMIT 1`,
      [stripeEmailNorm]
    );

    if (userQuery.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Nu am găsit niciun cont cu acest email Stripe. Verifică dacă ai scris corect.'
      });
    }

    const user = userQuery.rows[0];

    // 3. Verific că are subscription activ sau în grace period
    if (!user.status || (user.status !== 'active' && user.status !== 'grace_period')) {
      return res.status(403).json({
        error: 'Nu există un abonament activ pentru acest email. Status: ' + (user.status || 'fără abonament')
      });
    }

    // 4. Actualizez email-ul user-ului la cel curent (Google)
    await pool.query(
      'UPDATE users SET email = $1 WHERE id = $2',
      [current_email.trim(), user.id]
    );

    console.log(`✅ Claim subscription: user_id ${user.id} - email schimbat din ${stripeEmailNorm} în ${currentEmailNorm}`);

    // 5. Telegram notification
    await sendTelegram(
      `🔗 <b>Claim Subscription</b>\n` +
      `📧 Email vechi (Stripe): ${stripeEmailNorm}\n` +
      `📧 Email nou (Google): ${currentEmailNorm}\n` +
      `📦 Plan: ${user.plan}\n` +
      `✅ Cont conectat cu succes`
    );

    res.json({
      success: true,
      message: 'Cont conectat cu succes! Reîncarcă pagina ca să accesezi portalul.',
      user_id: user.id,
      plan: user.plan
    });

  } catch (e) {
    console.error('claim-subscription error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// 🆕 SESIUNEA 18: Endpoint preview schimbare plan
// Returnează info pentru fiecare plan: limită, conflict, conturi active
app.get('/api/plan-change-preview', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'email required' });

  try {
    // Caut user-ul
    const userQ = await pool.query(
      `SELECT u.id, s.plan AS current_plan, s.max_mt5_accounts AS current_max
       FROM users u
       LEFT JOIN subscriptions s ON s.user_id = u.id
       WHERE u.email = $1 LIMIT 1`,
      [email]
    );
    if (userQ.rows.length === 0) return res.status(404).json({ error: 'user not found' });
    const user = userQ.rows[0];

    // Conturile active ale userului (în ordinea adăugării)
    const accountsQ = await pool.query(
      `SELECT account_number, added_at
       FROM mt5_accounts
       WHERE user_id = $1 AND is_active = true
       ORDER BY added_at ASC`,
      [user.id]
    );
    const activeAccounts = accountsQ.rows.map(r => ({
      number: r.account_number,
      added_at: r.added_at
    }));
    const totalActive = activeAccounts.length;

    // Pentru fiecare plan, calculează dacă există conflict
    const planLimits = { basic: 1, pro: 2, full_access: 3 };
    const plans = {};
    for (const [planName, maxAcc] of Object.entries(planLimits)) {
      plans[planName] = {
        max: maxAcc,
        needs_choice: totalActive > maxAcc,
        to_remove: Math.max(0, totalActive - maxAcc)
      };
    }

    res.json({
      active_accounts: activeAccounts,
      current_plan: user.current_plan,
      current_max_accounts: user.current_max,
      plans: plans
    });
  } catch (e) {
    console.error('plan-change-preview error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// 🆕 SESIUNEA 18: Endpoint salvare alegere conturi + deschidere Stripe Portal
// Clientul a ales conturile pe care vrea să le păstreze; salvăm temporar (30 min)
// Apoi la webhook customer.subscription.updated vom citi această alegere
app.post('/api/save-plan-choice', async (req, res) => {
  const { email, target_plan, accounts_to_keep } = req.body;
  if (!email || !target_plan || !Array.isArray(accounts_to_keep)) {
    return res.status(400).json({ error: 'email, target_plan, accounts_to_keep required' });
  }

  // Validez target_plan
  const validPlans = ['basic', 'pro', 'full_access'];
  if (!validPlans.includes(target_plan)) {
    return res.status(400).json({ error: 'Invalid target_plan' });
  }

  // Validez limita
  const planLimits = { basic: 1, pro: 2, full_access: 3 };
  if (accounts_to_keep.length > planLimits[target_plan]) {
    return res.status(400).json({ error: `Planul ${target_plan} permite max ${planLimits[target_plan]} conturi` });
  }

  try {
    // Găsesc user-ul
    const userQ = await pool.query(
      'SELECT id, stripe_customer_id FROM users WHERE email = $1 LIMIT 1',
      [email]
    );
    if (userQ.rows.length === 0) return res.status(404).json({ error: 'user not found' });
    const user = userQ.rows[0];

    // Verific că toate conturile alese sunt active și ale userului
    const ownedAccountsQ = await pool.query(
      `SELECT account_number FROM mt5_accounts 
       WHERE user_id = $1 AND is_active = true AND account_number = ANY($2::text[])`,
      [user.id, accounts_to_keep]
    );
    if (ownedAccountsQ.rows.length !== accounts_to_keep.length) {
      return res.status(400).json({ error: 'Unele conturi alese nu sunt valide' });
    }

    // Șterg orice pending change vechi pentru acest user (curățare)
    await pool.query('DELETE FROM pending_plan_changes WHERE user_id = $1', [user.id]);

    // Salvez noua alegere
    await pool.query(
      `INSERT INTO pending_plan_changes (user_id, target_plan, accounts_to_keep)
       VALUES ($1, $2, $3)`,
      [user.id, target_plan, accounts_to_keep]
    );

    // Găsesc/creez stripe_customer_id
    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customers = await stripe.customers.list({ email, limit: 1 });
      if (customers.data.length > 0) {
        customerId = customers.data[0].id;
        await pool.query('UPDATE users SET stripe_customer_id=$1 WHERE id=$2', [customerId, user.id]);
      } else {
        return res.status(404).json({ error: 'No Stripe customer found' });
      }
    }

    // Creez sesiune Stripe Customer Portal
    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: 'https://ea-license-server-lrsl.onrender.com/client'
    });

    console.log(`✅ Plan choice saved for ${email}: ${target_plan} keep ${accounts_to_keep.join(',')}`);
    res.json({ success: true, stripe_portal_url: session.url });
  } catch (e) {
    console.error('save-plan-choice error:', e.message);
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

// 🆕 SESIUNEA 14: Endpoint - lista EA-uri disponibile + cele active ale userului
app.get('/api/my-eas', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'email required' });
  
  const ALL_EAS = [
    { name: 'ZigZag Fibo EA', file: 'Fibo_Final_V3.ex5' },
    { name: 'Killer Indices EA', file: 'Killer_Indices_RobertAbo_V3.ex5' },
    { name: 'Meneger Stock EA', file: 'Meneger_Stock_MarketsABO_V3.ex5' },
    { name: 'Range Breakout EA', file: 'Range_Breakout_Abo_V3.ex5' },
    { name: 'Robert Long EA', file: 'Robert_Long_Indices_ABO_V3.ex5' },
    { name: 'Simple BuyDay EA', file: 'Simple__BuyDay_EAABO_V3.ex5' }
  ];
  
  try {
    const userRes = await pool.query(`
      SELECT u.id, s.plan 
      FROM users u 
      LEFT JOIN subscriptions s ON s.user_id=u.id 
      WHERE u.email=$1
    `, [email]);
    
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'user not found' });
    const { id: userId, plan } = userRes.rows[0];
    
    // Max EA-uri permise pe plan
    const planLimits = { 'basic': 1, 'pro': 3, 'full_access': 6 };
    const maxEAs = planLimits[plan] || 1;
    
    // EA-urile active ale userului
    const activeRes = await pool.query(
      `SELECT ea_name FROM ea_licenses WHERE user_id=$1 AND status='active'`,
      [userId]
    );
    const activeNames = activeRes.rows.map(r => r.ea_name);
    
    res.json({
      plan: plan,
      max_eas: maxEAs,
      can_choose: plan !== 'full_access', // Full primește toate automat
      all_eas: ALL_EAS.map(e => e.name),
      active_eas: activeNames
    });
  } catch (e) {
    console.error('my-eas error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// 🆕 SESIUNEA 15: Endpoint - lista facturilor clientului (pentru portal RECHNUNGEN)
app.get('/api/my-invoices', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'email required' });

  try {
    const userQuery = await pool.query(
      `SELECT id FROM users WHERE email = $1 LIMIT 1`,
      [email]
    );

    if (userQuery.rows.length === 0) {
      return res.json({ invoices: [] });
    }

    const userId = userQuery.rows[0].id;

    const invoicesQuery = await pool.query(`
      SELECT 
        i.stripe_invoice_id,
        i.amount_cents,
        i.currency,
        i.status,
        i.invoice_pdf_url,
        i.paid_at,
        i.created_at,
        s.plan
      FROM invoices i
      LEFT JOIN subscriptions s ON s.id = i.subscription_id
      WHERE i.user_id = $1
      ORDER BY COALESCE(i.paid_at, i.created_at) DESC
      LIMIT 50
    `, [userId]);

    res.json({
      invoices: invoicesQuery.rows.map(r => ({
        id: r.stripe_invoice_id,
        amount: (r.amount_cents / 100).toFixed(2),
        currency: (r.currency || 'eur').toUpperCase(),
        status: r.status,
        pdf_url: r.invoice_pdf_url,
        paid_at: r.paid_at,
        created_at: r.created_at,
        plan: r.plan || 'unknown'
      }))
    });
  } catch (e) {
    console.error('Eroare listare facturi:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

// 🆕 SESIUNEA 14: Endpoint - clientul își alege EA-urile
app.post('/api/update-my-eas', async (req, res) => {
  const { email, ea_names } = req.body;
  if (!email || !Array.isArray(ea_names)) return res.status(400).json({ error: 'email and ea_names required' });
  
  const EA_MAP = {
    'ZigZag Fibo EA': 'Fibo_Final_V3.ex5',
    'Killer Indices EA': 'Killer_Indices_RobertAbo_V3.ex5',
    'Meneger Stock EA': 'Meneger_Stock_MarketsABO_V3.ex5',
    'Range Breakout EA': 'Range_Breakout_Abo_V3.ex5',
    'Robert Long EA': 'Robert_Long_Indices_ABO_V3.ex5',
    'Simple BuyDay EA': 'Simple__BuyDay_EAABO_V3.ex5'
  };
  const ALL_EAS = Object.keys(EA_MAP);
  
  try {
    // Verific user și plan
    const userRes = await pool.query(`
      SELECT u.id, s.id AS sub_id, s.plan, s.current_period_end
      FROM users u 
      LEFT JOIN subscriptions s ON s.user_id=u.id 
      WHERE u.email=$1
    `, [email]);
    
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'user not found' });
    const { id: userId, sub_id: subId, plan, current_period_end } = userRes.rows[0];
    
    // Verific dacă userul poate alege (Full primește toate automat)
    if (plan === 'full_access') return res.status(400).json({ error: 'Full Access primește toate EA-urile automat' });
    
    // Verific limita
    const planLimits = { 'basic': 1, 'pro': 3 };
    const maxEAs = planLimits[plan];
    if (!maxEAs) return res.status(400).json({ error: 'Plan invalid' });
    
    // Validez EA-urile alese
    const valid = ea_names.filter(name => ALL_EAS.includes(name));
    if (valid.length === 0) return res.status(400).json({ error: 'Niciun EA valid' });
    if (valid.length > maxEAs) return res.status(400).json({ error: `Maxim ${maxEAs} EA-uri pentru planul ${plan}` });
    
    // Șterg toate EA-urile vechi și adaug doar cele alese
    await pool.query('DELETE FROM ea_licenses WHERE user_id=$1', [userId]);
    
    const expires = current_period_end || new Date(Date.now() + 30*24*60*60*1000).toISOString();
    for (const eaName of valid) {
      await pool.query(
        `INSERT INTO ea_licenses (user_id, subscription_id, ea_name, file_name, status, activated_at, expires_at)
         VALUES ($1, $2, $3, $4, 'active', NOW(), $5)`,
        [userId, subId, eaName, EA_MAP[eaName], expires]
      );
    }
    
    await sendTelegram(`✏️ <b>EA-uri actualizate de client</b>\n📧 ${email}\n📦 Plan: ${plan}\n🤖 EA-uri: ${valid.join(', ')}`);
    
    res.json({ success: true, active_eas: valid, max_eas: maxEAs });
  } catch (e) {
    console.error('update-my-eas error:', e.message);
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

    // 🆕 AUTO-JOIN: dacă userul nu e pe server, îl adăugăm automat folosind guilds.join
    let autoJoinMsg = '';
    try {
      if (discordClient.isReady()) {
        const guild = await discordClient.guilds.fetch(DISCORD_GUILD_ID);
        const existingMember = await guild.members.fetch(discordUserId).catch(() => null);

        if (!existingMember) {
          console.log(`🔗 Auto-join: ${discordUsername} (${discordUserId}) nu e pe server, îl adaug...`);
          const joinRes = await fetch(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}`, {
            method: 'PUT',
            headers: {
              'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ access_token: tokenData.access_token })
          });

          if (joinRes.status === 201) {
            console.log(`✅ Auto-join: ${discordUsername} adăugat pe server`);
            autoJoinMsg = `<p style="color:#00e5a0;font-size:14px;">🎉 Ai fost adăugat automat pe serverul Discord!</p>`;
            await sendTelegram(`🔗 <b>Auto-join Discord:</b>\n📧 ${portalEmail}\n💬 ${discordUsername}`);
            // Log în discord_events
            await pool.query(
              'INSERT INTO discord_events (user_id, discord_user_id, event_type, details) VALUES ($1, $2, $3, $4)',
              [upd.rows[0].id, discordUserId, 'auto_joined', 'Adăugat automat prin OAuth guilds.join']
            ).catch(e => console.error('Log auto_join error:', e.message));
          } else if (joinRes.status === 204) {
            console.log(`ℹ Auto-join: ${discordUsername} deja pe server`);
          } else {
            const joinErr = await joinRes.text();
            console.error(`❌ Auto-join failed: HTTP ${joinRes.status} - ${joinErr}`);
          }
        } else {
          console.log(`ℹ Auto-join: ${discordUsername} deja pe server, sar peste`);
        }
      }
    } catch (joinErr) {
      console.error('Auto-join exception:', joinErr.message);
      // Nu blocăm flow-ul — rolul se va încerca oricum
    }

    // 🆕 SESIUNEA 14: Auto-verificare abonament activ → dă rolul automat
    let autoRoleMsg = '';
    try {
      const subCheck = await pool.query(
        `SELECT plan FROM subscriptions WHERE user_id=$1 AND status IN ('active', 'grace_period') LIMIT 1`,
        [upd.rows[0].id]
      );
      if (subCheck.rows.length > 0) {
        const plan = subCheck.rows[0].plan;
        const planForDiscord = plan === 'full_access' ? 'full' : plan;
        const roleAdded = await addDiscordRole(portalEmail, planForDiscord);
        if (roleAdded) {
          autoRoleMsg = `<p style="color:#00e5a0;font-size:14px;">🎉 Rolul <b>${plan.toUpperCase()}</b> a fost adăugat automat pe Discord!</p>`;
          await sendTelegram(`💬 <b>Discord conectat + rol auto:</b>\n📧 ${portalEmail}\n📦 Plan: ${plan}`);
        }
      }
    } catch (e) {
      console.error('Auto-role error:', e.message);
    }

    // Redirect înapoi la portal
    res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#0a0c0f;color:#e8eaf0;">
      <h1 style="color:#00e5a0;">✅ Discord conectat!</h1>
      <p>Contul Discord <b>${discordUsername}</b> a fost conectat la <b>${portalEmail}</b></p>
      ${autoJoinMsg}
      ${autoRoleMsg}
      <a href="/client" style="color:#00e5a0;">Înapoi la portal →</a>
      <script>setTimeout(() => window.location.href='/client', 3500);</script>
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
  
  // 🆕 SESIUNEA 13: Mapare price_id după plan
  const PLAN_PRICES = {
    'basic': process.env.STRIPE_PRICE_BASIC || process.env.STRIPE_PRICE_ID,
    'pro': process.env.STRIPE_PRICE_PRO || process.env.STRIPE_PRICE_ID,
    'full': process.env.STRIPE_PRICE_FULL || process.env.STRIPE_PRICE_ID,
    'full_access': process.env.STRIPE_PRICE_FULL || process.env.STRIPE_PRICE_ID
  };
  const priceId = PLAN_PRICES[plan.toLowerCase()] || PLAN_PRICES['basic'];
  
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      customer_email: email || undefined,
      line_items: [{ price: priceId, quantity: months }],
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
    const { account_id, months, plan, eas } = session.metadata;
    // 🆕 FIX: Email-ul vine din Stripe customer_details (după plată) sau metadata sau customer_email
    // Stripe garantează că customer_details.email există DUPĂ plată reușită
    const email = session.customer_details?.email 
                || session.customer_email 
                || session.metadata.email 
                || null;
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

        // 🆕 SESIUNEA 15-FIX v2: Sincronizez TOATE facturile lipsă ale acestui customer
        await saveInvoiceFromStripe(session.invoice || null, userId, subId, email, session.customer || null);
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

  // 🆕 SESIUNEA 13: Gestionare schimbare plan (upgrade/downgrade)
  if (event.type === 'customer.subscription.updated') {
    const sub = event.data.object;
    const stripeCustomerId = sub.customer;
    const stripeSubId = sub.id;
    
    try {
      // 🛡️ Caut period_end oriunde e (Stripe variază între versiuni)
      const rawPeriodEnd = sub.current_period_end 
                        || sub.items?.data?.[0]?.current_period_end 
                        || sub.billing_cycle_anchor;
      
      // Caut user după stripe_customer_id
      let userResult = await pool.query('SELECT id, email FROM users WHERE stripe_customer_id=$1', [stripeCustomerId]);
      if (userResult.rows.length === 0) {
        console.log(`Webhook update: user neînregistrat pentru ${stripeCustomerId}`);
        return res.json({ received: true });
      }
      const user = userResult.rows[0];
      
      // Determin noul plan din price amount
      const priceAmount = sub.items?.data?.[0]?.price?.unit_amount; // în cenți
      
      let newPlan = 'basic';
      let maxAccounts = 1;
      if (priceAmount >= 6500) { newPlan = 'full_access'; maxAccounts = 3; }
      else if (priceAmount >= 4000) { newPlan = 'pro'; maxAccounts = 2; }
      
      // Calculez period_end, default 30 zile dacă lipsește
      let periodEnd;
      if (rawPeriodEnd && !isNaN(rawPeriodEnd)) {
        periodEnd = new Date(rawPeriodEnd * 1000);
      } else {
        periodEnd = new Date();
        periodEnd.setDate(periodEnd.getDate() + 30);
        console.log('⚠️ period_end lipsește, folosesc default +30 zile');
      }
      
      const newStatus = 'active';
      
      // Update subscription în DB (sistem nou)
      await pool.query(
        `UPDATE subscriptions SET plan=$1, max_mt5_accounts=$2, status=$3, current_period_end=$4 
         WHERE user_id=$5`,
        [newPlan, maxAccounts, newStatus, periodEnd.toISOString(), user.id]
      );

      // 🆕 SESIUNEA 18: Verifică dacă există alegerea clientului în pending_plan_changes
      // Dacă DA → respectă alegerea (păstrează doar conturile alese de client)
      // Dacă NU → fallback la comportamentul automat (cele mai vechi rămân)
      try {
        const activeAccountsQuery = await pool.query(
          `SELECT id, account_number FROM mt5_accounts 
           WHERE user_id=$1 AND is_active=true 
           ORDER BY added_at ASC`,
          [user.id]
        );
        const activeAccounts = activeAccountsQuery.rows;
        
        if (activeAccounts.length > maxAccounts) {
          // Caut alegerea clientului (nu expirată)
          const pendingQ = await pool.query(
            `SELECT accounts_to_keep FROM pending_plan_changes 
             WHERE user_id=$1 AND target_plan=$2 AND expires_at > NOW()
             ORDER BY created_at DESC LIMIT 1`,
            [user.id, newPlan]
          );
          
          let accountsToKeep = [];
          let choiceSource = '';
          
          if (pendingQ.rows.length > 0) {
            // CLIENTUL A ALES — respectă alegerea lui
            accountsToKeep = pendingQ.rows[0].accounts_to_keep || [];
            choiceSource = 'alegerea clientului';
          } else {
            // FALLBACK — păstrează cele mai vechi N
            accountsToKeep = activeAccounts.slice(0, maxAccounts).map(a => a.account_number);
            choiceSource = 'cele mai vechi (auto)';
          }
          
          // Dezactivez conturile care NU sunt în lista de păstrat
          const toDeactivate = activeAccounts.filter(a => !accountsToKeep.includes(a.account_number));
          for (const acc of toDeactivate) {
            await pool.query(
              `UPDATE mt5_accounts SET is_active=false, removed_at=NOW() WHERE id=$1`,
              [acc.id]
            );
            console.log(`🚫 Dezactivat cont MT5 ${acc.account_number} pentru ${user.email} (downgrade la ${newPlan}, sursă: ${choiceSource})`);
          }
          
          if (toDeactivate.length > 0) {
            await sendTelegram(
              `⚠️ <b>Dezactivare conturi la downgrade</b>\n📧 ${user.email}\n📦 Plan nou: ${newPlan} (max ${maxAccounts} conturi)\n✅ Păstrate: ${accountsToKeep.map(n => '#' + n).join(', ')}\n🚫 Dezactivate: ${toDeactivate.map(a => '#' + a.account_number).join(', ')}\nℹ️ Sursă alegere: ${choiceSource}`
            );
          }
          
          // Cleanup pending_plan_changes după ce am aplicat alegerea
          if (pendingQ.rows.length > 0) {
            await pool.query('DELETE FROM pending_plan_changes WHERE user_id=$1', [user.id]);
          }
        }
      } catch (e) {
        console.error('Plan change accounts handling error:', e.message);
      }
      
      // 🆕 Update și tabela licenses (sistem vechi folosit de admin panel)
      const legacyPlan = newPlan === 'full_access' ? 'full' : newPlan;
      const legacyExpires = periodEnd.toISOString().split('T')[0];
      await pool.query(
        `UPDATE licenses SET plan=$1, expires_at=$2, status='active' WHERE email=$3`,
        [legacyPlan, legacyExpires, user.email]
      );
      
      // 🆕 SESIUNEA 14: La schimbare plan, șterg EA-urile vechi
      // - Pentru full_access → adaug toate 6 automat
      // - Pentru basic/pro → șterg toate (clientul alege din portal)
      const EA_MAP = {
        'ZigZag Fibo EA': 'Fibo_Final_V3.ex5',
        'Killer Indices EA': 'Killer_Indices_RobertAbo_V3.ex5',
        'Meneger Stock EA': 'Meneger_Stock_MarketsABO_V3.ex5',
        'Range Breakout EA': 'Range_Breakout_Abo_V3.ex5',
        'Robert Long EA': 'Robert_Long_Indices_ABO_V3.ex5',
        'Simple BuyDay EA': 'Simple__BuyDay_EAABO_V3.ex5'
      };
      
      // Șterg toate EA-urile vechi
      await pool.query('DELETE FROM ea_licenses WHERE user_id=$1', [user.id]);
      
      // Iau sub_id pentru folosire ulterioară
      const subQuery = await pool.query('SELECT id FROM subscriptions WHERE user_id=$1', [user.id]);
      const subIdForUser = subQuery.rows[0]?.id;
      
      if (newPlan === 'full_access' && subIdForUser) {
        // Full = adaug toate 6 automat
        for (const [eaName, fileName] of Object.entries(EA_MAP)) {
          await pool.query(
            `INSERT INTO ea_licenses (user_id, subscription_id, ea_name, file_name, status, activated_at, expires_at)
             VALUES ($1, $2, $3, $4, 'active', NOW(), $5)`,
            [user.id, subIdForUser, eaName, fileName, periodEnd.toISOString()]
          );
        }
      }
      // Pentru basic/pro: rămân fără EA-uri, clientul va alege din portal
      
      // Update Discord rol
      await addDiscordRole(user.email, newPlan === 'full_access' ? 'full' : newPlan);
      
      const planLabel = sub.cancel_at_period_end ? `${newPlan} (anulare programată)` : newPlan;
      await sendTelegram(
        `🔄 <b>ABONAMENT MODIFICAT</b>\n📧 ${user.email}\n📦 Plan nou: <b>${planLabel}</b>\n📅 Activ până: ${periodEnd.toISOString().split('T')[0]}`
      );
      
      console.log(`✅ Subscription updated for ${user.email}: ${newPlan}`);

      // 🆕 SESIUNEA 15-FIX v2: Sincronizez TOATE facturile lipsă ale acestui customer
      // Aceasta abordare e robustă: cere lista completă de la Stripe, salvează doar cele NOI
      if (subIdForUser) {
        await saveInvoiceFromStripe(sub.latest_invoice || null, user.id, subIdForUser, user.email, stripeCustomerId);
      }
    } catch (e) {
      console.error('Subscription update error:', e.message);
      await sendTelegram(`⚠️ <b>Eroare update sub:</b>\n${e.message}`);
    }
  }

  // 🆕 SESIUNEA 13: Gestionare anulare abonament
  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const stripeCustomerId = sub.customer;
    
    try {
      const userResult = await pool.query('SELECT id, email FROM users WHERE stripe_customer_id=$1', [stripeCustomerId]);
      if (userResult.rows.length === 0) return res.json({ received: true });
      const user = userResult.rows[0];
      
      // Marchez subscription expirat + intră în grace 30 zile
      const graceEnd = new Date();
      graceEnd.setDate(graceEnd.getDate() + 30);
      
      await pool.query(
        `UPDATE subscriptions SET status='grace_period', grace_period_until=$1 WHERE user_id=$2`,
        [graceEnd.toISOString(), user.id]
      );
      
      // Marchez și EA licenses (rămân active 30 zile prin grace_period)
      await pool.query(
        `UPDATE ea_licenses SET expires_at=$1 WHERE user_id=$2 AND status='active'`,
        [graceEnd.toISOString(), user.id]
      );
      
      // Trimit DM pe Discord cu avertisment grace
      await removeDiscordRole(user.email, true, 'Abonament anulat — grace 30 zile');
      
      // Legacy sistem
      await pool.query("UPDATE licenses SET status='expired' WHERE email=$1", [user.email]);
      
      await sendTelegram(
        `❌ <b>ABONAMENT ANULAT</b>\n📧 ${user.email}\n⏰ Grace 30 zile activ\n📅 Kick automat: ${graceEnd.toISOString().split('T')[0]}`
      );
      
      console.log(`✅ Subscription cancelled for ${user.email}, grace until ${graceEnd}`);
    } catch (e) {
      console.error('Subscription delete error:', e.message);
    }
  }

  // 🆕 SESIUNEA 15: Handler pentru invoice.paid (BACKUP — Stripe poate să nu-l trimită mereu)
  // Soluția principală e în customer.subscription.updated mai sus (care vine 100%)
  if (event.type === 'invoice.paid' || event.type === 'invoice.payment_succeeded') {
    const inv = event.data.object;
    const customerEmail = inv.customer_email || (inv.customer_address && inv.customer_address.email);

    try {
      // Găsim user-ul în Supabase după email sau stripe_customer_id
      let userQuery = null;
      if (inv.customer) {
        userQuery = await pool.query(
          `SELECT id, email FROM users WHERE stripe_customer_id = $1 LIMIT 1`,
          [inv.customer]
        );
      }
      if ((!userQuery || userQuery.rows.length === 0) && customerEmail) {
        userQuery = await pool.query(
          `SELECT id, email FROM users WHERE email = $1 LIMIT 1`,
          [customerEmail]
        );
      }

      if (userQuery && userQuery.rows.length > 0) {
        const userId = userQuery.rows[0].id;
        const userEmail = userQuery.rows[0].email || customerEmail;

        // Găsim subscription_id dacă există
        let subId = null;
        if (inv.subscription) {
          const subQuery = await pool.query(
            `SELECT id FROM subscriptions WHERE stripe_subscription_id = $1 LIMIT 1`,
            [inv.subscription]
          );
          if (subQuery.rows.length > 0) subId = subQuery.rows[0].id;
        }

        // Folosim funcția unificată (sync TOATE facturile lipsă)
        await saveInvoiceFromStripe(inv.id, userId, subId, userEmail, inv.customer || null);
      } else {
        console.warn(`⚠️ Invoice ${inv.id} primit dar user negăsit (email: ${customerEmail})`);
      }
    } catch (e) {
      console.error('Eroare salvare factură (invoice.paid handler):', e.message);
    }
  }

  if (event.type === 'invoice.payment_failed') {
    const obj = event.data.object;
    const email = obj.customer_email || obj.metadata?.email;
    if (email) {
      await sendTelegram(`⚠️ <b>Plată eșuată</b>\n📧 ${email}\n💳 Stripe va încerca din nou automat`);
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

// ─── 🆕 ACTIVITATE LIVE: Monitor pentru tab-ul nou din admin ──────────────────
// Returnează toate datele necesare pentru dashboard-ul Activitate Live
// Citește din: access_log_v2, users, subscriptions, ea_licenses, mt5_accounts
app.get('/admin/activity-monitor', adminAuth, async (req, res) => {
  try {
    // 1. Sumar status clienți (activi/inactivi/dispăruți/erori azi)
    const summaryQuery = await pool.query(`
      SELECT
        (SELECT COUNT(DISTINCT user_id) FROM access_log_v2 
         WHERE checked_at > NOW() - INTERVAL '2 hours' AND result = 'VALID_NEW' AND user_id IS NOT NULL) AS active_now,
        (SELECT COUNT(DISTINCT user_id) FROM access_log_v2 
         WHERE user_id IS NOT NULL AND result = 'VALID_NEW' 
         AND user_id NOT IN (
           SELECT DISTINCT user_id FROM access_log_v2 
           WHERE checked_at > NOW() - INTERVAL '24 hours' AND user_id IS NOT NULL
         )
         AND user_id IN (
           SELECT DISTINCT user_id FROM access_log_v2 
           WHERE checked_at > NOW() - INTERVAL '48 hours' AND user_id IS NOT NULL
         )
        ) AS inactive_24_48h,
        (SELECT COUNT(*) FROM access_log_v2 
         WHERE checked_at > NOW() - INTERVAL '24 hours' AND result != 'VALID_NEW' AND result != 'VALID_OLD' AND result != 'DOWNLOAD') AS errors_today
    `);

    // 2. Sumar financiar (clienți activi + venit)
    const financialQuery = await pool.query(`
      SELECT 
        COUNT(*) AS total_active,
        COUNT(CASE WHEN plan = 'basic' THEN 1 END) AS basic_count,
        COUNT(CASE WHEN plan = 'pro' THEN 1 END) AS pro_count,
        COUNT(CASE WHEN plan = 'full_access' THEN 1 END) AS full_count,
        COUNT(CASE WHEN current_period_end < NOW() + INTERVAL '7 days' AND current_period_end > NOW() THEN 1 END) AS expiring_soon
      FROM subscriptions
      WHERE status = 'active'
    `);

    // 3. Lista clienți cu status (pentru lista de selectare)
    const clientsListQuery = await pool.query(`
      SELECT 
        u.id AS user_id,
        u.email,
        u.discord_username,
        s.plan,
        s.status,
        s.current_period_end,
        s.max_mt5_accounts,
        (SELECT MAX(checked_at) FROM access_log_v2 WHERE user_id = u.id AND result = 'VALID_NEW') AS last_checkin,
        (SELECT COUNT(*) FROM ea_licenses WHERE user_id = u.id AND status = 'active') AS active_eas_count,
        (SELECT COUNT(*) FROM mt5_accounts WHERE user_id = u.id AND is_active = true) AS active_accounts_count
      FROM users u
      LEFT JOIN subscriptions s ON s.user_id = u.id
      WHERE s.status IS NOT NULL
      ORDER BY s.current_period_end DESC NULLS LAST
    `);

    // 4. Top EA-uri în ultimele 7 zile
    const topEasQuery = await pool.query(`
      SELECT 
        ea_name,
        COUNT(*) AS checkins_count,
        COUNT(DISTINCT account_number) AS unique_accounts
      FROM access_log_v2
      WHERE checked_at > NOW() - INTERVAL '7 days'
        AND result = 'VALID_NEW'
        AND ea_name IS NOT NULL
      GROUP BY ea_name
      ORDER BY checkins_count DESC
      LIMIT 6
    `);

    // 5. Activitate săptămânală (ultimele 7 zile, grupată pe zile)
    const weeklyActivityQuery = await pool.query(`
      SELECT 
        DATE(checked_at AT TIME ZONE 'Europe/Bucharest') AS day,
        COUNT(*) AS checkins,
        COUNT(DISTINCT account_number) AS unique_accounts
      FROM access_log_v2
      WHERE checked_at > NOW() - INTERVAL '7 days'
        AND result = 'VALID_NEW'
      GROUP BY DATE(checked_at AT TIME ZONE 'Europe/Bucharest')
      ORDER BY day ASC
    `);

    // 6. Ultimele check-in-uri (10 recente)
    const recentCheckinsQuery = await pool.query(`
      SELECT 
        l.user_id,
        u.email,
        l.ea_name,
        l.account_number,
        l.result,
        l.hmac_valid,
        l.checked_at
      FROM access_log_v2 l
      LEFT JOIN users u ON u.id = l.user_id
      WHERE l.result = 'VALID_NEW'
      ORDER BY l.checked_at DESC
      LIMIT 10
    `);

    // 7. Conturi MT5 active (mapă brokeri)
    const mt5AccountsQuery = await pool.query(`
      SELECT 
        m.account_number,
        m.broker,
        m.added_at,
        u.email,
        s.plan
      FROM mt5_accounts m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN subscriptions s ON s.id = m.subscription_id
      WHERE m.is_active = true
      ORDER BY m.added_at DESC
    `);

    res.json({
      summary: summaryQuery.rows[0],
      financial: financialQuery.rows[0],
      clients: clientsListQuery.rows,
      top_eas: topEasQuery.rows,
      weekly_activity: weeklyActivityQuery.rows,
      recent_checkins: recentCheckinsQuery.rows,
      mt5_accounts: mt5AccountsQuery.rows,
      generated_at: new Date().toISOString()
    });
  } catch (e) {
    console.error('Activity monitor error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── 🆕 FAZA 2: EXTINDERE ABONAMENT GRATUIT ──────────────────────────────────

// Helper: Actualizează billing_cycle_anchor în Stripe cu proration_behavior='none'
// Asta înseamnă: Stripe AMÂNĂ data următoarei facturări, FĂRĂ să genereze ajustări
async function updateStripeBillingAnchor(stripeSubId, newPeriodEnd) {
  if (!stripeSubId) return { synced: false, error: 'no_stripe_subscription' };
  try {
    const trialEndUnix = Math.floor(new Date(newPeriodEnd).getTime() / 1000);
    // trial_end mută anchor-ul în viitor FĂRĂ proration
    // (alternativă mai sigură decât billing_cycle_anchor direct)
    const updated = await stripe.subscriptions.update(stripeSubId, {
      trial_end: trialEndUnix,
      proration_behavior: 'none'
    });
    console.log(`✅ Stripe billing anchor actualizat: ${stripeSubId} → ${newPeriodEnd}`);
    return { synced: true, stripe_status: updated.status };
  } catch (e) {
    console.error('Stripe billing anchor error:', e.message);
    return { synced: false, error: e.message };
  }
}

// POST /admin/extend-subscription
// Body: { user_id, days, reason_tag, reason_notes, sync_stripe (bool, default true) }
app.post('/admin/extend-subscription', adminAuth, async (req, res) => {
  const { user_id, days, reason_tag, reason_notes, sync_stripe = true } = req.body;

  // Validări
  if (!user_id || !days || !reason_tag) {
    return res.status(400).json({ error: 'user_id, days și reason_tag sunt obligatorii' });
  }
  const daysInt = parseInt(days);
  if (isNaN(daysInt) || daysInt < 1 || daysInt > 365) {
    return res.status(400).json({ error: 'days trebuie între 1 și 365' });
  }
  const validTags = ['compensation', 'loyalty', 'gift', 'friend_bonus', 'apology', 'other'];
  if (!validTags.includes(reason_tag)) {
    return res.status(400).json({ error: 'reason_tag invalid', valid: validTags });
  }

  try {
    // 1. Iau subscription-ul curent
    const subQuery = await pool.query(
      `SELECT s.*, u.email, u.discord_user_id 
       FROM subscriptions s 
       JOIN users u ON u.id = s.user_id 
       WHERE s.user_id = $1 AND s.status IN ('active', 'grace_period')
       ORDER BY s.id DESC LIMIT 1`,
      [user_id]
    );
    if (subQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Nu am găsit abonament activ pentru acest user' });
    }
    const sub = subQuery.rows[0];
    const oldPeriodEnd = sub.current_period_end ? new Date(sub.current_period_end) : new Date();
    const newPeriodEnd = new Date(oldPeriodEnd);
    newPeriodEnd.setDate(newPeriodEnd.getDate() + daysInt);

    // 2. Sincronizare Stripe (dacă există subscription Stripe + sync activat)
    let stripeSyncResult = { synced: false, error: 'sync_disabled' };
    if (sync_stripe && sub.stripe_subscription_id && !sub.is_trial) {
      stripeSyncResult = await updateStripeBillingAnchor(
        sub.stripe_subscription_id,
        newPeriodEnd.toISOString()
      );
    }

    // 3. Actualizez DB
    await pool.query(
      `UPDATE subscriptions 
       SET current_period_end = $1, status = 'active', grace_period_until = NULL 
       WHERE id = $2`,
      [newPeriodEnd.toISOString(), sub.id]
    );

    // 4. Actualizez ea_licenses expires_at
    await pool.query(
      `UPDATE ea_licenses SET expires_at = $1 WHERE user_id = $2 AND status IN ('active', 'expired')`,
      [newPeriodEnd.toISOString(), user_id]
    );

    // 5. Update și tabela veche licenses (backwards compat)
    if (sub.email) {
      const legacyDate = newPeriodEnd.toISOString().split('T')[0];
      await pool.query(
        `UPDATE licenses SET expires_at = $1, status = 'active' WHERE email = $2`,
        [legacyDate, sub.email]
      );
    }

    // 6. Loghez în manual_extensions
    const extLog = await pool.query(
      `INSERT INTO manual_extensions 
       (user_id, subscription_id, days_added, reason_tag, reason_notes, 
        old_period_end, new_period_end, stripe_synced, stripe_error) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [user_id, sub.id, daysInt, reason_tag, reason_notes || null,
       oldPeriodEnd.toISOString(), newPeriodEnd.toISOString(),
       stripeSyncResult.synced, stripeSyncResult.error || null]
    );

    // 7. Telegram
    const reasonLabels = {
      compensation: 'Compensare', loyalty: 'Loialitate', gift: 'Cadou',
      friend_bonus: 'Prieten/Bonus', apology: 'Scuze', other: 'Altul'
    };
    await sendTelegram(
      `🎁 <b>Extindere gratuită acordată</b>\n` +
      `📧 ${sub.email}\n` +
      `➕ ${daysInt} zile gratis\n` +
      `📌 Motiv: ${reasonLabels[reason_tag]}\n` +
      `📅 Nouă expirare: ${newPeriodEnd.toISOString().split('T')[0]}\n` +
      `💳 Stripe sync: ${stripeSyncResult.synced ? '✅ OK' : '⚠️ ' + (stripeSyncResult.error || 'eșuat')}` +
      (reason_notes ? `\n📝 Note: ${reason_notes}` : '')
    );

    // 8. DM Discord pentru client (opțional, dacă are Discord)
    if (sub.discord_user_id && discordClient.isReady()) {
      try {
        const guild = await discordClient.guilds.fetch(DISCORD_GUILD_ID);
        const member = await guild.members.fetch(sub.discord_user_id).catch(() => null);
        if (member) {
          await member.send(
            `🎁 **Surpriză!** Ai primit **${daysInt} zile gratuite** la abonamentul tău EA Strategies! ` +
            `Noua dată de expirare: **${newPeriodEnd.toISOString().split('T')[0]}**. Mulțumim că ești cu noi! 🚀`
          );
        }
      } catch (e) { /* DM eșuat */ }
    }

    res.json({
      success: true,
      extension_id: extLog.rows[0].id,
      old_period_end: oldPeriodEnd.toISOString(),
      new_period_end: newPeriodEnd.toISOString(),
      days_added: daysInt,
      stripe_synced: stripeSyncResult.synced,
      stripe_error: stripeSyncResult.error || null
    });
  } catch (e) {
    console.error('Extend subscription error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /admin/extensions-log
// Returnează jurnalul complet al extinderilor (cu filtru optional ?user_id=X)
app.get('/admin/extensions-log', adminAuth, async (req, res) => {
  try {
    const { user_id } = req.query;
    let query, params;
    if (user_id) {
      query = `
        SELECT me.*, u.email 
        FROM manual_extensions me 
        LEFT JOIN users u ON u.id = me.user_id 
        WHERE me.user_id = $1 
        ORDER BY me.created_at DESC LIMIT 100`;
      params = [user_id];
    } else {
      query = `
        SELECT me.*, u.email 
        FROM manual_extensions me 
        LEFT JOIN users u ON u.id = me.user_id 
        ORDER BY me.created_at DESC LIMIT 100`;
      params = [];
    }
    const r = await pool.query(query, params);
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 🆕 FAZA 3: TRIAL GRATUIT PENTRU PRIETENI ────────────────────────────────

// POST /admin/create-trial
// Body: { email, plan, days, trial_source, trial_notes, mt5_account (optional), ea_names (optional array) }
app.post('/admin/create-trial', adminAuth, async (req, res) => {
  const { 
    email, plan, days, trial_source, trial_notes, 
    mt5_account, ea_names 
  } = req.body;

  // Validări
  if (!email || !plan || !days || !trial_source) {
    return res.status(400).json({ 
      error: 'email, plan, days și trial_source sunt obligatorii' 
    });
  }
  const daysInt = parseInt(days);
  if (isNaN(daysInt) || daysInt < 1 || daysInt > 365) {
    return res.status(400).json({ error: 'days trebuie între 1 și 365' });
  }
  const validPlans = ['basic', 'pro', 'full_access'];
  if (!validPlans.includes(plan)) {
    return res.status(400).json({ error: 'plan invalid', valid: validPlans });
  }
  const validSources = ['friend', 'influencer', 'tester', 'demo', 'other'];
  if (!validSources.includes(trial_source)) {
    return res.status(400).json({ error: 'trial_source invalid', valid: validSources });
  }

  const emailNorm = email.trim().toLowerCase();

  try {
    // 1. Verific dacă există deja user cu acest email
    let userId;
    const existingUser = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [emailNorm]);
    
    if (existingUser.rows.length > 0) {
      userId = existingUser.rows[0].id;
      // Verific dacă are deja subscription activ
      const existingSub = await pool.query(
        `SELECT id, status, is_trial FROM subscriptions 
         WHERE user_id = $1 AND status IN ('active', 'grace_period') LIMIT 1`,
        [userId]
      );
      if (existingSub.rows.length > 0) {
        return res.status(409).json({ 
          error: 'Acest user are deja un abonament activ',
          existing_subscription_id: existingSub.rows[0].id,
          is_trial: existingSub.rows[0].is_trial
        });
      }
    } else {
      // Creez user nou (fără stripe_customer_id — trial e gratis)
      const newUser = await pool.query(
        'INSERT INTO users (email) VALUES ($1) RETURNING id',
        [email.trim()]
      );
      userId = newUser.rows[0].id;
    }

    // 2. Calculez expirare trial
    const trialEnd = new Date();
    trialEnd.setDate(trialEnd.getDate() + daysInt);

    // 3. Determin max_mt5_accounts pe baza planului
    const maxAccountsByPlan = { basic: 1, pro: 2, full_access: 3 };
    const maxAccounts = maxAccountsByPlan[plan];

    // 4. Creez subscription cu is_trial=true
    const subResult = await pool.query(
      `INSERT INTO subscriptions 
       (user_id, plan, max_mt5_accounts, status, current_period_end, 
        is_trial, trial_source, trial_notes) 
       VALUES ($1, $2, $3, 'active', $4, true, $5, $6) RETURNING id`,
      [userId, plan, maxAccounts, trialEnd.toISOString(), trial_source, trial_notes || null]
    );
    const subId = subResult.rows[0].id;

    // 5. Adaug cont MT5 (dacă e furnizat)
    if (mt5_account) {
      await pool.query(
        `INSERT INTO mt5_accounts (user_id, subscription_id, account_number, is_active, added_at)
         VALUES ($1, $2, $3, true, NOW())
         ON CONFLICT DO NOTHING`,
        [userId, subId, String(mt5_account)]
      );
    }

    // 6. Creez ea_licenses
    const EA_MAP = {
      'ZigZag Fibo EA': 'Fibo_Final_V3.ex5',
      'Killer Indices EA': 'Killer_Indices_RobertAbo_V3.ex5',
      'Meneger Stock EA': 'Meneger_Stock_MarketsABO_V3.ex5',
      'Range Breakout EA': 'Range_Breakout_Abo_V3.ex5',
      'Robert Long EA': 'Robert_Long_Indices_ABO_V3.ex5',
      'Simple BuyDay EA': 'Simple__BuyDay_EAABO_V3.ex5'
    };
    const ALL_EAS = Object.keys(EA_MAP);

    let eaList = [];
    if (plan === 'full_access') {
      // Full = toate 6 automat
      eaList = ALL_EAS;
    } else if (Array.isArray(ea_names) && ea_names.length > 0) {
      // EA-uri alese explicit
      eaList = ea_names.filter(n => ALL_EAS.includes(n));
      const maxEAs = plan === 'pro' ? 3 : 1;
      eaList = eaList.slice(0, maxEAs);
    }

    for (const eaName of eaList) {
      await pool.query(
        `INSERT INTO ea_licenses 
         (user_id, subscription_id, ea_name, file_name, status, activated_at, expires_at)
         VALUES ($1, $2, $3, $4, 'active', NOW(), $5)`,
        [userId, subId, eaName, EA_MAP[eaName], trialEnd.toISOString()]
      );
    }

    // 7. Telegram
    const sourceLabels = {
      friend: 'Prieten', influencer: 'Influencer', tester: 'Tester',
      demo: 'Demo', other: 'Altul'
    };
    await sendTelegram(
      `🎁 <b>TRIAL GRATUIT CREAT</b>\n` +
      `📧 ${email}\n` +
      `📦 Plan: ${plan.toUpperCase()}\n` +
      `⏱️ Durată: ${daysInt} zile\n` +
      `📅 Expiră: ${trialEnd.toISOString().split('T')[0]}\n` +
      `🏷️ Sursă: ${sourceLabels[trial_source]}\n` +
      `🤖 EA-uri: ${eaList.length > 0 ? eaList.join(', ') : 'niciuna'}` +
      (mt5_account ? `\n💼 Cont MT5: #${mt5_account}` : '') +
      (trial_notes ? `\n📝 Note: ${trial_notes}` : '')
    );

    res.json({
      success: true,
      user_id: userId,
      subscription_id: subId,
      email: email.trim(),
      plan: plan,
      trial_end: trialEnd.toISOString(),
      days: daysInt,
      eas_assigned: eaList,
      mt5_account: mt5_account || null
    });
  } catch (e) {
    console.error('Create trial error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /admin/trial-list
// Returnează lista trial-urilor (active + expirate, cu filtru ?status=active)
app.get('/admin/trial-list', adminAuth, async (req, res) => {
  try {
    const { status } = req.query;
    let whereClause = 's.is_trial = true';
    const params = [];
    if (status === 'active') {
      whereClause += " AND s.status = 'active' AND s.current_period_end > NOW()";
    } else if (status === 'expired') {
      whereClause += " AND (s.status = 'expired' OR s.current_period_end < NOW())";
    }
    const r = await pool.query(`
      SELECT 
        s.id AS subscription_id,
        s.user_id,
        s.plan,
        s.status,
        s.current_period_end,
        s.trial_source,
        s.trial_notes,
        s.created_at,
        u.email,
        u.discord_username,
        EXTRACT(DAY FROM (s.current_period_end - NOW())) AS days_left,
        (SELECT COUNT(*) FROM ea_licenses WHERE user_id = s.user_id AND status = 'active') AS active_eas,
        (SELECT COUNT(*) FROM mt5_accounts WHERE user_id = s.user_id AND is_active = true) AS active_accounts
      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      WHERE ${whereClause}
      ORDER BY s.current_period_end DESC
    `, params);
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /admin/trial/:id
// Anulează un trial înainte de expirare (manual)
app.delete('/admin/trial/:id', adminAuth, async (req, res) => {
  try {
    const subId = req.params.id;
    
    // Verific că e trial
    const check = await pool.query(
      `SELECT s.user_id, s.is_trial, u.email 
       FROM subscriptions s JOIN users u ON u.id = s.user_id 
       WHERE s.id = $1 LIMIT 1`,
      [subId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Subscription not found' });
    if (!check.rows[0].is_trial) return res.status(400).json({ error: 'Acest abonament nu e trial' });
    
    const { user_id, email } = check.rows[0];

    // Marchez ca expired (păstrez înregistrarea pentru istoric)
    await pool.query("UPDATE subscriptions SET status='expired', current_period_end=NOW() WHERE id=$1", [subId]);
    await pool.query("UPDATE ea_licenses SET status='expired' WHERE user_id=$1", [user_id]);

    // Scot rol Discord
    if (email) await removeDiscordRole(email, false, 'Trial anulat manual');

    await sendTelegram(`🚫 <b>Trial anulat manual</b>\n📧 ${email}\n⏰ Acces blocat imediat`);
    
    res.json({ success: true, subscription_id: subId, user_id, email });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
