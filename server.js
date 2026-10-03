const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

/* =====================================================
   КОНФИГ
   ===================================================== */
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'neaboba228';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SITE_COOKIE = 'raidwiki_session';
const ADMIN_COOKIE = 'raidwiki_admin';
const COOKIE_MAX_AGE = 1000 * 60 * 60 * 24 * 7; // 7 дней

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_KEY) {
  console.error('Не заданы SUPABASE_URL / SUPABASE_ANON_KEY / SUPABASE_SERVICE_KEY');
  process.exit(1);
}

const supabaseRead = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false }
});
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false }
});

/* =====================================================
   ЗАЩИТА
   ===================================================== */
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "img-src 'self' data: https:",
      "media-src 'self' data: https:",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self' 'unsafe-inline'",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'self'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; ')
  );
  next();
});

const BAD_UA = /(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wfuzz|hydra|zgrab|semrush|ahrefsbot|mj12bot|dotbot|petalbot|bytespider|blexbot)/i;

app.use((req, res, next) => {
  const ua = req.headers['user-agent'] || '';
  if (!ua || BAD_UA.test(ua)) return res.status(403).send('Forbidden');
  next();
});

app.use(express.json({ limit: '512kb' }));
app.use(express.urlencoded({ extended: false, limit: '512kb' }));

/* Rate limit */
const RL_WINDOW = 60 * 1000;
const hits = new Map();
function rateLimit(max) {
  return (req, res, next) => {
    const now = Date.now();
    const ip = req.ip || 'unknown';
    const arr = (hits.get(ip) || []).filter(t => now - t < RL_WINDOW);
    if (arr.length >= max) {
      res.setHeader('Retry-After', '30');
      return res.status(429).json({ error: 'Too many requests' });
    }
    arr.push(now);
    hits.set(ip, arr);
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    const fresh = arr.filter(t => now - t < RL_WINDOW);
    if (fresh.length) hits.set(ip, fresh);
    else hits.delete(ip);
  }
}, 5 * 60 * 1000);

/* =====================================================
   СЕССИИ
   ===================================================== */
function signSession(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}
function verifySession(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  } catch { return null; }
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach(pair => {
    const i = pair.indexOf('=');
    if (i < 0) return;
    const k = pair.slice(0, i).trim();
    const v = pair.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}
function setCookie(res, name, token) {
  res.setHeader(
    'Set-Cookie',
    `${name}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${COOKIE_MAX_AGE / 1000}`
  );
}
function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`);
}
function isSiteAuthed(req) {
  const cookies = parseCookies(req.headers.cookie);
  return !!verifySession(cookies[SITE_COOKIE]);
}
function isAdminAuthed(req) {
  const cookies = parseCookies(req.headers.cookie);
  const s = verifySession(cookies[ADMIN_COOKIE]);
  return !!s && s.role === 'admin';
}
function safeCompare(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/* =====================================================
   ОДНОРАЗОВЫЕ ПАРОЛИ
   -----------------------------------------------------
   Возвращает true, если пароль подошёл и был успешно
   помечен как использованный. false — если пароль не
   найден или уже использован.
   ===================================================== */
async function consumeOneTimePassword(password, ip) {
  try {
    /* Ищем пароль, который ещё не использован */
    const { data, error } = await supabaseAdmin
      .from('one_time_passwords')
      .select('id, used')
      .eq('password', password)
      .maybeSingle();

    if (error) {
      console.error('Ошибка чтения OTP:', error.message);
      return false;
    }
    if (!data) return false;      // нет такого пароля
    if (data.used) return false;  // уже использован

    /* Помечаем как использованный (только если ещё не использован) */
    const { error: updErr, count } = await supabaseAdmin
      .from('one_time_passwords')
      .update(
        { used: true, used_at: new Date().toISOString(), used_ip: ip || null },
        { count: 'exact' }
      )
      .eq('id', data.id)
      .eq('used', false);

    if (updErr) {
      console.error('Ошибка обновления OTP:', updErr.message);
      return false;
    }
    /* Если count = 0, значит кто-то успел использовать параллельно */
    return (count || 0) > 0;
  } catch (e) {
    console.error('Ошибка OTP:', e.message || e);
    return false;
  }
}

/* =====================================================
   ПУБЛИЧНОЕ API
   ===================================================== */
app.post('/api/login', rateLimit(30), async (req, res) => {
  const { password } = req.body || {};
  if (typeof password !== 'string' || !password) {
    return res.status(400).json({ error: 'Пароль не указан' });
  }

  /* 1. Проверяем основной пароль */
  if (safeCompare(password, SITE_PASSWORD)) {
    const token = signSession({ role: 'site', exp: Date.now() + COOKIE_MAX_AGE });
    setCookie(res, SITE_COOKIE, token);
    return res.json({ ok: true, type: 'main' });
  }

  /* 2. Проверяем одноразовый пароль */
  const ip = req.ip || req.headers['x-forwarded-for'] || null;
  const otpOk = await consumeOneTimePassword(password, ip);
  if (otpOk) {
    const token = signSession({ role: 'site', exp: Date.now() + COOKIE_MAX_AGE });
    setCookie(res, SITE_COOKIE, token);
    return res.json({ ok: true, type: 'onetime' });
  }

  return res.status(401).json({ error: 'Неверный пароль' });
});

app.post('/api/logout', (req, res) => {
  clearCookie(res, SITE_COOKIE);
  res.json({ ok: true });
});

app.get('/api/session', (req, res) => {
  res.json({ authed: isSiteAuthed(req), admin: isAdminAuthed(req) });
});

app.get('/api/wiki', rateLimit(120), async (req, res) => {
  if (!isSiteAuthed(req)) return res.status(401).json({ error: 'Не авторизован' });
  try {
    const { data, error } = await supabaseRead
      .from('wiki')
      .select('*')
      .order('category', { ascending: true })
      .order('sort_order', { ascending: true });
    if (error) throw error;

    const result = { raiders: [], antiraiders: [] };
    for (const row of data || []) {
      if (!result[row.category]) continue;
      result[row.category].push({
        id: row.page_id,
        title: row.title,
        avatar: row.avatar,
        status: row.status,
        owner: row.owner,
        secret: row.secret,
        shame: row.shame,
        content: row.content
      });
    }
    res.set('Cache-Control', 'no-store');
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Ошибка базы: ' + (e.message || 'unknown') });
  }
});

/* Комментарии */
app.get('/api/comments/:category/:pageId', rateLimit(120), async (req, res) => {
  if (!isSiteAuthed(req)) return res.status(401).json({ error: 'Не авторизован' });
  const { category, pageId } = req.params;
  try {
    const { data, error } = await supabaseRead
      .from('comments')
      .select('id, author, text, created_at')
      .eq('page_category', category)
      .eq('page_id', pageId)
      .order('created_at', { ascending: true })
      .limit(200);
    if (error) throw error;
    res.set('Cache-Control', 'no-store');
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: 'Ошибка базы: ' + (e.message || 'unknown') });
  }
});

app.post('/api/comments/:category/:pageId', rateLimit(20), async (req, res) => {
  if (!isSiteAuthed(req)) return res.status(401).json({ error: 'Не авторизован' });
  const { category, pageId } = req.params;
  const { author, text } = req.body || {};

  if (!text || typeof text !== 'string' || !text.trim()) {
    return res.status(400).json({ error: 'Текст комментария обязателен' });
  }
  if (text.length > 1000) {
    return res.status(400).json({ error: 'Слишком длинный комментарий (макс. 1000)' });
  }
  if (!['raiders', 'antiraiders'].includes(category)) {
    return res.status(400).json({ error: 'Неверная категория' });
  }

  const row = {
    page_category: category,
    page_id: pageId,
    author: (author && String(author).trim().slice(0, 40)) || 'Аноним',
    text: String(text).trim()
  };

  try {
    const { data, error } = await supabaseAdmin
      .from('comments')
      .insert(row)
      .select()
      .single();
    if (error) throw error;
    res.json({ ok: true, item: data });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка базы: ' + (e.message || 'unknown') });
  }
});

/* =====================================================
   АДМИНКА
   ===================================================== */
app.post('/api/admin/login', rateLimit(20), (req, res) => {
  const { password } = req.body || {};
  if (typeof password !== 'string' || !password) {
    return res.status(400).json({ error: 'Пароль не указан' });
  }
  if (!safeCompare(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: 'Неверный пароль админа' });
  }
  const token = signSession({ role: 'admin', exp: Date.now() + COOKIE_MAX_AGE });
  setCookie(res, ADMIN_COOKIE, token);
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  clearCookie(res, ADMIN_COOKIE);
  res.json({ ok: true });
});

app.get('/api/admin/session', (req, res) => {
  res.json({ authed: isAdminAuthed(req) });
});

app.get('/api/admin/wiki', rateLimit(120), async (req, res) => {
  if (!isAdminAuthed(req)) return res.status(401).json({ error: 'Не авторизован' });
  try {
    const { data, error } = await supabaseAdmin
      .from('wiki')
      .select('*')
      .order('category', { ascending: true })
      .order('sort_order', { ascending: true });
    if (error) throw error;
    res.set('Cache-Control', 'no-store');
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: 'Ошибка базы: ' + (e.message || 'unknown') });
  }
});

app.post('/api/admin/wiki', rateLimit(60), async (req, res) => {
  if (!isAdminAuthed(req)) return res.status(401).json({ error: 'Не авторизован' });
  const body = req.body || {};
  const {
    category, page_id, title, avatar, status, owner, secret, shame, content, sort_order
  } = body;

  if (!category || !page_id || !title) {
    return res.status(400).json({ error: 'category, page_id и title обязательны' });
  }
  if (!['raiders', 'antiraiders'].includes(category)) {
    return res.status(400).json({ error: 'category должен быть raiders или antiraiders' });
  }

  const row = {
    category,
    page_id: String(page_id).trim(),
    title: String(title).trim(),
    avatar: avatar || null,
    status: status || null,
    owner: owner || null,
    secret: !!secret,
    shame: shame || null,
    content: content || '',
    sort_order: Number.isFinite(sort_order) ? sort_order : 999,
    updated_at: new Date().toISOString()
  };

  try {
    const { data: existing } = await supabaseAdmin
      .from('wiki')
      .select('id')
      .eq('category', category)
      .eq('page_id', row.page_id)
      .maybeSingle();

    let result;
    if (existing && existing.id) {
      result = await supabaseAdmin
        .from('wiki')
        .update(row)
        .eq('id', existing.id)
        .select()
        .single();
    } else {
      result = await supabaseAdmin
        .from('wiki')
        .insert(row)
        .select()
        .single();
    }
    if (result.error) throw result.error;
    res.json({ ok: true, item: result.data });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка базы: ' + (e.message || 'unknown') });
  }
});

app.delete('/api/admin/wiki/:category/:pageId', rateLimit(60), async (req, res) => {
  if (!isAdminAuthed(req)) return res.status(401).json({ error: 'Не авторизован' });
  const { category, pageId } = req.params;
  try {
    const { error } = await supabaseAdmin
      .from('wiki')
      .delete()
      .eq('category', category)
      .eq('page_id', pageId);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка базы: ' + (e.message || 'unknown') });
  }
});

/* Список оставшихся одноразовых паролей (для админа) */
app.get('/api/admin/otp', rateLimit(60), async (req, res) => {
  if (!isAdminAuthed(req)) return res.status(401).json({ error: 'Не авторизован' });
  try {
    const { data, error } = await supabaseAdmin
      .from('one_time_passwords')
      .select('id, password, used, used_at, used_ip')
      .order('id', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: 'Ошибка базы: ' + (e.message || 'unknown') });
  }
});

/* =====================================================
   ОТДАЧА СТРАНИЦ
   ===================================================== */
const INDEX = path.join(__dirname, 'index.html');
const ADMIN = path.join(__dirname, 'admin.html');

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

app.get('/', (req, res) => res.sendFile(INDEX));
app.get('/index.html', (req, res) => res.sendFile(INDEX));
app.get('/admin', (req, res) => res.sendFile(ADMIN));
app.get('/admin.html', (req, res) => res.sendFile(ADMIN));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(INDEX);
});

/* =====================================================
   СТАРТ
   ===================================================== */
app.listen(PORT, () => {
  console.log(`MAX Raid Wiki запущен на порту ${PORT}`);
});
