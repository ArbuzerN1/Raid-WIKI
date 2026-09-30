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
  const session = verifySession(cookies[SITE_COOKIE]);
  return !!session;
}
function isAdminAuthed(req) {
  const cookies = parseCookies(req.headers.cookie);
  const session = verifySession(cookies[ADMIN_COOKIE]);
  return !!session && session.role === 'admin';
}
function safeCompare(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/* =====================================================
   СТАРТОВЫЕ ДАННЫЕ
   ===================================================== */
const SEED = [
  {
    category: 'raiders', page_id: 'uotb', title: 'UOTB', sort_order: 1,
    avatar: 'https://cdn.phototourl.com/free/2026-09-20-f3938c33-1e29-4753-a965-f26629537a3b.jpg',
    status: 'жив', owner: 'Пабло', secret: false, shame: null,
    content: `<p>UOTB, или же «Union Of The Brash» — первые рейдеры в максе. Данной
      группировке более 4-ех лет и находились они до MAX'а в Viber и Telegram.
      Именно с них началось рейдерство в MAX'е.</p>`
  },
  {
    category: 'raiders', page_id: 'mars', title: 'MARS', sort_order: 2,
    avatar: 'https://cdn.phototourl.com/free/2026-09-20-f93f9e0d-7fc5-4d78-8a91-881dd0d61730.jpg',
    status: 'жив', owner: 'SPAWN', secret: false, shame: null,
    content: `<p>MARS — крупнейший подклан UOTB, занимается он в основном шпионством,
      но они также и рейдеры. На данный момент в чате адаптации MARS'а
      650+ участников.</p>`
  },
  {
    category: 'raiders', page_id: 'fiery-empire', title: 'Fiery Empire', sort_order: 3,
    avatar: '🔥', status: 'жив', owner: 'FE ASAHI SE', secret: false, shame: null,
    content: `<p>Fiery Empire — это рейдеры, которые раньше были просто чатом. Раньше
      они назывались «Британской Империи» и зависли от НИЕ, но потом пришёл Cold,
      и сделал их свободными, после чего они стали рейдерами. Самый крутой именно
      в личных достижениях владелец. На данный момент в их чате примерно
      400+ участников.</p>`
  },
  {
    category: 'antiraiders', page_id: 'ftaj', title: 'FTAJ', sort_order: 1,
    avatar: '🛡️', status: 'жив', owner: 'даник', secret: false, shame: null,
    content: `<p>FTAJ — вторые рейдеры (на данный момент антирейдеры) в MAX'е.
      Сейчас занимаются антирейдерством, уничтожают неизвестные и мелкие
      рейдерские группировки, а также конфликтуют с существуещими крупными.</p>`
  },
  {
    category: 'antiraiders', page_id: 'tspr', title: 'ЦПР', sort_order: 2,
    avatar: 'https://cdn.phototourl.com/free/2026-09-20-490ac874-41a7-4be0-8ea7-ce6cb4c60c77.jpg',
    status: 'жив', owner: 'shalow dern (шейд)', secret: true,
    shame: {
      title: 'ПОЗОРНЫЕ СТОРОНЫ ЦПР',
      text: `Были зарейжено однажды по ошибке в коде MAX'а, что резко пошатнуло
             их репутацию, быстро восстановились и даже стали лучше, но позор`,
      stamp: 'НЕ СКРЫТЬ!'
    },
    content: `<p>ЦПР, или же Центр Противодействия Рейдерам — первая антирейдерская
      группировка. ЦПР создавался просто канал против обмана со стороны UOTB,
      но потом перерос в более крупный проект по сливам рейдеров, и их уничтожению.
      Были созданы в один день с KR.</p>`
  },
  {
    category: 'antiraiders', page_id: 'kr', title: 'KR', sort_order: 3,
    avatar: '✨', status: 'жив', owner: 'user (Крутой Челик)', secret: false, shame: null,
    content: `<p>KR — бывшие рейдеры, на данный момент антирейдеры. Самые известные
      свежаки среди всех. Были созданы в один день с ЦПР.</p>`
  }
];

async function seedIfEmpty() {
  try {
    const { count, error } = await supabaseAdmin
      .from('wiki')
      .select('id', { count: 'exact', head: true });
    if (error) throw error;
    if ((count || 0) > 0) {
      console.log(`База уже содержит ${count} статей`);
      return;
    }
    console.log('База пуста, заливаю стартовые данные...');
    const { error: insErr } = await supabaseAdmin.from('wiki').insert(SEED);
    if (insErr) throw insErr;
    console.log('Стартовые данные залиты');
  } catch (e) {
    console.error('Ошибка сидинга:', e.message || e);
  }
}

/* =====================================================
   ПУБЛИЧНЫЕ РОУТЫ — ПАРОЛЬ САЙТА
   ===================================================== */
app.post('/api/login', rateLimit(30), (req, res) => {
  const { password } = req.body || {};
  if (typeof password !== 'string' || !password) {
    return res.status(400).json({ error: 'Пароль не указан' });
  }
  if (!safeCompare(password, SITE_PASSWORD)) {
    return res.status(401).json({ error: 'Неверный пароль' });
  }
  const token = signSession({ role: 'site', exp: Date.now() + COOKIE_MAX_AGE });
  setCookie(res, SITE_COOKIE, token);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  clearCookie(res, SITE_COOKIE);
  res.json({ ok: true });
});

app.get('/api/session', (req, res) => {
  res.json({ authed: isSiteAuthed(req) });
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

/* =====================================================
   АДМИНКА — ОТДЕЛЬНАЯ СЕССИЯ
   -----------------------------------------------------
   Пароль: process.env.ADMIN_PASSWORD или 'neaboba228'
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

/* Полный список статей для админки (включая приватные поля) */
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

/* Создать/обновить статью */
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
    /* upsert по (category, page_id) — считаем их уникальной парой */
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

/* Удалить статью */
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

/* =====================================================
   ОТДАЧА index.html
   ===================================================== */
const INDEX = path.join(__dirname, 'index.html');

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

app.get('/', (req, res) => res.sendFile(INDEX));
app.get('/index.html', (req, res) => res.sendFile(INDEX));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(INDEX);
});

/* =====================================================
   СТАРТ
   ===================================================== */
app.listen(PORT, async () => {
  console.log(`MAX Raid Wiki запущен на порту ${PORT}`);
  console.log(`Пароль админки: ${ADMIN_PASSWORD === 'neaboba228' ? 'по умолчанию (neaboba228)' : 'из переменной окружения'}`);
  await seedIfEmpty();
});
