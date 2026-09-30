const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

/* =====================================================
   БАЗОВЫЕ НАСТРОЙКИ БЕЗОПАСНОСТИ
   ===================================================== */
app.disable('x-powered-by');

/* Доверяем прокси Render (нужно для корректного req.ip) */
app.set('trust proxy', 1);

/* Заголовки безопасности */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  /* CSP — разрешаем inline-стили/скрипты и картинки с любого https */
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

/* =====================================================
   БЛОКИРОВКА ЯВНЫХ СКАМ-БОТОВ И СКАНЕРОВ
   ===================================================== */
const BAD_UA = /(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wfuzz|hydra|zgrab|semrush|ahrefsbot|mj12bot|dotbot|petalbot|bytespider|blexbot)/i;

app.use((req, res, next) => {
  const ua = req.headers['user-agent'] || '';
  if (!ua || BAD_UA.test(ua)) {
    return res.status(403).send('Forbidden');
  }
  next();
});

/* =====================================================
   ПРОСТОЙ RATE LIMIT (in-memory)
   -----------------------------------------------------
   По IP: не более 120 запросов / минуту.
   Для API — не более 60 запросов / минуту.
   ===================================================== */
const RL_WINDOW = 60 * 1000;
const RL_MAX = 120;
const RL_MAX_API = 60;
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

/* Периодическая чистка карты */
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    const fresh = arr.filter(t => now - t < RL_WINDOW);
    if (fresh.length) hits.set(ip, fresh);
    else hits.delete(ip);
  }
}, 5 * 60 * 1000);

/* =====================================================
   ПРОВЕРКА ORIGIN / REFERER ДЛЯ API
   -----------------------------------------------------
   Разрешаем запросы только со своего же origin.
   ===================================================== */
function sameOrigin(req) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  const host = req.headers.host;

  /* Если origin есть — он должен совпадать с host */
  if (origin) {
    try {
      const o = new URL(origin);
      return o.host === host;
    } catch { return false; }
  }
  /* Если origin нет — проверяем referer */
  if (referer) {
    try {
      const r = new URL(referer);
      return r.host === host;
    } catch { return false; }
  }
  /* Ни origin, ни referer — блокируем (curl, скрипты, боты) */
  return false;
}

/* =====================================================
   ДАННЫЕ ВИКИ — ЖИВУТ ТОЛЬКО НА СЕРВЕРЕ
   ===================================================== */
const WIKI = {
  raiders: [
    {
      id: 'uotb',
      title: 'UOTB',
      avatar: 'https://cdn.phototourl.com/free/2026-09-20-f3938c33-1e29-4753-a965-f26629537a3b.jpg',
      status: 'жив',
      owner: 'Пабло',
      content: `
        <p>UOTB, или же «Union Of The Brash» — первые рейдеры в максе. Данной
        группировке более 4-ех лет и находились они до MAX'а в Viber и Telegram.
        Именно с них началось рейдерство в MAX'е.</p>
      `
    },
    {
      id: 'mars',
      title: 'MARS',
      avatar: 'https://cdn.phototourl.com/free/2026-09-20-f93f9e0d-7fc5-4d78-8a91-881dd0d61730.jpg',
      status: 'жив',
      owner: 'SPAWN',
      content: `
        <p>MARS — крупнейший подклан UOTB, занимается он в основном шпионством,
        но они также и рейдеры. На данный момент в чате адаптации MARS'а
        650+ участников.</p>
      `
    },
    {
      id: 'fiery-empire',
      title: 'Fiery Empire',
      avatar: '🔥',
      status: 'жив',
      owner: 'FE ASAHI SE',
      content: `
        <p>Fiery Empire — это рейдеры, которые раньше были просто чатом. Раньше
        они назывались «Британской Империи» и зависли от НИЕ, но потом пришёл Cold,
        и сделал их свободными, после чего они стали рейдерами. Самый крутой именно
        в личных достижениях владелец. На данный момент в их чате примерно
        400+ участников.</p>
      `
    }
  ],
  antiraiders: [
    {
      id: 'ftaj',
      title: 'FTAJ',
      avatar: '🛡️',
      status: 'жив',
      owner: 'даник',
      content: `
        <p>FTAJ — вторые рейдеры (на данный момент антирейдеры) в MAX'е.
        Сейчас занимаются антирейдерством, уничтожают неизвестные и мелкие
        рейдерские группировки, а также конфликтуют с существуещими крупными.</p>
      `
    },
    {
      id: 'tspr',
      title: 'ЦПР',
      avatar: 'https://cdn.phototourl.com/free/2026-09-20-490ac874-41a7-4be0-8ea7-ce6cb4c60c77.jpg',
      status: 'жив',
      owner: 'shalow dern (шейд)',
      secret: true,
      shame: {
        title: 'ПОЗОРНЫЕ СТОРОНЫ ЦПР',
        text: `Были зарейжено однажды по ошибке в коде MAX'а, что резко пошатнуло
               их репутацию, быстро восстановились и даже стали лучше, но позор`,
        stamp: 'НЕ СКРЫТЬ!'
      },
      content: `
        <p>ЦПР, или же Центр Противодействия Рейдерам — первая антирейдерская
        группировка. ЦПР создавался просто канал против обмана со стороны UOTB,
        но потом перерос в более крупный проект по сливам рейдеров, и их уничтожению.
        Были созданы в один день с KR.</p>
      `
    },
    {
      id: 'kr',
      title: 'KR',
      avatar: '✨',
      status: 'жив',
      owner: 'user (Крутой Челик)',
      content: `
        <p>KR — бывшие рейдеры, на данный момент антирейдеры. Самые известные
        свежаки среди всех. Были созданы в один день с ЦПР.</p>
      `
    }
  ]
};

/* =====================================================
   API — ОТДАЁТ ДАННЫЕ ВИКИ
   -----------------------------------------------------
   Защита:
   - rate limit
   - origin/referer check
   - no-store
   ===================================================== */
app.get(
  '/api/wiki',
  rateLimit(RL_MAX_API),
  (req, res) => {
    if (!sameOrigin(req)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.json(WIKI);
  }
);

/* =====================================================
   ОТДАЧА index.html И ДРУГИХ GET
   ===================================================== */
const INDEX = path.join(__dirname, 'index.html');

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

app.get('/', rateLimit(RL_MAX), (req, res) => res.sendFile(INDEX));
app.get('/index.html', rateLimit(RL_MAX), (req, res) => res.sendFile(INDEX));

/* Всё, что не API и не корень — отдаём index (SPA) */
app.get('*', rateLimit(RL_MAX), (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(INDEX);
});

/* =====================================================
   ЗАПУСК
   ===================================================== */
app.listen(PORT, () => {
  console.log(`MAX Raid Wiki запущен на порту ${PORT}`);
});
