/* FiribStop UZ link checker — local heuristics only; no network requests. */
(function (root) {
  'use strict';

  const MAX_LENGTH = 2048;
  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'goo.gl', 'rebrand.ly',
    'clck.ru', 'vk.cc', 'ow.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'l.wl.co'
  ]);
  const SUSPICIOUS_TLDS = new Set([
    'xyz', 'top', 'click', 'link', 'online', 'site', 'club', 'icu', 'buzz', 'live',
    'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'vip', 'fun', 'cfd', 'sbs'
  ]);
  const LURE_WORDS = /(^|[-.])(login|log-in|verify|verification|secure|security|bank|wallet|bonus|gift|prize|claim|payment|account|support|update|confirm|password|signin|sign-in)([-.]|$)/i;
  const BRANDS = [
    ['google', ['google.com', 'googlemail.com', 'googleapis.com', 'googleusercontent.com', 'withgoogle.com', 'g.co', 'google.co.uk', 'google.uz', 'google.ru', 'google.de', 'google.fr', 'google.kz', 'google.co.uz', 'google.com.uz', 'google.co.in', 'google.ca', 'google.com.au', 'google.co.jp', 'google.com.tr', 'google.com.br', 'google.es', 'google.it', 'google.pl', 'google.nl', 'google.com.mx', 'google.com.ar', 'google.com.sg', 'google.co.kr', 'google.co.nz', 'google.com.hk', 'google.com.tw', 'google.com.ua', 'google.com.vn', 'google.com.pk', 'google.com.sa', 'google.com.eg', 'google.com.ng', 'google.com.ph', 'google.com.my', 'google.com.co', 'google.com.pe', 'google.com.cl', 'google.com.bd', 'google.com.kh', 'google.com.cy', 'google.com.mt']], ['apple', ['apple.com']], ['telegram', ['telegram.org', 't.me']],
    ['payme', ['payme.uz']], ['paynet', ['paynet.uz']], ['click', ['click.uz']],
    ['uzcard', ['uzcard.uz']], ['humo', ['humo.uz']], ['uzum', ['uzum.uz']],
    ['olx', ['olx.uz']], ['soliq', ['soliq.uz']], ['mygov', ['my.gov.uz']],
    ['kapitalbank', ['kapitalbank.uz']], ['anorbank', ['anorbank.uz']],
    ['ucell', ['ucell.uz']], ['beeline', ['beeline.uz']], ['mobiuz', ['mobiuz.uz']],
    ['uztelecom', ['uztelecom.uz']], ['visa', ['visa.com']], ['mastercard', ['mastercard.com']]
  ];

  function bad(reason) { return { ok: false, reason }; }
  // Refuse invisible formatting marks and bidi overrides that can make an address
  // render differently from its logical character order in some interfaces.
  const INVISIBLE_OR_BIDI = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/;
  const BRAND_SUFFIXES = new Set([
    'login', 'secure', 'security', 'verify', 'verification', 'support', 'account',
    'bank', 'wallet', 'payment', 'bonus', 'gift', 'update', 'confirm', 'signin',
    'auth', 'id', 'web', 'online', 'help', 'app', 'site', 'service', 'official',
    'claim', 'prize', 'card', 'mobile', 'check', 'info', 'billing', 'reset',
    'recovery', 'portal', 'center', 'client', 'mail'
  ]);
  function editDistance(a, b, limit = 1) {
    if (Math.abs(a.length - b.length) > limit) return limit + 1;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const next = [i]; let rowMin = i;
      for (let j = 1; j <= b.length; j++) {
        next[j] = Math.min(next[j - 1] + 1, prev[j] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        rowMin = Math.min(rowMin, next[j]);
      }
      if (rowMin > limit) return limit + 1;
      prev = next;
    }
    return prev[b.length];
  }
  function normalizeLookalike(label) {
    return label.toLowerCase()
      .replace(/rn/g, 'm').replace(/vv/g, 'w')
      .replace(/0/g, 'o').replace(/[1|]/g, 'l').replace(/3/g, 'e')
      .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't');
  }
  function brandMatch(label, brand) {
    const lower = label.toLowerCase();
    const segments = lower.split('-').filter(Boolean);
    if (segments.includes(brand)) return { exact: true };
    // A single brand-like component may be altered with digits or homoglyphs:
    // g00gle-login, payrne-verify, paym3, etc. Check each token independently so
    // lure suffixes do not hide the spoofed token.
    for (const segment of segments) {
      const normalizedSegment = normalizeLookalike(segment);
      if (normalizedSegment === brand && segment !== brand) return { exact: false };
      if (brand.length >= 4 && Math.abs(normalizedSegment.length - brand.length) <= 1 && editDistance(normalizedSegment, brand, 1) <= 1) {
        return { exact: false };
      }
    }
    // Brand plus a familiar lure term (e.g. googlelogin, paymeverify) is suspicious,
    // but unrelated words such as "visage" should not match the short brand "visa".
    for (const suffix of BRAND_SUFFIXES) {
      if (lower === brand + suffix || lower === suffix + brand) return { exact: true };
    }
    const compact = lower.replace(/-/g, '');
    if (compact.includes(brand)) {
      const rest = compact.replace(brand, '');
      if (!rest || BRAND_SUFFIXES.has(rest)) return { exact: true };
    }
    const normalized = normalizeLookalike(compact);
    if (brand.length >= 4 && Math.abs(normalized.length - brand.length) <= 1 && editDistance(normalized, brand, 1) <= 1) {
      return { exact: false };
    }
    return null;
  }
  function isIPv4(host) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false;
    return host.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  function isIP(host) { return isIPv4(host) || host.includes(':'); }
  function isPrivateIPv4(host) {
    if (!isIPv4(host)) return false;
    const [a, b, c] = host.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
      (a === 192 && b === 0 && c === 0) || (a === 192 && b === 0 && c === 2) ||
      (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) || a >= 224;
  }
  function isPrivateIPv6(host) {
    const h = host.replace(/^\[|\]$/g, '').toLowerCase();
    return h === '::' || h === '::1' || /^f[cd][0-9a-f:]*$/.test(h) ||
      /^fe[89ab][0-9a-f:]*$/.test(h) || h.startsWith('::ffff:');
  }
  function isUnderDomain(host, domain) {
    return host === domain || host.endsWith('.' + domain);
  }
  function normalizeInput(raw) {
    if (typeof raw !== 'string') return bad('Введите ссылку текстом.');
    const s = raw.trim();
    if (!s) return bad('Введите ссылку для проверки.');
    if (s.length > MAX_LENGTH) return bad(`Ссылка слишком длинная. Максимум ${MAX_LENGTH} символов.`);
    if (/[\u0000-\u001f\u007f\\]/.test(s)) return bad('В адресе есть управляющие символы или обратная косая черта. Скопируйте ссылку заново.');
    if (INVISIBLE_OR_BIDI.test(s)) return bad('В адресе есть невидимые или управляющие направлением текста символы. Скопируйте ссылку заново и проверьте домен.');
    if (/^\/\//.test(s)) return bad('Укажите адрес с https:// или домен без префикса.');
    const hostWithPort = /^(?:[a-z0-9.-]+|\[[0-9a-f:]+\]):\d+(?:[/?#]|$)/i.test(s);
    if (/^[a-z][a-z0-9+.-]*:/i.test(s) && !/^https?:\/\//i.test(s) && !hostWithPort) {
      return bad('Разрешены только адреса HTTP или HTTPS. Другие схемы открывать нельзя.');
    }
    const candidate = /^https?:\/\//i.test(s) ? s : `https://${s}`;
    let url;
    try { url = new URL(candidate); }
    catch { return bad('Не удалось распознать ссылку. Проверьте адрес и попробуйте снова.'); }
    if (!['http:', 'https:'].includes(url.protocol)) return bad('Разрешены только адреса HTTP или HTTPS.');
    if (!url.hostname) return bad('В ссылке не указан домен.');
    if (url.username || url.password) return bad('Адрес содержит логин или пароль перед доменом (@). Не открывайте его.');

    let host = url.hostname.toLowerCase().replace(/\.$/, '');
    const ipLiteral = isIP(host.replace(/^\[|\]$/g, ''));
    if (!ipLiteral) {
      if (host.length > 253) return bad('Имя домена превышает допустимую длину.');
      const labels = host.split('.');
      if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
        return bad('Домен содержит некорректные части. Проверьте адрес посимвольно.');
      }
    } else if (host.includes(':')) {
      host = host.replace(/^\[|\]$/g, '');
    } else if (!isIPv4(host)) {
      return bad('IP-адрес указан некорректно.');
    }
    return { ok: true, url, host, ipLiteral };
  }

  function analyze(raw) {
    const parsed = normalizeInput(raw);
    if (!parsed.ok) return parsed;
    const { url, host, ipLiteral } = parsed;
    const findings = [];
    let score = 0;
    const add = (points, text, code) => {
      if (findings.some((item) => item.code === code)) return;
      findings.push({ points, text, code });
      score += points;
    };

    if (url.protocol === 'http:') add(12, 'Используется HTTP без TLS-шифрования. HTTPS тоже не доказывает честность сайта.', 'http');
    if (ipLiteral) add(24, 'Вместо обычного доменного имени указан IP-адрес.', 'ip-literal');
    if (host.includes('xn--')) add(20, 'Домен записан с помощью Punycode: проверьте, не маскируются ли похожие символы.', 'punycode');
    if (host === 'localhost' || !host.includes('.') || host.endsWith('.local') || host.endsWith('.internal')) {
      add(18, 'Похоже на локальное или внутреннее имя, а не на обычный публичный сайт.', 'local-host');
    }
    const plainHost = host.replace(/^\[|\]$/g, '');
    if ((isIPv4(plainHost) && isPrivateIPv4(plainHost)) || (plainHost.includes(':') && isPrivateIPv6(plainHost))) {
      add(18, 'Адрес относится к локальной, частной или специальной IP-сети. Не передавайте ему секретные данные.', 'private-ip');
    }
    const labels = host.split('.');
    if (!ipLiteral && labels.length > 4) add(10, 'У домена необычно много поддоменов. Проверьте, какая часть является настоящим доменом.', 'many-subdomains');
    if (SHORTENERS.has(host)) add(18, 'Это сокращатель ссылок: конечный адрес скрыт до перехода.', 'shortener');
    if (!ipLiteral && SUSPICIOUS_TLDS.has(labels[labels.length - 1])) {
      add(12, 'Доменная зона иногда встречается в подозрительных ссылках. Одна эта особенность не означает мошенничество.', 'tld');
    }
    if (!ipLiteral && LURE_WORDS.test(host)) add(12, 'В домене есть слова, часто используемые в приманках (например, login или verify). Это только сигнал для проверки.', 'lure-word');
    if (url.port && !((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443'))) {
      add(10, 'Указан нестандартный порт веб-сервера.', 'unusual-port');
    }
    if (!ipLiteral) {
      const searchableLabels = labels.slice(0, -1);
      for (const [brand, domains] of BRANDS) {
        const isOfficialDomain = domains.some((domain) => isUnderDomain(host, domain));
        if (isOfficialDomain) continue;
        const match = searchableLabels.map((label) => brandMatch(label, brand)).find(Boolean);
        if (match?.exact) {
          add(35, `В домене есть название бренда «${brand}», но адрес не совпадает с известным доменом. Проверьте сайт через официальное приложение или самостоятельно найденный адрес.`, `brand-${brand}`);
        } else if (match) {
          add(35, `Домен похож на название бренда «${brand}» (возможна подмена похожими символами). Не вводите пароли и коды; перепроверьте адрес через официальный канал.`, `brand-lookalike-${brand}`);
        }
      }
    }
    score = Math.min(100, score);
    const risk = score >= 55 ? 'Высокий' : score >= 25 ? 'Средний' : 'Мало сигналов';
    return {
      ok: true,
      url: url.href,
      hostname: host,
      protocol: url.protocol,
      score,
      risk,
      findings,
      summary: findings.length
        ? `Найдено признаков для проверки: ${findings.length}. Балл — эвристический индикатор, а не вероятность мошенничества.`
        : 'Локальные правила не нашли явных сигналов. Это не подтверждает безопасность сайта.',
      disclaimer: 'Проверка работает локально, не открывает ссылку и не сверяет её с актуальными чёрными списками. Она может ошибаться.'
    };
  }

  const api = { analyze, MAX_LENGTH };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.FiribStopLinkChecker = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
