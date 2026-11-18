'use strict';
/* ==========================================================================
   НАСТРОЙКИ, которые можно менять без правки HTML
   ========================================================================== */

// Видео. Достаточно заполнить одно из полей. Приоритет: local, rutube, vk, youtube.
//  youtube: идентификатор из ссылки (после v=)
//  rutube:  идентификатор из ссылки rutube.ru/video/ИДЕНТИФИКАТОР/
//  vk:      строка вида 'oid_id', например '-12345678_456239017' (из ссылки vk.com/video-12345678_456239017)
//  local:   путь к файлу в папке assets/video, например 'assets/video/bitcoin.mp4'
const VIDEOS = {
  bitcoin: { title: 'Как на самом деле работает Bitcoin', author: '3Blue1Brown', youtube: 'bBC-nXj3Ng4', rutube: '', vk: '', local: '' },
  blockchain: { title: 'Технология блокчейн: двухчасовой курс', author: 'Coding Tech', youtube: 'qOVAbKKSH10', rutube: '', vk: '', local: '' },
  web3sec: { title: 'Безопасность Web3: уязвимости на стыке блокчейна и веб-технологий', author: 'Cyber Academy', youtube: 'J4tZHDyM7rA', rutube: '', vk: '', local: '' },
};

// Аудио. Если для раздела указан файл, кнопка «Слушать» включит его,
// иначе текст озвучит синтезатор речи браузера. Пример: intro: 'assets/audio/intro.mp3'
const AUDIO = {};

/* ==========================================================================
   Вспомогательные функции
   ========================================================================== */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const toast = (msg) => {
  const t = $('#toast'); if (!t) return;
  t.textContent = msg; t.classList.add('show');
  clearTimeout(toast.id); toast.id = setTimeout(() => t.classList.remove('show'), 2200);
};

/* ===== SHA-256 (чистый JS, работает без https) ===== */
const K256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
function sha256(str) {
  const bytes = new TextEncoder().encode(str), len = bytes.length;
  const nWords = (((len + 8) >> 6) + 1) << 4;
  const w = new Uint32Array(nWords);
  for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << (24 - (i & 3) * 8);
  w[len >> 2] |= 0x80 << (24 - (len & 3) * 8);
  w[nWords - 1] = (len * 8) >>> 0;
  w[nWords - 2] = Math.floor((len * 8) / 4294967296);
  const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const W = new Uint32Array(64);
  const ror = (x, n) => (x >>> n) | (x << (32 - n));
  for (let o = 0; o < nWords; o += 16) {
    for (let t = 0; t < 16; t++) W[t] = w[o + t];
    for (let t = 16; t < 64; t++) {
      const s0 = ror(W[t - 15], 7) ^ ror(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = ror(W[t - 2], 17) ^ ror(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[t] + W[t]) | 0;
      const S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  return H.map((x) => (x >>> 0).toString(16).padStart(8, '0')).join('');
}

/* ==========================================================================
   Тема, прогресс чтения, кнопка «наверх»
   ========================================================================== */
function initChrome() {
  const root = document.documentElement;
  const saved = localStorage.getItem('lr-theme');
  const dark = saved ? saved === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'dark' : 'light';
  const tb = $('#theme');
  const paint = () => { tb.querySelector('.ico').textContent = root.dataset.theme === 'dark' ? '☀' : '☾'; tb.setAttribute('aria-pressed', root.dataset.theme === 'dark'); };
  paint();
  tb.addEventListener('click', () => { root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark'; localStorage.setItem('lr-theme', root.dataset.theme); paint(); });

  const bar = $('#progress'), top = $('#toTop');
  let tick = false;
  const onScroll = () => {
    const h = document.documentElement.scrollHeight - innerHeight;
    bar.style.width = (h > 0 ? Math.min(100, (scrollY / h) * 100) : 0) + '%';
    top.classList.toggle('show', scrollY > 900);
    tick = false;
  };
  addEventListener('scroll', () => { if (!tick) { tick = true; requestAnimationFrame(onScroll); } }, { passive: true });
  onScroll();
  top.addEventListener('click', () => scrollTo({ top: 0 }));

  const clone = $('article').cloneNode(true);
  clone.querySelectorAll('.refs, .links, .quiz, .lab, .contents, .stats, .section-tools, #sources, script, style').forEach((e) => e.remove());
  const words = (clone.textContent.match(/\S+/g) || []).length;
  const rt = $('#readTime'); if (rt) rt.textContent = '≈ ' + Math.max(1, Math.round(words / 190)) + ' мин чтения, ' + words.toLocaleString('ru-RU') + ' слов';
}

/* ==========================================================================
   Оглавление: боковая панель, подсветка текущего раздела, якоря
   ========================================================================== */
function initToc() {
  const heads = $$('article h2[id], article h3[id]');
  const ol = $('#tocList');
  heads.forEach((h) => {
    const a = document.createElement('a'); a.className = 'anchor'; a.href = '#' + h.id; a.textContent = '#'; a.setAttribute('aria-label', 'Ссылка на раздел «' + h.textContent + '»');
    a.addEventListener('click', (e) => { e.preventDefault(); history.replaceState(null, '', '#' + h.id); const url = location.origin + location.pathname + '#' + h.id; (navigator.clipboard ? navigator.clipboard.writeText(url) : Promise.reject()).then(() => toast('Ссылка на раздел скопирована'), () => toast('Ссылка: #' + h.id)); h.scrollIntoView(); });
    h.prepend(a);
    const li = document.createElement('li'); li.className = h.tagName === 'H3' ? 'l3' : 'l2';
    const l = document.createElement('a'); l.href = '#' + h.id; l.textContent = h.dataset.short || h.textContent.replace(/^#/, '').trim(); l.dataset.target = h.id;
    li.append(l); ol.append(li);
  });
  const links = $$('a', ol), side = $('#side'), scrim = $('#scrim'), btn = $('#tocBtn');
  const set = (open) => { side.classList.toggle('open', open); scrim.classList.toggle('show', open); btn.setAttribute('aria-expanded', open); };
  btn.addEventListener('click', () => set(!side.classList.contains('open')));
  scrim.addEventListener('click', () => set(false));
  links.forEach((a) => a.addEventListener('click', () => set(false)));
  addEventListener('keydown', (e) => { if (e.key === 'Escape') set(false); });
  const io = new IntersectionObserver((es) => {
    es.forEach((e) => { if (e.isIntersecting) { links.forEach((x) => x.classList.toggle('active', x.dataset.target === e.target.id)); const act = $('a.active', ol); if (act && side.scrollHeight > side.clientHeight) act.scrollIntoView({ block: 'nearest' }); } });
  }, { rootMargin: '-12% 0px -80% 0px' });
  heads.forEach((h) => io.observe(h));
}

/* ==========================================================================
   Подсказки к терминам (определения при наведении, фокусе и касании)
   ========================================================================== */
function initTerms() {
  const tip = document.createElement('div'); tip.className = 'tip'; tip.setAttribute('role', 'tooltip'); document.body.append(tip);
  let cur = null;
  const show = (el) => {
    cur = el; tip.textContent = el.dataset.def; tip.classList.add('show');
    const r = el.getBoundingClientRect(), w = tip.offsetWidth, h = tip.offsetHeight;
    const left = Math.min(Math.max(8, r.left + r.width / 2 - w / 2), innerWidth - w - 8);
    const top = r.top - h - 10 < 8 ? r.bottom + 10 : r.top - h - 10;
    tip.style.left = left + 'px'; tip.style.top = top + 'px';
  };
  const hide = () => { cur = null; tip.classList.remove('show'); };
  $$('abbr.term').forEach((el) => {
    el.addEventListener('mouseenter', () => show(el)); el.addEventListener('mouseleave', hide);
    el.addEventListener('focus', () => show(el)); el.addEventListener('blur', hide);
    el.addEventListener('click', () => (cur === el ? hide() : show(el)));
  });
  addEventListener('scroll', hide, { passive: true });
}

/* ==========================================================================
   Анимации появления и счетчики
   ========================================================================== */
function initReveal() {
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }), { threshold: .12 });
  $$('.reveal, .timeline li').forEach((el, i) => { el.style.transitionDelay = (el.matches('.timeline li') ? (i % 4) * 60 : 0) + 'ms'; io.observe(el); });
  const fmt = (n, d) => n.toLocaleString('ru-RU', { minimumFractionDigits: d, maximumFractionDigits: d });
  const cio = new IntersectionObserver((es) => es.forEach((e) => {
    if (!e.isIntersecting) return; cio.unobserve(e.target);
    const el = e.target, to = parseFloat(el.dataset.count), d = parseInt(el.dataset.dec || '0', 10), pre = el.dataset.prefix || '', suf = el.dataset.suffix || '';
    const t0 = performance.now(), dur = 1400;
    const step = (t) => { const p = Math.min(1, (t - t0) / dur), v = to * (1 - Math.pow(1 - p, 3)); el.textContent = pre + fmt(v, d) + suf; if (p < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }), { threshold: .4 });
  $$('[data-count]').forEach((el) => cio.observe(el));
}

/* ==========================================================================
   Вкладки (универсальные)
   ========================================================================== */
function initTabs() {
  $$('.tabs').forEach((root) => {
    const tabs = $$('[role=tab]', root), panels = $$('[role=tabpanel]', root);
    const show = (i, focus) => {
      tabs.forEach((t, k) => { t.setAttribute('aria-selected', k === i); t.tabIndex = k === i ? 0 : -1; });
      panels.forEach((p, k) => { p.hidden = k !== i; });
      if (focus) tabs[i].focus();
      root.dispatchEvent(new CustomEvent('tabchange', { detail: i }));
    };
    tabs.forEach((t, i) => {
      t.addEventListener('click', () => show(i));
      t.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowRight') { e.preventDefault(); show((i + 1) % tabs.length, true); }
        if (e.key === 'ArrowLeft') { e.preventDefault(); show((i - 1 + tabs.length) % tabs.length, true); }
      });
    });
    show(0);
  });
}

/* ==========================================================================
   Песочница блокчейна: измените данные и посмотрите, что сломается
   ========================================================================== */
function initSandbox() {
  const box = $('#chainBox'); if (!box) return;
  const diffSel = $('#diff'), GENESIS = '0'.repeat(64);
  const initial = ['Алиса переводит Бобу 10 BTC', 'Боб переводит Чарли 5 BTC', 'Чарли переводит Дэвиду 2 BTC'];
  let blocks = [], busy = false;
  const hashOf = (i, b) => sha256(i + '|' + b.prev + '|' + b.data + '|' + b.nonce);
  const diff = () => parseInt(diffSel.value, 10);
  const okPow = (h) => h.startsWith('0'.repeat(diff()));

  function mine(i, onTick) {
    return new Promise((resolve) => {
      const b = blocks[i]; let n = 0; const t0 = performance.now();
      const chunk = () => {
        for (let k = 0; k < 2500; k++, n++) { b.nonce = n; if (okPow(hashOf(i, b))) { resolve({ tries: n + 1, ms: performance.now() - t0 }); return; } }
        if (onTick) onTick(n); setTimeout(chunk, 0);
      };
      chunk();
    });
  }
  function reset() {
    blocks = initial.map((d, i) => ({ data: d, prev: i ? '' : GENESIS, nonce: 0 }));
    return rebuildFrom(0);
  }
  async function rebuildFrom(start) {
    if (busy) return; busy = true; $$('button', $('#labTools')).forEach((x) => (x.disabled = true));
    let total = 0, ms = 0;
    for (let i = start; i < blocks.length; i++) {
      if (i > 0) blocks[i].prev = hashOf(i - 1, blocks[i - 1]);
      const r = await mine(i, (n) => { $('#labStat').textContent = 'Блок ' + (i + 1) + ': перебрано ' + n.toLocaleString('ru-RU') + ' значений nonce…'; });
      total += r.tries; ms += r.ms; render();
    }
    $('#labStat').textContent = 'Цепочка пересчитана: перебрано ' + total.toLocaleString('ru-RU') + ' значений nonce за ' + Math.round(ms) + ' мс. Чем выше сложность, тем дороже пересчет.';
    busy = false; $$('button', $('#labTools')).forEach((x) => (x.disabled = false)); render();
  }
  function render() {
    box.innerHTML = '';
    let prevHash = GENESIS;
    blocks.forEach((b, i) => {
      const h = hashOf(i, b), linkOk = b.prev === prevHash, powOk = okPow(h), valid = linkOk && powOk;
      const el = document.createElement('div'); el.className = 'bk' + (valid ? '' : ' bad');
      const why = valid ? 'Действителен' : (!linkOk ? 'Связь нарушена' : 'Хеш не проходит сложность');
      el.innerHTML = '<h5><span>Блок ' + (i + 1) + (i === 0 ? ' · генезисный' : '') + '</span><span class="st"></span></h5>' +
        '<label>Данные</label><input type="text" aria-label="Данные блока ' + (i + 1) + '">' +
        '<label>Nonce</label><div class="hash nn"></div><label>Хеш предыдущего блока</label><div class="hash pv"></div>' +
        '<label>Хеш блока</label><div class="hash hh"></div><button class="btn mine" type="button">Майнить блок ' + (i + 1) + '</button>';
      $('.st', el).textContent = why;
      const inp = $('input', el); inp.value = b.data; inp.disabled = busy;
      $('.nn', el).textContent = b.nonce;
      $('.pv', el).textContent = b.prev.slice(0, 24) + '…';
      const z = h.match(/^0*/)[0].length; $('.hh', el).innerHTML = '<b>' + h.slice(0, z) + '</b>' + h.slice(z, 24) + '…';
      inp.addEventListener('input', () => { b.data = inp.value; const pos = inp.selectionStart; render(); const ni = $$('.bk input', box)[i]; ni.focus(); try { ni.setSelectionRange(pos, pos); } catch (e) { /* ignore */ } $('#labStat').textContent = 'Вы изменили блок ' + (i + 1) + ': его хеш стал другим, и связь со следующими блоками нарушена.'; });
      $('.mine', el).addEventListener('click', async () => { if (busy) return; busy = true; const r = await mine(i, null); busy = false; render(); $('#labStat').textContent = 'Блок ' + (i + 1) + ' пересчитан за ' + r.tries.toLocaleString('ru-RU') + ' попыток. Следующий блок все еще хранит старый хеш, поэтому цепочка сломана. Нажмите «Пересчитать всю цепочку».'; });
      box.append(el); prevHash = h;
    });
  }
  diffSel.addEventListener('change', () => { render(); $('#labStat').textContent = 'Сложность изменена: блоки, чей хеш не начинается с нужного числа нулей, стали недействительными.'; });
  $('#labRebuild').addEventListener('click', () => rebuildFrom(0));
  $('#labReset').addEventListener('click', () => reset());
  reset();
}

/* ==========================================================================
   Лавинный эффект: хеш текста и текста с одним добавленным символом
   ========================================================================== */
function initAvalanche() {
  const inp = $('#avIn'); if (!inp) return;
  const A = $('#avA'), B = $('#avB'), R = $('#avRes');
  const pop = (n) => { let c = 0; while (n) { c += n & 1; n >>= 1; } return c; };
  const upd = () => {
    const a = sha256(inp.value), b = sha256(inp.value + '.');
    let bits = 0, ha = '', hb = '';
    for (let i = 0; i < 64; i++) {
      const same = a[i] === b[i]; bits += pop(parseInt(a[i], 16) ^ parseInt(b[i], 16));
      ha += same ? a[i] : '<b>' + a[i] + '</b>'; hb += same ? b[i] : '<b>' + b[i] + '</b>';
    }
    A.innerHTML = ha; B.innerHTML = hb;
    R.textContent = 'Отличается ' + bits + ' из 256 бит, то есть около ' + Math.round((bits / 256) * 100) + '%. В среднем хеши отличаются примерно наполовину.';
  };
  inp.addEventListener('input', upd); upd();
}

/* ==========================================================================
   Мастер выбора «Нужен ли блокчейн?»
   ========================================================================== */
function initDecision() {
  const body = $('#decBody'); if (!body) return;
  const Q = {
    q1: { t: 'Нужно ли хранить общее состояние, то есть данные, которые со временем меняются?', y: 'q2', n: 'r_none' },
    q2: { t: 'Записывать данные будут несколько независимых участников?', y: 'q3', n: 'r_db' },
    q3: { t: 'Есть ли посредник, которому доверяют все участники и который всегда доступен?', y: 'r_central', n: 'q4' },
    q4: { t: 'Участники доверяют друг другу и работают по общим правилам?', y: 'r_shared', n: 'q5' },
    q5: { t: 'Нужна ли возможность проверки записей любым желающим, без разрешения?', y: 'r_public', n: 'r_cons' },
  };
  const R = {
    r_none: ['Блокчейн не нужен', 'Достаточно обычных вычислений: общее изменяемое состояние не требуется.'],
    r_db: ['Нужна обычная база данных', 'Когда пишет один участник, блокчейн лишь замедлит и удорожит систему. При необходимости добавьте журнал аудита.'],
    r_central: ['Подойдет централизованная система', 'Если есть общий доверенный посредник, система с ним проще, быстрее и дешевле.'],
    r_shared: ['Достаточно общей базы данных', 'Участники и так доверяют друг другу, хватит базы с контролем доступа и журналированием.'],
    r_public: ['Подходит публичный блокчейн', 'Нужна проверяемость без разрешения и без единого владельца. Учтите издержки: комиссии, скорость, прозрачность данных.'],
    r_cons: ['Подходит приватный или консорциумный блокчейн', 'Участников несколько, они не доверяют друг другу полностью, но круг ограничен. Так устроен пилот Walmart.'],
  };
  let step = 0;
  const draw = (id) => {
    body.innerHTML = '';
    if (R[id]) {
      const d = document.createElement('div'); d.className = 'verdict' + (id === 'r_public' || id === 'r_cons' ? '' : ' mid');
      const st = document.createElement('strong'); st.textContent = R[id][0]; const p = document.createElement('div'); p.textContent = R[id][1]; d.append(st, p); body.append(d); return;
    }
    step++;
    const n = document.createElement('p'); n.className = 'step-no'; n.textContent = 'Вопрос ' + step; const q = document.createElement('p'); q.className = 'dec-q'; q.textContent = Q[id].t;
    const act = document.createElement('div'); act.className = 'dec-actions';
    [['Да', Q[id].y], ['Нет', Q[id].n]].forEach(([l, nx]) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'btn'; b.textContent = l; b.addEventListener('click', () => draw(nx)); act.append(b); });
    body.append(n, q, act);
  };
  const reset = () => { step = 0; draw('q1'); };
  $('#decReset').addEventListener('click', reset); reset();
}

/* ==========================================================================
   Чек-лист «Личный минимум безопасности» (отметки хранятся в браузере)
   ========================================================================== */
function initChecklist() {
  const root = $('#check'); if (!root) return;
  const boxes = $$('input[type=checkbox]', root), bar = $('#chkBar'), score = $('#chkScore'), out = $('#chkOut');
  let saved = []; try { saved = JSON.parse(localStorage.getItem('lr-check') || '[]'); } catch (e) { saved = []; }
  boxes.forEach((b, i) => { b.checked = !!saved[i]; });
  const upd = () => {
    const n = boxes.filter((b) => b.checked).length;
    score.textContent = n + ' из ' + boxes.length; bar.style.width = (n / boxes.length) * 100 + '%';
    const v = n <= 3 ? ['bad', 'Начальный уровень. Начните с первых двух пунктов: ключи доступа и менеджер паролей дают наибольший эффект.'] : n <= 6 ? ['mid', 'Средний уровень. Основа есть, закройте оставшиеся пункты, особенно связанные с подписью транзакций.'] : ['', 'Хороший уровень. Поддерживайте привычки и периодически пересматривайте разрешения.'];
    out.className = 'verdict ' + v[0]; out.textContent = v[1];
    try { localStorage.setItem('lr-check', JSON.stringify(boxes.map((b) => b.checked))); } catch (e) { /* ignore */ }
  };
  boxes.forEach((b) => b.addEventListener('change', upd)); upd();
}

/* ==========================================================================
   Глоссарий (поиск) и вопросы и ответы (раскрыть все)
   ========================================================================== */
function initGlossary() {
  const f = $('#glFilter'); if (!f) return;
  const rows = $$('#gloss > div'), cnt = $('#glCount');
  const upd = () => {
    const q = f.value.trim().toLowerCase(); let n = 0;
    rows.forEach((r) => { const t = $('dt', r), d = $('dd', r); const show = !q || (t.textContent + ' ' + d.textContent).toLowerCase().includes(q); r.hidden = !show; if (show) n++; });
    cnt.textContent = n ? 'Найдено терминов: ' + n + ' из ' + rows.length : 'Ничего не найдено. Попробуйте другое слово.';
  };
  f.addEventListener('input', upd); upd();
}
function initFaq() {
  const all = $$('.faq details'); if (!all.length) return;
  $('#faqOpen').addEventListener('click', () => all.forEach((d) => (d.open = true)));
  $('#faqClose').addEventListener('click', () => all.forEach((d) => (d.open = false)));
}

/* ==========================================================================
   Консенсус: ползунки атаки и счетчик энергии
   ========================================================================== */
function initConsensus() {
  const root = $('#consensus-tabs'); if (!root) return;
  const set = (rangeId, outId, valId, fn) => {
    const r = $(rangeId), o = $(outId), v = $(valId); if (!r) return;
    const upd = () => { v.textContent = r.value + '%'; const x = fn(+r.value); o.className = 'verdict ' + x[0]; o.textContent = x[1]; };
    r.addEventListener('input', upd); upd();
  };
  set('#powRange', '#powOut', '#powVal', (v) => v < 40 ? ['', 'Честные майнеры продлевают цепочку быстрее атакующего. Переписать историю практически невозможно.'] : v < 50 ? ['mid', 'Опасная зона: вероятность успеха растет, но у атакующего все еще меньше мощности, чем у остальной сети.'] : ['bad', 'Атакующий получает возможность переписывать недавние блоки и повторно тратить монеты. Для крупной сети такая мощность стоит огромных денег.']);
  set('#posRange', '#posOut', '#posVal', (v) => v < 33 ? ['', 'Ниже одной трети залога атаковать финализацию блоков невозможно.'] : v < 67 ? ['mid', 'Выше одной трети залога атакующий может задерживать финализацию блоков, но не навязывать свою версию истории.'] : ['bad', 'Выше двух третей залога атакующий мог бы финализировать нужные ему блоки, но при обнаружении его залог будет уничтожен слэшингом.']);
  root.addEventListener('tabchange', () => { $$('.meter i', root).forEach((m) => { m.style.width = '0'; requestAnimationFrame(() => requestAnimationFrame(() => (m.style.width = m.dataset.w + '%'))); }); });
  $$('.meter i', root).forEach((m) => (m.style.width = m.dataset.w + '%'));
}

/* ==========================================================================
   VPN и Tor: что видит каждый узел
   ========================================================================== */
function initRoute() {
  const root = $('#route'); if (!root) return;
  const modes = {
    vpn: [
      { i: '💻', n: 'Вы', s: 'Вы знаете все: свой адрес, сайт и содержимое запроса.' },
      { i: '🛡', n: 'VPN-сервер', s: 'Видит ваш реальный IP-адрес и весь исходящий трафик. Доверие переносится на провайдера VPN, а не исчезает.' },
      { i: '🌐', n: 'Сайт', s: 'Видит адрес VPN-сервера, но не ваш настоящий IP.' },
    ],
    tor: [
      { i: '💻', n: 'Вы', s: 'Шифруете трафик по слоям отдельно для каждого из трех узлов.' },
      { i: '1️⃣', n: 'Входной узел', s: 'Знает ваш IP-адрес, но не знает, куда направлен трафик.' },
      { i: '2️⃣', n: 'Средний узел', s: 'Не знает ни вас, ни конечный сайт: видит только соседние узлы.' },
      { i: '3️⃣', n: 'Выходной узел', s: 'Видит сайт, но не знает, кто вы. Содержимое защищено, только если соединение с сайтом шифруется (HTTPS).' },
      { i: '🌐', n: 'Сайт', s: 'Видит адрес выходного узла. Противник, наблюдающий оба конца цепочки, может сопоставить трафик по времени и объему.' },
    ],
  };
  const row = $('#routeRow'), info = $('#routeInfo'), btns = $$('[data-mode]', root);
  function draw(mode) {
    btns.forEach((b) => b.setAttribute('aria-pressed', b.dataset.mode === mode)); row.innerHTML = '';
    modes[mode].forEach((n, k) => {
      if (k) { const l = document.createElement('span'); l.className = 'link'; row.append(l); }
      const b = document.createElement('button'); b.type = 'button'; b.className = 'node'; b.innerHTML = '<b>' + n.i + '</b>' + n.n;
      b.addEventListener('click', () => { $$('.node', row).forEach((x) => x.classList.remove('on')); b.classList.add('on'); info.innerHTML = ''; const s = document.createElement('strong'); s.textContent = n.n + ': '; info.append(s, document.createTextNode(n.s)); });
      row.append(b);
    });
    info.textContent = 'Нажмите на любой узел, чтобы узнать, что он видит.';
  }
  btns.forEach((b) => b.addEventListener('click', () => draw(b.dataset.mode)));
  draw('tor');
}

/* ==========================================================================
   Видео: превью, затем загрузка плеера по клику (YouTube, RuTube, VK или файл)
   ========================================================================== */
function initVideos() {
  $$('[data-video]').forEach((box) => {
    const v = VIDEOS[box.dataset.video]; if (!v) return;
    const yt = v.youtube ? 'https://www.youtube.com/watch?v=' + v.youtube : '';
    const rt = v.rutube ? 'https://rutube.ru/video/' + v.rutube + '/' : '';
    const vk = v.vk ? 'https://vk.com/video' + v.vk : '';
    box.classList.add('video');
    box.innerHTML = '<div class="frame"><button class="play" type="button" aria-label="Смотреть видео: ' + v.title.replace(/"/g, '') + '"><span></span></button><div class="vt"></div></div><div class="vinfo"></div>';
    const frame = $('.frame', box), info = $('.vinfo', box);
    $('.vt', box).textContent = v.title;
    if (v.youtube && !v.local) {
      const img = new Image(); img.className = 'poster'; img.alt = ''; img.loading = 'lazy'; img.src = 'https://i.ytimg.com/vi/' + v.youtube + '/hqdefault.jpg';
      img.onerror = () => img.remove(); frame.prepend(img);
    }
    info.append(document.createTextNode(v.author + ' · '));
    [['YouTube', yt], ['RuTube', rt], ['VK Видео', vk]].forEach(([n, u]) => { if (!u) return; const a = document.createElement('a'); a.href = u; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = 'Открыть на ' + n; info.append(a); });
    const load = () => {
      let el;
      if (v.local) { el = document.createElement('video'); el.src = v.local; el.controls = true; el.autoplay = true; el.setAttribute('playsinline', ''); }
      else {
        el = document.createElement('iframe'); el.title = v.title; el.setAttribute('allow', 'accelerometer; autoplay; encrypted-media; picture-in-picture; fullscreen');
        el.referrerPolicy = 'strict-origin-when-cross-origin';
        if (v.rutube) el.src = 'https://rutube.ru/play/embed/' + v.rutube;
        else if (v.vk) { const [oid, id] = v.vk.split('_'); el.src = 'https://vk.com/video_ext.php?oid=' + oid + '&id=' + id + '&hd=2'; }
        else el.src = 'https://www.youtube-nocookie.com/embed/' + v.youtube + '?autoplay=1&rel=0';
      }
      frame.innerHTML = ''; frame.style.cursor = 'default'; frame.append(el);
    };
    frame.addEventListener('click', load, { once: true });
  });
}

/* ==========================================================================
   Аудио: озвучивание разделов (файл из AUDIO или синтезатор речи браузера)
   ========================================================================== */
function initAudio() {
  const player = $('#player'), label = $('#playerLabel'), pp = $('#playPause'), stop = $('#playStop'), rate = $('#playRate');
  const synth = window.speechSynthesis;
  let queue = [], idx = 0, state = 'idle', fileAudio = null, cur = null;
  const clear = () => { $$('.speaking').forEach((x) => x.classList.remove('speaking')); };
  const paras = (sel) => $$(sel + ' p', document).filter((p) => !p.closest('.lab, .quiz, .video, .links, .refs, figure, .player, .contents, .stats'));
  function finish() { clear(); state = 'idle'; player.classList.remove('show'); if (synth) synth.cancel(); if (fileAudio) { fileAudio.pause(); fileAudio = null; } }
  function speak() {
    if (idx >= queue.length) { finish(); toast('Озвучивание завершено'); return; }
    const p = queue[idx]; clear(); p.classList.add('speaking'); p.scrollIntoView({ block: 'center', behavior: 'smooth' });
    label.textContent = 'Абзац ' + (idx + 1) + ' из ' + queue.length;
    const u = new SpeechSynthesisUtterance(p.innerText.replace(/\[[\d, ]+\]/g, '').replace(/#/g, '')); u.lang = 'ru-RU'; u.rate = parseFloat(rate.value);
    const ru = synth.getVoices().find((v) => /^ru/i.test(v.lang)); if (ru) u.voice = ru;
    u.onend = () => { if (state === 'playing') { idx++; speak(); } };
    u.onerror = () => { if (state === 'playing') { idx++; speak(); } };
    cur = u; synth.speak(u);
  }
  function start(sectionId) {
    finish();
    if (AUDIO[sectionId]) { fileAudio = new Audio(AUDIO[sectionId]); fileAudio.play(); state = 'file'; player.classList.add('show'); label.textContent = 'Аудиозапись раздела'; pp.textContent = '⏸'; fileAudio.onended = finish; return; }
    if (!synth) { toast('Ваш браузер не поддерживает озвучивание текста'); return; }
    const scope = sectionId === 'all' ? 'article section' : '#' + sectionId;
    queue = paras(scope); idx = 0; if (!queue.length) return;
    state = 'playing'; player.classList.add('show'); pp.textContent = '⏸'; speak();
  }
  $$('[data-listen]').forEach((b) => b.addEventListener('click', () => start(b.dataset.listen)));
  pp.addEventListener('click', () => {
    if (state === 'file') { if (fileAudio.paused) { fileAudio.play(); pp.textContent = '⏸'; } else { fileAudio.pause(); pp.textContent = '▶'; } return; }
    if (state === 'playing') { state = 'paused'; synth.pause(); pp.textContent = '▶'; }
    else if (state === 'paused') { state = 'playing'; synth.resume(); pp.textContent = '⏸'; }
  });
  stop.addEventListener('click', finish);
  rate.addEventListener('change', () => { if (state === 'playing') { synth.cancel(); speak(); } });
  addEventListener('beforeunload', () => { if (synth) synth.cancel(); });
}

/* ==========================================================================
   Тест для самопроверки
   ========================================================================== */
function initQuiz() {
  const root = $('#quiz-box'); if (!root) return;
  const Q = [
    { q: 'Что на самом деле означает число 51% в контексте Bitcoin?', o: ['Правило, по которому сеть выбирает следующий блок', 'Порог атаки: доля вычислительной мощности, дающая возможность переписать недавнюю историю', 'Доля узлов, которые должны подтвердить транзакцию', 'Размер комиссии майнера'], a: 1, e: 'Сеть выбирает цепочку с наибольшей накопленной работой. 51% описывает порог атаки по вычислительной мощности, а не число компьютеров.' },
    { q: 'Почему правка данных в одном блоке делает недействительными все следующие?', o: ['Потому что блоки хранятся на одном сервере', 'Потому что каждый блок содержит хеш предыдущего, и ссылка перестает совпадать', 'Потому что новые блоки удаляются автоматически', 'Потому что майнеры наказываются штрафом'], a: 1, e: 'Хеш блока меняется при любой правке, а следующий блок хранит старое значение. Именно это вы наблюдали в песочнице.' },
    { q: 'Что показал инцидент Bybit в феврале 2025 года?', o: ['Смарт-контракты Safe содержали критическую уязвимость', 'Взломали сам протокол Ethereum', 'Атака прошла через подмену веб-интерфейса, а контракты взломаны не были', 'Биржа потеряла ключи из-за сбоя оборудования'], a: 2, e: 'Злоумышленники скомпрометировали компьютер разработчика Safe{Wallet} и подменили код интерфейса. Подписанты одобрили замаскированную транзакцию.' },
    { q: 'Чем Tor принципиально отличается от VPN?', o: ['Tor быстрее и дешевле', 'В Tor трафик проходит через три узла, и ни один не знает одновременно отправителя и получателя', 'VPN шифрует трафик, а Tor нет', 'Tor не защищает от наблюдения вообще'], a: 1, e: 'VPN-провайдер видит ваш адрес и трафик, то есть доверие переносится. В Tor знание разделено между узлами, хотя наблюдатель обоих концов может сопоставить трафик.' },
    { q: 'Почему неизменяемость блокчейна конфликтует с GDPR?', o: ['Блокчейн нельзя шифровать', 'Закон запрещает хранить любые хеши', 'Закон дает право на исправление и удаление данных, а запись в блокчейне изменить нельзя', 'GDPR действует только на серверах Евросоюза'], a: 2, e: 'Поэтому EDPB рекомендует хранить персональные данные вне цепочки, а в блоках оставлять только хеши и обязательства.' },
    { q: 'Какая технология, по нашему ранжированию, даст наибольший эффект в краткосрочной перспективе?', o: ['Постквантовая криптография', 'Беспарольная аутентификация на ключах доступа', 'Метавселенные', 'Консорциумные блокчейны'], a: 1, e: 'Она зрела и устраняет самый частый вектор атак: украденные учетные данные участвовали в 22% случаев первоначального доступа по данным Verizon DBIR 2025.' },
  ];
  let i = 0, score = 0;
  const draw = () => {
    if (i >= Q.length) {
      const pct = Math.round((score / Q.length) * 100);
      root.innerHTML = '<div class="qbar"><i style="width:100%"></i></div><p class="score">' + score + ' из ' + Q.length + '</p><p>' + (pct >= 80 ? 'Отлично: материал усвоен.' : pct >= 50 ? 'Неплохо. Перечитайте разделы, где ошиблись.' : 'Стоит вернуться к тексту и песочнице.') + '</p><button class="btn primary" type="button" id="qAgain">Пройти заново</button>';
      $('#qAgain').addEventListener('click', () => { i = 0; score = 0; draw(); }); return;
    }
    const q = Q[i];
    root.innerHTML = '<div class="qbar"><i style="width:' + (i / Q.length) * 100 + '%"></i></div><p><strong>Вопрос ' + (i + 1) + ' из ' + Q.length + '.</strong> <span id="qt"></span></p><div class="opts"></div><p class="explain" aria-live="polite"></p><button class="btn primary" type="button" id="qNext" hidden>Дальше</button>';
    $('#qt').textContent = q.q;
    const opts = $('.opts', root);
    q.o.forEach((t, k) => { const b = document.createElement('button'); b.type = 'button'; b.textContent = t; b.addEventListener('click', () => { $$('button', opts).forEach((x, n) => { x.disabled = true; if (n === q.a) x.classList.add('right'); }); if (k === q.a) score++; else b.classList.add('wrong'); $('.explain', root).textContent = (k === q.a ? 'Верно. ' : 'Неверно. ') + q.e; const nx = $('#qNext'); nx.hidden = false; nx.textContent = i === Q.length - 1 ? 'Показать результат' : 'Дальше'; nx.focus(); }); opts.append(b); });
    $('#qNext').addEventListener('click', () => { i++; draw(); });
  };
  draw();
}

/* ===== Запуск ===== */
document.addEventListener('DOMContentLoaded', () => {
  initChrome(); initToc(); initTerms(); initReveal(); initTabs(); initSandbox(); initAvalanche(); initDecision(); initChecklist(); initGlossary(); initFaq(); initConsensus(); initRoute(); initVideos(); initAudio(); initQuiz();
});
