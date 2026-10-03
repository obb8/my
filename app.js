/*
 * app.js -- 浏览器端解密 + 渲染
 *
 * 安全模型（先懂这个再读代码）：
 *   服务器上只有密文。密钥由密码在**你的浏览器里**派生，密码从不离开本机。
 *   攻击者能拿到的 = 密文 + 这份源码。缺密码什么都还原不出来。
 *   这里没有后门判断、没有明文密码常量、没有隐藏接口。
 *
 * 密码学：
 *   PBKDF2-HMAC-SHA256 (600k 轮) -> AES-256-GCM
 *   GCM 自带完整性校验：密文被改过会直接解密失败。
 *
 * 渲染器（全部本地部署，不连任何 CDN，jsdelivr 挂了也不影响）：
 *   PDF  -> vendor/pdf.min.mjs (pdf.js)，渲染到 canvas
 *   DOCX -> vendor/mammoth.browser.min.js，转 HTML
 */

const GATE = document.getElementById('gate');
const VAULT = document.getElementById('vault');
const PWD = document.getElementById('pwd');
const UNLOCK_BTN = document.getElementById('unlock-btn');
const GATE_MSG = document.getElementById('gate-msg');
const GATE_META = document.getElementById('gate-meta');
const FILTER = document.getElementById('filter');
const FILE_COUNT = document.getElementById('file-count');
const LOCK_BTN = document.getElementById('lock-btn');
const REMEMBER = document.getElementById('remember');
const TIMER = document.getElementById('timer');
const BACK_BTN = document.getElementById('back-btn');
const LIST_FAB = document.getElementById('list-fab');
const VIEW_TITLE = document.getElementById('view-title');
const SIDEBAR = document.getElementById('sidebar');
const CONTENT = document.getElementById('content');
const BODY = document.body;
const LOADING = document.getElementById('loading');
const LOADING_TEXT = document.getElementById('loading-text');
const TAB_PHOTOS = document.getElementById('tab-photos');
const TAB_FILES = document.getElementById('tab-files');
const WALL = document.getElementById('wall');
const WALL_BODY = document.getElementById('wall-body');
const WALL_COUNT = document.getElementById('wall-count');
const WALL_FILTER = document.getElementById('wall-filter');
const FILES_PANEL = document.getElementById('files-panel');

/*
 * 照片区是独立的"照片墙"容器（#wall），文件区才是侧栏面板。
 * 两者互斥显示：照片墙铺满整屏，侧栏只在文件标签出现。
 */
function activePanel() {
  return currentBucket() === 'photos' ? WALL_BODY : FILES_PANEL;
}

const MAGIC = 'VAULT1';
const IDLE_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------- 状态

const S = {
  config: null,
  manifest: null,
  key: null,
  current: null,
  bucket: 'photos',      // 当前标签页：photos | files
  cache: new Map(),      // id -> Uint8Array
  thumbs: new Map(),     // id -> dataURL 缩略图（给灯箱底部条复用）
  objectUrls: [],
  idleTimer: null,
  unlocking: false,
  pdf: { doc: null, page: 1, scale: 1, numPages: 0, task: null },
  mammoth: null,
};

// ---------------------------------------------------------------- 工具

const $ = (id) => document.getElementById(id);

function human(n) {
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(1) + ' ' + u[i];
}

function gateMsg(text, kind) {
  GATE_MSG.textContent = text || '';
  GATE_MSG.className = 'msg' + (kind ? ' ' + kind : '');
}

const detectMobile = () => window.matchMedia('(max-width: 768px)').matches;

function showLoading(text) {
  LOADING_TEXT.textContent = text || '正在解密…';
  LOADING.hidden = false;
}

function hideLoading() { LOADING.hidden = true; }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// ---------------------------------------------------------------- 容器解析
// 磁盘布局（Python 端 encrypt_vault.py 写入）：
//   [0:6]  MAGIC "VAULT1"
//   [6:18] 12 字节 IV
//   [18:]  AES-256-GCM 密文（含 16 字节 GCM 标签）

function splitContainer(buf) {
  const bytes = new Uint8Array(buf);
  if (bytes.length < 34) throw new Error('文件容器损坏');
  const magic = new TextDecoder().decode(bytes.slice(0, 6));
  if (magic !== MAGIC) throw new Error('格式不匹配：' + magic);
  return { iv: bytes.slice(6, 18), body: bytes.slice(18) };
}

async function decryptBuffer(url) {
  const res = await fetch(url, { cache: 'no-store', credentials: 'omit' });
  if (!res.ok) throw new Error('拉取失败（HTTP ' + res.status + '）');
  const { iv, body } = splitContainer(await res.arrayBuffer());
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, S.key, body));
}

// ---------------------------------------------------------------- 解锁

async function unlock(password) {
  const cfgRes = await fetch('vault/config.json', { cache: 'no-store', credentials: 'omit' });
  if (!cfgRes.ok) throw new Error('找不到 vault/config.json');
  S.config = await cfgRes.json();

  if (S.config.kdf !== 'PBKDF2-HMAC-SHA256' || S.config.cipher !== 'AES-256-GCM') {
    throw new Error('不支持的参数：' + S.config.kdf + ' / ' + S.config.cipher);
  }

  const salt = Uint8Array.from(atob(S.config.salt), (c) => c.charCodeAt(0));

  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  S.key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: S.config.iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: S.config.keyLength },
    false,
    ['decrypt']
  );

  // 明文密码在内存里立刻抹掉
  new TextEncoder().encode(password).fill(0);

  S.manifest = JSON.parse(new TextDecoder().decode(await decryptBuffer('vault/index.enc')));
}

// ---------------------------------------------------------------- 列表

const KIND_LABEL = {
  image: 'IMG', pdf: 'PDF', text: 'TXT',
  'office-docx': 'DOC', 'office-pptx': 'PPT', file: 'FILE',
};

function matches(f, q) {
  if (!q) return true;
  return f.name.toLowerCase().includes(q) ||
         String(f.path).toLowerCase().includes(q);
}

function currentBucket() {
  return S.bucket === 'photos' ? 'photos' : 'files';
}

// 当前 bucket 里、符合筛选条件的文件
function bucketFiles() {
  const b = currentBucket();
  // 两个区各有自己的筛选框，读当前正在显示的那个
  const box = b === 'photos' ? WALL_FILTER : FILTER;
  const q = (box ? box.value : '').trim().toLowerCase();
  return S.manifest.files.filter((f) => (f.bucket || 'files') === b && matches(f, q));
}

/*
 * 渲染当前 bucket 的列表。
 * photos -> 照片墙整屏，点一下开灯箱
 * files  -> 侧栏列表，点一下按类型打开预览
 *
 * 注意：函数开头就调 applyLayout()，因为它有三个提前 return
 * （照片墙 / 空列表 / 正常渲染），在末尾统一调用会漏掉前两条路径，
 * 切标签后 is-wall 没被清掉，文件列表就被藏没了。
 */
function renderList() {
  // 照片墙和文件列表各有自己的筛选框，各用各的
  const bucket = currentBucket();
  const q = bucket === 'photos'
    ? WALL_FILTER.value.trim().toLowerCase()
    : FILTER.value.trim().toLowerCase();

  applyLayout();          // 先定布局，再填内容

  // 照片墙整屏显示，侧栏只在文件标签出现
  const panel = activePanel();
  panel.innerHTML = '';
  if (bucket === 'photos') {
    FILES_PANEL.innerHTML = '';
    FILTER.value = '';                     // 切回来时不要留旧筛选
  } else {
    WALL_BODY.innerHTML = '';
    WALL_FILTER.value = '';
  }

  // 标签页计数（标签上的数字永远显示总数，不受筛选影响）
  const nPhoto = S.manifest.files.filter((f) => (f.bucket || 'files') === 'photos').length;
  const nFile = S.manifest.files.filter((f) => (f.bucket || 'files') === 'files').length;
  const nPhotoQ = S.manifest.files.filter((f) => (f.bucket || 'files') === 'photos' && matches(f, q)).length;
  const nFileQ = S.manifest.files.filter((f) => (f.bucket || 'files') === 'files' && matches(f, q)).length;
  TAB_PHOTOS.textContent = '照片 ' + nPhoto;
  TAB_FILES.textContent = '文件 ' + nFile;
  TAB_PHOTOS.classList.toggle('is-active', bucket === 'photos');
  TAB_FILES.classList.toggle('is-active', bucket === 'files');
  WALL_COUNT.textContent = q ? nPhotoQ + ' / ' + nPhoto + ' 张' : nPhoto + ' 张';
  FILE_COUNT.textContent = q ? nFileQ + ' / ' + nFile : nFile + ' / ' + nFile;

  if (bucket === 'photos') {
    renderPhotoGrid();
    return;
  }

  const files = bucketFiles();
  if (!files.length) {
    panel.innerHTML = '<p class="hint">' +
      (q ? '没有匹配的文件' : 'files 目录还是空的，把文件放进去再运行一次启动网站.bat') + '</p>';
    return;
  }

  // files 桶里也按子目录分组（兼容按文件夹整理的习惯）
  // 注意兜底名要区分 bucket：照片桶叫"全部照片"，文件桶叫"全部文件"
  const fallback = bucket === 'photos' ? '全部照片' : '全部文件';
  const groups = new Map();
  for (const f of files) {
    const parts = String(f.path).split('/');
    const g = parts.length > 1 ? parts.slice(0, -1).join(' / ') : fallback;
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(f);
  }

  for (const [name, items] of groups) {
    const sec = document.createElement('section');
    sec.className = 'group';

    const h = document.createElement('h2');
    h.className = 'group-name';
    h.textContent = name + '（' + items.length + '）';
    sec.appendChild(h);

    for (const f of items) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'file';
      btn.dataset.id = f.id;

      const icon = document.createElement('span');
      icon.className = 'ficon ficon-' + f.kind;
      icon.textContent = KIND_LABEL[f.kind] || 'FILE';

      const meta = document.createElement('span');
      meta.className = 'fmeta';
      const nm = document.createElement('span');
      nm.className = 'fname';
      nm.textContent = f.name;
      const sz = document.createElement('span');
      sz.className = 'fsize';
      sz.textContent = human(f.size) + ' · ' + f.mtime.slice(0, 10);
      meta.append(nm, sz);

      btn.append(icon, meta);
      sec.appendChild(btn);
    }
    panel.appendChild(sec);
  }
}

// ---------------------------------------------------------------- 灯箱
//
// 照片墙点一下弹出的小窗。不跳转到独立页面，背景还是照片墙，
// 关掉就回到原来的位置。底部一排小缩略图可以直接跳到别的照片。

const LB = {
  open: false,
  list: [],        // 当前 bucket 里的照片
  index: -1,
  url: null,       // 当前大图的 blob URL
  keyHandler: null,
  // ---- 缩放状态
  zoom: 1,         // 当前缩放倍数
  fitZoom: 1,      // "适应窗口"对应的倍数
  minZoom: 1,      // 不允许缩小到比适应窗口更小
  maxZoom: 8,
  panning: false,  // 放大后是否在拖动
  panX: 0,
  panY: 0,
};

// ---------------------------------------------------------------- 缩放

/*
 * 缩放思路：
 *   图片用 CSS transform: translate(...) scale(...)，
 *   不用改 width/height —— 改尺寸会触发重排、放大后卡顿；
 *   transform 走合成层，缩放平移都是 GPU 干的，60fps 很顺。
 *
 * "适应"是基准：图片刚好塞进 .lb-stage 时的缩放（=1）。
 * 放大后舞台会滚动，靠 overflow:auto + 手动 translate 来定位看哪一块。
 */
function applyZoom() {
  const img = $('lb-img');
  const z = LB.zoom;
  img.style.transform =
    'translate(' + LB.panX + 'px,' + LB.panY + 'px) scale(' + z + ')';
  img.style.transformOrigin = 'center center';
  img.classList.toggle('is-zoomed', z > 1.01);

  const stage = $('lb-stage');
  // 放大后允许拖动查看：给舞台加可滚动区域
  if (z > 1.01) {
    const w = stage.clientWidth;
    const h = stage.clientHeight;
    stage.style.width = (w * z) + 'px';
    stage.style.height = (h * z) + 'px';
    stage.classList.add('is-scrollable');
  } else {
    stage.style.width = '';
    stage.style.height = '';
    stage.classList.remove('is-scrollable');
  }

  $('lb-zoom-reset').textContent = z <= 1.01 ? '适应' : Math.round(z * 100) + '%';
}

function setZoom(z, anchorX, anchorY) {
  const old = LB.zoom;
  const next = Math.min(LB.maxZoom, Math.max(LB.minZoom, z));
  if (Math.abs(next - old) < 0.001) return;
  LB.zoom = next;

  if (next <= 1.01) {
    LB.panX = 0;
    LB.panY = 0;
  } else {
    // 保持鼠标/手指指向的那一点不动：以舞台中心为锚点缩放
    const stage = $('lb-stage');
    const cx = anchorX === undefined ? stage.clientWidth / 2 : anchorX;
    const cy = anchorY === undefined ? stage.clientHeight / 2 : anchorY;
    const k = next / old;
    // 锚点相对中心的位置，按比例放大后补偿回去
    LB.panX = cx - (cx - LB.panX) * k;
    LB.panY = cy - (cy - LB.panY) * k;
  }
  applyZoom();
}

function stepZoom(factor, anchorX, anchorY) {
  setZoom(LB.zoom * factor, anchorX, anchorY);
}

function resetZoom() {
  LB.zoom = 1;
  LB.panX = 0;
  LB.panY = 0;
  applyZoom();
}

async function openLightbox(id) {
  if (S.idleTimer) resetIdle();
  LB.list = bucketFiles();
  const i = LB.list.findIndex((f) => f.id === id);
  if (i < 0) return;

  $('lightbox').hidden = false;
  document.documentElement.style.overflow = 'hidden';   // 锁背景滚动
  LB.open = true;
  renderThumbStrip();
  await showLightboxAt(i);
}

async function showLightboxAt(i) {
  if (i < 0 || i >= LB.list.length) return;
  LB.index = i;
  const entry = LB.list[i];

  $('lb-name').textContent = entry.name;
  $('lb-info').textContent = (i + 1) + ' / ' + LB.list.length + '  ·  ' + human(entry.size);
  $('lb-prev').hidden = i <= 0;
  $('lb-next').hidden = i >= LB.list.length - 1;
  S.current = entry;
  resetZoom();               // 换图必须复位，否则缩放状态会串到下一张

  // 高亮缩略图条
  for (const el of $('lb-thumbs').children) {
    el.classList.toggle('is-active', el.dataset.idx === String(i));
  }

  const stage = $('lb-stage');
  stage.classList.add('is-loading');
  try {
    const data = await getFileData(entry.id);
    if (LB.url) URL.revokeObjectURL(LB.url);
    LB.url = URL.createObjectURL(new Blob([data.slice()], { type: mimeOf(entry) }));
    $('lb-img').src = LB.url;
  } catch (e) {
    $('lb-name').textContent = '打开失败：' + (e && e.message ? e.message : e);
  } finally {
    stage.classList.remove('is-loading');
  }
}

function stepLightbox(delta) {
  const next = LB.index + delta;
  if (next < 0 || next >= LB.list.length) return;
  showLightboxAt(next);
}

function closeLightbox() {
  if (!LB.open) return;
  LB.open = false;
  $('lightbox').hidden = true;
  document.documentElement.style.overflow = '';
  if (LB.url) { URL.revokeObjectURL(LB.url); LB.url = null; }
  $('lb-img').removeAttribute('src');
  resetZoom();
  S.current = null;
  applyLayout();
}

// 底部缩略图条：只用已缓存的缩略图，不额外解密
function renderThumbStrip() {
  const strip = $('lb-thumbs');
  strip.innerHTML = '';
  const frag = document.createDocumentFragment();
  LB.list.forEach((f, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'lb-thumb';
    b.dataset.idx = String(i);
    b.title = f.name;
    const cached = S.thumbs.get(f.id);
    if (cached) b.style.backgroundImage = 'url("' + cached + '")';
    frag.appendChild(b);
  });
  strip.appendChild(frag);
}

// ---------------------------------------------------------------- 视图

const VIEW_IDS = ['text-view', 'pdf-view', 'office-view', 'opaque-view', 'err-view'];

function hideViewers() {
  for (const id of VIEW_IDS) $(id).hidden = true;
  $('empty-hint').hidden = false;
  $('office-body').innerHTML = '';
  S.pdf.doc = null;
  S.pdf.page = 1;
  S.pdf.task = null;
}

function revokeUrls() {
  for (const u of S.objectUrls) URL.revokeObjectURL(u);
  S.objectUrls = [];
}

function setView(name) {
  hideViewers();
  hideLoading();
  $(name).hidden = false;
  $('empty-hint').hidden = true;
}

/*
 * 三种布局状态：
 *   wall  —— 照片墙：侧栏与预览区都藏起来，照片铺满整屏（用户要的）
 *   list  —— 文件列表：侧栏在左/上，预览区空着
 *   viewer—— 正在看某个文件：手机上侧栏收起，靠返回/FAB 回来
 */
function applyLayout() {
  const photosMode = currentBucket() === 'photos';
  const viewing = !!S.current;

  // 照片墙模式：不要任何侧栏和空预览区
  SIDEBAR.classList.toggle('is-hidden', photosMode && !viewing);
  BODY.classList.toggle('is-wall', photosMode && !viewing);

  if (photosMode && !viewing) {
    LIST_FAB.hidden = true;
    BACK_BTN.hidden = true;
    VIEW_TITLE.textContent = '照片';
    return;
  }

  if (detectMobile()) {
    SIDEBAR.classList.toggle('is-hidden', viewing);
    LIST_FAB.hidden = !viewing;
    BACK_BTN.hidden = !viewing;
    VIEW_TITLE.textContent = viewing && S.current ? S.current.name : 'Private Vault';
  } else {
    SIDEBAR.classList.remove('is-hidden');
    LIST_FAB.hidden = true;
    BACK_BTN.hidden = true;
    VIEW_TITLE.textContent = 'Private Vault';
  }
}

// ---------------------------------------------------------------- 照片网格
//
// 照片要"能看"，就得先把密文解成图。这里有个取舍要讲清楚：
//   为了让网格里有缩略图，必须把每张照片都解密一遍。
//   100 张照片 = 100 次解密 + 100 个 blob，内存会涨。
//   所以做成**懒加载**：滚动到才解密，且只生成缩略图尺寸的预览，
//   点开大图时才用完整数据。photoQueue 限制并发，避免手机卡死。

const thumbQueue = { running: 0, max: 3, waiting: [] };

/*
 * 生成缩略图。返回 { url, ratio }，ratio = 宽/高。
 * 照片墙要用 ratio 按原始宽高比排版，所以这里必须把比例带出去。
 */
function makeThumb(data, mime) {
  return new Promise((resolve) => {
    const blob = new Blob([data.slice()], { type: mime });
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.onload = () => {
      try {
        const MAX = 320;
        const scale = Math.min(1, MAX / Math.max(img.width, img.height));
        const w = Math.max(1, Math.round(img.width * scale));
        const h = Math.max(1, Math.round(img.height * scale));
        const c = document.createElement('canvas');
        c.width = w; c.height = h;
        c.getContext('2d').drawImage(img, 0, 0, w, h);
        URL.revokeObjectURL(url);
        resolve({ url: c.toDataURL('image/jpeg', 0.72), ratio: img.width / img.height });
      } catch (e) {
        URL.revokeObjectURL(url);
        resolve(null);
      }
    };
    img.onerror = () => { URL.revokeObjectURL(url); resolve(null); };
    img.src = url;
  });
}

/*
 * 按图片真实宽高比设置格子宽度：高度固定（CSS 的 --cell-h），宽度按比例算。
 * 这样横图宽、竖图窄，照片能紧密排在一起，且一行能排满。
 */
function sizeCell(cell, ratio) {
  if (!ratio || !isFinite(ratio) || ratio <= 0) {
    cell.style.width = '';      // 拿不到比例就用 CSS 的 flex 兜底
    return;
  }
  const h = parseFloat(getComputedStyle(cell).height) || 150;
  // 极端比例（全景图/竖长图）做夹逼，避免出现 1px 宽或5000px 宽的格子
  const ratioClamped = Math.min(3.2, Math.max(0.28, ratio));
  cell.style.width = Math.round(h * ratioClamped) + 'px';
}

function scheduleThumb(entry, imgEl) {
  thumbQueue.waiting.push({ entry, imgEl });
  pumpThumbs();
}

function pumpThumbs() {
  while (thumbQueue.running < thumbQueue.max && thumbQueue.waiting.length) {
    const job = thumbQueue.waiting.shift();
    thumbQueue.running++;
    (async () => {
      try {
        const data = await getFileData(job.entry.id);
        if (!data) return;
        const thumb = await makeThumb(data, mimeOf(job.entry));
        if (thumb && thumb.url) {
          // 存一份给灯箱底部缩略图条复用，避免重复解密
          S.thumbs.set(job.entry.id, thumb.url);
          if (document.body.contains(job.imgEl.parentElement)) {
            // 拿到真实宽高比后把格子宽度定下来
            sizeCell(job.imgEl.parentElement, thumb.ratio);
            job.imgEl.src = thumb.url;
          }
        }
      } catch (e) {
        /* 单张失败不影响整页 */
      } finally {
        thumbQueue.running--;
        pumpThumbs();
      }
    })();
  }
}

function renderPhotoGrid() {
  const files = bucketFiles();
  if (!files.length) {
    WALL_BODY.innerHTML = '<p class="hint">' +
      (WALL_FILTER.value.trim()
        ? '没有匹配的照片'
        : 'photos 目录还是空的，把照片放进去再运行一次启动网站.bat') + '</p>';
    return;
  }

  // 按子目录分组（photos/2024 旅行/x.jpg -> "2024 旅行"）
  const groups = new Map();
  for (const f of files) {
    const parts = String(f.path).split('/');
    const g = parts.length > 1 ? parts.slice(0, -1).join(' / ') : '';
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(f);
  }

  WALL_BODY.innerHTML = '';
  for (const [name, items] of groups) {
    // 根目录（无子目录）不显示分组标题，省一层视觉噪音
    if (name) {
      const h = document.createElement('h2');
      h.className = 'wall-group-title';
      h.textContent = name + '（' + items.length + '）';
      WALL_BODY.appendChild(h);
    }

    const grid = document.createElement('div');
    grid.className = 'wall-grid';
    for (const f of items) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'wall-cell';
      btn.dataset.id = f.id;
      btn.title = f.name;

      const img = document.createElement('img');
      img.alt = f.name;
      img.loading = 'lazy';
      // 占位灰块，解密完成后再填真实缩略图
      img.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

      const cap = document.createElement('span');
      cap.className = 'wall-cap';
      cap.textContent = f.name;

      btn.append(img, cap);
      grid.appendChild(btn);
      scheduleThumb(f, img);
    }
    WALL_BODY.appendChild(grid);
  }
}

// 统一取文件数据：命中缓存直接给，否则解密后进缓存
async function getFileData(id) {
  let d = S.cache.get(id);
  if (d) return d;
  d = await decryptBuffer('vault/' + id + '.enc');
  if (S.cache.size >= 8) S.cache.delete(S.cache.keys().next().value);
  S.cache.set(id, d);
  return d;
}

// ---------------------------------------------------------------- 打开文件

async function openEntry(id) {
  if (S.idleTimer) resetIdle();

  const entry = S.manifest.files.find((f) => f.id === id);
  if (!entry) return;

  // 清高亮：照片墙格子是 .wall-cell，文件行是 .file，两个区域都要清
  for (const p of [WALL_BODY, FILES_PANEL]) {
    for (const el of p.querySelectorAll('.is-active')) el.classList.remove('is-active');
  }
  // 点中后把对应格子/行高亮（可能在任一区域，尤其翻页后）
  for (const p of [WALL_BODY, FILES_PANEL]) {
    const el = p.querySelector('[data-id="' + id + '"]');
    if (el) { el.classList.add('is-active'); break; }
  }

  S.current = entry;
  hideViewers();
  showLoading('正在解密 ' + entry.name + '…');
  applyLayout();

  try {
    const data = await getFileData(id);
    revokeUrls();
    await render(entry, data);
  } catch (err) {
    hideViewers();
    $('err-text').textContent = '打开失败：' + (err && err.message ? err.message : String(err));
    $('err-view').hidden = false;
    $('empty-hint').hidden = true;
    hideLoading();
  }
}

async function render(entry, data) {
  if (entry.kind === 'text') {
    setView('text-view');
    $('text-name').textContent = entry.name;
    $('text-body').textContent = new TextDecoder().decode(data);

  } else if (entry.kind === 'image') {
    // 照片放在 files/ 里的情况：也用灯箱看，不走独立的预览区
    applyLayout();
    await openLightbox(entry.id);
    return;

  } else if (entry.kind === 'pdf') {
    setView('pdf-view');
    $('pdf-name').textContent = entry.name;
    await renderPdf(data);

  } else if (entry.kind === 'office-docx') {
    setView('office-view');
    $('office-name').textContent = entry.name;
    await renderDocx(data);

  } else {
    setView('opaque-view');
    $('opaque-name').textContent = entry.name;
    const why = (entry.ext === '.xlsx' || entry.ext === '.xls')
      ? 'Excel 需要计算引擎才能正确显示，手机浏览器做不到。'
      : (entry.ext === '.pptx' || entry.ext === '.ppt')
        ? 'PPT 的排版和动画依赖 PowerPoint 引擎，浏览器无法还原。'
        : '浏览器没有这种格式的渲染器。';
    $('opaque-text').innerHTML =
      why + '<br>它的明文<b>只存在于你此刻的内存里</b>，下载后用本地 App 打开。';
  }
}

// ---------------------------------------------------------------- PDF（pdf.js）
//
// 为什么不用 iframe + blob URL：
//   iOS Safari 对 blob: 里的 PDF 在 iframe 中经常白屏或直接触发下载。
//   pdf.js 把每页画到 canvas，所有浏览器行为一致，还能翻页、缩放。

let pdfjsLib = null;

async function getPdfjs() {
  if (pdfjsLib) return pdfjsLib;
  showLoading('正在加载 PDF 渲染器…');
  const lib = await import('./vendor/pdf.min.mjs');
  // workerSrc 与 standardFontDataUrl 必须显式指定，不能靠 pdf.js 自动推断：
  //   - 它在 Node 里会推断出 "./pdf.worker.mjs"（无 .min）导致加载失败
  //   - 缺标准字体数据时，PDF 里的非嵌入字体会显示成方块
  lib.GlobalWorkerOptions.workerSrc =
    new URL('./vendor/pdf.worker.min.mjs', import.meta.url).href;
  pdfjsLib = lib;
  return lib;
}

async function renderPdf(data) {
  const lib = await getPdfjs();
  // 关键：把解密后的字节直接交给 pdf.js，不经过 blob URL
  const task = lib.getDocument({
    data: data.slice(),
    standardFontDataUrl: new URL('./vendor/standard_fonts/', import.meta.url).href,
    // 允许在不支持离屏 canvas 的环境退回普通渲染
    isOffscreenCanvasSupported: false,
  });
  S.pdf.doc = await task.promise;
  S.pdf.numPages = S.pdf.doc.numPages;
  S.pdf.page = 1;
  S.pdf.scale = fitScale(S.pdf.doc);
  $('pdf-page').textContent = '1 / ' + S.pdf.numPages;
  // 换文档时重置查找状态，并载入该文档的书签
  closeFind();
  $('pdf-marks').hidden = true;
  loadMarks();
  await paintPdf();
}

// 按容器宽度算"刚好放得下"的缩放，手机上体验最好
function fitScale(doc) {
  const stage = $('pdf-stage');
  const avail = Math.max(240, stage.clientWidth - 20);
  const page = doc.getPage(1);
  // 用第一页的 CSS 宽度做基准（避免异步拿 viewport 打乱调用链）
  const base = page.view ? Math.abs(page.view[2] - page.view[0]) : 595;
  if (!base) return 1;
  return Math.min(3, Math.max(0.35, avail / base));
}

async function paintPdf() {
  const doc = S.pdf.doc;
  if (!doc) return;
  const canvas = $('pdf-canvas');
  const ctx = canvas.getContext('2d', { alpha: false });

  try {
    if (S.pdf.task) { try { S.pdf.task.cancel(); } catch (_) {} }
    showLoading('正在渲染第 ' + S.pdf.page + ' 页…');
    const page = await doc.getPage(S.pdf.page);

    // 先按逻辑缩放渲染，再乘设备像素比，保证手机屏幕不发虚
    const baseViewport = page.getViewport({ scale: S.pdf.scale });
    const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
    const viewport = page.getViewport({ scale: S.pdf.scale * dpr });

    canvas.width = Math.max(1, Math.floor(viewport.width));
    canvas.height = Math.max(1, Math.floor(viewport.height));
    canvas.style.width = Math.floor(baseViewport.width) + 'px';
    canvas.style.height = Math.floor(baseViewport.height) + 'px';

    S.pdf.task = page.render({ canvasContext: ctx, viewport });
    await S.pdf.task.promise;
    S.pdf.task = null;

    $('pdf-page').textContent = S.pdf.page + ' / ' + S.pdf.numPages;
    $('pdf-zoom').textContent = Math.round(S.pdf.scale * 100) + '%';
    hideLoading();

    // 页面重绘后，把查找高亮重新贴到新的 canvas 位置上
    if (FIND.pageHits.length) {
      try { await drawHighlights(); } catch (_) { /* 高亮失败不影响阅读 */ }
    }
  } catch (e) {
    if (e && e.name === 'RenderingCancelledException') return;
    hideLoading();
    throw e;
  }
}

async function pdfGo(delta) {
  const next = S.pdf.page + delta;
  if (next < 1 || next > S.pdf.numPages) return;
  S.pdf.page = next;
  await paintPdf();
}

async function pdfZoom(factor) {
  const next = Math.min(4, Math.max(0.35, S.pdf.scale * factor));
  if (Math.abs(next - S.pdf.scale) < 0.01) return;
  S.pdf.scale = next;
  await paintPdf();
}

// ---------------------------------------------------------------- DOCX（mammoth）

let mammothLib = null;

async function getMammoth() {
  if (mammothLib) return mammothLib;
  showLoading('正在加载 Word 解析器…');
  if (!window.mammoth) {
    // mammoth 浏览器版是 UMD，用动态 script 挂全局
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'vendor/mammoth.browser.min.js';
      s.onload = resolve;
      s.onerror = () => reject(new Error('mammoth 加载失败'));
      document.head.appendChild(s);
    });
  }
  mammothLib = window.mammoth;
  return mammothLib;
}

async function renderDocx(data) {
  const body = $('office-body');
  body.innerHTML = '';

  let lib;
  try {
    lib = await getMammoth();
  } catch (e) {
    body.innerHTML = '<p class="doc-note">Word 解析器加载失败，请用下载按钮在本地打开。</p>';
    hideLoading();
    return;
  }

  showLoading('正在解析 Word 文档…');
  try {
    const result = await lib.convertToHtml({ arrayBuffer: data.buffer }, {
      includeDefaultStyleMap: true,
    });
    body.innerHTML = result.value || '<p class="doc-note">（文档是空的）</p>';

    if (result.messages && result.messages.length) {
      const note = document.createElement('p');
      note.className = 'doc-note';
      note.textContent = '提示：文档中有 ' + result.messages.length +
        ' 处复杂排版（分栏、文本框等）无法完整还原，下载后用 Word 打开可看原始效果。';
      body.appendChild(note);
    }
  } catch (e) {
    body.innerHTML = '<p class="doc-note">解析失败：' +
      escapeHtml(String(e && e.message ? e.message : e)) + '</p>';
  }
  hideLoading();
}

// ---------------------------------------------------------------- PDF 查找
//
// pdf.js 只能拿到每页的"文字内容 + 坐标"，没有现成的全文搜索 API，
// 所以流程是：逐页取textContent -> 拼成"每页一个字符串" -> 字符串匹配。
// 拿到页码后跳过去，并把命中位置用坐标画成高亮矩形。
//
// 为什么不用 cMaps：cMaps 是给"提取文本"用的额外字典。我们这里的 PDF
// 本身带文字层（复制能选中的那种），直接 getTextContent 就有结果。
// 扫描件（图片型PDF）提取不到文字，会提示"该文档没有可搜索的文字"。

const FIND = {
  q: '',
  hits: [],        // [{ page, index }] 按页分组
  pageHits: [],    // 扁平数组，方便上/下一个跳
  cur: -1,
  scanned: false,  // 提取不到文字 -> 可能是扫描件
  building: false,
};

async function buildFindIndex() {
  const doc = S.pdf.doc;
  if (!doc) return;
  FIND.pageHits = [];
  FIND.scanned = false;
  FIND.building = true;
  $('pdf-find-count').textContent = '检索中…';

  try {
    for (let p = 1; p <= doc.numPages; p++) {
      const page = await doc.getPage(p);
      const tc = await page.getTextContent();
      const text = tc.items.map((i) => i.str).join('');
      if (!text.trim()) continue;

      // 大小写不敏感匹配，记下每个命中的位置
      const lower = text.toLowerCase();
      const q = FIND.q.toLowerCase();
      let from = 0;
      for (;;) {
        const at = lower.indexOf(q, from);
        if (at < 0) break;
        FIND.pageHits.push({ page: p, index: at, len: q.length });
        from = at + Math.max(1, q.length);
      }
    }
    // 全文一个汉字都没提到-> 大概率是扫描件
    let totalChars = 0;
    for (let p = 1; p <= doc.numPages; p++) {
      const page = await doc.getPage(p);
      const tc = await page.getTextContent();
      totalChars += tc.items.length;
    }
    FIND.scanned = totalChars < 5;
  } catch (e) {
    FIND.scanned = true;
  } finally {
    FIND.building = false;
    updateFindCount();
  }
}

function updateFindCount() {
  const el = $('pdf-find-count');
  if (!el) return;
  if (FIND.building) { el.textContent = '检索中…'; return; }
  if (FIND.scanned) { el.textContent = '该 PDF 没有可搜索的文字（可能是扫描件）'; return; }
  if (!FIND.q) { el.textContent = ''; return; }
  const n = FIND.pageHits.length;
  el.textContent = n ? (FIND.cur + 1) + ' / ' + n : '无结果';
}

async function runFind(q) {
  FIND.q = q.trim();
  FIND.cur = -1;
  if (!FIND.q) {
    FIND.pageHits = [];
    updateFindCount();
    hideHighlights();
    return;
  }
  await buildFindIndex();
  if (FIND.pageHits.length) {
    FIND.cur = 0;
    await gotoFindHit(0);
  } else {
    updateFindCount();
    hideHighlights();
  }
}

async function stepFind(delta) {
  if (!FIND.pageHits.length) return;
  const n = FIND.pageHits.length;
  FIND.cur = (FIND.cur + delta + n) % n;
  await gotoFindHit(FIND.cur);
}

async function gotoFindHit(i) {
  const hit = FIND.pageHits[i];
  if (!hit) return;
  if (S.pdf.page !== hit.page) {
    S.pdf.page = hit.page;
    await paintPdf();
  }
  updateFindCount();
  await drawHighlights();
}

/*
 * 高亮命中位置。
 * pdf.js 给的 item.transform 是 [a,b,c,d,e,f]，e/f 是文字基线坐标。
 * 我们按 item 的宽高估算一个矩形，够用且不精确（字号/行距有误差）。
 */
async function drawHighlights() {
  clearHighlightLayer();
  if (FIND.cur < 0 || !FIND.pageHits.length) return;
  const hit = FIND.pageHits[FIND.cur];
  if (hit.page !== S.pdf.page) return;

  const doc = S.pdf.doc;
  if (!doc) return;
  const page = await doc.getPage(hit.page);
  const tc = await page.getTextContent();

  /*
   * 坐标换算（这块容易写错，务必看清）：
   *   PDF 用户空间：原点左下，y 向上，单位 pt
   *   canvas：原点左上，y 向下
   *   paintPdf 里 canvas.style.height = page.getViewport({scale:S.pdf.scale}).height
   *                      = pdfHeight * s
   *   所以 CSS 像素 = PDF 用户空间 * s
   *
   *   top = (pdfHeight - y - fontH) * s
   *       ↑ PDF 里 y 是基线（从底部算），要翻到顶部坐标系
   *       ↑ 减fontH 让框顶贴住字顶（基线在字底）
   *       ↑ 乘 s 因为 CSS 尺寸是缩放后的
   *
   * 注意：不能用 vp.height 再除以 s —— vp = getViewport({scale:s}) 里
   * vp.height 已经是 pdfHeight * s 了，再除 s 才回到 PDF 空间。
   * 那样写虽然数值接近，但语义混乱、容易在换 scale 时算错。
   */
  const sc = S.pdf.scale || 1;
  const pdfH = page.view ? Math.abs(page.view[3] - page.view[1]) : 842;
  const vp = page.getViewport({ scale: sc });
  const layer = $('pdf-highlight');
  if (!layer) return;
  // 高亮层尺寸对齐 canvas 的显示尺寸
  layer.style.width = vp.width + 'px';
  layer.style.height = vp.height + 'px';

  let cursor = 0;

  for (const item of tc.items) {
    const s = item.str;
    const start = cursor;
    const end = cursor + s.length;
    cursor = end;

    const overlapStart = Math.max(start, hit.index);
    const overlapEnd = Math.min(end, hit.index + hit.len);
    if (overlapStart >= overlapEnd) continue;

    const fracStart = (overlapStart - start) / Math.max(1, s.length);
    const fracEnd = (overlapEnd - start) / Math.max(1, s.length);

    const tr = item.transform;
    // 文字基线坐标（PDF 空间，y 向上）
    const fontH = Math.hypot(tr[2], tr[3]) || 10;
    const x = tr[4];
    const yTop = tr[5] + fontH * 0.75;   // 字顶约在基线上方 0.75em

    // 粗略估算文字宽度：CJK 接近 1em，西文约 0.5em
    const cjk = /[\u3400-\u9fff\u3040-\u30ff\uac00-\ud7af]/.test(s);
    const perChar = cjk ? fontH * 0.95 : fontH * 0.5;
    const itemW = s.length * perChar;

    const box = document.createElement('div');
    box.className = 'pdf-hl';
    box.style.left = ((x + itemW * fracStart) * sc) + 'px';
    box.style.top = ((pdfH - yTop) * sc) + 'px';
    box.style.width = Math.max(4, itemW * (fracEnd - fracStart) * sc) + 'px';
    box.style.height = (fontH * 1.2 * sc) + 'px';
    layer.appendChild(box);
  }
}

function clearHighlightLayer() {
  const layer = $('pdf-highlight');
  if (layer) layer.innerHTML = '';
}

function hideHighlights() {
  clearHighlightLayer();
}

// ---------------------------------------------------------------- PDF 书签
//
// 书签必须持久化，否则关掉页面就没了 —— 用 localStorage。
// key 按文件 id+页码 存，同一个文件在不同电脑/浏览器各自一份。
// 注意：书签只存"哪一页"，不存内容，所以不会泄露文档信息（且本身是明文的，
// 这与"明文不落盘"的原则有冲突，所以 key 里只放文件 id，不放文件名）。

const MARKS = { data: [] };

/*
 * 书签的存储 key。
 *
 * 用 stableId（内容哈希）而不是 enc_id（f0001 这种顺序编号）：
 *   编号会随增删文件而平移，改密码重新加密后全部错位，
 *   旧书签就会指到别的文件上。stableId 是内容哈希，不会变。
 *
 * 回退到 enc_id 是为了兼容旧版本生成的数据（那时没有 stableId）。
 */
function marksKey() {
  const f = S.current;
  const key = (f && (f.stableId || f.id)) || 'unknown';
  return 'pv-marks:' + key;
}

function loadMarks() {
  try {
    const raw = localStorage.getItem(marksKey());
    MARKS.data = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(MARKS.data)) MARKS.data = [];
  } catch (e) {
    MARKS.data = [];
  }
}

function saveMarks() {
  try {
    localStorage.setItem(marksKey(), JSON.stringify(MARKS.data));
  } catch (e) {
    // 隐私模式下 localStorage 会抛错，忽略即可
  }
}

function renderMarks() {
  const list = $('pdf-marks-list');
  list.innerHTML = '';
  const data = MARKS.data.slice().sort((a, b) => a.page - b.page);
  for (const m of data) {
    const li = document.createElement('li');
    li.className = 'marks-item';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'marks-jump';
    btn.textContent = '第 ' + m.page + ' 页';
    if (m.page === S.pdf.page) btn.classList.add('is-current');
    btn.addEventListener('click', async () => {
      S.pdf.page = m.page;
      await paintPdf();
    });

    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'marks-del';
    del.textContent = '×';
    del.title = '删除';
    del.addEventListener('click', () => {
      MARKS.data = MARKS.data.filter((x) => x.page !== m.page);
      saveMarks();
      renderMarks();
    });

    li.append(btn, del);
    list.appendChild(li);
  }
  $('pdf-marks-hint').textContent = data.length
    ? data.length + ' 个书签（本机保存，关掉页面也在）'
    : '还没有书签。翻到想标记的页，点「+ 标记当前页」。';
}

function addMark() {
  const p = S.pdf.page;
  if (MARKS.data.some((m) => m.page === p)) {
    renderMarks();
    return;
  }
  MARKS.data.push({ page: p, at: Date.now() });
  saveMarks();
  renderMarks();
}

function clearMarks() {
  MARKS.data = [];
  saveMarks();
  renderMarks();
}



function mimeOf(entry) {
  const m = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', bmp: 'image/bmp', svg: 'image/svg+xml', avif: 'image/avif',
    heic: 'image/heic', pdf: 'application/pdf',
    txt: 'text/plain', md: 'text/plain', csv: 'text/csv', tsv: 'text/tab-separated-values',
    json: 'application/json', log: 'text/plain', srt: 'text/plain',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  };
  return m[entry.ext.replace('.', '')] || 'application/octet-stream';
}

function download() {
  if (!S.current) return;
  const data = S.cache.get(S.current.id);
  if (!data) return;
  const url = URL.createObjectURL(new Blob([data.slice()], { type: mimeOf(S.current) }));
  const a = document.createElement('a');
  a.href = url;
  a.download = S.current.name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

// ---------------------------------------------------------------- 锁 / 返回

function destroyPdf() {
  if (S.pdf.doc) { try { S.pdf.doc.destroy(); } catch (_) {} }
  S.pdf.doc = null;
  S.pdf.task = null;
  // 清查找与高亮（DOM 可能还没建好，所以逐个判存在）
  FIND.q = '';
  FIND.pageHits = [];
  FIND.cur = -1;
  FIND.building = false;
  const hl = $('pdf-highlight');
  if (hl) hl.innerHTML = '';
  const box = $('pdf-find-input');
  if (box) box.value = '';
}

function lock() {
  S.key = null;
  S.manifest = null;
  S.current = null;
  S.cache.clear();
  revokeUrls();
  hideViewers();
  hideLoading();
  destroyPdf();
  if (S.idleTimer) clearTimeout(S.idleTimer);
  TIMER.hidden = true;
  PWD.value = '';
  VAULT.hidden = true;
  GATE.hidden = false;
  gateMsg('');
  PWD.focus();
}

function backToList() {
  S.current = null;
  hideViewers();
  hideLoading();
  destroyPdf();
  revokeUrls();
  S.cache.clear();
  // 重新渲染列表：可能是从预览状态返回，也可能是切标签时走这条路。
  // renderList() 内部会调 applyLayout()，这里不用重复调。
  renderList();
  $('empty-hint').hidden = false;
}

function resetIdle() {
  if (!REMEMBER.checked) { TIMER.hidden = true; return; }
  if (S.idleTimer) clearTimeout(S.idleTimer);
  const deadline = Date.now() + IDLE_MS;

  S.idleTimer = setTimeout(() => {
    if (Date.now() >= deadline) { lock(); gateMsg('长时间无操作，已自动上锁。', 'warn'); }
  }, IDLE_MS);

  const tick = setInterval(() => {
    const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    TIMER.hidden = false;
    TIMER.textContent = Math.floor(left / 60) + ':' +
      String(left % 60).padStart(2, '0') + ' 后自动上锁';
    if (left <= 0) clearInterval(tick);
  }, 1000);
  setTimeout(() => clearInterval(tick), IDLE_MS + 2000);
}

// ---------------------------------------------------------------- 事件

$('gate-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (S.unlocking) return;
  const pw = PWD.value;
  if (!pw) return;

  S.unlocking = true;
  UNLOCK_BTN.disabled = true;
  UNLOCK_BTN.textContent = '正在派生密钥…';
  gateMsg('');

  try {
    await unlock(pw);
    GATE.hidden = true;
    VAULT.hidden = false;
    renderList();
    applyLayout();
    resetIdle();
    PWD.value = '';
  } catch (err) {
    S.key = null;
    S.manifest = null;
    const txt = String((err && err.name) + ' ' + (err && err.message));
    const wrongPwd = /operation|decrypt|checksum|auth|config/i.test(txt);
    gateMsg(wrongPwd ? '密码不对，或文件已被改动。' : '无法解锁：' + (err.message || err), 'error');
    PWD.select();
  } finally {
    S.unlocking = false;
    UNLOCK_BTN.disabled = false;
    UNLOCK_BTN.textContent = '解锁';
  }
});

LOCK_BTN.addEventListener('click', lock);
FILTER.addEventListener('input', renderList);
WALL_FILTER.addEventListener('input', renderList);
BACK_BTN.addEventListener('click', backToList);
LIST_FAB.addEventListener('click', backToList);

TAB_PHOTOS.addEventListener('click', () => {
  if (S.bucket === 'photos') return;
  S.bucket = 'photos';
  if (S.current) backToList(); else renderList();
});

TAB_FILES.addEventListener('click', () => {
  if (S.bucket === 'files') return;
  S.bucket = 'files';
  if (S.current) backToList(); else renderList();
});

// 照片墙格子点开灯箱，文件行点开预览器 —— 行为不同，分开绑定。
WALL_BODY.addEventListener('click', (e) => {
  const cell = e.target.closest('.wall-cell');
  if (cell) openLightbox(cell.dataset.id);
});

FILES_PANEL.addEventListener('click', (e) => {
  const row = e.target.closest('.file');
  if (row) openEntry(row.dataset.id);
});

// ---- 灯箱交互
$('lb-close').addEventListener('click', closeLightbox);
$('lb-prev').addEventListener('click', () => stepLightbox(-1));
$('lb-next').addEventListener('click', () => stepLightbox(1));

$('lb-dl').addEventListener('click', () => {
  if (!S.current) return;
  const data = S.cache.get(S.current.id);
  if (!data) return;
  const url = URL.createObjectURL(new Blob([data.slice()], { type: mimeOf(S.current) }));
  const a = document.createElement('a');
  a.href = url;
  a.download = S.current.name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
});

$('lb-thumbs').addEventListener('click', (e) => {
  const b = e.target.closest('.lb-thumb');
  if (b) showLightboxAt(Number(b.dataset.idx));
});

// 点图片周围的空白关闭，点图片本身不关
$('lb-stage').addEventListener('click', (e) => {
  if (e.target === $('lb-stage')) closeLightbox();
});

// ---- 灯箱缩放控件
$('lb-zoom-in').addEventListener('click', () => stepZoom(1.25));
$('lb-zoom-out').addEventListener('click', () => stepZoom(1 / 1.25));
$('lb-zoom-reset').addEventListener('click', resetZoom);

// 桌面端滚轮缩放。必须 { passive: false }，否则 preventDefault 无效。
$('lb-stage').addEventListener('wheel', (e) => {
  if (!LB.open) return;
  e.preventDefault();
  const r = $('lb-stage').getBoundingClientRect();
  const ax = e.clientX - r.left;
  const ay = e.clientY - r.top;
  stepZoom(e.deltaY < 0 ? 1.12 : 1 / 1.12, ax, ay);
}, { passive: false });

/*
 * 灯箱手势：分两种情况，不能混。
 *
 *  未放大（zoom == 1）：单指左右滑 = 翻页
 *  已放大（zoom > 1）：单指拖 = 移动图片；双指捏合 = 缩放
 *
 * 之前只有一个 touchstart/touchend，翻页在放大后也会触发——
 * 放大状态下用户想挪一下图片，结果翻到下一张了。
 */
(() => {
  const stage = $('lb-stage');
  // 单指
  let sx = 0, sy = 0, moved = false, baseX = 0, baseY = 0;
  // 双指
  let pinchStartDist = 0, pinchStartZoom = 1, pinchAnchor = null;

  const dist = (t) => Math.hypot(
    t[0].clientX - t[1].clientX,
    t[0].clientY - t[1].clientY
  );
  const mid = (t) => ({
    x: (t[0].clientX + t[1].clientX) / 2,
    y: (t[0].clientY + t[1].clientY) / 2,
  });

  stage.addEventListener('touchstart', (e) => {
    if (!LB.open) return;
    if (e.touches.length === 2) {
      pinchStartDist = dist(e.touches);
      pinchStartZoom = LB.zoom;
      const m = mid(e.touches);
      const r = stage.getBoundingClientRect();
      pinchAnchor = { x: m.x - r.left, y: m.y - r.top };
      moved = true;                       // 双指期间不要触发翻页
    } else if (e.touches.length === 1) {
      const t = e.touches[0];
      sx = t.clientX; sy = t.clientY;
      baseX = LB.panX; baseY = LB.panY;
      moved = false;
    }
  }, { passive: true });

  stage.addEventListener('touchmove', (e) => {
    if (!LB.open) return;

    if (e.touches.length === 2 && pinchStartDist > 0) {
      e.preventDefault();
      const d = dist(e.touches);
      const target = pinchStartZoom * (d / pinchStartDist);
      setZoom(target, pinchAnchor ? pinchAnchor.x : undefined,
                     pinchAnchor ? pinchAnchor.y : undefined);
      return;
    }

    if (e.touches.length === 1 && LB.zoom > 1.01) {
      // 放大状态：单指拖动图片
      e.preventDefault();
      const t = e.touches[0];
      LB.panX = baseX + (t.clientX - sx);
      LB.panY = baseY + (t.clientY - sy);
      applyZoom();
      moved = true;
    }
  }, { passive: false });

  stage.addEventListener('touchend', (e) => {
    if (!LB.open) return;
    if (e.touches.length < 2) pinchStartDist = 0;

    // 放大状态下不翻页
    if (LB.zoom > 1.01) return;
    if (moved) return;

    const t = e.changedTouches[0];
    if (!t) return;
    const dx = t.clientX - sx;
    const dy = t.clientY - sy;
    if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) {
      stepLightbox(dx < 0 ? 1 : -1);
    }
  }, { passive: true });
})();

$('pdf-prev').addEventListener('click', () => pdfGo(-1));
$('pdf-next').addEventListener('click', () => pdfGo(1));
$('pdf-zoom-in').addEventListener('click', () => pdfZoom(1.2));
$('pdf-zoom-out').addEventListener('click', () => pdfZoom(1 / 1.2));

// ---- PDF 查找
const findInput = $('pdf-find-input');
let findTimer = null;
findInput.addEventListener('input', () => {
  clearTimeout(findTimer);
  // 输入停顿 300ms 才检索，避免每敲一个字就全文扫一遍
  findTimer = setTimeout(() => runFind(findInput.value), 300);
});
findInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    clearTimeout(findTimer);
    if (FIND.pageHits.length) stepFind(e.shiftKey ? -1 : 1);
    else runFind(findInput.value);
  } else if (e.key === 'Escape') {
    e.preventDefault();
    closeFind();
  }
});
$('pdf-find-prev').addEventListener('click', () => stepFind(-1));
$('pdf-find-next').addEventListener('click', () => stepFind(1));
$('pdf-find-close').addEventListener('click', closeFind);
$('pdf-find-toggle').addEventListener('click', () => {
  const bar = $('pdf-find');
  bar.hidden = !bar.hidden;
  if (bar.hidden) { closeFind(); } else { findInput.focus(); findInput.select(); }
});

function closeFind() {
  const bar = $('pdf-find');
  if (bar) bar.hidden = true;
  FIND.q = '';
  FIND.pageHits = [];
  FIND.cur = -1;
  const box = $('pdf-find-input');
  if (box) box.value = '';
  const cnt = $('pdf-find-count');
  if (cnt) cnt.textContent = '';
  hideHighlights();
}

// ---- PDF 书签
$('pdf-mark-toggle').addEventListener('click', () => {
  const p = $('pdf-marks');
  p.hidden = !p.hidden;
  if (!p.hidden) renderMarks();
});
$('pdf-mark-close').addEventListener('click', () => { $('pdf-marks').hidden = true; });
$('pdf-mark-add').addEventListener('click', addMark);
$('pdf-mark-clear').addEventListener('click', clearMarks);

// 桌面端滚轮翻页；手机端用工具栏按钮
CONTENT.addEventListener('wheel', (e) => {
  if ($('pdf-view').hidden || !S.pdf.doc) return;
  if (Math.abs(e.deltaY) < 24) return;
  e.preventDefault();
  pdfGo(e.deltaY > 0 ? 1 : -1);
}, { passive: false });

document.addEventListener('keydown', (e) => {
  // 灯箱开着时，键盘优先归灯箱管
  if (LB.open) {
    if (e.key === 'Escape') { e.preventDefault(); closeLightbox(); return; }
    // 缩放快捷键
    if (e.key === '+' || e.key === '=') { e.preventDefault(); stepZoom(1.25); return; }
    if (e.key === '-' || e.key === '_') { e.preventDefault(); stepZoom(1 / 1.25); return; }
    if (e.key === '0') { e.preventDefault(); resetZoom(); return; }

    // 放大后方向键改为平移图片；未放大时才翻页
    if (LB.zoom > 1.01) {
      const step = e.shiftKey ? 80 : 32;
      if (e.key === 'ArrowLeft') { e.preventDefault(); LB.panX += step; applyZoom(); return; }
      if (e.key === 'ArrowRight') { e.preventDefault(); LB.panX -= step; applyZoom(); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); LB.panY += step; applyZoom(); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); LB.panY -= step; applyZoom(); return; }
    } else {
      if (e.key === 'ArrowLeft') { e.preventDefault(); stepLightbox(-1); return; }
      if (e.key === 'ArrowRight') { e.preventDefault(); stepLightbox(1); return; }
    }
    return;
  }

  if (VAULT.hidden) return;
  if (e.key === 'Escape') {
    if (S.current) backToList();
    else if (currentBucket() === 'files') lock();
    // 照片墙是主界面，Esc 不该直接关掉整个网站（容易误触）
    return;
  }

  if (!$('pdf-view').hidden && S.pdf.doc) {
    if (e.key === 'ArrowLeft' || e.key === 'PageUp') pdfGo(-1);
    if (e.key === 'ArrowRight' || e.key === 'PageDown') pdfGo(1);
  }
});

document.addEventListener('click', (e) => {
  if (e.target.closest('[data-act="dl"]')) { download(); return; }
  if (e.target.closest('[data-act="retry"]') && S.current) openEntry(S.current.id);
});

['click', 'keydown', 'touchstart'].forEach((ev) => {
  document.addEventListener(ev, resetIdle, { passive: true });
});

window.addEventListener('resize', () => {
  applyLayout();
  if (S.pdf.doc && !$('pdf-view').hidden) {
    S.pdf.scale = fitScale(S.pdf.doc);
    paintPdf().catch(() => {});
  }
});

window.addEventListener('beforeunload', () => {
  S.key = null;
  S.cache.clear();
  revokeUrls();
});

// ---------------------------------------------------------------- 启动

PWD.focus();
(async () => {
  try {
    const res = await fetch('vault/config.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const cfg = await res.json();
    GATE_META.textContent = cfg.fileCount + ' 个文件 · ' +
      cfg.kdf + ' ' + cfg.iterations.toLocaleString() + ' 轮 · ' + cfg.cipher;
  } catch (e) {
    gateMsg('找不到 vault/config.json —— 保险库还没生成。先运行 tools/encrypt_vault.py。');
    UNLOCK_BTN.disabled = true;
  }
})();
