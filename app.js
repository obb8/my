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

/*
 * ---- 记住密码（仅本次浏览器会话）
 *
 * ★ 为什么用 sessionStorage 而不是 localStorage：
 *   localStorage 会**长期**留在磁盘上，同一台电脑上的任何脚本 / 扩展
 *   / 别人的脚本都能读走。sessionStorage 随标签页/窗口一起销毁，
 *   关掉浏览器就没了 —— 便利性够用，风险小得多。
 *
 * ★ 安全约束（必须都做到，否则这个功能是危险的）：
 *   1. 默认**不勾选** —— 不主动问就不会存
 *   2. 点「上锁」立刻清除 —— 锁了就该忘掉密码
 *   3. 页面隐藏（切走/最小化）不清除，但要能通过"上锁"按钮销毁
 *   4. 存之前先确认密码**真的有效** —— 密码错就别存，
 *      否则下次自动填充一个错的，用户还以为密码坏了
 *   5. 绝不在 URL / 日志 / 错误信息里出现密码
 */
const PW_STORE_KEY = 'vault.pw.session';
const REMEMBER_PW = document.getElementById('remember-pw');
const REMEMBER_STATE = document.getElementById('remember-state');

function readRememberedPw() {
  try {
    return sessionStorage.getItem(PW_STORE_KEY) || '';
  } catch (_) {
    // 隐私模式 / 禁用 storage：安静降级成"没记住"
    return '';
  }
}

function writeRememberedPw(pw) {
  try {
    sessionStorage.setItem(PW_STORE_KEY, pw);
    return true;
  } catch (_) {
    return false;
  }
}

function clearRememberedPw() {
  try {
    sessionStorage.removeItem(PW_STORE_KEY);
  } catch (_) {
    /* 忽略 */
  }
}

function syncRememberUI() {
  if (!REMEMBER_STATE) return;
  const has = !!readRememberedPw();
  REMEMBER_STATE.hidden = !has;
  // 已经记住时把复选框勾上（用户刷新页面仍能解锁）
  if (REMEMBER_PW) REMEMBER_PW.checked = has;
}

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
const WALL_SORT = document.getElementById('wall-sort-sel');
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
  idleTick: null,   // 倒计时的 setInterval（必须和 idleTimer 一起清理，见 resetIdle 注释）
  unlocking: false,
  /*
   * PDF 状态。
   * pages 记录每页的 DOM 与渲染状态 —— 连续滚动模式下，
   * 页面是「按需渲染」的：滚到哪渲染哪，离开远了可以回收。
   */
  pdf: {
    doc: null,
    page: 1,          // 当前视口顶部附近的页码（进度条用）
    scale: 1,
    numPages: 0,
    task: null,
    pages: new Map(), // pageNo -> { wrap, canvas, ctx, rendered, w, h }
    renderedUpTo: 0,  // 已经顺序渲染到第几页
    pending: false,   // 是否有渲染任务在跑（防并发）
  },
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
  dragging: false, // 鼠标/手指是否正按下（用于切grab 光标）
  // 拖动惯性
  velX: 0,
  velY: 0,
  inertiaRaf: 0,
};

// ---------------------------------------------------------------- 缩放

/*
 * 缩放思路：
 *   图片用 CSS transform: translate(...) scale(...)，
 *   不用改 width/height —— 改尺寸会触发重排、放大后卡顿；
 *   transform 走合成层，缩放平移都是 GPU 干的，60fps 很顺。
 *
 *  "适应"是基准：图片刚好塞进 .lb-stage 时的缩放（=1）。
 *
 * ★ 关键：只用 transform，绝不改.stage 的 width/height。
 *   之前同时用了「transform 平移」+「改容器尺寸制造滚动区」，
 *   两套机制互相打架 —— 容器一变，视口跟着跳，缩放就不是原位的；
 *   而且拖动会同时触发容器滚动和 transform，图像会飘。
 *   现在容器恒定，所有位移都靠 transform，锚点才能真正锁死。
 *   平移量按缩放后的溢出量夹逼，所以永远拖不出边界。
 */
function applyZoom() {
  const img = $('lb-img');
  const z = LB.zoom;
  img.style.transform =
    'translate(' + LB.panX + 'px,' + LB.panY + 'px) scale(' + z + ')';
  img.style.transformOrigin = 'center center';
  img.classList.toggle('is-zoomed', z > 1.01);

  // 容器尺寸恒定，只切一个类供 CSS 切光标样式
  const stage = $('lb-stage');
  stage.classList.toggle('is-scrollable', z > 1.01);
  stage.classList.toggle('is-grabbing', LB.dragging);

  // 操作提示只在放大时出现 —— 平时不占地方，也不干扰看图
  const hint = $('lb-hint');
  if (hint) hint.hidden = z <= 1.01;

  $('lb-zoom-reset').textContent = z <= 1.01 ? '适应' : Math.round(z * 100) + '%';
}

/**
 * 算出缩放后图片相对舞台的溢出量，并据此夹逼平移量。
 *
 * 图片的布局尺寸（未缩放时）是 fitW x fitH；缩放 z 倍后超出舞台的部分
 * 才是可以平移的范围。平移量必须夹在这个范围内，否则能拖出黑边。
 */
function clampPan() {
  const stage = $('lb-stage');
  const img = $('lb-img');
  const z = LB.zoom;
  if (z <= 1.01) {
    LB.panX = 0;
    LB.panY = 0;
    return;
  }
  // 图片当前的渲染尺寸（transform 后的视觉大小）
  const w = img.offsetWidth * z;
  const h = img.offsetHeight * z;
  // 最多能平移的距离：超出舞台的那一半
  const maxX = Math.max(0, (w - stage.clientWidth) / 2);
  const maxY = Math.max(0, (h - stage.clientHeight) / 2);
  LB.panX = Math.min(maxX, Math.max(-maxX, LB.panX));
  LB.panY = Math.min(maxY, Math.max(-maxY, LB.panY));
}

function setZoom(z, anchorX, anchorY) {
  const old = LB.zoom;
  const next = Math.min(LB.maxZoom, Math.max(LB.minZoom, z));
  if (Math.abs(next - old) < 0.0001) {
    clampPan();
    applyZoom();
    return;
  }

  const stage = $('lb-stage');
  // 锚点默认取舞台中心（点按钮/键盘缩放时）
  const cx = anchorX === undefined ? stage.clientWidth / 2 : anchorX;
  const cy = anchorY === undefined ? stage.clientHeight / 2 : anchorY;

  if (next <= 1.01) {
    LB.panX = 0;
    LB.panY = 0;
  } else {
    /*
     * ★ 锚点缩放：缩放后，鼠标/手指指向的那个点必须**停在原地不动**。
     *
     * 推导（把图片中心当作原点，u 是内容坐标）：
     *   屏幕位置 S(u) = pan + u * z
     *   锚点 P 处的内容坐标 uA = (P - pan_old) / z_old
     *   要求缩放后 uA 仍在 P：pan_new + uA * z_new = P
     *   =>  pan_new = P - uA * z_new
     *           = P - (P - pan_old) / z_old * z_new
     *           = P - (P - pan_old) * k        （k = z_new / z_old）
     *
     * ⚠️ 别写成 pan*k - (k-1)*(P - center) —— 那个多减了一个中心偏移，
     *   实测偏差 225px。这就是"放大不是原位"的真正原因。
     */
    const k = next / old;
    LB.panX = cx - (cx - LB.panX) * k;
    LB.panY = cy - (cy - LB.panY) * k;
  }
  LB.zoom = next;
  clampPan();
  applyZoom();
}

function stepZoom(factor, anchorX, anchorY) {
  setZoom(LB.zoom * factor, anchorX, anchorY);
}

function resetZoom() {
  // 复位时必须停掉惯性，否则 requestAnimationFrame 会在
  // 图片已卸载（src 被清空）后继续跑，白烧 CPU
  if (LB.inertiaRaf) {
    cancelAnimationFrame(LB.inertiaRaf);
    LB.inertiaRaf = 0;
  }
  LB.velX = 0;
  LB.velY = 0;
  LB.dragging = false;
  LB.zoom = 1;
  LB.panX = 0;
  LB.panY = 0;
  applyZoom();
}

async function openLightbox(id) {
  resetIdle();
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
    // 桌面端：侧栏始终显示，但用户可以手动折叠（阅读长文档时占满宽度更舒服）
    SIDEBAR.classList.remove('is-hidden');
    LIST_FAB.hidden = true;
    BACK_BTN.hidden = true;
    VIEW_TITLE.textContent = 'Private Vault';
  }
}

/*
 * ---- 桌面端侧栏折叠
 *
 * 只在宽屏生效。手机上侧栏本来就会在打开文件时收起，
 * 再加一个折叠按钮反而多余（那里用 LIST_FAB「文件列表」就够了）。
 *
 * 状态记在 localStorage —— 每次刷新都要重新点开太烦。
 */
const SIDEBAR_KEY = 'pv.sidebar.collapsed';

function loadSidebarPref() {
  try {
    return localStorage.getItem(SIDEBAR_KEY) === '1';
  } catch (_) {
    return false;
  }
}

function saveSidebarPref(collapsed) {
  try {
    localStorage.setItem(SIDEBAR_KEY, collapsed ? '1' : '0');
  } catch (_) {
    /* 隐私模式，忽略 */
  }
}

function isSidebarCollapsed() {
  return BODY.classList.contains('sidebar-collapsed');
}

function setSidebarCollapsed(collapsed) {
  BODY.classList.toggle('sidebar-collapsed', !!collapsed);
  saveSidebarPref(!!collapsed);
  // 宽度变了，PDF 的「适应宽度」要重算
  if (S.pdf.doc && !$('pdf-view').hidden) {
    S.pdf.scale = fitScale(S.pdf.doc);
    repaintAllPdfPages();
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

/*
 * 照片墙排序。
 *
 * 6 张照片时排序没什么用，600 张时是刚需 —— 找某张特定时间拍的要靠它。
 * 'group' 保持按子目录分组（默认，符合"整理过"的直觉），
 * 其余模式把整个照片墙当成一个扁平列表按单一关键字排。
 */
function sortPhotos(list, mode) {
  const arr = list.slice();
  const byName = (a, b) => String(a.name).localeCompare(String(b.name), 'zh');
  switch (mode) {
    case 'name':
      arr.sort(byName);
      break;
    case 'new':
      // mtime 是 ISO 字符串，字典序 == 时间序
      arr.sort((a, b) => String(b.mtime).localeCompare(String(a.mtime)));
      break;
    case 'old':
      arr.sort((a, b) => String(a.mtime).localeCompare(String(b.mtime)));
      break;
    case 'big':
      arr.sort((a, b) => (b.size || 0) - (a.size || 0));
      break;
    default:
      return arr;   // group：保持原样
  }
  return arr;
}

function renderPhotoGrid() {
  const mode = ($('wall-sort-sel') || {}).value || 'group';
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

  // 非分组模式下把所有照片并成一个匿名组，实现整体排序
  let pairs = [...groups.entries()];
  if (mode !== 'group') {
    const all = sortPhotos(files, mode);
    pairs = [['', all]];
  } else {
    // 分组内也按名称排，避免同组内顺序随机
    pairs = pairs.map(([k, v]) => [k, sortPhotos(v, 'name')]);
  }

  WALL_BODY.innerHTML = '';
  for (const [name, items] of pairs) {
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
  resetIdle();

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
  // 换文档时载入该文档的书签
  $('pdf-marks').hidden = true;
  loadMarks();
  initPdfSeek();
  // 回到上次读到的那一页（连续滚动下要先建好容器再滚）
  const pos = loadReadPos('pdf');
  await paintPdf();
  if (pos && pos.value > 1 && pos.value <= S.pdf.numPages) {
    scrollToPage(Math.round(pos.value));
  }
}

/*
 * ---- PDF 阅读进度条
 *
 * ★ 为什么用 <input type="range"> 而不是自定义 div：
 *   range 自带键盘操作（←→  Home/End  PageUp/PageDown）、
 *   读屏软件能识别成 slider、触摸拖动也顺滑。
 *   自己画div 得把这三样全手写一遍，还容易漏。
 *
 * 拖动时的处理有个坑：input 会连续触发 input 事件，
 * 每一次都重渲染 canvas 会被拖爆。所以：
 *   -拖动中（isSeeking）只更新气泡数字，不重渲染
 *   - 松手（change）才真正跳页
 */
let isSeeking = false;
let seekRaf = 0;

function initPdfSeek() {
  const seek = $('pdf-seek');
  if (!seek) return;
  seek.max = String(S.pdf.numPages);
  seek.value = String(S.pdf.page);
  seek.disabled = S.pdf.numPages <= 1;
  syncPdfProgressLabel();
  renderMarkFlags();
}

/** 刷新 PDF 进度条左侧的「当前页 / 总页数」标签。 */
function syncPdfProgressLabel() {
  const el = $('pdf-progress-val');
  if (!el) return;
  const n = S.pdf.numPages || 0;
  el.textContent = n ? S.pdf.page + ' / ' + n : '—';
}

/** 刷新 Word 进度条左侧的百分比标签。 */
function syncOfficeProgressLabel() {
  const el = $('office-progress-val');
  if (!el) return;
  el.textContent = Math.round(officeProgress()) + '%';
}

/** 书签在进度条上的小旗标记。 */
function renderMarkFlags() {
  const box = $('pdf-progress-flags');
  if (!box) return;
  const marks = MARKS.data.slice().sort((a, b) => a.page - b.page);
  const n = S.pdf.numPages;
  box.innerHTML = '';
  if (n <= 1) return;
  for (const m of marks) {
    if (!m || typeof m.page !== 'number') continue;
    if (m.page < 1 || m.page > n) continue;
    const flag = document.createElement('button');
    flag.type = 'button';
    flag.className = 'pdf-flag';
    flag.style.left = ((m.page - 1) / (n - 1) * 100) + '%';
    flag.title = '第 ' + m.page + ' 页书签';
    flag.setAttribute('aria-label', '跳到第 ' + m.page + ' 页书签');
    flag.addEventListener('click', (e) => {
      e.stopPropagation();
      pdfGoTo(m.page);
    });
    box.appendChild(flag);
  }
}

/** 跳到指定页（拖动松手、点旗、书签列表都走这里）。 */
async function pdfGoTo(page) {
  const n = S.pdf.numPages;
  const target = Math.min(n, Math.max(1, Math.round(page)));
  if (target === S.pdf.page && S.pdf.pages.has(target)) return;
  scrollToPage(target);
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

/*
 * ================================================================
 *  PDF 连续滚动阅读
 * ================================================================
 *
 * 之前是「一次一页」：单canvas，render() 一次只画一页。
 * 用户要的是**固定的框 + 框内滚动**，所以改成：
 *
 *   .pdf-stage  flex:1 + overflow:auto  -> 高度固定，页面在它内部滚
 *   .pdf-pages  纵向 flex，JS 按需注入每页的 <div class="pdf-page">
 *
 * ★ 为什么必须「按需渲染」而不是一次性全画：
 *   300 页的论文，每页 canvas按 2x DPR 算大约 1200x1700，
 *   一次性全画 = 300 x 8MB = 2.4GB，浏览器直接崩。
 *   现在只渲染视口附近的页面，远处的回收掉。
 *
 * ★ 为什么保留 S.pdf.page 这个「当前页」概念：
 *   进度条、书签、查找跳转都以它为接口，
 *   连续滚动下它的含义变成「视口顶部附近的页码」，
 *   由滚动位置反算。这样上层逻辑不用大改。
 */

/** 视口上下各留几页做预渲染，滚动时不会白屏。 */
const PDF_PRE_AHEAD = 2;
const PDF_PRE_BEHIND = 1;

function pdfPageBox(no) {
  let rec = S.pdf.pages.get(no);
  if (rec) return rec;
  const wrap = document.createElement('div');
  wrap.className = 'pdf-page';
  wrap.dataset.page = String(no);

  const canvas = document.createElement('canvas');
  wrap.appendChild(canvas);

  const label = document.createElement('span');
  label.className = 'pdf-page-no';
  label.textContent = String(no);
  wrap.appendChild(label);

  // 书签旗标（挂在页角，点它跳到该页）
  if (isMarked(no)) {
    const flag = document.createElement('button');
    flag.type = 'button';
    flag.className = 'pdf-page-flag';
    flag.title = '第 ' + no + ' 页 · 有书签';
    flag.setAttribute('aria-label', '跳到第 ' + no + ' 页书签');
    flag.addEventListener('click', () => scrollToPage(no));
    wrap.appendChild(flag);
  }

  const host = $('pdf-pages');
  // 按页号顺序插入（通常就是追加，乱序跳时才需要比较）
  let placed = false;
  for (const child of host.children) {
    if (Number(child.dataset.page) > no) {
      host.insertBefore(wrap, child);
      placed = true;
      break;
    }
  }
  if (!placed) host.appendChild(wrap);

  rec = { wrap, canvas, ctx: canvas.getContext('2d', { alpha: false }),
          rendered: false, w: 0, h: 0 };
  S.pdf.pages.set(no, rec);
  return rec;
}

function isMarked(no) {
  if (!MARKS || !Array.isArray(MARKS.data)) return false;
  return MARKS.data.some((m) => m && m.page === no);
}

/** 渲染指定页到它自己的 canvas。已渲染则跳过。 */
async function renderPdfPage(no) {
  const doc = S.pdf.doc;
  if (!doc) return;
  const rec = pdfPageBox(no);
  if (rec.rendered || rec.rendering) return;
  rec.rendering = true;
  try {
    const page = await doc.getPage(no);
    // 逻辑缩放 × 设备像素比，保证手机屏不发虚
    const baseViewport = page.getViewport({ scale: S.pdf.scale });
    const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
    const viewport = page.getViewport({ scale: S.pdf.scale * dpr });

    rec.canvas.width = Math.max(1, Math.floor(viewport.width));
    rec.canvas.height = Math.max(1, Math.floor(viewport.height));
    rec.canvas.style.width = Math.floor(baseViewport.width) + 'px';
    rec.canvas.style.height = Math.floor(baseViewport.height) + 'px';
    rec.w = Math.floor(baseViewport.width);
    rec.h = Math.floor(baseViewport.height);
    rec.pageObj = page;

    await page.render({ canvasContext: rec.ctx, viewport }).promise;
    rec.rendered = true;
  } catch (e) {
    if (e && e.name === 'RenderingCancelledException') {
      /* 被取消不算失败 */
    } else {
      rec.failed = true;
    }
  } finally {
    rec.rendering = false;
  }
}

/** 丢弃离视口很远的页，省内存。 */
function recycleFarPages(keepFrom, keepTo) {
  const margin = PDF_PRE_AHEAD + 2;
  for (const [no, rec] of S.pdf.pages) {
    if (no >= keepFrom - margin && no <= keepTo + margin) continue;
    rec.wrap.remove();
    S.pdf.pages.delete(no);
  }
}

/**
 * 根据滚动位置算出「当前页」，并渲染/回收附近的页。
 * 这是滚动事件的唯一入口。
 */
let pdfScrollRaf = 0;
function onPdfScroll() {
  if (pdfScrollRaf) return;
  pdfScrollRaf = requestAnimationFrame(() => {
    pdfScrollRaf = 0;
    syncPdfFromScroll();
  });
}

function syncPdfFromScroll() {
  const stage = $('pdf-stage');
  if (!stage || !S.pdf.doc) return;

  // 找到视口顶部最近的那一页
  const top = stage.scrollTop;
  const children = $('pdf-pages').children;
  let current = 1;
  for (const el of children) {
    if (el.offsetTop + el.offsetHeight > top + 1) {
      current = Number(el.dataset.page) || 1;
      break;
    }
    current = Number(el.dataset.page) || current;
  }

  if (current !== S.pdf.page) {
    S.pdf.page = current;
    $('pdf-page').textContent = current + ' / ' + S.pdf.numPages;
    const seek = $('pdf-seek');
    if (seek) seek.value = String(current);
    syncPdfProgressLabel();
    saveReadPos('pdf', current);
  }

  // 渲染视口附近的页
  const from = Math.max(1, current - PDF_PRE_BEHIND);
  const to = Math.min(S.pdf.numPages, current + PDF_PRE_AHEAD);
  for (let p = from; p <= to; p++) {
    if (S.pdf.pages.get(p) && !S.pdf.pages.get(p).rendered) renderPdfPage(p);
  }
  recycleFarPages(from, to);
}

/** 滚到指定页。进度条拖动、书签跳转都走这里。 */
function scrollToPage(no, smooth = false) {
  const stage = $('pdf-stage');
  if (!stage || !S.pdf.doc) return;
  const target = Math.min(S.pdf.numPages, Math.max(1, Math.round(no)));
  const rec = pdfPageBox(target);
  // 先把容器高度撑出来，否则 offsetTop 还是 0
  if (!rec.rendered) renderPdfPage(target);
  // 等 DOM 布局完再滚
  requestAnimationFrame(() => {
    const r2 = S.pdf.pages.get(target);
    const y = r2 ? r2.wrap.offsetTop : 0;
    stage.scrollTo({ top: y, behavior: smooth ? 'smooth' : 'auto' });
    S.pdf.page = target;
    $('pdf-page').textContent = target + ' / ' + S.pdf.numPages;
    const seek = $('pdf-seek');
    if (seek) seek.value = String(target);
    syncPdfProgressLabel();
    saveReadPos('pdf', target);
    syncPdfFromScroll();
  });
}

/** 缩放变化后所有已渲染的页都要重画。 */
async function repaintAllPdfPages() {
  if (!S.pdf.doc) return;
  // 丢掉旧的，重来一遍
  for (const [, rec] of S.pdf.pages) rec.wrap.remove();
  S.pdf.pages.clear();
  const keep = S.pdf.page;
  await renderPdfPage(keep);
  syncPdfFromScroll();
}

/**
 * 兼容旧调用点：paintPdf() 现在只是"同步一次"。
 * 真正的工作在 syncPdfFromScroll() 里按需做。
 */
async function paintPdf() {
  if (!S.pdf.doc) return;
  $('pdf-zoom').textContent = Math.round(S.pdf.scale * 100) + '%';
  const from = Math.max(1, S.pdf.page - PDF_PRE_BEHIND);
  const to = Math.min(S.pdf.numPages, S.pdf.page + PDF_PRE_AHEAD);
  for (let p = from; p <= to; p++) {
    if (!S.pdf.pages.get(p)) pdfPageBox(p);
  }
  for (let p = from; p <= to; p++) await renderPdfPage(p);
  $('pdf-page').textContent = S.pdf.page + ' / ' + S.pdf.numPages;
  hideLoading();
}


async function pdfGo(delta) {
  const next = S.pdf.page + delta;
  if (next < 1 || next > S.pdf.numPages) return;
  // 连续滚动模式下"翻页"= 滚到目标页顶部
  scrollToPage(next);
}

async function pdfZoom(factor) {
  const next = Math.min(4, Math.max(0.35, S.pdf.scale * factor));
  if (Math.abs(next - S.pdf.scale) < 0.01) return;
  S.pdf.scale = next;
  // 缩放后所有已渲染的页都失效，必须全部重画
  await repaintAllPdfPages();
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
  buildOfficeToc([]);

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
    /*
     *★ styleMap 把 Word 的"标题 1/2/3"映射成<h1>/<h2>/<h3>。
     *   不加这个 mammoth 只输出 <p>，几百页文档就完全没有结构，
     *   既没法生成目录，也没法看出章节层次。
     *p:heading[style-name='Heading 1'] => h1:fresh
     *   .. 依此类推
     */
    const result = await lib.convertToHtml({ arrayBuffer: data.buffer }, {
      includeDefaultStyleMap: true,
      styleMap: [
        "p[style-name='Title'] => h1.doc-title:fresh",
        "p[style-name='Heading 1'] => h1:fresh",
        "p[style-name='Heading 2'] => h2:fresh",
        "p[style-name='Heading 3'] => h3:fresh",
        "p[style-name='Heading 4'] => h4:fresh",
        "p[style-name='Heading 5'] => h5:fresh",
        "p[style-name='标题 1'] => h1:fresh",
        "p[style-name='标题 2'] => h2:fresh",
        "p[style-name='标题 3'] => h3:fresh",
      ],
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

  buildOfficeToc(collectHeadings(body));
  // 换文档时载入该文档的 Word 书签
  $('office-marks').hidden = true;
  loadOfficeMarks();
  renderOfficeMarks();
  restoreOfficePos();
  initOfficeSeek();
}

/* ---------------------------------------------------------------- Word 目录 */

/** 从渲染好的 HTML 里抽出标题，生成可点击的目录。 */
function collectHeadings(body) {
  const out = [];
  const nodes = body.querySelectorAll('h1, h2, h3, h4, h5, h6');
  nodes.forEach((el, i) => {
    const text = (el.textContent || '').trim();
    if (!text) return;
    const id = 'sec-' + i;
    el.id = id;
    const level = Number(el.tagName.slice(1)) || 1;
    out.push({ id, text, level });
  });
  return out;
}

function buildOfficeToc(items) {
  const list = $('office-toc-list');
  const panel = $('office-toc');
  const btn = $('office-toc-toggle');
  if (!list) return;

  list.innerHTML = '';
  if (!items.length) {
    // 没标题（纯文字文档）就把目录按钮藏起来，别给一个点不开的面板
    if (btn) btn.hidden = true;
    return;
  }
  if (btn) btn.hidden = false;

  for (const h of items) {
    const a = document.createElement('button');
    a.type = 'button';
    a.className = 'office-toc-item lv' + Math.min(h.level, 4);
    a.textContent = h.text;
    a.title = h.text;
    a.addEventListener('click', () => {
      const el = document.getElementById(h.id);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    list.appendChild(a);
  }
}

/* ---------------------------------------------------------------- Word 进度 */

let officeTicking = false;

function initOfficeSeek() {
  const seek = $('office-seek');
  if (!seek) return;
  seek.value = '0';
  seek.disabled = false;
  officeTicking = false;
  const lab = $('office-progress-val');
  if (lab) lab.textContent = '0%';
}

function officeProgress() {
  const stage = $('office-stage');
  if (!stage) return 0;
  // 可滚动距离为 0（内容不足一屏）时返回 0，避免除零
  const max = stage.scrollHeight - stage.clientHeight;
  if (max <= 0) return 0;
  const p = stage.scrollTop / max;
  return Math.min(100, Math.max(0, p * 100));
}

function syncOfficeSeek() {
  const seek = $('office-seek');
  if (seek) seek.value = String(officeProgress());
  syncOfficeProgressLabel();
}

function restoreOfficePos() {
  const pos = loadReadPos('office');
  const stage = $('office-stage');
  if (!pos || !stage) return;
  // 等布局稳定后再滚，否则 scrollHeight 还是 0
  requestAnimationFrame(() => {
    const max = stage.scrollHeight - stage.clientHeight;
    if (max <= 0) return;
    stage.scrollTop = (pos.value / 100) * max;
    syncOfficeSeek();
  });
}

/* ================================================================
 *  Word 书签
 * ================================================================
 *
 * ★ PDF 书签记「第几页」，Word 没有页码概念
 *   -> 记**滚动百分比**（和saveReadPos 同一套机制）。
 *
 * 记百分比而不是像素/offsetTop：
 *   - 改字号后所有位置都变了，像素坐标全废
 *   - 百分比对缩放/字号都不敏感（只要内容比例不变）
 */

function renderOfficeMarks() {
  const list = $('office-marks-list');
  if (!list) return;
  list.innerHTML = '';
  const data = OFFMARKS.data.slice().sort((a, b) => a.at - b.at);
  const cur = officeProgress();

  for (const m of data) {
    const li = document.createElement('li');
    li.className = 'marks-item';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'marks-jump';
    btn.textContent = Math.round(m.pct) + '%';
    // 当前滚动位置附近的书签高亮
    if (Math.abs(m.pct - cur) < 3) btn.classList.add('is-current');
    btn.addEventListener('click', () => scrollOfficeToPct(m.pct));

    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'marks-del';
    del.textContent = '×';
    del.title = '删除';
    del.addEventListener('click', () => {
      OFFMARKS.data = OFFMARKS.data.filter((x) => x.at !== m.at);
      saveOfficeMarks();
      renderOfficeMarks();
    });

    li.append(btn, del);
    list.appendChild(li);
  }

  const hint = $('office-marks-hint');
  if (hint) {
    hint.textContent = data.length
      ? data.length + ' 个书签（本机保存，关掉页面也在）'
      : '还没有书签。滚到想标记的位置，点「+ 标记当前位置」。';
  }
}

function addOfficeMark() {
  const pct = officeProgress();
  // 同一位置附近不重复加
  if (OFFMARKS.data.some((m) => Math.abs(m.pct - pct) < 2)) {
    renderOfficeMarks();
    return;
  }
  OFFMARKS.data.push({ pct, at: Date.now() });
  saveOfficeMarks();
  renderOfficeMarks();
}

function clearOfficeMarks() {
  OFFMARKS.data = [];
  saveOfficeMarks();
  renderOfficeMarks();
}

function scrollOfficeToPct(pct) {
  const stage = $('office-stage');
  if (!stage) return;
  const max = stage.scrollHeight - stage.clientHeight;
  if (max <= 0) return;
  stage.scrollTo({ top: (pct / 100) * max, behavior: 'smooth' });
}


// ---------------------------------------------------------------- PDF 书签
//
// 书签必须持久化，否则关掉页面就没了 —— 用 localStorage。
// key 按文件 id+页码 存，同一个文件在不同电脑/浏览器各自一份。
// 注意：书签只存"哪一页"，不存内容，所以不会泄露文档信息（且本身是明文的，
// 这与"明文不落盘"的原则有冲突，所以 key 里只放文件 id，不放文件名）。

const MARKS = { data: [] };

/* ---- Word 书签状态 ---- */

// 书签：记滚动百分比（Word 没有页码）
const OFFMARKS = { data: [] };

// Word 书签的 key 策略与 PDF 书签一致（用 stableId）
function officeMarksKey() {
  const f = S.current;
  const key = (f && (f.stableId || f.id)) || 'unknown';
  return 'pv-o-marks:' + key;
}

function loadOfficeMarks() {
  try {
    const raw = localStorage.getItem(officeMarksKey());
    OFFMARKS.data = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(OFFMARKS.data)) OFFMARKS.data = [];
    OFFMARKS.data = OFFMARKS.data.filter(
      (m) => m && typeof m.pct === 'number' && isFinite(m.pct));
  } catch (_) {
    OFFMARKS.data = [];
  }
}

function saveOfficeMarks() {
  try {
    localStorage.setItem(officeMarksKey(), JSON.stringify(OFFMARKS.data));
  } catch (_) {
    /* 隐私模式，忽略 */
  }
}

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

/*
 * ---- 记住读到哪了
 *
 * 和书签一样的 key 策略（用 stableId，改密码或增删其他文件都不会错位）。
 * 存两个东西：
 *   pos:{...}    进度（PDF 是页码，Word 是百分比）
 *   ts   记下时间，用来判断"要不要提示上次读到哪"
 *
 * 只存页码/百分比，不存任何内容 —— 这不是保险库的密钥。
 */
function readPosKey() {
  const f = S.current;
  const key = (f && (f.stableId || f.id)) || 'unknown';
  return 'pv-pos:' + key;
}

function saveReadPos(kind, value) {
  if (!S.current) return;
  try {
    localStorage.setItem(readPosKey(), JSON.stringify({
      kind, value, ts: Date.now(),
    }));
  } catch (_) {
    /* 隐私模式，忽略 */
  }
}

function loadReadPos(kind) {
  if (!S.current) return null;
  try {
    const raw = localStorage.getItem(readPosKey());
    if (!raw) return null;
    const o = JSON.parse(raw);
    if (!o || o.kind !== kind || typeof o.value !== 'number') return null;
    if (!isFinite(o.value)) return null;
    return o;
  } catch (_) {
    return null;
  }
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
      await pdfGoTo(m.page);
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
  // 进度条上的小旗要跟着书签一起更新
  if (typeof renderMarkFlags === 'function') renderMarkFlags();
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
  // 连续滚动模式：清掉所有页的 DOM，否则下次打开会看到旧内容
  S.pdf.pages.clear();
  S.pdf.renderedUpTo = 0;
  const host = $('pdf-pages');
  if (host) host.innerHTML = '';

  $('office-marks').hidden = true;
  OFFMARKS.data = [];
}

function lock(clearPw = true) {
  S.key = null;
  S.manifest = null;
  S.current = null;
  S.cache.clear();
  revokeUrls();
  hideViewers();
  hideLoading();
  destroyPdf();
  if (S.idleTimer) { clearTimeout(S.idleTimer); S.idleTimer = null; }
  // 倒计时的 interval 也要停：上锁后它还会每秒往 TIMER 写一次
  if (S.idleTick) { clearInterval(S.idleTick); S.idleTick = null; }
  TIMER.hidden = true;
  TIMER.classList.remove('is-urgent');
  PWD.value = '';
  VAULT.hidden = true;
  GATE.hidden = false;
  gateMsg('');
  /*
   * ★ 点「上锁」意味着用户想锁上，这时**必须把记住的密码也忘掉**。
   *   否则「上锁」只是换个界面，密码还在浏览器里 —— 形同虚设。
   *   clearPw=false 只用于「刷新后自动解锁」那条路径，
   *   那种情况下不能清。
   */
  if (clearPw) {
    clearRememberedPw();
    if (REMEMBER_PW) REMEMBER_PW.checked = false;
  }
  syncRememberUI();
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

/**
 * 重置空闲倒计时。
 *
 * ⚠️ 这里踩过一个很典型的坑（2026-10-04 修）：
 *   resetIdle 挂在 click / keydown / touchstart 上，调用极其频繁。
 *   原实现每次都新建一个 setInterval，但**从不清理上一个**，
 *   而清理用的 setTimeout 只在 IDLE_MS+2000 之后才跑。
 *   → 每点一次屏幕就多一个 interval 同时往同一个元素写 textContent，
 *     显示的数字会在几个不同 deadline 之间来回跳（肉眼看到"时间在乱跳"），
 *     而且这些 interval 一直跑到 10 分钟后才各自结束。
 *
 * 正确做法：interval 也存进状态，每次 reset 先 clearInterval 再建新的。
 */
function resetIdle() {
  // 无论开关状态如何，先把上一次的 interval 停掉
  if (S.idleTick) { clearInterval(S.idleTick); S.idleTick = null; }
  if (S.idleTimer) { clearTimeout(S.idleTimer); S.idleTimer = null; }

  if (!REMEMBER.checked) { TIMER.hidden = true; return; }
  const deadline = Date.now() + IDLE_MS;

  S.idleTimer = setTimeout(() => {
    S.idleTimer = null;
    if (Date.now() >= deadline) { lock(); gateMsg('长时间无操作，已自动上锁。', 'warn'); }
  }, IDLE_MS);

  // 立即刷新一次，别等 1 秒后才出现
  paintCountdown(deadline);
  S.idleTick = setInterval(() => paintCountdown(deadline), 1000);
}

/** 把「还剩多少秒」画成 mm:ss。到点就隐藏，不留在 0:00。 */
function paintCountdown(deadline) {
  const left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
  if (left <= 0) {
    // 即将上锁（或已经上锁），别显示 "0:00后自动上锁" 卡在那儿
    TIMER.hidden = true;
    TIMER.classList.remove('is-urgent');
    return;
  }
  const mm = Math.floor(left / 60);
  const ss = String(left % 60).padStart(2, '0');
  TIMER.hidden = false;
  // 分钟数可能超过 99（如果以后把 IDLE_MS 调大），别溢出
  TIMER.textContent = mm + ':' + ss + ' 后自动上锁';
  TIMER.title = '距自动上锁还有 ' + mm + ' 分 ' + ss + ' 秒（任意操作都会重置）';
  // 最后一分钟换个颜色，别让人被突然上锁吓到
  TIMER.classList.toggle('is-urgent', left <= 60);
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
    // 恢复侧栏折叠状态（在 renderList 之前，避免布局闪一下）
    if (loadSidebarPref()) BODY.classList.add('sidebar-collapsed');
    // ★ 解锁成功了才考虑记住 —— 密码错的时候绝不能存，
    //   否则下次自动填一个错的，用户会以为密码坏了。
    if (REMEMBER_PW && REMEMBER_PW.checked) {
      if (writeRememberedPw(pw)) {
        syncRememberUI();
      } else {
        // 隐私模式下 storage 不可用，如实告诉用户，别假装记住了
        gateMsg('浏览器不允许存储（可能在隐私模式），本次会话不会记住密码。', 'warn');
      }
    } else {
      clearRememberedPw();
    }
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
// 排序改变时重画照片墙。change 而非 input（下拉框没有连续输入）
if (WALL_SORT) WALL_SORT.addEventListener('change', renderList);
BACK_BTN.addEventListener('click', backToList);
LIST_FAB.addEventListener('click', backToList);

// ---- 桌面端侧栏折叠
if ($('sidebar-toggle')) {
  $('sidebar-toggle').addEventListener('click', () => {
    setSidebarCollapsed(!isSidebarCollapsed());
  });
}

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

/*
 * 点图片周围的空白关闭，点图片本身不关。
 *
 * ★ 用坐标判断而不是 e.target：
 *   图片设了 pointer-events:none（为的是让 dblclick /拖动统一
 *   由 stage 处理，也避免浏览器自带的图片拖拽），所以 e.target
 *   永远是 stage，拿它没法区分点在图上还是图外。
 */
$('lb-stage').addEventListener('click', (e) => {
  const img = $('lb-img');
  const r = img.getBoundingClientRect();
  // 浏览器窗口坐标 -> 图片盒内部
  const inX = e.clientX >= r.left && e.clientX <= r.right;
  const inY = e.clientY >= r.top && e.clientY <= r.bottom;
  // 图片本身的盒子是缩放后的视觉大小（transform 已生效），
  // 所以命中判断自动跟着缩放走。
  if (!inX || !inY) closeLightbox();
});

// ---- 灯箱缩放控件
$('lb-zoom-in').addEventListener('click', () => stepZoom(1.25));
$('lb-zoom-out').addEventListener('click', () => stepZoom(1 / 1.25));
$('lb-zoom-reset').addEventListener('click', resetZoom);

// 桌面端滚轮缩放。必须 { passive: false }，否则 preventDefault 无效。
$('lb-stage').addEventListener('wheel', (e) => {
  if (!LB.open) return;
  e.preventDefault();
  // 横向滚轮 / 带shift 的纵向滚轮 -> 平移；纵向滚轮 -> 缩放
  // （触控板双指横向滑动很自然，不该被当缩放）
  const horiz = Math.abs(e.deltaX) > Math.abs(e.deltaY) || e.shiftKey;
  if (horiz && LB.zoom > 1.01) {
    LB.panX -= (Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY);
    clampPan();
    applyZoom();
    return;
  }
  const r = $('lb-stage').getBoundingClientRect();
  const ax = e.clientX - r.left;
  const ay = e.clientY - r.top;
  stepZoom(e.deltaY < 0 ? 1.12 : 1 / 1.12, ax, ay);
}, { passive: false });

/*
 * 双击 / 双指轻点：在「适应」和「2倍」之间切换，以点击处为锚点。
 * 这是看图最常用的一步——先放大看细节，再退回全景。
 * 用 dblclick 而不是自己计时器：浏览器已经处理了双击的判定，
 * 而且移动端 Safari/Chrome 的 dblclick 在非缩放页面上也可靠。
 */
$('lb-stage').addEventListener('dblclick', (e) => {
  if (!LB.open) return;
  e.preventDefault();
  const r = $('lb-stage').getBoundingClientRect();
  const ax = e.clientX - r.left;
  const ay = e.clientY - r.top;
  if (LB.zoom > 1.01) {
    setZoom(1);                       // 退回全景，平移自动复位
  } else {
    setZoom(2.4, ax, ay);             // 以点击处为锚点放大
  }
});

/*
 * 灯箱手势：分两种情况，不能混。
 *
 *  未放大（zoom == 1）：单指左右滑 = 翻页；单击空白 = 关闭
 *  已放大（zoom > 1）：单指拖 = 移动图片；双指捏合 = 缩放
 *
 * 之前只有一个 touchstart/touchend，翻页在放大后也会触发——
 * 放大状态下用户想挪一下图片，结果翻到下一张了。
 *
 * ★ 拖动补了三样，让手感"灵动"：
 *   1. clampPan()  —— 拖不出边界，不会把图片甩到看不见的地方
 *   2. 惯性        —— 松手后按最后速度滑一小段并渐停
 *   3. 边界回弹    —— 拖过头了松手会弹回来
 */
(() => {
  const stage = $('lb-stage');
  // 单指
  let sx = 0, sy = 0, moved = false, baseX = 0, baseY = 0;
  let lastX = 0, lastY = 0, lastT = 0, vX = 0, vY = 0;
  // 双指
  let pinchStartDist = 0, pinchStartZoom = 1, pinchAnchor = null;
  let inertiaRaf = 0;

  const dist = (t) => Math.hypot(
    t[0].clientX - t[1].clientX,
    t[0].clientY - t[1].clientY
  );
  const mid = (t) => ({
    x: (t[0].clientX + t[1].clientX) / 2,
    y: (t[0].clientY + t[1].clientY) / 2,
  });

  function stopInertia() {
    if (inertiaRaf) {
      cancelAnimationFrame(inertiaRaf);
      inertiaRaf = 0;
    }
    LB.velX = 0;
    LB.velY = 0;
  }

  // 惯性滑动 + 边界回弹。每帧衰减 0.92，超界则用 0.18 拉回。
  function startInertia() {
    stopInertia();
    if (LB.zoom <= 1.01) return;
    const step = () => {
      const still = () => {
        inertiaRaf = 0;
        LB.velX = 0;
        LB.velY = 0;
        LB.dragging = false;
        applyZoom();
      };
      const sp = Math.hypot(LB.velX, LB.velY);
      if (sp < 0.25) { still(); return; }

      const before = { x: LB.panX, y: LB.panY };
      LB.panX += LB.velX;
      LB.panY += LB.velY;
      clampPan();
      // 撞到边界了就把该轴速度清零（另一轴继续滑）
      if (Math.abs(LB.panX - before.x) < Math.abs(LB.velX) * 0.5) LB.velX = 0;
      if (Math.abs(LB.panY - before.y) < Math.abs(LB.velY) * 0.5) LB.velY = 0;
      LB.velX *= 0.92;
      LB.velY *= 0.92;
      applyZoom();
      inertiaRaf = requestAnimationFrame(step);
    };
    LB.dragging = false;
    inertiaRaf = requestAnimationFrame(step);
  }

  stage.addEventListener('touchstart', (e) => {
    if (!LB.open) return;
    stopInertia();
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
      lastX = t.clientX; lastY = t.clientY; lastT = e.timeStamp;
      vX = 0; vY = 0;
      moved = false;
      if (LB.zoom > 1.01) {
        LB.dragging = true;
        applyZoom();
      }
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
      clampPan();
      // 记速度（每 100ms 算一次，太密的样本噪声大）
      const dt = e.timeStamp - lastT;
      if (dt > 0) {
        const nvX = (t.clientX - lastX) / dt * 16;
        const nvY = (t.clientY - lastY) / dt * 16;
        // 平滑一下，避免手指抖动导致速度跳变
        vX = vX * 0.5 + nvX * 0.5;
        vY = vY * 0.5 + nvY * 0.5;
        lastX = t.clientX; lastY = t.clientY; lastT = e.timeStamp;
      }
      LB.velX = vX; LB.velY = vY;
      applyZoom();
      moved = true;
    }
  }, { passive: false });

  stage.addEventListener('touchend', (e) => {
    if (!LB.open) return;
    if (e.touches.length < 2) pinchStartDist = 0;

    // 放大状态下：松手给惯性，不翻页
    if (LB.zoom > 1.01) {
      LB.dragging = false;
      if (moved) startInertia();
      else applyZoom();
      return;
    }
    if (moved) return;

    const t = e.changedTouches[0];
    if (!t) return;
    const dx = t.clientX - sx;
    const dy = t.clientY - sy;
    if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) {
      stepLightbox(dx < 0 ? 1 : -1);
    }
  }, { passive: true });

  // ---- 桌面端：鼠标拖动
  let mDown = false, mStartX = 0, mStartY = 0, mBaseX = 0, mBaseY = 0;
  let mLastX = 0, mLastY = 0, mLastT = 0, mVX = 0, mVY = 0, mMoved = false;

  stage.addEventListener('mousedown', (e) => {
    if (!LB.open || LB.zoom <= 1.01 || e.button !== 0) return;
    stopInertia();
    mDown = true;
    mMoved = false;
    mStartX = e.clientX; mStartY = e.clientY;
    mBaseX = LB.panX; mBaseY = LB.panY;
    mLastX = e.clientX; mLastY = e.clientY; mLastT = performance.now();
    mVX = 0; mVY = 0;
    LB.dragging = true;
    applyZoom();
  });

  window.addEventListener('mousemove', (e) => {
    if (!mDown) return;
    e.preventDefault();
    LB.panX = mBaseX + (e.clientX - mStartX);
    LB.panY = mBaseY + (e.clientY - mStartY);
    clampPan();
    const now = performance.now();
    const dt = now - mLastT;
    if (dt > 0) {
      mVX = mVX * 0.5 + ((e.clientX - mLastX) / dt * 16) * 0.5;
      mVY = mVY * 0.5 + ((e.clientY - mLastY) / dt * 16) * 0.5;
      mLastX = e.clientX; mLastY = e.clientY; mLastT = now;
    }
    LB.velX = mVX; LB.velY = mVY;
    mMoved = true;
    applyZoom();
  });

  window.addEventListener('mouseup', () => {
    if (!mDown) return;
    mDown = false;
    LB.dragging = false;
    if (mMoved) startInertia();
    else applyZoom();
  });
})();

// 连续滚动：滚动时同步当前页 + 按需渲染
$('pdf-stage').addEventListener('scroll', onPdfScroll, { passive: true });
// 窗口尺寸变化会改变"适应宽度"的缩放，需要重画
let pdfResizeTimer = 0;
window.addEventListener('resize', () => {
  if (!S.pdf.doc) return;
  clearTimeout(pdfResizeTimer);
  pdfResizeTimer = setTimeout(() => {
    S.pdf.scale = fitScale(S.pdf.doc);
    repaintAllPdfPages();
  }, 250);
});

$('pdf-prev').addEventListener('click', () => pdfGo(-1));
$('pdf-next').addEventListener('click', () => pdfGo(1));
$('pdf-zoom-in').addEventListener('click', () => pdfZoom(1.2));
$('pdf-zoom-out').addEventListener('click', () => pdfZoom(1 / 1.2));

// ---- PDF 进度条拖拽
//
// ★ 拖动时**不重渲染**，松手才跳页。
//   input 事件在拖动中会连续触发（每像素一次），
//   每次都 await paintPdf()（canvas 逐页重绘）会把主线程卡死。
//   现在拖动中只记下目标页，松手（change）才执行。
$('pdf-seek').addEventListener('input', (e) => {
  isSeeking = true;
  const n = Number(e.target.value) || 1;
  $('pdf-page').textContent = n + ' / ' + S.pdf.numPages;
  // 拖动中同步底部进度条的页码标签（不触发跳转，避免 canvas 重渲染）
  const lab = $('pdf-progress-val');
  if (lab) lab.textContent = n + ' / ' + S.pdf.numPages;
  if (seekRaf) cancelAnimationFrame(seekRaf);
  seekRaf = requestAnimationFrame(() => { seekRaf = 0; });
});
$('pdf-seek').addEventListener('change', async (e) => {
  isSeeking = false;
  const n = Number(e.target.value) || 1;
  await pdfGoTo(n);
});
// 点进度条（range 自带 click-to-seek），但要阻止拖动结束时误触发
$('pdf-seek').addEventListener('pointerdown', () => { isSeeking = true; });
window.addEventListener('pointerup', () => { isSeeking = false; });

// ---- Word 目录面板
$('office-toc-toggle').addEventListener('click', () => {
  const panel = $('office-toc');
  const open = panel.hidden;
  panel.hidden = !open;
  $('office-toc-toggle').setAttribute('aria-expanded', String(open));
});
$('office-toc-close').addEventListener('click', () => {
  $('office-toc').hidden = true;
  $('office-toc-toggle').setAttribute('aria-expanded', 'false');
});

// ---- Word 字号
const OFFICE_FONT_MIN = 12;
const OFFICE_FONT_MAX = 26;
const OFFICE_FONT_DEFAULT = 16;
function officeFontStep(delta) {
  const body = $('office-body');
  if (!body) return;
  const cur = parseFloat(body.style.fontSize)
           || parseFloat(getComputedStyle(body).fontSize)
           || OFFICE_FONT_DEFAULT;
  const next = Math.min(OFFICE_FONT_MAX, Math.max(OFFICE_FONT_MIN, cur + delta));
  body.style.fontSize = next + 'px';
  syncOfficeSeek();
}
$('office-font-up').addEventListener('click', () => officeFontStep(1));
$('office-font-down').addEventListener('click', () => officeFontStep(-1));

// ---- Word 滚动进度联动
$('office-stage').addEventListener('scroll', () => {
  if (officeTicking) return;         // rAF 节流：滚动事件很密集
  officeTicking = true;
  requestAnimationFrame(() => {
    officeTicking = false;
    syncOfficeSeek();
  });
}, { passive: true });

// 滚动停止后再记位置（滚动中不停写 localStorage 是浪费）
let officeSaveTimer = 0;
$('office-stage').addEventListener('scroll', () => {
  clearTimeout(officeSaveTimer);
  officeSaveTimer = setTimeout(() => {
    saveReadPos('office', officeProgress());
  }, 400);
}, { passive: true });

// ---- Word 进度条拖拽
$('office-seek').addEventListener('input', (e) => {
  const stage = $('office-stage');
  if (!stage) return;
  const p = Math.min(100, Math.max(0, Number(e.target.value) || 0));
  // 拖动时立刻更新标签，让用户看到当前位置（不必等滚动事件）
  const lab = $('office-progress-val');
  if (lab) lab.textContent = Math.round(p) + '%';
  const max = stage.scrollHeight - stage.clientHeight;
  if (max > 0) stage.scrollTop = (p / 100) * max;
});

// ---- Word 书签
$('office-mark-toggle').addEventListener('click', () => {
  const p = $('office-marks');
  p.hidden = !p.hidden;
  if (!p.hidden) renderOfficeMarks();
});
$('office-mark-close').addEventListener('click', () => { $('office-marks').hidden = true; });
$('office-mark-add').addEventListener('click', addOfficeMark);
$('office-mark-clear').addEventListener('click', clearOfficeMarks);

// ---- 记住上次读到的位置：离开文档时保存

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
      if (e.key === 'ArrowLeft') { e.preventDefault(); LB.panX += step; clampPan(); applyZoom(); return; }
      if (e.key === 'ArrowRight') { e.preventDefault(); LB.panX -= step; clampPan(); applyZoom(); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); LB.panY += step; clampPan(); applyZoom(); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); LB.panY -= step; clampPan(); applyZoom(); return; }
    } else {
      if (e.key === 'ArrowLeft') { e.preventDefault(); stepLightbox(-1); return; }
      if (e.key === 'ArrowRight') { e.preventDefault(); stepLightbox(1); return; }
    }
    return;
  }

  if (VAULT.hidden) return;

  /*
   * 注：这里**故意不拦Ctrl+F**。
   * 自建查找已删除，但浏览器/系统自带的查找（Ctrl+F）还能用 ——
   * 对 PDF 无效（文字在canvas 里），但对 Word 和文本预览有效。
   * 不 preventDefault 就是把它留给浏览器。
   */

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

/*
 * ---- 会话内自动解锁
 *
 * 如果 sessionStorage 里有记住的密码（用户勾过"记住"），打开页面就自动解锁。
 * 失败（密码变了 / vault 被重新加密过）就静默退回密码框，
 * 并把记住的密码清掉 —— 不然每次打开都要试一次错密码，很烦。
 */
(async () => {
  syncRememberUI();
  const saved = readRememberedPw();
  if (!saved) {
    PWD.focus();
    return;
  }
  PWD.value = saved;
  UNLOCK_BTN.disabled = true;
  UNLOCK_BTN.textContent = '正在解锁…';
  try {
    await unlock(saved);
    // 不走 submit 处理器：这里已经解锁成功了
    if (loadSidebarPref()) BODY.classList.add('sidebar-collapsed');
    GATE.hidden = true;
    VAULT.hidden = false;
    renderList();
    applyLayout();
    resetIdle();
    PWD.value = '';
    UNLOCK_BTN.textContent = '解锁';
    UNLOCK_BTN.disabled = false;
  } catch (e) {
    // 密码失效（改了密码或重新加密过）：清掉，退回手动输入
    clearRememberedPw();
    syncRememberUI();
    PWD.value = '';
    PWD.focus();
    UNLOCK_BTN.textContent = '解锁';
    UNLOCK_BTN.disabled = false;
    gateMsg('记住的密码已失效，请重新输入。', 'warn');
  }
})();

// 「本会话保持解锁」开关：切换后倒计时必须立刻跟着变
// （勾上 → 立刻开始 10:00；取消 → 立刻隐藏，不是等下一次点击才生效）
if (REMEMBER) {
  REMEMBER.addEventListener('change', () => {
    resetIdle();
  });
}

// 勾选状态变化时给即时反馈：取消勾选就立刻清掉已存的
if (REMEMBER_PW) {
  REMEMBER_PW.addEventListener('change', () => {
    if (!REMEMBER_PW.checked) {
      clearRememberedPw();
      syncRememberUI();
    }
  });
}
