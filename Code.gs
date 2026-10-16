/**
 * Kisan Enterprises Central Business Portal  —  Code.gs
 *
 * Pure Google Apps Script. All persistent data lives in Script Properties
 * (PropertiesService). No Google Sheets, no external database.
 *
 * SECURITY MODEL (read this once):
 *  - Every top-level function WITHOUT a trailing underscore can be called from
 *    any browser via google.script.run. Therefore the only public entry points
 *    are the api* functions below, and every internal helper ends with "_".
 *  - Public API: apiGetPublicData, apiGetQrData, apiSetupStatus, apiSetup, apiLogin.
 *  - Admin API: apiAdmin(token, action, payload). The session token is validated
 *    on EVERY call before anything else happens.
 *  - Editor-only functions (initializePortal, resetAdminAccess, benchmarkHashing)
 *    refuse to run unless the caller is the signed-in project owner.
 */

/* ============================== CONFIG ============================== */

const PORTAL = {
  DEFAULT_ADMIN_EMAIL: 'mis@kisanenterprises.in',
  SCHEMA: 1,
  // PBKDF2-HMAC-SHA256 implemented on top of Utilities.computeHmacSha256Signature.
  // Apps Script has no native PBKDF2, and each HMAC call is slow, so this is far
  // below desktop recommendations. Run benchmarkHashing() to tune BEFORE setup.
  // The iteration count is stored with the hash, so changing this later only
  // affects newly created passwords.
  PBKDF2_ITERATIONS: 5000,
  SESSION_IDLE_MS: 30 * 60 * 1000,        // 30 min of inactivity
  SESSION_MAX_MS: 8 * 60 * 60 * 1000,     // 8 h absolute
  MAX_SESSIONS: 5,
  SETUP_TTL_MS: 30 * 60 * 1000,           // setup code valid for 30 min
  SETUP_MAX_TRIES: 5,
  MAX_APPS: 150,
  MAX_CATS: 30,
  MAX_LOG: 150,
  LOG_CHUNKS: 4,
  LOG_CHUNK_CHARS: 7500,
  MAX_VALUE_BYTES: 8800,                  // platform limit is ~9 KB per value
  TOTAL_LIMIT_BYTES: 500 * 1024,          // platform limit is ~500 KB per store
  SOFT_LIMIT_BYTES: 440 * 1024,           // normal writes refused above this
  HARD_LIMIT_BYTES: 485 * 1024,           // security writes (session/log) allowed up to this
  CACHE_KEY: 'kb.public.v1',
  CACHE_TTL_S: 120
};

const K = {
  META: 'kb.meta', AUTH: 'kb.auth', SETUP: 'kb.setup', SESS: 'kb.sess', THR: 'kb.thr',
  SET: 'kb.settings', CATS: 'kb.cats', IDX: 'kb.appIdx', APP: 'kb.app.', LOG: 'kb.log.'
};

class AppError extends Error {
  constructor(code, message) { super(message); this.code = code; this.isApp = true; }
}
function bad_(msg) { return new AppError('INVALID', msg); }

/* ============================== WEB APP ENTRY ============================== */

function doGet(e) {
  const view = (e && e.parameter && e.parameter.page === 'admin') ? 'admin' : 'public';
  let title = 'Kisan Enterprises Central Business Portal';
  try {
    const s = parse_(PropertiesService.getScriptProperties().getProperty(K.SET));
    if (s && s.portalName) title = String(s.portalName);
  } catch (err) { /* keep default */ }
  const t = HtmlService.createTemplateFromFile('Index');
  t.bootView = view;
  return t.evaluate()
    .setTitle(title)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/* ============================== EDITOR-ONLY FUNCTIONS ============================== */

/** Run once from the Apps Script editor. Safe to re-run. */
function initializePortal() {
  assertEditorRun_();
  withLock_(function () {
    const all = readAll_();
    const sets = {};
    if (!all[K.META]) sets[K.META] = JSON.stringify({ schema: PORTAL.SCHEMA, createdAt: Date.now() });
    if (!all[K.SET]) sets[K.SET] = JSON.stringify(defaultSettings_());
    if (!all[K.CATS]) sets[K.CATS] = JSON.stringify(defaultCategories_());
    if (!all[K.IDX]) sets[K.IDX] = '[]';
    if (Object.keys(sets).length) commit_(sets, [], true);
  });
  const all = readAll_();
  if (all[K.AUTH]) {
    Logger.log('Portal data is initialised and the administrator is already configured.\n' +
      'If you lost the password, run resetAdminAccess() to issue a new one-time setup code.');
    return;
  }
  const code = issueSetupCode_();
  Logger.log('==============================================================');
  Logger.log(' ONE-TIME ADMIN SETUP CODE:  ' + code);
  Logger.log(' Valid for ' + (PORTAL.SETUP_TTL_MS / 60000) + ' minutes, single use.');
  Logger.log(' Open the web app, choose Admin Sign In > First-time setup, and enter');
  Logger.log(' the administrator email (' + PORTAL.DEFAULT_ADMIN_EMAIL + '), this code, and a new password.');
  Logger.log(' Re-run initializePortal() for a fresh code if this one expires.');
  Logger.log('==============================================================');
}

/** Editor-only. Removes the admin credential + sessions and issues a new setup code. */
function resetAdminAccess() {
  assertEditorRun_();
  initializePortalDataOnly_();
  withLock_(function () {
    commit_({}, [K.AUTH, K.SESS, K.THR, K.SETUP], true);
    logEvent_('ADMIN_RESET', 'Administrator', 'Credential removed from the Apps Script editor; setup code issued');
  });
  const code = issueSetupCode_();
  Logger.log('ONE-TIME ADMIN SETUP CODE:  ' + code + '   (valid ' + (PORTAL.SETUP_TTL_MS / 60000) + ' minutes, single use)');
}

/** Editor-only. Measures hashing speed so you can choose PBKDF2_ITERATIONS. */
function benchmarkHashing() {
  assertEditorRun_();
  const n = 300;
  const t0 = Date.now();
  pbkdf2Sha256_('benchmark-password', randomHex_(16), n);
  const per = (Date.now() - t0) / n;
  Logger.log('~' + per.toFixed(2) + ' ms per iteration.');
  [2000, 5000, 10000, 20000].forEach(function (it) {
    Logger.log(it + ' iterations  ->  about ' + (per * it / 1000).toFixed(1) + ' seconds per password check');
  });
  Logger.log('Pick a value that keeps a login under ~3-5 seconds, then edit PORTAL.PBKDF2_ITERATIONS before first-time setup.');
}

function initializePortalDataOnly_() {
  withLock_(function () {
    const all = readAll_();
    const sets = {};
    if (!all[K.META]) sets[K.META] = JSON.stringify({ schema: PORTAL.SCHEMA, createdAt: Date.now() });
    if (!all[K.SET]) sets[K.SET] = JSON.stringify(defaultSettings_());
    if (!all[K.CATS]) sets[K.CATS] = JSON.stringify(defaultCategories_());
    if (!all[K.IDX]) sets[K.IDX] = '[]';
    if (Object.keys(sets).length) commit_(sets, [], true);
  });
}

function assertEditorRun_() {
  let a = '', e = '';
  try { a = Session.getActiveUser().getEmail(); e = Session.getEffectiveUser().getEmail(); } catch (err) { /* ignore */ }
  if (!a || !e || a !== e) {
    throw new Error('This function can only be run from the Apps Script editor by the project owner.');
  }
}

/* ============================== PUBLIC API ============================== */

function apiGetPublicData() {
  return safe_(function () {
    const cache = CacheService.getScriptCache();
    const hit = cache.get(PORTAL.CACHE_KEY);
    if (hit) { try { return JSON.parse(hit); } catch (e) { /* rebuild */ } }
    const payload = buildPublicPayload_();
    const s = JSON.stringify(payload);
    if (s.length < 90000) { try { cache.put(PORTAL.CACHE_KEY, s, PORTAL.CACHE_TTL_S); } catch (e) { /* ignore */ } }
    return payload;
  });
}

/** Fresh, authoritative URL for the QR modal (active + QR-enabled apps only). */
function apiGetQrData(appId) {
  return safe_(function () {
    const id = String(appId || '');
    if (!/^[a-z0-9]{6,16}$/.test(id)) throw bad_('Invalid application.');
    const app = loadApps_(readAll_()).list.filter(function (a) { return a.id === id; })[0];
    if (!app || !app.active || !app.qr) throw new AppError('NOT_FOUND', 'No QR code is available for this application.');
    return { id: app.id, name: app.name, url: normalizeUrl_(app.url) };
  });
}

function apiSetupStatus() {
  return safe_(function () {
    const all = readAll_();
    const st = parse_(all[K.SETUP]);
    return {
      configured: !!all[K.AUTH],
      setupReady: !all[K.AUTH] && !!st && Date.now() < st.exp && st.tries < PORTAL.SETUP_MAX_TRIES
    };
  });
}

function apiSetup(email, code, password) {
  return safe_(function () {
    const all = readAll_();
    if (all[K.AUTH]) throw new AppError('CONFIGURED', 'The administrator account is already set up.');
    const st = parse_(all[K.SETUP]);
    if (!st || Date.now() > st.exp || st.tries >= PORTAL.SETUP_MAX_TRIES) {
      throw new AppError('NO_SETUP', 'No active setup code. Run initializePortal() in the Apps Script editor to generate a new one.');
    }
    const emailOk = safeEqual_(normEmail_(email), PORTAL.DEFAULT_ADMIN_EMAIL);
    const codeOk = safeEqual_(sha256Hex_(st.s + normCode_(code)), st.h);
    if (!(emailOk && codeOk)) {
      withLock_(function () {
        const cur = parse_(readAll_()[K.SETUP]);
        if (cur) { cur.tries = (cur.tries || 0) + 1; commit_(sub_(K.SETUP, cur), [], true); }
        logEvent_('SETUP_FAIL', 'Administrator', 'Incorrect email or setup code');
      });
      Utilities.sleep(800);
      throw new AppError('BAD_SETUP', 'The email or setup code is incorrect.');
    }
    checkPasswordPolicy_(password);
    const auth = createAuth_(password, PORTAL.DEFAULT_ADMIN_EMAIL);
    withLock_(function () {
      if (readAll_()[K.AUTH]) throw new AppError('CONFIGURED', 'The administrator account is already set up.');
      commit_(sub_(K.AUTH, auth), [K.SETUP, K.SESS, K.THR], true);
      logEvent_('ADMIN_SETUP', 'Administrator', 'Administrator account created');
    });
    return { done: true };
  });
}

function apiLogin(email, password) {
  return safe_(function () {
    const now = Date.now();
    ensureNotLocked_();
    const auth = parse_(PropertiesService.getScriptProperties().getProperty(K.AUTH));
    if (!auth) throw new AppError('NOT_CONFIGURED', 'The administrator account has not been set up yet.');
    const pw = (typeof password === 'string') ? password.slice(0, 256) : '';
    const pwOk = checkPassword_(auth, pw);
    const emailOk = safeEqual_(normEmail_(email), auth.email);
    if (pwOk && emailOk) {
      const token = withLock_(function () {
        commit_({}, [K.THR], true);
        const t = createSession_();
        logEvent_('LOGIN_OK', 'Administrator', 'Signed in');
        return t;
      });
      return { token: token, email: auth.email, idleMs: PORTAL.SESSION_IDLE_MS };
    }
    withLock_(function () { registerFailure_('LOGIN_FAIL', 'Failed sign-in attempt'); });
    Utilities.sleep(700);
    throw new AppError('BAD_LOGIN', 'Invalid email or password.');
  });
}

/* ============================== ADMIN API ============================== */

const ADMIN_ACTIONS_ = {
  ping: adminPing_, logout: adminLogout_, dashboard: adminDashboard_,
  listApps: adminListApps_, saveApp: adminSaveApp_, deleteApp: adminDeleteApp_,
  toggleApp: adminToggleApp_, reorderApps: adminReorderApps_, qrData: adminQrData_, checkUrl: adminCheckUrl_,
  listCategories: adminListCategories_, saveCategory: adminSaveCategory_,
  deleteCategory: adminDeleteCategory_, reorderCategories: adminReorderCategories_,
  getSettings: adminGetSettings_, saveSettings: adminSaveSettings_, resetDisplay: adminResetDisplay_,
  changePassword: adminChangePassword_, listLog: adminListLog_
};

function apiAdmin(token, action, payload) {
  return safe_(function () {
    const sid = validateSession_(token);                       // 1. validate session
    if (typeof action !== 'string' || !Object.prototype.hasOwnProperty.call(ADMIN_ACTIONS_, action)) {
      throw new AppError('BAD_ACTION', 'Unknown action.');
    }
    const p = (payload && typeof payload === 'object' && !Array.isArray(payload)) ? payload : {};
    return ADMIN_ACTIONS_[action](p, sid);                     // 2. handlers validate params, act, log
  });
}

function adminPing_(p, sid) {
  const auth = parse_(readAll_()[K.AUTH]);
  return { email: auth ? auth.email : '', idleMs: PORTAL.SESSION_IDLE_MS };
}

function adminLogout_(p, sid) {
  withLock_(function () {
    const sess = parse_(readAll_()[K.SESS]) || {};
    delete sess[sid];
    commit_(sub_(K.SESS, sess), [], true);
    logEvent_('LOGOUT', 'Administrator', 'Signed out');
  });
  return { done: true };
}

/* ---------- Dashboard ---------- */

function adminDashboard_() {
  const all = readAll_();
  const ld = loadApps_(all);
  const cats = readCats_(all);
  const catName = {}; cats.forEach(function (c) { catName[c.id] = c.name; });
  const active = ld.list.filter(function (a) { return a.active; }).length;
  const recent = ld.list.slice().sort(function (a, b) { return b.updatedAt - a.updatedAt; }).slice(0, 5)
    .map(function (a) { return { id: a.id, name: a.name, active: a.active, category: catName[a.cat] || 'Unassigned', updatedAt: a.updatedAt }; });
  return {
    total: ld.list.length, active: active, inactive: ld.list.length - active,
    categories: cats.length, recent: recent, corrupted: ld.corrupted,
    storage: storageStats_(all), maxApps: PORTAL.MAX_APPS
  };
}

function storageStats_(all) {
  let used = 0;
  Object.keys(all).forEach(function (k) { used += bytes_(k) + bytes_(all[k]); });
  return { usedBytes: used, limitBytes: PORTAL.TOTAL_LIMIT_BYTES, softLimitBytes: PORTAL.SOFT_LIMIT_BYTES };
}

/* ---------- Applications ---------- */

function adminListApps_() {
  const all = readAll_();
  const ld = loadApps_(all);
  const s = readSettings_(all);
  return { apps: ld.list, categories: readCats_(all), maxApps: PORTAL.MAX_APPS, qrForNew: !!s.qr.enableForNew, defaultCategory: s.defaultCategory, corrupted: ld.corrupted };
}

function adminSaveApp_(p) {
  return withLock_(function () {
    const all = readAll_();
    const cats = readCats_(all);
    const ld = loadApps_(all);
    const isNew = !p.id;
    let existing = null;
    if (!isNew) {
      existing = ld.list.filter(function (a) { return a.id === String(p.id); })[0];
      if (!existing) throw new AppError('NOT_FOUND', 'Application not found (it may have been deleted).');
    } else if (ld.list.length >= PORTAL.MAX_APPS) {
      throw new AppError('CAPACITY', 'Maximum of ' + PORTAL.MAX_APPS + ' applications reached. Delete an unused application first.');
    }
    const v = validateApp_(p, cats);
    const urlKey = urlKey_(v.url);
    ld.list.forEach(function (a) {
      if (existing && a.id === existing.id) return;
      if (a.name.toLowerCase() === v.name.toLowerCase()) throw bad_('Another application is already named "' + a.name + '".');
      if (urlKey_(a.url) === urlKey) throw bad_('Another application ("' + a.name + '") already uses this URL.');
    });
    const now = Date.now();
    const rec = {
      id: existing ? existing.id : newId_(all),
      name: v.name, url: v.url, desc: v.desc, cat: v.cat, icon: v.icon, label: v.label,
      active: v.active, qr: v.qr, notes: v.notes,
      createdAt: existing ? existing.createdAt : now, updatedAt: now
    };
    const ids = ld.ids.filter(function (id) { return id !== rec.id; });
    let pos;
    if (p.order === undefined || p.order === null || p.order === '') pos = existing ? Math.min(ld.ids.indexOf(rec.id), ids.length) : ids.length;
    else {
      const n = parseInt(p.order, 10);
      if (isNaN(n) || n < 1) throw bad_('Display order must be a whole number of 1 or more.');
      pos = Math.min(n - 1, ids.length);
    }
    ids.splice(pos, 0, rec.id);
    const sets = {}; sets[K.APP + rec.id] = JSON.stringify(rec); sets[K.IDX] = JSON.stringify(ids);
    commit_(sets, []);
    if (isNew) logEvent_('APP_CREATED', rec.name, rec.active ? 'Active' : 'Inactive');
    else {
      const ch = [];
      ['name', 'url', 'desc', 'cat', 'icon', 'label', 'qr', 'notes'].forEach(function (f) { if (existing[f] !== rec[f]) ch.push(f === 'desc' ? 'description' : (f === 'cat' ? 'category' : (f === 'qr' ? 'QR setting' : f))); });
      if (ch.length) logEvent_('APP_UPDATED', rec.name, 'Changed: ' + ch.join(', '));
      if (existing.active !== rec.active) logEvent_(rec.active ? 'APP_ACTIVATED' : 'APP_DEACTIVATED', rec.name, '');
    }
    return { app: rec, apps: loadApps_(readAll_()).list };
  });
}

function adminDeleteApp_(p) {
  return withLock_(function () {
    const all = readAll_();
    const ld = loadApps_(all);
    const app = ld.list.filter(function (a) { return a.id === String(p.id); })[0];
    if (!app) throw new AppError('NOT_FOUND', 'Application not found.');
    const sets = {}; sets[K.IDX] = JSON.stringify(ld.ids.filter(function (id) { return id !== app.id; }));
    commit_(sets, [K.APP + app.id]);
    logEvent_('APP_DELETED', app.name, '');
    return { apps: loadApps_(readAll_()).list };
  });
}

function adminToggleApp_(p) {
  return withLock_(function () {
    const all = readAll_();
    const app = loadApps_(all).list.filter(function (a) { return a.id === String(p.id); })[0];
    if (!app) throw new AppError('NOT_FOUND', 'Application not found.');
    const want = p.active === true;
    if (app.active !== want) {
      app.active = want; app.updatedAt = Date.now();
      commit_(sub_(K.APP + app.id, app), []);
      logEvent_(want ? 'APP_ACTIVATED' : 'APP_DEACTIVATED', app.name, '');
    }
    return { apps: loadApps_(readAll_()).list };
  });
}

function adminReorderApps_(p) {
  return withLock_(function () {
    const all = readAll_();
    const ld = loadApps_(all);
    const ids = checkPermutation_(p.ids, ld.ids);
    if (ids.join(',') !== ld.ids.join(',')) { commit_(sub_(K.IDX, ids), []); logEvent_('APPS_REORDERED', 'Applications', ''); }
    return { apps: loadApps_(readAll_()).list };
  });
}

function adminQrData_(p) {
  const app = loadApps_(readAll_()).list.filter(function (a) { return a.id === String(p.id); })[0];
  if (!app) throw new AppError('NOT_FOUND', 'Application not found.');
  return { id: app.id, name: app.name, url: normalizeUrl_(app.url) };
}

/** Optional reachability check. Informational only; needs the external-request permission. */
function adminCheckUrl_(p) {
  const url = normalizeUrl_(p.url);
  try {
    const r = UrlFetchApp.fetch(url, { method: 'get', muteHttpExceptions: true, followRedirects: true, headers: { 'User-Agent': 'KisanPortalLinkCheck/1.0' } });
    const c = r.getResponseCode();
    let msg;
    if (c >= 200 && c < 400) msg = 'Reachable (HTTP ' + c + ').';
    else if (c === 401 || c === 403) msg = 'The server answered with HTTP ' + c + '. The app probably requires sign-in or blocks automated checks, which is normal for protected apps.';
    else if (c === 404 || c === 410) msg = 'Not found (HTTP ' + c + '). Please check the URL.';
    else if (c >= 500) msg = 'The server reported an error (HTTP ' + c + ').';
    else msg = 'Unexpected response (HTTP ' + c + ').';
    return { status: c, message: msg };
  } catch (err) {
    return { status: 0, message: 'The address could not be reached from Google servers. Check the URL.' };
  }
}

/* ---------- Categories ---------- */

function adminListCategories_() {
  const all = readAll_();
  return { categories: catsWithCounts_(all), max: PORTAL.MAX_CATS };
}

function catsWithCounts_(all) {
  const cats = readCats_(all);
  const counts = {};
  loadApps_(all).list.forEach(function (a) { counts[a.cat] = (counts[a.cat] || 0) + 1; });
  return cats.map(function (c) { return { id: c.id, name: c.name, icon: c.icon, count: counts[c.id] || 0 }; });
}

function adminSaveCategory_(p) {
  return withLock_(function () {
    const all = readAll_();
    const cats = readCats_(all);
    const name = str_(p.name, 'Category name', 2, 40);
    const icon = String(p.icon || 'tag');
    if (!/^[a-z0-9-]{1,24}$/.test(icon)) throw bad_('Invalid icon.');
    const id = p.id ? String(p.id) : '';
    const existing = id ? cats.filter(function (c) { return c.id === id; })[0] : null;
    if (id && !existing) throw new AppError('NOT_FOUND', 'Category not found.');
    cats.forEach(function (c) { if ((!existing || c.id !== existing.id) && c.name.toLowerCase() === name.toLowerCase()) throw bad_('A category named "' + c.name + '" already exists.'); });
    if (existing) { const old = existing.name; existing.name = name; existing.icon = icon; logEvent_('CATEGORY_UPDATED', name, old !== name ? 'Renamed from "' + old + '"' : 'Updated'); }
    else {
      if (cats.length >= PORTAL.MAX_CATS) throw new AppError('CAPACITY', 'Maximum of ' + PORTAL.MAX_CATS + ' categories reached.');
      cats.push({ id: 'c' + newId_(all), name: name, icon: icon }); logEvent_('CATEGORY_CREATED', name, '');
    }
    commit_(sub_(K.CATS, cats), []);
    return { categories: catsWithCounts_(readAll_()) };
  });
}

function adminDeleteCategory_(p) {
  return withLock_(function () {
    const all = readAll_();
    const cats = readCats_(all);
    const cat = cats.filter(function (c) { return c.id === String(p.id); })[0];
    if (!cat) throw new AppError('NOT_FOUND', 'Category not found.');
    if (cats.length <= 1) throw bad_('At least one category must remain.');
    const used = loadApps_(all).list.filter(function (a) { return a.cat === cat.id; });
    const sets = {};
    if (used.length) {
      const target = cats.filter(function (c) { return c.id === String(p.reassignTo || '') && c.id !== cat.id; })[0];
      if (!target) throw new AppError('IN_USE', used.length + ' application(s) still use "' + cat.name + '". Choose another category to move them to first.');
      used.forEach(function (a) { a.cat = target.id; a.updatedAt = Date.now(); sets[K.APP + a.id] = JSON.stringify(a); });
    }
    sets[K.CATS] = JSON.stringify(cats.filter(function (c) { return c.id !== cat.id; }));
    const s = readSettings_(all);
    if (s.defaultCategory === cat.id) { s.defaultCategory = 'all'; sets[K.SET] = JSON.stringify(s); }
    commit_(sets, []);
    logEvent_('CATEGORY_DELETED', cat.name, used.length ? used.length + ' app(s) reassigned' : '');
    return { categories: catsWithCounts_(readAll_()) };
  });
}

function adminReorderCategories_(p) {
  return withLock_(function () {
    const all = readAll_();
    const cats = readCats_(all);
    const ids = checkPermutation_(p.ids, cats.map(function (c) { return c.id; }));
    const by = {}; cats.forEach(function (c) { by[c.id] = c; });
    const next = ids.map(function (id) { return by[id]; });
    if (ids.join(',') !== cats.map(function (c) { return c.id; }).join(',')) { commit_(sub_(K.CATS, next), []); logEvent_('CATEGORIES_REORDERED', 'Categories', ''); }
    return { categories: catsWithCounts_(readAll_()) };
  });
}

/* ---------- Settings ---------- */

function adminGetSettings_() {
  const all = readAll_();
  const auth = parse_(all[K.AUTH]);
  return { settings: readSettings_(all), adminEmail: auth ? auth.email : '', categories: readCats_(all) };
}

function adminSaveSettings_(p, sid) {
  return withLock_(function () {
    const all = readAll_();
    const cats = readCats_(all);
    const next = sanitizeSettings_(p.settings || {}, cats);
    const sets = {}; sets[K.SET] = JSON.stringify(next);
    const auth = parse_(all[K.AUTH]);
    const newEmail = p.adminEmail !== undefined ? normEmail_(p.adminEmail) : auth.email;
    let emailChanged = false;
    if (newEmail !== auth.email) {
      if (!/^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/.test(newEmail) || newEmail.length > 120) throw bad_('Enter a valid administrator email address.');
      ensureNotLocked_();
      if (!checkPassword_(auth, String(p.currentPassword || ''))) {
        registerFailure_('PWD_VERIFY_FAIL', 'Wrong password while changing administrator email');
        throw bad_('Your current password is required to change the administrator email, and it was incorrect.');
      }
      auth.email = newEmail; auth.updatedAt = Date.now(); sets[K.AUTH] = JSON.stringify(auth); emailChanged = true;
    }
    commit_(sets, []);
    logEvent_('SETTINGS_CHANGED', 'Portal settings', 'Settings saved');
    if (emailChanged) logEvent_('ADMIN_EMAIL_CHANGED', 'Administrator', 'Sign-in email changed');
    return { settings: next, adminEmail: auth.email };
  });
}

function adminResetDisplay_() {
  return withLock_(function () {
    const all = readAll_();
    const cur = readSettings_(all), def = defaultSettings_();
    ['accent', 'cardLayout', 'defaultCategory', 'refreshMinutes', 'qr'].forEach(function (k) { cur[k] = def[k]; });
    commit_(sub_(K.SET, cur), []);
    logEvent_('SETTINGS_CHANGED', 'Portal settings', 'Display defaults restored');
    return { settings: cur };
  });
}

function adminChangePassword_(p, sid) {
  ensureNotLocked_();
  const auth = parse_(readAll_()[K.AUTH]);
  if (!checkPassword_(auth, String(p.currentPassword || ''))) {
    withLock_(function () { registerFailure_('PWD_VERIFY_FAIL', 'Wrong current password while changing password'); });
    Utilities.sleep(700);
    throw bad_('Your current password is incorrect.');
  }
  if (p.newPassword !== p.confirmPassword) throw bad_('The new password and its confirmation do not match.');
  checkPasswordPolicy_(p.newPassword);
  if (safeEqual_(String(p.newPassword), String(p.currentPassword))) throw bad_('The new password must be different from the current one.');
  const next = createAuth_(p.newPassword, auth.email);
  withLock_(function () {
    const all = readAll_();
    const sess = parse_(all[K.SESS]) || {};
    const keep = {}; if (sess[sid]) keep[sid] = sess[sid];          // sign out every other session
    const sets = {}; sets[K.AUTH] = JSON.stringify(next); sets[K.SESS] = JSON.stringify(keep);
    commit_(sets, [K.THR], true);
    logEvent_('PASSWORD_CHANGED', 'Administrator', 'Other sessions were signed out');
  });
  return { done: true };
}

/* ---------- Activity log ---------- */

function adminListLog_() {
  const all = readAll_();
  return { entries: readLog_(all), max: PORTAL.MAX_LOG };
}

/* ============================== DATA HELPERS ============================== */

function defaultSettings_() {
  return {
    portalName: 'Kisan Enterprises Central Business Portal',
    tagline: 'One secure place for every Kisan business application',
    description: 'Find and open the business applications used across Kisan Enterprises.',
    monogram: 'KE', accent: 'navy', cardLayout: 'grid', defaultCategory: 'all', refreshMinutes: 0,
    footerText: 'Kisan Enterprises. All rights reserved.',
    qr: { size: 300, caption: true, enableForNew: false }
  };
}

function defaultCategories_() {
  return [
    ['c_management', 'Management', 'briefcase'], ['c_sales', 'Sales', 'cart'], ['c_hr', 'Human Resources', 'users'],
    ['c_finance', 'Finance', 'rupee'], ['c_operations', 'Operations', 'truck'], ['c_productivity', 'Productivity', 'clipboard'],
    ['c_reports', 'Reports', 'chart'], ['c_other', 'Other', 'grid']
  ].map(function (a) { return { id: a[0], name: a[1], icon: a[2] }; });
}

function readSettings_(all) {
  const def = defaultSettings_();
  const s = parse_(all[K.SET]);
  if (!s || typeof s !== 'object') return def;
  const out = {};
  Object.keys(def).forEach(function (k) { out[k] = (s[k] === undefined) ? def[k] : s[k]; });
  out.qr = { size: def.qr.size, caption: def.qr.caption, enableForNew: def.qr.enableForNew };
  if (s.qr && typeof s.qr === 'object') { Object.keys(out.qr).forEach(function (k) { if (s.qr[k] !== undefined) out.qr[k] = s.qr[k]; }); }
  return out;
}

function sanitizeSettings_(s, cats) {
  const out = {};
  out.portalName = str_(s.portalName, 'Portal name', 3, 80);
  out.tagline = str_(s.tagline, 'Tagline', 0, 120);
  out.description = str_(s.description, 'Portal description', 0, 300);
  out.monogram = str_(s.monogram, 'Monogram', 1, 3).toUpperCase();
  if (!/^[A-Z0-9]{1,3}$/.test(out.monogram)) throw bad_('Monogram must be 1-3 letters or digits.');
  if (['navy', 'blue', 'teal'].indexOf(s.accent) < 0) throw bad_('Unknown accent colour.');
  out.accent = s.accent;
  if (['grid', 'list', 'compact'].indexOf(s.cardLayout) < 0) throw bad_('Unknown card layout.');
  out.cardLayout = s.cardLayout;
  const dc = String(s.defaultCategory || 'all');
  if (dc !== 'all' && !cats.some(function (c) { return c.id === dc; })) throw bad_('Default category does not exist.');
  out.defaultCategory = dc;
  const rm = parseInt(s.refreshMinutes, 10);
  if ([0, 1, 5, 15, 30].indexOf(rm) < 0) throw bad_('Invalid refresh interval.');
  out.refreshMinutes = rm;
  out.footerText = str_(s.footerText, 'Footer text', 0, 120);
  const q = s.qr || {};
  const size = parseInt(q.size, 10);
  if ([240, 300, 360, 420].indexOf(size) < 0) throw bad_('Invalid QR size.');
  out.qr = { size: size, caption: q.caption === true, enableForNew: q.enableForNew === true };
  return out;
}

function readCats_(all) {
  const c = parse_(all[K.CATS]);
  if (!Array.isArray(c)) return [];
  return c.filter(function (x) { return x && typeof x.id === 'string' && typeof x.name === 'string'; })
    .map(function (x) { return { id: x.id, name: x.name, icon: typeof x.icon === 'string' ? x.icon : 'tag' }; });
}

function loadApps_(all) {
  const idxRaw = parse_(all[K.IDX]);
  const idx = Array.isArray(idxRaw) ? idxRaw.filter(function (x) { return typeof x === 'string'; }) : [];
  const byId = {}; let corrupted = 0;
  Object.keys(all).forEach(function (k) {
    if (k.indexOf(K.APP) === 0) {
      const r = parse_(all[k]);
      if (r && r.id === k.slice(K.APP.length) && typeof r.name === 'string' && typeof r.url === 'string') byId[r.id] = r; else corrupted++;
    }
  });
  const list = [], seen = {};
  idx.forEach(function (id) { if (byId[id] && !seen[id]) { list.push(byId[id]); seen[id] = 1; } });
  Object.keys(byId).filter(function (id) { return !seen[id]; })
    .sort(function (a, b) { return (byId[a].createdAt || 0) - (byId[b].createdAt || 0); })
    .forEach(function (id) { list.push(byId[id]); });
  return { list: list, ids: list.map(function (a) { return a.id; }), corrupted: corrupted };
}

function buildPublicPayload_() {
  const all = readAll_();
  const s = readSettings_(all);
  const cats = readCats_(all);
  const apps = loadApps_(all).list.filter(function (a) { return a.active; });
  const counts = {}; apps.forEach(function (a) { counts[a.cat] = (counts[a.cat] || 0) + 1; });
  return {
    settings: {
      portalName: s.portalName, tagline: s.tagline, description: s.description, monogram: s.monogram, accent: s.accent,
      cardLayout: s.cardLayout, defaultCategory: s.defaultCategory, refreshMinutes: s.refreshMinutes, footerText: s.footerText,
      qr: { size: s.qr.size, caption: s.qr.caption }
    },
    categories: cats.filter(function (c) { return counts[c.id]; }).map(function (c) { return { id: c.id, name: c.name, icon: c.icon, count: counts[c.id] }; }),
    allCategories: cats.map(function (c) { return { id: c.id, name: c.name }; }),
    apps: apps.map(function (a) { return { id: a.id, name: a.name, url: a.url, desc: a.desc, cat: a.cat, icon: a.icon, label: a.label, qr: !!a.qr }; }),
    generatedAt: Date.now()
  };
}

/* ============================== VALIDATION ============================== */

function str_(v, label, min, max, multiline) {
  if (v !== undefined && v !== null && typeof v !== 'string') throw bad_(label + ' must be text.');
  let s = v || '';
  s = multiline ? s.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '') : s.replace(/[\u0000-\u001f\u007f]+/g, ' ');
  s = s.trim();
  if (s.length < min) throw bad_(min > 0 && s.length === 0 ? label + ' is required.' : label + ' must be at least ' + min + ' characters.');
  if (s.length > max) throw bad_(label + ' must be at most ' + max + ' characters.');
  return s;
}

function validateApp_(p, cats) {
  const out = {};
  out.name = str_(p.name, 'Application name', 2, 60);
  out.url = normalizeUrl_(p.url);
  out.desc = str_(p.desc, 'Short description', 5, 200);
  const cat = String(p.cat || '');
  if (!cats.some(function (c) { return c.id === cat; })) throw bad_('Please choose a valid category.');
  out.cat = cat;
  const icon = String(p.icon || 'grid');
  if (!/^[a-z0-9-]{1,24}$/.test(icon)) throw bad_('Invalid icon.');
  out.icon = icon;
  out.label = str_(p.label, 'Display label', 0, 24);
  out.active = p.active === true;
  out.qr = p.qr === true;
  out.notes = str_(p.notes, 'Administrator notes', 0, 300, true);
  return out;
}

/** Accepts only plain http/https URLs. Rejects javascript:, data:, credentials in URL, whitespace, etc. */
function normalizeUrl_(raw) {
  const s = String(raw === undefined || raw === null ? '' : raw).trim();
  if (!s) throw bad_('Application URL is required.');
  if (s.length > 1000) throw bad_('Application URL must be at most 1000 characters.');
  if (/[\u0000-\u0020\u007f<>"'`\\^{}|]/.test(s)) throw bad_('The URL contains spaces or characters that are not allowed.');
  const m = s.match(/^(https?):\/\/([^\/?#]+)([\s\S]*)$/i);
  if (!m) throw bad_('The URL must start with http:// or https:// (other schemes such as javascript: or data: are rejected).');
  const host = m[2];
  if (host.indexOf('@') >= 0) throw bad_('URLs containing a username or password are not allowed.');
  const hostname = host.replace(/:\d{1,5}$/, '');
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(hostname) || hostname.indexOf('..') >= 0 || hostname.indexOf('.') < 0) {
    throw bad_('The URL does not contain a valid domain name.');
  }
  return m[1].toLowerCase() + '://' + host + m[3];
}

function urlKey_(u) { return String(u).toLowerCase().replace(/\/+$/, ''); }

function checkPermutation_(ids, current) {
  if (!Array.isArray(ids) || ids.length !== current.length) throw bad_('The new order does not match the current list. Refresh and try again.');
  const seen = {};
  ids.forEach(function (id) {
    if (typeof id !== 'string' || seen[id] || current.indexOf(id) < 0) throw bad_('The new order does not match the current list. Refresh and try again.');
    seen[id] = 1;
  });
  return ids.slice();
}

function normEmail_(e) { return String(e === undefined || e === null ? '' : e).trim().toLowerCase().slice(0, 200); }
function normCode_(c) { return String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 32); }

function checkPasswordPolicy_(pw) {
  if (typeof pw !== 'string' || pw.length < 12) throw bad_('Password must be at least 12 characters.');
  if (pw.length > 128) throw bad_('Password must be at most 128 characters.');
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) throw bad_('Password must include an upper-case letter, a lower-case letter and a digit.');
}

/* ============================== CRYPTO / AUTH ============================== */

function toHex_(bytes) { return bytes.map(function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join(''); }
function hexToBytes_(hex) { const out = []; for (let i = 0; i < hex.length; i += 2) { const v = parseInt(hex.substr(i, 2), 16); out.push(v > 127 ? v - 256 : v); } return out; }
function sha256Hex_(str) { return toHex_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, str, Utilities.Charset.UTF_8)); }
function randomHex_(nBytes) { let s = ''; while (s.length < nBytes * 2) s += Utilities.getUuid().replace(/-/g, ''); return s.slice(0, nBytes * 2); }

function safeEqual_(a, b) {
  a = String(a); b = String(b);
  let d = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

/** PBKDF2-HMAC-SHA256, single 32-byte output block, built on the Apps Script HMAC primitive. */
function pbkdf2Sha256_(password, saltHex, iterations) {
  let pw = Utilities.newBlob(String(password)).getBytes();
  if (!pw.length) pw = [0];
  const salt = hexToBytes_(saltHex).concat([0, 0, 0, 1]);
  let u = Utilities.computeHmacSha256Signature(salt, pw);
  const t = u.slice();
  for (let i = 1; i < iterations; i++) {
    u = Utilities.computeHmacSha256Signature(u, pw);
    for (let j = 0; j < 32; j++) t[j] ^= u[j];
  }
  return toHex_(t);
}

function createAuth_(password, email) {
  const salt = randomHex_(16);
  return { v: 1, email: email, salt: salt, iter: PORTAL.PBKDF2_ITERATIONS, hash: pbkdf2Sha256_(password, salt, PORTAL.PBKDF2_ITERATIONS), updatedAt: Date.now() };
}

/** Always performs a full hash (even with no account) so response time does not leak anything. */
function checkPassword_(auth, password) {
  const salt = auth ? auth.salt : '00112233445566778899aabbccddeeff';
  const iter = auth ? auth.iter : PORTAL.PBKDF2_ITERATIONS;
  const h = pbkdf2Sha256_(password, salt, iter);
  return !!auth && safeEqual_(h, auth.hash);
}

function issueSetupCode_() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // 32 symbols, no 0/O/1/I
  const raw = hexToBytes_(randomHex_(12));
  let code = '';
  for (let i = 0; i < 12; i++) code += alphabet.charAt((raw[i] & 0xff) % 32);
  const salt = randomHex_(8);
  const rec = { s: salt, h: sha256Hex_(salt + code), exp: Date.now() + PORTAL.SETUP_TTL_MS, tries: 0 };
  withLock_(function () { commit_(sub_(K.SETUP, rec), [], true); });
  return code.slice(0, 4) + '-' + code.slice(4, 8) + '-' + code.slice(8, 12);
}

/* ---------- Throttling ---------- */

function ensureNotLocked_() {
  const thr = parse_(PropertiesService.getScriptProperties().getProperty(K.THR));
  if (thr && thr.lockUntil > Date.now()) {
    throw new AppError('LOCKED', 'Too many failed attempts. Try again in ' + Math.ceil((thr.lockUntil - Date.now()) / 60000) + ' minute(s).');
  }
}

/** Call inside withLock_. Locks for 15 min after every 5th consecutive failure (doubling, max 4 h). */
function registerFailure_(action, detail) {
  const now = Date.now();
  let thr = parse_(readAll_()[K.THR]) || { fails: 0, lockUntil: 0, lastFail: 0 };
  if (now - thr.lastFail > 24 * 3600 * 1000) thr.fails = 0;
  thr.fails++; thr.lastFail = now;
  if (thr.fails % 5 === 0) thr.lockUntil = now + Math.min(15 * Math.pow(2, Math.floor(thr.fails / 5) - 1), 240) * 60000;
  commit_(sub_(K.THR, thr), [], true);
  logEvent_(action, 'Administrator', detail + ' (consecutive failures: ' + thr.fails + ')');
}

/* ---------- Sessions ---------- */

function createSession_() {
  const token = randomHex_(32);                                  // 256-bit random bearer token
  const now = Date.now();
  const sess = parse_(readAll_()[K.SESS]) || {};
  Object.keys(sess).forEach(function (h) { if (now - sess[h].c > PORTAL.SESSION_MAX_MS || now - sess[h].l > PORTAL.SESSION_IDLE_MS) delete sess[h]; });
  sess[sha256Hex_(token)] = { c: now, l: now };                  // only the hash of the token is stored
  const keys = Object.keys(sess).sort(function (a, b) { return sess[b].c - sess[a].c; });
  const next = {}; keys.slice(0, PORTAL.MAX_SESSIONS).forEach(function (k) { next[k] = sess[k]; });
  commit_(sub_(K.SESS, next), [], true);
  return token;
}

function validateSession_(token) {
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) throw new AppError('SESSION', 'Please sign in.');
  const P = PropertiesService.getScriptProperties();
  const sess = parse_(P.getProperty(K.SESS)) || {};
  const h = sha256Hex_(token);
  const e = Object.prototype.hasOwnProperty.call(sess, h) ? sess[h] : null;
  const now = Date.now();
  if (!e || now - e.c > PORTAL.SESSION_MAX_MS || now - e.l > PORTAL.SESSION_IDLE_MS) {
    if (e) { try { withLock_(function () { const s2 = parse_(readAll_()[K.SESS]) || {}; delete s2[h]; commit_(sub_(K.SESS, s2), [], true); }); } catch (x) { /* ignore */ } }
    throw new AppError('SESSION', 'Your session has expired. Please sign in again.');
  }
  if (now - e.l > 60000) {                                       // refresh idle timer at most once a minute
    const lock = LockService.getScriptLock();
    if (lock.tryLock(2000)) {
      try { const s2 = parse_(P.getProperty(K.SESS)) || {}; if (s2[h]) { s2[h].l = now; P.setProperty(K.SESS, JSON.stringify(s2)); } } finally { lock.releaseLock(); }
    }
  }
  return h;
}

/* ============================== ACTIVITY LOG ============================== */

function readLog_(all) {
  let out = [];
  for (let i = 0; i < PORTAL.LOG_CHUNKS; i++) { const c = parse_(all[K.LOG + i]); if (Array.isArray(c)) out = out.concat(c); }
  return out;
}

/** Newest first. Bounded by MAX_LOG entries AND LOG_CHUNKS x ~7.5 KB. Never pass secrets in here. */
function logEvent_(action, record, detail) {
  try {
    const all = readAll_();
    let log = readLog_(all);
    log.unshift({ t: Date.now(), a: String(action), r: String(record || '').replace(/[\u0000-\u001f]+/g, ' ').slice(0, 80), d: String(detail || '').replace(/[\u0000-\u001f]+/g, ' ').slice(0, 140) });
    log = log.slice(0, PORTAL.MAX_LOG);
    const chunks = []; let cur = [];
    for (let i = 0; i < log.length; i++) {
      if (cur.length && JSON.stringify(cur.concat([log[i]])).length > PORTAL.LOG_CHUNK_CHARS) {
        chunks.push(cur); cur = [];
        if (chunks.length >= PORTAL.LOG_CHUNKS) break;
      }
      cur.push(log[i]);
    }
    if (cur.length && chunks.length < PORTAL.LOG_CHUNKS) chunks.push(cur);
    const sets = {}, dels = [];
    for (let i = 0; i < PORTAL.LOG_CHUNKS; i++) { if (chunks[i]) sets[K.LOG + i] = JSON.stringify(chunks[i]); else dels.push(K.LOG + i); }
    commit_(sets, dels, true);
  } catch (err) {
    console.error('Log write failed: ' + err);                  // logging must never break the operation
  }
}

/* ============================== STORAGE LAYER ============================== */

function readAll_() { return PropertiesService.getScriptProperties().getProperties(); }
function parse_(s) { if (s === undefined || s === null || s === '') return null; try { return JSON.parse(s); } catch (e) { return null; } }
function sub_(key, obj) { const o = {}; o[key] = JSON.stringify(obj); return o; }
function bytes_(s) { return encodeURIComponent(String(s)).replace(/%[0-9A-F]{2}/g, 'x').length; }

function newId_(all) {
  for (let i = 0; i < 20; i++) {
    const id = randomHex_(5);                                    // 10 hex chars
    if (all[K.APP + id] === undefined) return id;
  }
  throw new AppError('SERVER', 'Could not allocate an identifier.');
}

/**
 * The single write path. Checks per-value and total size BEFORE writing, then
 * applies all sets in one setProperties() call (all-or-nothing), then deletes.
 * sys=true lets security data (sessions, throttle, log) use the reserved headroom.
 * Must be called while holding the script lock.
 */
function commit_(sets, dels, sys) {
  const P = PropertiesService.getScriptProperties();
  const all = P.getProperties();
  let used = 0;
  Object.keys(all).forEach(function (k) { used += bytes_(k) + bytes_(all[k]); });
  const before = used;
  Object.keys(sets).forEach(function (k) {
    const vb = bytes_(sets[k]);
    if (vb > PORTAL.MAX_VALUE_BYTES) throw new AppError('TOO_LARGE', 'This record is too large to store (' + vb + ' bytes; the platform limit per value is about 9 KB). Shorten the text and try again.');
    if (all[k] !== undefined) used -= bytes_(k) + bytes_(all[k]);
    used += bytes_(k) + vb;
  });
  dels.forEach(function (k) { if (all[k] !== undefined && sets[k] === undefined) used -= bytes_(k) + bytes_(all[k]); });
  const limit = sys ? PORTAL.HARD_LIMIT_BYTES : PORTAL.SOFT_LIMIT_BYTES;
  if (used > before && used > limit) {
    throw new AppError('STORAGE_FULL', 'Portal storage is full (' + Math.round(used / 1024) + ' KB of about ' + Math.round(PORTAL.TOTAL_LIMIT_BYTES / 1024) + ' KB). Nothing was saved. Delete unused applications or shorten notes, then try again.');
  }
  try {
    if (Object.keys(sets).length) P.setProperties(sets, false);
    dels.forEach(function (k) { P.deleteProperty(k); });
  } catch (err) {
    throw new AppError('STORAGE', 'The platform rejected the save (storage quota or service error). Existing data was not modified by this request. Details: ' + String(err).slice(0, 120));
  }
  try { CacheService.getScriptCache().remove(PORTAL.CACHE_KEY); } catch (e) { /* ignore */ }
}

function withLock_(fn) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) throw new AppError('BUSY', 'The portal is busy. Please try again in a moment.');
  try { return fn(); } finally { lock.releaseLock(); }
}

function safe_(fn) {
  try { return { ok: true, data: fn() }; }
  catch (err) {
    if (err && err.isApp) return { ok: false, code: err.code, error: err.message };
    const ref = randomHex_(3);
    console.error('[' + ref + '] ' + (err && err.stack ? err.stack : err));
    return { ok: false, code: 'SERVER', error: 'Unexpected server error (ref ' + ref + '). Details are in Executions in the Apps Script editor.' };
  }
}
/* =====================================================================
   ACCESS CODE GATE  -  paste at the very END of Code.gs (change nothing else)
   Same technique as before: the later definition of a function wins, so
   the functions below replace their older versions automatically.

   Rules:
   - Portal-wide code (Settings) applies to every app set to "Follow portal setting".
   - An app can instead have its own code, or no code.
   - The link of a protected app is NEVER sent to the browser until
     apiUnlock() confirms the code on the server.
   - Codes are stored salted+hashed, never logged, never sent back to admin.
   - 5 wrong codes lock that code for 15 min (doubling, max 4 h).
   ===================================================================== */
const GATE_KEY = 'kb.gate';
const GATE_THR = 'kb.gthr';

function readGate_(all) {
  const g = parse_(all[GATE_KEY]);
  return (g && typeof g === 'object') ? g : { on: false };
}
function codeHash_(salt, code) { return sha256Hex_(salt + ':' + code); }
function checkCodeFmt_(c) {
  if (!/^[0-9]{4}$/.test(String(c))) throw bad_('The security code must be exactly 4 digits.');
  return String(c);
}
/** '' = open, 'g' = portal-wide code, otherwise the app id (app has its own code). */
function gateScope_(app, g) {
  if (app.lock === 'none') return '';
  if (app.lock === 'own' && app.ch) return app.id;
  return (g.on && g.h) ? 'g' : '';
}

/* ---------- web app entry: adds ?open=<appId> support (used by QR codes) ---------- */
function doGet(e) {
  const prm = (e && e.parameter) || {};
  const view = prm.page === 'admin' ? 'admin' : 'public';
  const open = /^[a-z0-9]{6,16}$/.test(String(prm.open || '')) ? String(prm.open) : '';
  let title = 'Kisan Enterprises Central Business Portal';
  try {
    const s = parse_(PropertiesService.getScriptProperties().getProperty(K.SET));
    if (s && s.portalName) title = String(s.portalName);
  } catch (err) { /* keep default */ }
  const t = HtmlService.createTemplateFromFile('Index');
  t.bootView = view;
  t.bootOpen = open;
  return t.evaluate().setTitle(title).addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/* ---------- public data: protected apps get NO url ---------- */
function buildPublicPayload_() {
  const all = readAll_();
  const s = readSettings_(all);
  const g = readGate_(all);
  const cats = readCats_(all);
  const apps = loadApps_(all).list.filter(function (a) { return a.active; });
  const counts = {}; apps.forEach(function (a) { counts[a.cat] = (counts[a.cat] || 0) + 1; });
  return {
    settings: {
      portalName: s.portalName, tagline: s.tagline, description: s.description, monogram: s.monogram, accent: s.accent,
      cardLayout: s.cardLayout, defaultCategory: s.defaultCategory, refreshMinutes: s.refreshMinutes, footerText: s.footerText,
      qr: { size: s.qr.size, caption: s.qr.caption }
    },
    categories: cats.filter(function (c) { return counts[c.id]; }).map(function (c) { return { id: c.id, name: c.name, icon: c.icon, count: counts[c.id] }; }),
    allCategories: cats.map(function (c) { return { id: c.id, name: c.name }; }),
    apps: apps.map(function (a) {
      const restricted = a.acc === 'users';
      const locked = !restricted && !!gateScope_(a, g);
      return { id: a.id, name: a.name, url: (locked || restricted) ? '' : a.url, desc: a.desc, cat: a.cat, icon: a.icon, label: a.label, qr: !!a.qr, locked: locked, restricted: restricted };
    }),
    generatedAt: Date.now()
  };
}

/* ---------- QR codes: a protected app's QR opens the portal's code prompt, not the app ---------- */
function qrTarget_(app, all) {
  if (app.acc === 'users' || gateScope_(app, readGate_(all))) return ScriptApp.getService().getUrl() + '?open=' + app.id;
  return normalizeUrl_(app.url);
}
function apiGetQrData(appId) {
  return safe_(function () {
    const id = String(appId || '');
    if (!/^[a-z0-9]{6,16}$/.test(id)) throw bad_('Invalid application.');
    const all = readAll_();
    const app = loadApps_(all).list.filter(function (a) { return a.id === id; })[0];
    if (!app || !app.active || !app.qr) throw new AppError('NOT_FOUND', 'No QR code is available for this application.');
    return { id: app.id, name: app.name, url: qrTarget_(app, all) };
  });
}
function adminQrData_(p) {
  const all = readAll_();
  const app = loadApps_(all).list.filter(function (a) { return a.id === String(p.id); })[0];
  if (!app) throw new AppError('NOT_FOUND', 'Application not found.');
  return { id: app.id, name: app.name, url: qrTarget_(app, all) };
}

/* ---------- PUBLIC: check a code, return the link ---------- */
function apiUnlock(appId, code) {
  return safe_(function () {
    const id = String(appId || '');
    if (!/^[a-z0-9]{6,16}$/.test(id)) throw bad_('Invalid application.');
    const all = readAll_();
    const app = loadApps_(all).list.filter(function (a) { return a.id === id; })[0];
    if (!app || !app.active) throw new AppError('NOT_FOUND', 'This application is not available.');
    if (app.acc === 'users') throw new AppError('SIGNIN', 'This application requires sign-in.');
    const g = readGate_(all);
    const scope = gateScope_(app, g);
    if (!scope) return { url: normalizeUrl_(app.url) };
    const thr = parse_(all[GATE_THR]) || {};
    const e = thr[scope];
    if (e && e.u > Date.now()) {
      throw new AppError('LOCKED', 'Too many wrong codes. Try again in ' + Math.ceil((e.u - Date.now()) / 60000) + ' minute(s).');
    }
    const c = String(code === undefined || code === null ? '' : code);
    const salt = scope === 'g' ? g.s : app.cs;
    const hash = scope === 'g' ? g.h : app.ch;
    const ok = /^[0-9]{4}$/.test(c) && safeEqual_(codeHash_(salt, c), hash);
    if (ok) {
      if (e && e.f) withLock_(function () { gateClear_(scope); });
      return { url: normalizeUrl_(app.url) };
    }
    withLock_(function () { gateFail_(scope, scope === 'g' ? 'Portal-wide code' : app.name); });
    Utilities.sleep(600);
    throw new AppError('BAD_CODE', 'Incorrect security code.');
  });
}

/** Call inside withLock_. */
function gateFail_(scope, label) {
  const now = Date.now();
  const thr = parse_(readAll_()[GATE_THR]) || {};
  const e = thr[scope] || { f: 0, u: 0, t: 0 };
  if (now - e.t > 24 * 3600 * 1000) e.f = 0;
  e.f++; e.t = now;
  if (e.f % 5 === 0) {
    const mins = Math.min(15 * Math.pow(2, Math.floor(e.f / 5) - 1), 240);
    e.u = now + mins * 60000;
    logEvent_('GATE_LOCKED', label, 'Too many wrong codes; locked for ' + mins + ' minutes');
  }
  thr[scope] = e;
  Object.keys(thr).forEach(function (k) { if (now - thr[k].t > 7 * 24 * 3600 * 1000) delete thr[k]; });
  commit_(sub_(GATE_THR, thr), [], true);
}
/** Call inside withLock_. */
function gateClear_(scope) {
  const thr = parse_(readAll_()[GATE_THR]) || {};
  if (thr[scope]) { delete thr[scope]; commit_(sub_(GATE_THR, thr), [], true); }
}

/* ---------- ADMIN: save an application (now with its own access code) ---------- */
function adminSaveApp_(p) {
  return withLock_(function () {
    const all = readAll_();
    const cats = readCats_(all);
    const ld = loadApps_(all);
    const isNew = !p.id;
    let existing = null;
    if (!isNew) {
      existing = ld.list.filter(function (a) { return a.id === String(p.id); })[0];
      if (!existing) throw new AppError('NOT_FOUND', 'Application not found (it may have been deleted).');
    } else if (ld.list.length >= PORTAL.MAX_APPS) {
      throw new AppError('CAPACITY', 'Maximum of ' + PORTAL.MAX_APPS + ' applications reached. Delete an unused application first.');
    }
    const v = validateApp_(p, cats);
    const lock = ['default', 'own', 'none'].indexOf(p.lock) >= 0 ? p.lock : 'default';
    const acc = validateAccess_(p, existing);
    const code = String(p.code === undefined || p.code === null ? '' : p.code).trim();
    let cs = '', ch = '';
    if (lock === 'own') {
      if (code) { checkCodeFmt_(code); cs = randomHex_(8); ch = codeHash_(cs, code); }
      else if (existing && existing.ch) { cs = existing.cs; ch = existing.ch; }
      else throw bad_('Enter a 4-digit security code for this application.');
    }
    const urlKey = urlKey_(v.url);
    ld.list.forEach(function (a) {
      if (existing && a.id === existing.id) return;
      if (a.name.toLowerCase() === v.name.toLowerCase()) throw bad_('Another application is already named "' + a.name + '".');
      if (urlKey_(a.url) === urlKey) throw bad_('Another application ("' + a.name + '") already uses this URL.');
    });
    const now = Date.now();
    const rec = {
      id: existing ? existing.id : newId_(all),
      name: v.name, url: v.url, desc: v.desc, cat: v.cat, icon: v.icon, label: v.label,
            active: v.active, qr: v.qr, notes: v.notes, lock: lock, cs: cs, ch: ch, acc: acc.acc, au: acc.au,
      createdAt: existing ? existing.createdAt : now, updatedAt: now
    };
    const ids = ld.ids.filter(function (id) { return id !== rec.id; });
    let pos;
    if (p.order === undefined || p.order === null || p.order === '') pos = existing ? Math.min(ld.ids.indexOf(rec.id), ids.length) : ids.length;
    else {
      const n = parseInt(p.order, 10);
      if (isNaN(n) || n < 1) throw bad_('Display order must be a whole number of 1 or more.');
      pos = Math.min(n - 1, ids.length);
    }
    ids.splice(pos, 0, rec.id);
    const sets = {}; sets[K.APP + rec.id] = JSON.stringify(rec); sets[K.IDX] = JSON.stringify(ids);
    commit_(sets, []);
    if (code && lock === 'own') gateClear_(rec.id);
    if (isNew) logEvent_('APP_CREATED', rec.name, rec.active ? 'Active' : 'Inactive');
    else {
      const chg = [];
      ['name', 'url', 'desc', 'cat', 'icon', 'label', 'qr', 'notes'].forEach(function (f) { if (existing[f] !== rec[f]) chg.push(f === 'desc' ? 'description' : (f === 'cat' ? 'category' : (f === 'qr' ? 'QR setting' : f))); });
      if ((existing.lock || 'default') !== lock || (lock === 'own' && code)) chg.push('access code');
            if ((existing.acc || 'open') !== acc.acc || JSON.stringify(existing.au || []) !== JSON.stringify(acc.au)) chg.push('user access');
      if (chg.length) logEvent_('APP_UPDATED', rec.name, 'Changed: ' + chg.join(', '));
      if (existing.active !== rec.active) logEvent_(rec.active ? 'APP_ACTIVATED' : 'APP_DEACTIVATED', rec.name, '');
    }
    return { app: rec, apps: loadApps_(readAll_()).list };
  });
}

/* ---------- ADMIN: portal-wide code ---------- */
function adminGetGate_() {
  const g = readGate_(readAll_());
  return { on: !!g.on, hasCode: !!g.h };
}
function adminSaveGate_(p) {
  return withLock_(function () {
    const old = readGate_(readAll_());
    const on = p.on === true;
    const code = String(p.code === undefined || p.code === null ? '' : p.code).trim();
    const g = { on: on, s: old.s || '', h: old.h || '' };
    if (code) { checkCodeFmt_(code); g.s = randomHex_(8); g.h = codeHash_(g.s, code); }
    if (on && !g.h) throw bad_('Enter a 4-digit security code to turn this on.');
    commit_(sub_(GATE_KEY, g), []);
    if (code) gateClear_('g');
    logEvent_('GATE_CHANGED', 'Portal-wide code', (on ? 'On' : 'Off') + (code ? ', new code set' : ''));
    return { on: g.on, hasCode: !!g.h };
  });
}
ADMIN_ACTIONS_.getGate = adminGetGate_;
ADMIN_ACTIONS_.saveGate = adminSaveGate_;

/* ---------- never send code hashes to the browser, even to the admin ---------- */
function scrubApp_(a) {
  const o = {};
  Object.keys(a).forEach(function (k) { if (k !== 'cs' && k !== 'ch') o[k] = a[k]; });
  o.lock = a.lock || 'default';
  o.hasCode = !!a.ch;
  return o;
}
['listApps', 'saveApp', 'deleteApp', 'toggleApp', 'reorderApps'].forEach(function (k) {
  const fn = ADMIN_ACTIONS_[k];
  ADMIN_ACTIONS_[k] = function (p, sid) {
    const r = fn(p, sid);
    if (r && r.apps) r.apps = r.apps.map(scrubApp_);
    if (r && r.app) r.app = scrubApp_(r.app);
    return r;
  };
});

function checkGateInstall() {
  assertEditorRun_();
  const all = readAll_(), g = readGate_(all);
  Logger.log('getGate action: ' + typeof ADMIN_ACTIONS_.getGate);
  Logger.log('Portal-wide code: ' + (g.on && g.h ? 'ON' : 'OFF'));
  loadApps_(all).list.forEach(function (a) { Logger.log(a.name + ' -> ' + (gateScope_(a, g) ? 'CODE REQUIRED' : 'open')); });
}

/* =====================================================================
   FORGOT PASSWORD BY EMAIL  -  paste at the very END of Code.gs
   (below the ACCESS CODE GATE block). Change nothing else in Code.gs.

   How it works
   - apiRequestReset(email): emails a one-time code to the stored
     administrator email. It ALWAYS answers the same way, so nobody can
     learn whether an address is the administrator.
   - apiResetPassword(email, code, newPassword): checks the code and sets
     the new password. All sessions are signed out and any login lock-out
     is cleared.
   - Anti-abuse: at most 3 emails per hour and one every 2 minutes (for the
     whole portal), the code lives 15 minutes, and 5 wrong guesses cancel it.
   - Codes are stored salted+hashed and are never logged.
   ===================================================================== */
const RST_KEY = 'kb.rst';
const RESET = {
  TTL_MS: 15 * 60 * 1000,        // code valid for 15 minutes
  MAX_TRIES: 5,                  // wrong guesses before the code is cancelled
  COOLDOWN_MS: 2 * 60 * 1000,    // minimum gap between emails
  MAX_PER_HOUR: 3                // emails per rolling hour
};

function resetCode_() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // 32 symbols, no 0/O/1/I
  const raw = hexToBytes_(randomHex_(10));
  let c = '';
  for (let i = 0; i < 10; i++) c += alphabet.charAt((raw[i] & 0xff) % 32);
  return c;
}

/** PUBLIC. Same answer whether or not the email matches or the limits were hit. */
function apiRequestReset(email) {
  return safe_(function () {
    const given = normEmail_(email);
    let toSend = null;
    withLock_(function () {
      const now = Date.now();
      const all = readAll_();
      const auth = parse_(all[K.AUTH]);
      if (!auth) return;                                        // no admin yet: nothing to reset
      const rec = parse_(all[RST_KEY]) || {};
      const sent = (Array.isArray(rec.sent) ? rec.sent : []).filter(function (t) { return now - t < 3600000; });
      const last = sent.length ? sent[sent.length - 1] : 0;
      if (sent.length >= RESET.MAX_PER_HOUR || now - last < RESET.COOLDOWN_MS) return;   // silently limited
      if (!safeEqual_(given, auth.email)) return;               // wrong address: silently ignored
      const code = resetCode_();
      const salt = randomHex_(8);
      sent.push(now);
      commit_(sub_(RST_KEY, { s: salt, h: sha256Hex_(salt + code), exp: now + RESET.TTL_MS, tries: 0, sent: sent }), [], true);
      logEvent_('RESET_REQUESTED', 'Administrator', 'Password reset code emailed');
      toSend = { to: auth.email, code: code.slice(0, 5) + '-' + code.slice(5) };
    });
    if (toSend) {
      try {
        const when = Utilities.formatDate(new Date(), 'Asia/Kolkata', 'dd MMM yyyy, hh:mm a');
        MailApp.sendEmail({
          to: toSend.to,
          name: 'Kisan Enterprises Portal',
          subject: 'Your portal password reset code',
          body: 'A password reset was requested for the Kisan Enterprises Central Business Portal administrator account on ' + when + ' (IST).\n\n' +
                'Reset code:  ' + toSend.code + '\n\n' +
                'The code is valid for ' + (RESET.TTL_MS / 60000) + ' minutes and can be used once.\n' +
                'Open the portal, choose Admin Login > Forgot password, and enter this code with a new password.\n\n' +
                'If you did not request this, ignore this email. Your password has not been changed.'
        });
      } catch (err) {
        console.error('Reset email failed: ' + err);            // never tell the caller
      }
    }
    if (!toSend) Utilities.sleep(1800);                         // roughly match the time taken to send an email
    Utilities.sleep(800);
    return { sent: true };
  });
}

/** PUBLIC. Verifies the emailed code and sets the new password. */
function apiResetPassword(email, code, password) {
  return safe_(function () {
    const rec = parse_(readAll_()[RST_KEY]);
    const auth0 = parse_(PropertiesService.getScriptProperties().getProperty(K.AUTH));
    if (!auth0) throw new AppError('NOT_CONFIGURED', 'The administrator account has not been set up yet.');
    if (!rec || !rec.h || Date.now() > rec.exp || (rec.tries || 0) >= RESET.MAX_TRIES) {
      throw new AppError('NO_RESET', 'There is no active reset code. Request a new code and try again.');
    }
    const emailOk = safeEqual_(normEmail_(email), auth0.email);
    const codeOk = safeEqual_(sha256Hex_(rec.s + normCode_(code)), rec.h);
    if (!(emailOk && codeOk)) {
      withLock_(function () {
        const cur = parse_(readAll_()[RST_KEY]);
        if (cur && cur.h) { cur.tries = (cur.tries || 0) + 1; commit_(sub_(RST_KEY, cur), [], true); }
        logEvent_('RESET_FAIL', 'Administrator', 'Incorrect email or reset code');
      });
      Utilities.sleep(800);
      throw new AppError('BAD_RESET', 'The email or reset code is incorrect.');
    }
    checkPasswordPolicy_(password);
    const auth = createAuth_(password, auth0.email);            // slow hash, done outside the lock
    withLock_(function () {
      const cur = parse_(readAll_()[RST_KEY]);
      if (!cur || cur.h !== rec.h || Date.now() > cur.exp) throw new AppError('NO_RESET', 'The reset code is no longer valid. Request a new one.');
      const sets = {};
      sets[K.AUTH] = JSON.stringify(auth);
      cur.s = ''; cur.h = ''; cur.exp = 0; cur.tries = 0;       // code is single-use; keep the email history for rate limiting
      sets[RST_KEY] = JSON.stringify(cur);
      commit_(sets, [K.SESS, K.THR], true);                     // sign out everyone, clear any login lock
      logEvent_('PASSWORD_RESET', 'Administrator', 'Password reset with an emailed code; all sessions signed out');
    });
    return { done: true };
  });
}

/** Editor-only. Run ONCE: it asks you to authorise sending email, then sends a test message. */
function testResetEmail() {
  assertEditorRun_();
  const auth = parse_(PropertiesService.getScriptProperties().getProperty(K.AUTH));
  const to = auth ? auth.email : PORTAL.DEFAULT_ADMIN_EMAIL;
  MailApp.sendEmail({ to: to, name: 'Kisan Enterprises Portal', subject: 'Portal email test', body: 'Email sending works. The Forgot password feature can now deliver reset codes to this address.' });
  Logger.log('Test email sent to ' + to + '. Remaining email quota today: ' + MailApp.getRemainingDailyQuota());
  Logger.log('Now deploy a NEW VERSION (Deploy > Manage deployments > Edit > New version > Deploy).');
}

/* ===== Password rule: minimum 8 characters, nothing else required ===== */
function checkPasswordPolicy_(pw) {
  if (typeof pw !== 'string' || pw.length < 8) throw bad_('Password must be at least 8 characters.');
  if (pw.length > 128) throw bad_('Password must be at most 128 characters.');
}

/* =====================================================================
   PRIMARY + SECONDARY ADMINISTRATORS  -  paste at the very END of Code.gs
   (below the FORGOT PASSWORD block, in the SAME file; do not create a new file).

   Rules
   - The existing administrator (mis@kisanenterprises.in) is the PRIMARY.
   - Only the primary can add or remove other administrators.
   - Adding an email sends that person an invitation code by email.
     They open Admin Login > "Join here", enter the email, the code and
     choose their own password. The primary never sees their password.
   - Secondary administrators can use everything except the Administrators
     page and the primary's sign-in email.
   - Invitation: valid 48 hours, 5 wrong tries cancel it, up to 10 secondary
     administrators. The primary can resend an invitation or reset a
     secondary's password from the Administrators page.
   - The Activity Log now shows which administrator did each action.
   ===================================================================== */
const ADM_KEY = 'kb.adm';
const ADM = {
  MAX: 10,
  INVITE_TTL_MS: 48 * 60 * 60 * 1000,
  INVITE_MAX_TRIES: 5,
  MAX_SESSIONS: 15,
  EMAIL_RE: /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/
};

/** Who is making the current request (set per request by apiAdmin / apiLogin). */
let CUR_USER_ = { email: '', primary: true };

/* ---------- helpers ---------- */
function readAdmins_(all) {
  const a = parse_(all[ADM_KEY]);
  return Array.isArray(a) ? a.filter(function (r) { return r && typeof r.e === 'string' && (r.st === 'invited' || r.st === 'active'); }) : [];
}
function readAdminsRaw_() {
  const o = {}; o[ADM_KEY] = PropertiesService.getScriptProperties().getProperty(ADM_KEY);
  return readAdmins_(o);
}
function findAdmin_(list, email) { return list.filter(function (r) { return r.e === email; })[0]; }
function requirePrimary_() {
  if (!CUR_USER_.primary) throw new AppError('FORBIDDEN', 'Only the primary administrator can do this.');
}
function fmtCode_(c) { return String(c).slice(0, 5) + '-' + String(c).slice(5); }
function newInvite_(code) {
  const salt = randomHex_(8);
  return { s: salt, h: sha256Hex_(salt + code), exp: Date.now() + ADM.INVITE_TTL_MS, tries: 0 };
}
function purgeSessions_(sess, email) {
  const out = {};
  Object.keys(sess).forEach(function (h) { const s = sess[h]; if (!(s && s.r === 's' && s.u === email)) out[h] = s; });
  return out;
}
function publicAdmin_(r) {
  return { email: r.e, status: r.st, createdAt: r.at || 0, joinedAt: r.ja || 0, inviteExp: r.inv ? r.inv.exp : 0 };
}
function adminsView_(all) {
  const auth = parse_(all[K.AUTH]);
  return { primary: auth ? auth.email : '', admins: readAdmins_(all).map(publicAdmin_), max: ADM.MAX };
}
function inviteBad_() {
  return new AppError('BAD_INVITE', 'The email or invitation code is incorrect, or the invitation has expired. Ask the primary administrator for a new invitation.');
}
function sendInviteMail_(to, code, isReset) {
  try {
    const url = ScriptApp.getService().getUrl() + '?page=admin';
    MailApp.sendEmail({
      to: to,
      name: 'Kisan Enterprises Portal',
      subject: isReset ? 'Your portal administrator password was reset' : 'You have been invited as a portal administrator',
      body: (isReset ? 'The primary administrator reset your access to the Kisan Enterprises Central Business Portal.\n\n'
                     : 'You have been invited to help administer the Kisan Enterprises Central Business Portal.\n\n') +
            'Invitation code:  ' + code + '\n' +
            'Valid for ' + (ADM.INVITE_TTL_MS / 3600000) + ' hours, single use.\n\n' +
            'How to join:\n' +
            '1. Open ' + url + '\n' +
            '2. Choose Admin Login, then "Join here".\n' +
            '3. Enter this email address, the invitation code and a password of your choice (8 or more characters).\n\n' +
            'If you were not expecting this, ignore this email.'
    });
    return true;
  } catch (err) {
    console.error('Invite email failed: ' + err);
    return false;
  }
}

/* ---------- activity log: show WHO did it ---------- */
const _logEventBase_ = logEvent_;
logEvent_ = function (action, record, detail) {
  const who = CUR_USER_.email ? CUR_USER_.email + ': ' : '';
  return _logEventBase_(action, record, who + String(detail || ''));
};

/* ---------- sessions remember who signed in ---------- */
function createSession_(email, role) {
  const token = randomHex_(32);
  const now = Date.now();
  const sess = parse_(readAll_()[K.SESS]) || {};
  Object.keys(sess).forEach(function (h) { if (now - sess[h].c > PORTAL.SESSION_MAX_MS || now - sess[h].l > PORTAL.SESSION_IDLE_MS) delete sess[h]; });
  sess[sha256Hex_(token)] = { c: now, l: now, u: String(email || ''), r: role === 'secondary' ? 's' : 'p' };
  const keys = Object.keys(sess).sort(function (a, b) { return sess[b].c - sess[a].c; });
  const next = {}; keys.slice(0, ADM.MAX_SESSIONS).forEach(function (k) { next[k] = sess[k]; });
  commit_(sub_(K.SESS, next), [], true);
  return token;
}

/* ---------- PUBLIC: sign in (primary or secondary) ---------- */
function apiLogin(email, password) {
  return safe_(function () {
    ensureNotLocked_();
    const all = readAll_();
    const primary = parse_(all[K.AUTH]);
    if (!primary) throw new AppError('NOT_CONFIGURED', 'The administrator account has not been set up yet.');
    const given = normEmail_(email);
    const pw = (typeof password === 'string') ? password.slice(0, 256) : '';
    let acct = null, role = '';
    if (safeEqual_(given, primary.email)) { acct = primary; role = 'primary'; }
    else {
      const rec = findAdmin_(readAdmins_(all), given);
      if (rec && rec.st === 'active' && rec.a) { acct = rec.a; role = 'secondary'; }
    }
    const pwOk = checkPassword_(acct, pw);           // always does a full hash, even with no account
    if (acct && pwOk) {
      const token = withLock_(function () {
        commit_({}, [K.THR], true);
        const t = createSession_(acct.email, role);
        CUR_USER_ = { email: acct.email, primary: role === 'primary' };
        logEvent_('LOGIN_OK', 'Administrator', 'Signed in');
        return t;
      });
      return { token: token, email: acct.email, role: role, idleMs: PORTAL.SESSION_IDLE_MS };
    }
    withLock_(function () { registerFailure_('LOGIN_FAIL', 'Failed sign-in attempt'); });
    Utilities.sleep(700);
    throw new AppError('BAD_LOGIN', 'Invalid email or password.');
  });
}

/* ---------- PUBLIC: an invited person creates their account ---------- */
function apiAcceptInvite(email, code, password) {
  return safe_(function () {
    const given = normEmail_(email);
    const rec = findAdmin_(readAdmins_(readAll_()), given);
    const valid = !!rec && rec.st === 'invited' && !!rec.inv && Date.now() <= rec.inv.exp && (rec.inv.tries || 0) < ADM.INVITE_MAX_TRIES;
    if (!valid) { Utilities.sleep(800); throw inviteBad_(); }
    if (!safeEqual_(sha256Hex_(rec.inv.s + normCode_(code)), rec.inv.h)) {
      withLock_(function () {
        const list = readAdmins_(readAll_());
        const r = findAdmin_(list, given);
        if (r && r.inv) { r.inv.tries = (r.inv.tries || 0) + 1; commit_(sub_(ADM_KEY, list), [], true); }
        logEvent_('ADMIN_INVITE_FAIL', given, 'Incorrect invitation code');
      });
      Utilities.sleep(800);
      throw inviteBad_();
    }
    checkPasswordPolicy_(password);
    const auth = createAuth_(password, given);       // slow hash, done outside the lock
    withLock_(function () {
      const list = readAdmins_(readAll_());
      const r = findAdmin_(list, given);
      if (!r || r.st !== 'invited' || !r.inv || r.inv.h !== rec.inv.h || Date.now() > r.inv.exp) throw inviteBad_();
      r.st = 'active'; r.a = auth; r.ja = Date.now(); delete r.inv;
      commit_(sub_(ADM_KEY, list), [], true);
      logEvent_('ADMIN_JOINED', given, 'Invitation accepted; password created');
    });
    return { done: true };
  });
}

/* ---------- admin API: knows who is calling ---------- */
function apiAdmin(token, action, payload) {
  return safe_(function () {
    const sid = validateSession_(token);
    const P = PropertiesService.getScriptProperties();
    const info = (parse_(P.getProperty(K.SESS)) || {})[sid] || {};
    if (info.r === 's') {
      const rec = findAdmin_(readAdminsRaw_(), info.u);
      if (!rec || rec.st !== 'active') throw new AppError('SESSION', 'Your administrator access has been removed. Please sign in again.');
      CUR_USER_ = { email: info.u, primary: false };
    } else {
      const auth = parse_(P.getProperty(K.AUTH));
      CUR_USER_ = { email: auth ? auth.email : '', primary: true };
    }
    if (typeof action !== 'string' || !Object.prototype.hasOwnProperty.call(ADMIN_ACTIONS_, action)) {
      throw new AppError('BAD_ACTION', 'Unknown action.');
    }
    const p = (payload && typeof payload === 'object' && !Array.isArray(payload)) ? payload : {};
    return ADMIN_ACTIONS_[action](p, sid);
  });
}

function adminPing_(p, sid) {
  return { email: CUR_USER_.email, role: CUR_USER_.primary ? 'primary' : 'secondary', idleMs: PORTAL.SESSION_IDLE_MS };
}

function adminGetSettings_() {
  const all = readAll_();
  const auth = parse_(all[K.AUTH]);
  return {
    settings: readSettings_(all),
    adminEmail: CUR_USER_.primary ? (auth ? auth.email : '') : CUR_USER_.email,
    role: CUR_USER_.primary ? 'primary' : 'secondary',
    categories: readCats_(all)
  };
}

/** Each administrator changes only their OWN password and signs out only their OWN other sessions. */
function adminChangePassword_(p, sid) {
  ensureNotLocked_();
  const all0 = readAll_();
  const rec0 = CUR_USER_.primary ? null : findAdmin_(readAdmins_(all0), CUR_USER_.email);
  const acct0 = CUR_USER_.primary ? parse_(all0[K.AUTH]) : (rec0 && rec0.a);
  if (!acct0) throw new AppError('NOT_FOUND', 'Your account was not found.');
  if (!checkPassword_(acct0, String(p.currentPassword || ''))) {
    withLock_(function () { registerFailure_('PWD_VERIFY_FAIL', 'Wrong current password while changing password'); });
    Utilities.sleep(700);
    throw bad_('Your current password is incorrect.');
  }
  if (p.newPassword !== p.confirmPassword) throw bad_('The new password and its confirmation do not match.');
  checkPasswordPolicy_(p.newPassword);
  if (safeEqual_(String(p.newPassword), String(p.currentPassword))) throw bad_('The new password must be different from the current one.');
  const next = createAuth_(p.newPassword, acct0.email);
  withLock_(function () {
    const all = readAll_();
    const sess = parse_(all[K.SESS]) || {};
    const keep = {};
    Object.keys(sess).forEach(function (h) {
      const s = sess[h];
      const mine = CUR_USER_.primary ? (s.r !== 's') : (s.r === 's' && s.u === CUR_USER_.email);
      if (!mine || h === sid) keep[h] = s;
    });
    const sets = {}; sets[K.SESS] = JSON.stringify(keep);
    if (CUR_USER_.primary) sets[K.AUTH] = JSON.stringify(next);
    else {
      const list = readAdmins_(all);
      const r = findAdmin_(list, CUR_USER_.email);
      if (!r || r.st !== 'active') throw new AppError('NOT_FOUND', 'Your account was not found.');
      r.a = next; sets[ADM_KEY] = JSON.stringify(list);
    }
    commit_(sets, [K.THR], true);
    logEvent_('PASSWORD_CHANGED', 'Administrator', 'Other sessions of this account were signed out');
  });
  return { done: true };
}

/* ---------- Settings: only the primary may change the sign-in email ---------- */
const _saveSettingsBase_ = ADMIN_ACTIONS_.saveSettings;
ADMIN_ACTIONS_.saveSettings = function (p, sid) {
  p = Object.assign({}, p);
  if (!CUR_USER_.primary) { delete p.adminEmail; delete p.currentPassword; }
  else if (p.adminEmail !== undefined && findAdmin_(readAdmins_(readAll_()), normEmail_(p.adminEmail))) {
    throw bad_('That email is already a secondary administrator. Remove it from the Administrators page first.');
  }
  const r = _saveSettingsBase_(p, sid);
  if (!CUR_USER_.primary) r.adminEmail = CUR_USER_.email;
  return r;
};

/* ---------- Administrators page (primary only) ---------- */
function adminListAdmins_() {
  requirePrimary_();
  return adminsView_(readAll_());
}

function adminAddAdmin_(p) {
  requirePrimary_();
  const email = normEmail_(p.email);
  if (!ADM.EMAIL_RE.test(email) || email.length > 120) throw bad_('Enter a valid email address.');
  let code = null;
  withLock_(function () {
    const all = readAll_();
    const auth = parse_(all[K.AUTH]);
    if (auth && safeEqual_(email, auth.email)) throw bad_('That is the primary administrator email.');
    const list = readAdmins_(all);
    if (findAdmin_(list, email)) throw bad_('That email is already an administrator.');
    if (list.length >= ADM.MAX) throw new AppError('CAPACITY', 'Maximum of ' + ADM.MAX + ' secondary administrators reached. Remove one first.');
    code = resetCode_();
    list.push({ e: email, st: 'invited', at: Date.now(), inv: newInvite_(code) });
    commit_(sub_(ADM_KEY, list), []);
    logEvent_('ADMIN_ADDED', email, 'Invitation created');
  });
  const mailed = sendInviteMail_(email, fmtCode_(code), false);
  return Object.assign(adminsView_(readAll_()), { mailed: mailed });
}

/** New code for a pending invitation, OR a password reset for an active secondary (signs them out). */
function adminResendInvite_(p) {
  requirePrimary_();
  const email = normEmail_(p.email);
  let code = null, wasActive = false;
  withLock_(function () {
    const all = readAll_();
    const list = readAdmins_(all);
    const r = findAdmin_(list, email);
    if (!r) throw new AppError('NOT_FOUND', 'Administrator not found.');
    wasActive = r.st === 'active';
    code = resetCode_();
    r.st = 'invited'; delete r.a; delete r.ja; r.inv = newInvite_(code);
    const sets = {};
    sets[ADM_KEY] = JSON.stringify(list);
    sets[K.SESS] = JSON.stringify(purgeSessions_(parse_(all[K.SESS]) || {}, email));
    commit_(sets, [], true);
    logEvent_('ADMIN_INVITE_SENT', email, wasActive ? 'Password reset; signed out; new invitation created' : 'New invitation created');
  });
  const mailed = sendInviteMail_(email, fmtCode_(code), wasActive);
  return Object.assign(adminsView_(readAll_()), { mailed: mailed });
}

function adminRemoveAdmin_(p) {
  requirePrimary_();
  const email = normEmail_(p.email);
  withLock_(function () {
    const all = readAll_();
    const list = readAdmins_(all);
    const next = list.filter(function (r) { return r.e !== email; });
    if (next.length === list.length) throw new AppError('NOT_FOUND', 'Administrator not found.');
    const sets = {};
    sets[ADM_KEY] = JSON.stringify(next);
    sets[K.SESS] = JSON.stringify(purgeSessions_(parse_(all[K.SESS]) || {}, email));
    commit_(sets, [], true);
    logEvent_('ADMIN_REMOVED', email, 'Administrator removed; signed out');
  });
  return adminsView_(readAll_());
}

ADMIN_ACTIONS_.ping = adminPing_;
ADMIN_ACTIONS_.getSettings = adminGetSettings_;
ADMIN_ACTIONS_.changePassword = adminChangePassword_;
ADMIN_ACTIONS_.listAdmins = adminListAdmins_;
ADMIN_ACTIONS_.addAdmin = adminAddAdmin_;
ADMIN_ACTIONS_.resendInvite = adminResendInvite_;
ADMIN_ACTIONS_.removeAdmin = adminRemoveAdmin_;

/* =====================================================================
   APPLICATION FORM: CHOOSE WHICH FIELDS ARE REQUIRED
   Paste at the very END of Code.gs (below the secondary-admin block).
   Change nothing else in Code.gs.

   - Always required (cannot be changed): Application name, Application URL, Category.
   - You can switch on/off "required" for: Short description, Display label,
     Administrator notes. The choice is saved in the portal and enforced by the
     server, so it cannot be bypassed from the browser.
   - Only the primary administrator can change these rules.
   ===================================================================== */
const REQ_KEY = 'kb.req';

function readReq_() {
  let r = null;
  try { r = JSON.parse(PropertiesService.getScriptProperties().getProperty(REQ_KEY) || 'null'); } catch (e) { r = null; }
  if (!r || typeof r !== 'object') r = {};
  return { desc: r.desc !== false, label: r.label === true, notes: r.notes === true };   // defaults = how it works today
}

/* same as the original, but Description / Label / Notes follow the saved rules */
function validateApp_(p, cats) {
  const req = readReq_();
  const out = {};
  out.name = str_(p.name, 'Application name', 2, 60);
  out.url = normalizeUrl_(p.url);
  out.desc = str_(p.desc, 'Short description', req.desc ? 5 : 0, 200);
  const cat = String(p.cat || '');
  if (!cats.some(function (c) { return c.id === cat; })) throw bad_('Please choose a valid category.');
  out.cat = cat;
  const icon = String(p.icon || 'grid');
  if (!/^[a-z0-9-]{1,24}$/.test(icon)) throw bad_('Invalid icon.');
  out.icon = icon;
  out.label = str_(p.label, 'Display label', req.label ? 1 : 0, 24);
  out.active = p.active === true;
  out.qr = p.qr === true;
  out.notes = str_(p.notes, 'Administrator notes', req.notes ? 1 : 0, 300, true);
  return out;
}

function adminGetFormRules_() { return readReq_(); }

function adminSaveFormRules_(p) {
  if (typeof requirePrimary_ === 'function') requirePrimary_();      // primary administrator only
  return withLock_(function () {
    const r = { desc: p.desc === true, label: p.label === true, notes: p.notes === true };
    commit_(sub_(REQ_KEY, r), [], true);
    const on = ['desc', 'label', 'notes'].filter(function (k) { return r[k]; })
      .map(function (k) { return k === 'desc' ? 'description' : (k === 'notes' ? 'notes' : 'label'); });
    logEvent_('FORM_RULES_CHANGED', 'Application form', 'Required (besides name, URL, category): ' + (on.length ? on.join(', ') : 'none'));
    return readReq_();
  });
}
ADMIN_ACTIONS_.getFormRules = adminGetFormRules_;
ADMIN_ACTIONS_.saveFormRules = adminSaveFormRules_;

/* =====================================================================
   USER MANAGEMENT + PER-APPLICATION AUTHORIZATION
   ===================================================================== */
const KB_USR = 'kb.usr.', KB_SES = 'kb.us.', KB_LT = 'kb.lt.', KB_AS = 'kb.as.';
const USER_EMAIL_RE = /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/;
const UAUTH = {
  MAX_USERS: 100, OTP_TTL_MS: 10 * 60 * 1000, OTP_TRIES: 5, OTP_COOLDOWN_MS: 60 * 1000, OTP_PER_HOUR: 5,
  SESS_SHORT_MS: 12 * 3600 * 1000, SESS_LONG_MS: 30 * 24 * 3600 * 1000, MAX_USER_SESS: 5,
  TICKET_MS: 60 * 1000, REF_MS: 12 * 3600 * 1000
};

/* ---------- helpers ---------- */
function readUsers_(all) {
  const out = [];
  Object.keys(all).forEach(function (k) {
    if (k.indexOf(KB_USR) !== 0) return;
    const u = parse_(all[k]);
    if (u && u.id === k.slice(KB_USR.length) && typeof u.e === 'string') out.push(u);
  });
  return out.sort(function (a, b) { return String(a.n).toLowerCase() < String(b.n).toLowerCase() ? -1 : 1; });
}
function publicUser_(u) { return { id: u.id, name: u.n, email: u.e, active: !!u.a, createdAt: u.c || 0 }; }
function userList_() { return { users: readUsers_(readAll_()).map(publicUser_), max: UAUTH.MAX_USERS }; }
function userSessionKeys_(all, userId) {
  return Object.keys(all).filter(function (k) {
    if (k.indexOf(KB_SES) !== 0) return false;
    const s = parse_(all[k]);
    return !s || s.u === userId;
  });
}
function expiredUserSessions_(all, now, userId, keepN) {
  const mine = [], dead = [];
  Object.keys(all).forEach(function (k) {
    if (k.indexOf(KB_SES) !== 0) return;
    const s = parse_(all[k]);
    if (!s || now - s.c > (s.k ? UAUTH.SESS_LONG_MS : UAUTH.SESS_SHORT_MS)) { dead.push(k); return; }
    if (s.u === userId) mine.push({ k: k, c: s.c });
  });
  mine.sort(function (a, b) { return b.c - a.c; });
  mine.slice(keepN).forEach(function (m) { dead.push(m.k); });
  return dead;
}
function userCode_() {
  let c = '';
  while (c.length < 6) {
    const b = hexToBytes_(randomHex_(8));
    for (let i = 0; i < b.length && c.length < 6; i++) { const v = b[i] & 0xff; if (v < 250) c += String(v % 10); }
  }
  return c;
}
function otpBad_() { return new AppError('BAD_CODE', 'The email or code is incorrect, or the code has expired. Request a new code.'); }

/** Re-reads the session AND the user on every call, so deactivation/deletion takes effect at once. */
function userFromToken_(token) {
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) return null;
  const P = PropertiesService.getScriptProperties();
  const key = KB_SES + sha256Hex_(token).slice(0, 40);
  const s = parse_(P.getProperty(key));
  if (!s || Date.now() - s.c > (s.k ? UAUTH.SESS_LONG_MS : UAUTH.SESS_SHORT_MS)) return null;
  const u = parse_(P.getProperty(KB_USR + s.u));
  if (!u || !u.a) return null;
  return { user: u, key: key };
}

/* ---------- admin: users ---------- */
function adminListUsers_() { return userList_(); }

function adminSaveUser_(p) {
  return withLock_(function () {
    const all = readAll_();
    const users = readUsers_(all);
    const name = str_(p.name, 'Name', 2, 60);
    const email = normEmail_(p.email);
    if (!USER_EMAIL_RE.test(email) || email.length > 120) throw bad_('Enter a valid email address.');
    const ex = p.id ? users.filter(function (u) { return u.id === String(p.id); })[0] : null;
    if (p.id && !ex) throw new AppError('NOT_FOUND', 'User not found.');
    if (!ex && users.length >= UAUTH.MAX_USERS) throw new AppError('CAPACITY', 'Maximum of ' + UAUTH.MAX_USERS + ' users reached.');
    users.forEach(function (u) { if ((!ex || u.id !== ex.id) && u.e === email) throw bad_('A user with this email already exists.'); });
    let id = ex ? ex.id : '';
    if (!ex) { do { id = randomHex_(5); } while (all[KB_USR + id] !== undefined); }
    const rec = ex || { id: id, c: Date.now() };
    const wasActive = ex ? !!ex.a : true;
    const emailChanged = !!ex && ex.e !== email;
    rec.n = name; rec.e = email;
    rec.a = p.active === undefined ? (ex ? ex.a : 1) : (p.active === true ? 1 : 0);
    if (emailChanged) delete rec.o;
    commit_(sub_(KB_USR + rec.id, rec), (emailChanged || !rec.a) ? userSessionKeys_(all, rec.id) : []);
    logEvent_(ex ? 'USER_UPDATED' : 'USER_ADDED', email, '');
    if (wasActive && !rec.a) logEvent_('USER_DEACTIVATED', email, '');
    return userList_();
  });
}

function adminToggleUser_(p) {
  return withLock_(function () {
    const all = readAll_();
    const u = readUsers_(all).filter(function (x) { return x.id === String(p.id); })[0];
    if (!u) throw new AppError('NOT_FOUND', 'User not found.');
    const want = p.active === true ? 1 : 0;
    if ((u.a ? 1 : 0) !== want) {
      u.a = want;
      commit_(sub_(KB_USR + u.id, u), want ? [] : userSessionKeys_(all, u.id));
      logEvent_(want ? 'USER_ACTIVATED' : 'USER_DEACTIVATED', u.e, '');
    }
    return userList_();
  });
}

function adminDeleteUser_(p) {
  return withLock_(function () {
    const all = readAll_();
    const u = readUsers_(all).filter(function (x) { return x.id === String(p.id); })[0];
    if (!u) throw new AppError('NOT_FOUND', 'User not found.');
    const sets = {}, now = Date.now();
    loadApps_(all).list.forEach(function (a) {
      if (Array.isArray(a.au) && a.au.indexOf(u.id) >= 0) {
        a.au = a.au.filter(function (x) { return x !== u.id; }); a.updatedAt = now; sets[K.APP + a.id] = JSON.stringify(a);
      }
    });
    commit_(sets, userSessionKeys_(all, u.id).concat([KB_USR + u.id]));
    logEvent_('USER_DELETED', u.e, '');
    return userList_();
  });
}
ADMIN_ACTIONS_.listUsers = adminListUsers_;
ADMIN_ACTIONS_.saveUser = adminSaveUser_;
ADMIN_ACTIONS_.toggleUser = adminToggleUser_;
ADMIN_ACTIONS_.deleteUser = adminDeleteUser_;

/* ---------- admin: per-app access (called from adminSaveApp_) ---------- */
function validateAccess_(p, existing) {
  if (p.acc === undefined) {
    return { acc: existing && existing.acc === 'users' ? 'users' : 'open', au: existing && Array.isArray(existing.au) ? existing.au.slice() : [] };
  }
  if (p.acc !== 'users') return { acc: 'open', au: [] };
  if (!Array.isArray(p.au)) throw bad_('Select the users who may open this application.');
  const valid = {}; readUsers_(readAll_()).forEach(function (u) { valid[u.id] = 1; });
  const au = [];
  p.au.forEach(function (id) { id = String(id); if (valid[id] && au.indexOf(id) < 0) au.push(id); });
  if (!au.length) throw bad_('Select at least one user, or choose "Anyone (Open to All)".');
  return { acc: 'users', au: au };
}

/* ---------- PUBLIC: user sign-in by emailed code ---------- */
function apiUserRequestCode(email) {
  return safe_(function () {
    const given = normEmail_(email);
    let send = null;
    withLock_(function () {
      const now = Date.now();
      const u = readUsers_(readAll_()).filter(function (x) { return x.e === given; })[0];
      if (!u || !u.a) return;
      const o = u.o || {};
      const sent = (Array.isArray(o.sent) ? o.sent : []).filter(function (t) { return now - t < 3600000; });
      if (sent.length >= UAUTH.OTP_PER_HOUR || (sent.length && now - sent[sent.length - 1] < UAUTH.OTP_COOLDOWN_MS)) return;
      const code = userCode_(), salt = randomHex_(8);
      sent.push(now);
      u.o = { s: salt, h: sha256Hex_(salt + code), exp: now + UAUTH.OTP_TTL_MS, tries: 0, sent: sent };
      commit_(sub_(KB_USR + u.id, u), [], true);
      send = { to: u.e, name: u.n, code: code };
    });
    if (send) {
      try {
        MailApp.sendEmail({ to: send.to, name: 'Kisan Enterprises Portal', subject: 'Your portal sign-in code',
          body: 'Hello ' + send.name + ',\n\nYour sign-in code for the Kisan Enterprises portal is:  ' + send.code + '\n\nIt is valid for ' + (UAUTH.OTP_TTL_MS / 60000) + ' minutes and works once.\nIf you did not request it, ignore this email.' });
      } catch (err) { console.error('Sign-in email failed: ' + err); }
    } else { Utilities.sleep(1500); }
    Utilities.sleep(600);
    return { sent: true };                                       // same answer for every email
  });
}

function apiUserSignIn(email, code, remember) {
  return safe_(function () {
    const given = normEmail_(email);
    const u0 = readUsers_(readAll_()).filter(function (x) { return x.e === given; })[0];
    const o0 = u0 && u0.o;
    if (!(u0 && u0.a && o0 && o0.h && Date.now() <= o0.exp && (o0.tries || 0) < UAUTH.OTP_TRIES)) { Utilities.sleep(800); throw otpBad_(); }
    const c = String(code || '').replace(/\D/g, '').slice(0, 6);
    if (!safeEqual_(sha256Hex_(o0.s + c), o0.h)) {
      withLock_(function () {
        const cur = readUsers_(readAll_()).filter(function (x) { return x.id === u0.id; })[0];
        if (cur && cur.o && cur.o.h) { cur.o.tries = (cur.o.tries || 0) + 1; commit_(sub_(KB_USR + cur.id, cur), [], true); }
      });
      Utilities.sleep(800);
      throw otpBad_();
    }
    const keep = remember === true;
    const out = withLock_(function () {
      const all = readAll_(), now = Date.now();
      const cur = readUsers_(all).filter(function (x) { return x.id === u0.id; })[0];
      if (!cur || !cur.a || !cur.o || cur.o.h !== o0.h || now > cur.o.exp) throw otpBad_();
      cur.o = { sent: cur.o.sent || [] };                        // code is single-use
      const token = randomHex_(32);
      const sets = {};
      sets[KB_SES + sha256Hex_(token).slice(0, 40)] = JSON.stringify({ u: cur.id, c: now, k: keep ? 1 : 0 });
      sets[KB_USR + cur.id] = JSON.stringify(cur);
      commit_(sets, expiredUserSessions_(all, now, cur.id, UAUTH.MAX_USER_SESS - 1), true);
      return { token: token, name: cur.n, email: cur.e };
    });
    return out;
  });
}

function apiUserSession(token) {
  return safe_(function () {
    const s = userFromToken_(token);
    if (!s) throw new AppError('SIGNIN', 'Please sign in.');
    return { name: s.user.n, email: s.user.e };
  });
}

function apiUserSignOut(token) {
  return safe_(function () {
    if (typeof token === 'string' && /^[0-9a-f]{64}$/.test(token)) PropertiesService.getScriptProperties().deleteProperty(KB_SES + sha256Hex_(token).slice(0, 40));
    return { done: true };
  });
}

/* ---------- PUBLIC: the ONLY way a restricted app's URL leaves the server ---------- */
function apiOpenApp(token, appId) {
  return safe_(function () {
    const id = String(appId || '');
    if (!/^[a-z0-9]{6,16}$/.test(id)) throw bad_('Invalid application.');
    const all = readAll_();
    const app = loadApps_(all).list.filter(function (a) { return a.id === id; })[0];
    if (!app || !app.active) throw new AppError('NOT_FOUND', 'This application is not available.');
    if (app.acc !== 'users') throw bad_('This application does not require sign-in.');
    const s = userFromToken_(token);
    if (!s) throw new AppError('SIGNIN', 'Please sign in to open this application.');
    if ((app.au || []).indexOf(s.user.id) < 0) throw new AppError('FORBIDDEN', 'Your account is not authorized to open this application.');
    return { url: launchUrl_(app, s, all) };
  });
}

/** One-time ticket (60 s) appended to the app URL as ?kbt=. The linked app exchanges it with the portal. */
function launchUrl_(app, s, all) {
  const now = Date.now(), t = randomHex_(24), sets = {}, dels = [];
  Object.keys(all).forEach(function (k) {
    if (k.indexOf(KB_LT) === 0) { const x = parse_(all[k]); if (!x || x.x < now) dels.push(k); }
    else if (k.indexOf(KB_AS) === 0) { const x = parse_(all[k]); if (!x || now - x.c > UAUTH.REF_MS) dels.push(k); }
  });
  sets[KB_LT + sha256Hex_(t).slice(0, 40)] = JSON.stringify({ u: s.user.id, a: app.id, sk: s.key, x: now + UAUTH.TICKET_MS });
  withLock_(function () { commit_(sets, dels, true); });
  const base = normalizeUrl_(app.url), hi = base.indexOf('#');
  const head = hi < 0 ? base : base.slice(0, hi), tail = hi < 0 ? '' : base.slice(hi);
  return head + (head.indexOf('?') < 0 ? '?' : '&') + 'kbt=' + t + tail;
}

/* ---------- verification endpoint for linked apps (GET ?kbx= / ?kbc=) ---------- */
function kbAppAccess_(P, appId, userId, sessKey) {
  const app = parse_(P.getProperty(K.APP + appId));
  if (!app) return { ok: false };
  if (app.acc !== 'users') return { ok: true, open: true };
  if (!app.active || !userId || (app.au || []).indexOf(userId) < 0) return { ok: false };
  const s = parse_(P.getProperty(sessKey));
  if (!s || s.u !== userId || Date.now() - s.c > (s.k ? UAUTH.SESS_LONG_MS : UAUTH.SESS_SHORT_MS)) return { ok: false };
  const u = parse_(P.getProperty(KB_USR + userId));
  if (!u || !u.a) return { ok: false };
  return { ok: true, name: u.n, email: u.e };
}
function kbExchange_(ticket, appId) {
  if (!/^[0-9a-f]{48}$/.test(ticket)) return { ok: false };
  return withLock_(function () {
    const P = PropertiesService.getScriptProperties();
    const key = KB_LT + sha256Hex_(ticket).slice(0, 40);
    const t = parse_(P.getProperty(key));
    if (!t) return { ok: false };
    P.deleteProperty(key);                                       // single use
    if (t.a !== appId || Date.now() > t.x) return { ok: false };
    const r = kbAppAccess_(P, appId, t.u, t.sk);
    if (!r.ok || r.open) return r;
    const ref = randomHex_(24);
    commit_(sub_(KB_AS + sha256Hex_(ref).slice(0, 40), { u: t.u, a: appId, sk: t.sk, c: Date.now() }), [], true);
    r.ref = ref;
    return r;
  });
}
function kbCheck_(ref, appId) {
  const P = PropertiesService.getScriptProperties();
  const app = parse_(P.getProperty(K.APP + appId));
  if (!app) return { ok: false };
  if (app.acc !== 'users') return { ok: true, open: true };
  if (!/^[0-9a-f]{48}$/.test(ref)) return { ok: false };
  const a = parse_(P.getProperty(KB_AS + sha256Hex_(ref).slice(0, 40)));
  if (!a || a.a !== appId || Date.now() - a.c > UAUTH.REF_MS) return { ok: false };
  return kbAppAccess_(P, appId, a.u, a.sk);                      // user + allow-list re-checked every time
}
function kbVerifyJson_(prm) {
  let out = { ok: false };
  try {
    const appId = String(prm.app || '');
    if (/^[a-z0-9]{6,16}$/.test(appId)) out = prm.kbx ? kbExchange_(String(prm.kbx), appId) : kbCheck_(String(prm.kbc), appId);
  } catch (err) { out = { ok: false }; }
  return ContentService.createTextOutput(JSON.stringify(out)).setMimeType(ContentService.MimeType.JSON);
}
const _doGetBeforeUsers_ = doGet;
doGet = function (e) {
  const prm = (e && e.parameter) || {};
  if (prm.kbx || prm.kbc) return kbVerifyJson_(prm);
  return _doGetBeforeUsers_(e);
};

/* =====================================================================
   REGISTRATION CHECK BEFORE EMAIL VERIFICATION (per application)
   Replaces apiUserRequestCode: now takes the application id, and sends a
   code ONLY if the email belongs to an active user who is on that
   application's allow-list.
   ===================================================================== */
function apiUserRequestCode(email, appId) {
  return safe_(function () {
    const given = normEmail_(email);
    const id = String(appId || '');
    if (!/^[a-z0-9]{6,16}$/.test(id)) throw bad_('Invalid application.');
    let send = null, registered = false;
    withLock_(function () {
      const now = Date.now();
      const all = readAll_();
      const app = loadApps_(all).list.filter(function (a) { return a.id === id; })[0];
      if (!app || !app.active) throw new AppError('NOT_FOUND', 'This application is not available.');
      if (app.acc !== 'users') throw bad_('This application does not require sign-in.');
      const u = readUsers_(all).filter(function (x) { return x.e === given; })[0];
      // registered = exists, active, and authorized for THIS application
      if (!u || !u.a || (app.au || []).indexOf(u.id) < 0) return;
      registered = true;
      const o = u.o || {};
      const sent = (Array.isArray(o.sent) ? o.sent : []).filter(function (t) { return now - t < 3600000; });
      if (sent.length >= UAUTH.OTP_PER_HOUR || (sent.length && now - sent[sent.length - 1] < UAUTH.OTP_COOLDOWN_MS)) return;
      const code = userCode_(), salt = randomHex_(8);
      sent.push(now);
      u.o = { s: salt, h: sha256Hex_(salt + code), exp: now + UAUTH.OTP_TTL_MS, tries: 0, sent: sent };
      commit_(sub_(KB_USR + u.id, u), [], true);
      send = { to: u.e, name: u.n, code: code };
    });
    if (!registered) {
      Utilities.sleep(600);
      throw new AppError('NOT_REGISTERED', 'You are not registered for this application. Please contact the administrator.');
    }
    if (send) {
      try {
        MailApp.sendEmail({ to: send.to, name: 'Kisan Enterprises Portal', subject: 'Your portal sign-in code',
          body: 'Hello ' + send.name + ',\n\nYour sign-in code for the Kisan Enterprises portal is:  ' + send.code + '\n\nIt is valid for ' + (UAUTH.OTP_TTL_MS / 60000) + ' minutes and works once.\nIf you did not request it, ignore this email.' });
      } catch (err) { console.error('Sign-in email failed: ' + err); }
    }
    return { sent: true };
  });
}

/* =====================================================================
   GOOGLE SHEET LINK PER APPLICATION + SHEET VIEWER LIST
   ===================================================================== */
const SHEETACL_KEY = 'kb.sheetacl';

function readSheetAcl_(all) {
  const a = parse_(all[SHEETACL_KEY]);
  return Array.isArray(a) ? a.filter(function (x) { return typeof x === 'string'; }) : [];
}

/** '' = no sheet. Otherwise only https://docs.google.com/spreadsheets/... is accepted. */
function normalizeSheetUrl_(raw) {
  const s = String(raw === undefined || raw === null ? '' : raw).trim();
  if (!s) return '';
  const u = normalizeUrl_(s);
  if (!/^https:\/\/docs\.google\.com\/spreadsheets\//i.test(u)) {
    throw bad_('The Google Sheet URL must start with https://docs.google.com/spreadsheets/');
  }
  return u;
}

/* ---------- save the sheet URL together with the application ---------- */
const _saveAppBeforeSheet_ = ADMIN_ACTIONS_.saveApp;
ADMIN_ACTIONS_.saveApp = function (p, sid) {
  const hasSheet = p.sheet !== undefined;
  const given = hasSheet ? normalizeSheetUrl_(p.sheet) : '';          // validate before saving anything
  const prev = p.id ? ((parse_(readAll_()[K.APP + String(p.id)]) || {}).sheet || '') : '';
  const target = hasSheet ? given : prev;                              // the base save rebuilds the record, so re-apply
  const r = _saveAppBeforeSheet_(p, sid);
  if (!r || !r.app) return r;
  return withLock_(function () {
    const rec = parse_(readAll_()[K.APP + r.app.id]);
    if (!rec || (rec.sheet || '') === target) return r;
    if (target) rec.sheet = target; else delete rec.sheet;
    commit_(sub_(K.APP + rec.id, rec), []);
    if (hasSheet && target !== prev) logEvent_('APP_UPDATED', rec.name, 'Changed: Google Sheet link');
    r.app = scrubApp_(rec);
    r.apps = loadApps_(readAll_()).list.map(scrubApp_);
    return r;
  });
};

/* ---------- admin: list of emails allowed to see the sheet option (primary only) ---------- */
function adminGetSheetAccess_() {
  requirePrimary_();
  return { emails: readSheetAcl_(readAll_()) };
}
function adminSaveSheetAccess_(p) {
  requirePrimary_();
  const raw = String(p.emails === undefined || p.emails === null ? '' : p.emails);
  if (raw.length > 6000) throw bad_('The list is too long.');
  const out = [];
  raw.split(/[,;\s]+/).forEach(function (part) {
    if (!part) return;
    const e = normEmail_(part);
    if (!USER_EMAIL_RE.test(e) || e.length > 120) throw bad_('"' + part.slice(0, 60) + '" is not a valid email address.');
    if (out.indexOf(e) < 0) out.push(e);
  });
  if (out.length > 100) throw bad_('At most 100 email addresses are allowed.');
  return withLock_(function () {
    commit_(sub_(SHEETACL_KEY, out), []);
    logEvent_('SHEET_ACCESS_CHANGED', 'Google Sheet access', out.length + ' email(s) in the list');
    return { emails: out };
  });
}
ADMIN_ACTIONS_.getSheetAccess = adminGetSheetAccess_;
ADMIN_ACTIONS_.saveSheetAccess = adminSaveSheetAccess_;

/* ---------- PUBLIC: sign-in code for sheet viewers (not tied to an application) ---------- */
function apiSheetRequestCode(email) {
  return safe_(function () {
    const given = normEmail_(email);
    let send = null, allowed = false, limited = false;
    withLock_(function () {
      const now = Date.now();
      const all = readAll_();
      const u = readUsers_(all).filter(function (x) { return x.e === given; })[0];
      if (!u || !u.a || readSheetAcl_(all).indexOf(given) < 0) return;
      allowed = true;
      const o = u.o || {};
      const sent = (Array.isArray(o.sent) ? o.sent : []).filter(function (t) { return now - t < 3600000; });
      if (sent.length >= UAUTH.OTP_PER_HOUR || (sent.length && now - sent[sent.length - 1] < UAUTH.OTP_COOLDOWN_MS)) { limited = true; return; }
      const code = userCode_(), salt = randomHex_(8);
      sent.push(now);
      u.o = { s: salt, h: sha256Hex_(salt + code), exp: now + UAUTH.OTP_TTL_MS, tries: 0, sent: sent };
      commit_(sub_(KB_USR + u.id, u), [], true);
      send = { to: u.e, name: u.n, code: code };
    });
    if (!allowed) {
      Utilities.sleep(600);
      throw new AppError('NOT_ALLOWED', 'This email is not authorized for Google Sheet access. Please contact the administrator.');
    }
    if (limited) throw new AppError('RATE_LIMITED', 'A code was requested recently. Please wait a minute, check your inbox and spam folder, then try again.');
    if (send) {
      try {
        MailApp.sendEmail({ to: send.to, name: 'Kisan Enterprises Portal', subject: 'Your portal sign-in code',
          body: 'Hello ' + send.name + ',\n\nYour sign-in code for the Kisan Enterprises portal is:  ' + send.code + '\n\nIt is valid for ' + (UAUTH.OTP_TTL_MS / 60000) + ' minutes and works once.\nIf you did not request it, ignore this email.' });
      } catch (err) { console.error('Sign-in email failed: ' + err); }
    }
    return { sent: true };
  });
}

/* ---------- PUBLIC: sheet links, returned ONLY to administrators and listed, signed-in users ---------- */
function apiGetSheets(userToken, adminToken) {
  return safe_(function () {
    let allowed = false;
    if (typeof adminToken === 'string' && adminToken) {
      try { validateSession_(adminToken); allowed = true; } catch (e) { /* not an admin session */ }
    }
    const all = readAll_();
    if (!allowed && typeof userToken === 'string' && userToken) {
      const s = userFromToken_(userToken);
      if (s && readSheetAcl_(all).indexOf(s.user.e) >= 0) allowed = true;
    }
    if (!allowed) return { sheets: [] };
    const out = [];
    loadApps_(all).list.forEach(function (a) {
      if (!a.active || !a.sheet) return;
      try { out.push({ id: a.id, url: normalizeSheetUrl_(a.sheet) }); } catch (e) { /* skip invalid */ }
    });
    return { sheets: out };
  });
}
function include_(name) {
  return HtmlService.createHtmlOutputFromFile(name).getContent();
}
