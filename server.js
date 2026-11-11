// THERCAY - Global Chat + Chat Pribadi (Node.js) untuk panel Pterodactyl
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');

const PORT = process.env.SERVER_PORT || process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });

const FILES = {
  users: path.join(DATA, 'users.json'),
  msgs: path.join(DATA, 'messages.json'),
  sess: path.join(DATA, 'sessions.json'),
  dms: path.join(DATA, 'dms.json'),
  reads: path.join(DATA, 'reads.json'),
  statuses: path.join(DATA, 'statuses.json'),
  meta: path.join(DATA, 'meta.json'),
};
const load = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } };
const users = load(FILES.users, {});      // key(lowercase) -> {name,salt,hash,avatar,av,created,muted,banned,banReason}
const msgs = load(FILES.msgs, []);        // 200 pesan terakhir
const sess = load(FILES.sess, {});        // token -> key
const dms = load(FILES.dms, {});          // 'a|b' (urut) -> pesan pribadi
const reads = load(FILES.reads, {});      // key -> { keyLawan: waktuBacaTerakhir }
const meta = load(FILES.meta, { locked: false, lockedBy: null }); // status global chat (dikunci admin atau tidak)
const pairKey = (a, b) => [a, b].sort().join('|');
// 1 perangkat = 1 akun. Perangkat dikenali lewat id di localStorage + cookie. Isi ONE_DEVICE=0 di panel untuk mematikan aturan ini.
const ONE_DEVICE = process.env.ONE_DEVICE !== '0';
const validDev = (d) => (typeof d === 'string' && /^[A-Za-z0-9_-]{16,64}$/.test(d) ? d : null);
const cookieDev = (hdr) => {
  const m = /(?:^|;\s*)pc_dev=([A-Za-z0-9_-]{16,64})/.exec(String(hdr || ''));
  return m ? m[1] : null;
};
const validFp = (f) => (typeof f === 'string' && /^[a-f0-9]{16,64}$/.test(f) ? f : null);
// sidik perangkat (dari hardware/layar/GPU) - tetap sama walau IP/VPN ganti, data dihapus, atau pakai mode samaran
const addFp = (key, fp) => {
  const u = users[key];
  fp = validFp(fp);
  if (!u || !fp || (u.fps || []).includes(fp)) return;
  u.fps = [...(u.fps || []), fp].slice(-6);
  save('users', users);
};
// daftar perangkat milik akun yang di-band: dicatat di meta.blk supaya tetap berlaku walau akunnya dihapus
if (!meta.blk) meta.blk = {};
const blkAdd = (key) => {
  const u = users[key];
  if (!u) return;
  const old = meta.blk[key] || { devs: [], fps: [] };
  meta.blk[key] = {
    devs: [...new Set([...(old.devs || []), ...(u.devs || [])])].slice(-12),
    fps: [...new Set([...(old.fps || []), ...(u.fps || [])])].slice(-12),
    at: old.at || Date.now(),
  };
  save('meta', meta);
};
const blockedBy = (ids, fp) => {
  fp = validFp(fp);
  return Object.keys(meta.blk).find((k) => {
    const b = meta.blk[k];
    return (b.devs || []).some((d) => ids.includes(d)) || (fp && (b.fps || []).includes(fp));
  }) || null;
};
const idsOf = (headerDev, cookieHdr) => [...new Set([validDev(headerDev), cookieDev(cookieHdr)].filter(Boolean))];
const reqIds = (req) => idsOf(req.headers['x-device'] || (req.body && req.body.dev), req.headers.cookie);
// akun (key) yang sudah terikat ke salah satu id perangkat ini
const ownerOfDev = (ids) => Object.keys(users).find((k) => (users[k].devs || []).some((d) => ids.includes(d))) || null;
// ikat perangkat ke akun: akun baru selalu diikat; akun lama diikat oleh perangkat pertama yang membukanya
const bindDevice = (key, ids, force) => {
  const u = users[key];
  if (!u || !ids.length) return;
  if (!force && (u.devs || []).length) return;
  u.devs = [...new Set([...(u.devs || []), ...ids])].slice(0, 6);
  save('users', users);
};
// file sekali-lihat: hanya bisa diambil lewat token sementara milik pembuka
const voFiles = new Set();
const voTok = new Map(); // token -> { file, key, exp }
const voScan = () => {
  msgs.forEach((x) => { if (x && x.viewOnce && x.media) voFiles.add(x.media.file); });
  Object.values(dms).forEach((arr) => (arr || []).forEach((x) => { if (x && x.viewOnce && x.media) voFiles.add(x.media.file); }));
};
setInterval(() => { const n = Date.now(); for (const [k, v] of voTok) if (v.exp < n) voTok.delete(k); }, 60 * 1000).unref();

const timers = {};
const save = (k, obj) => {
  clearTimeout(timers[k]);
  timers[k] = setTimeout(() => {
    fs.writeFile(FILES[k] + '.tmp', JSON.stringify(obj), (e) => {
      if (!e) fs.rename(FILES[k] + '.tmp', FILES[k], () => {});
    });
  }, 300);
};

const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const validAvatar = (a) =>
  typeof a === 'string' && a.length < 250000 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(a) ? a : null;

// batas percobaan login/daftar per IP
const hits = new Map();
const limiter = (req, res, next) => {
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
  const now = Date.now();
  const h = hits.get(ip) || { n: 0, t: now };
  if (now - h.t > 60000) { h.n = 0; h.t = now; }
  h.n++;
  hits.set(ip, h);
  if (h.n > 20) return res.status(429).json({ error: 'Terlalu banyak percobaan, tunggu semenit' });
  next();
};
setInterval(() => hits.clear(), 10 * 60 * 1000).unref();

// ---------- status (24 jam) ----------
const MEDIA = path.join(DATA, 'media');
fs.mkdirSync(MEDIA, { recursive: true });
const STK = path.join(DATA, 'stickers');
fs.mkdirSync(STK, { recursive: true });
const MAX_STK = 60;
const validSticker = (f) => typeof f === 'string' && /^[a-f0-9]{24}\.(png|webp)$/.test(f) && fs.existsSync(path.join(STK, f)) ? f : null;
const validMediaFile = (f) => typeof f === 'string' && /^[a-f0-9]{24}\.(jpg|png|webp|mp4|webm|mov|m4a|mp3|ogg|aac|wav)$/.test(f) && fs.existsSync(path.join(MEDIA, f)) ? f : null;
const mediaTypeOf = (f) => {
  if (!f) return null;
  if (/\.(jpg|png|webp)$/i.test(f)) return 'image';
  if (/\.(mp4|webm|mov)$/i.test(f)) return 'video';
  if (/\.(m4a|mp3|ogg|aac|wav)$/i.test(f)) return 'audio';
  return null;
};
const stkPreview = (m) => {
  if (!m) return '';
  if (m.sticker) return 'Stiker';
  if (m.media) {
    const t = m.media.type || mediaTypeOf(m.media.file);
    if (m.viewOnce) return t === 'video' ? 'Video sekali lihat' : 'Foto sekali lihat';
    return t === 'video' ? 'Video' : t === 'audio' ? 'Audio' : 'Foto';
  }
  return String(m.text || '').slice(0, 120);
};
const statuses = load(FILES.statuses, []);
const DAY = 24 * 60 * 60 * 1000;
const MAXMEDIA = 30 * 1024 * 1024;
const EXT = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp',
  'video/mp4': 'mp4', 'video/webm': 'webm', 'video/quicktime': 'mov',
  'audio/mpeg': 'mp3', 'audio/mp4': 'm4a', 'audio/aac': 'aac', 'audio/ogg': 'ogg', 'audio/wav': 'wav', 'audio/webm': 'webm', 'audio/x-m4a': 'm4a',
};
const dropFile = (f) => { if (f) fs.unlink(path.join(MEDIA, f), () => {}); };
const cleanup = () => {
  const now = Date.now();
  let ch = false;
  for (let i = statuses.length - 1; i >= 0; i--) {
    if (now - statuses[i].t > DAY) { dropFile(statuses[i].file); statuses.splice(i, 1); ch = true; }
  }
  if (ch) save('statuses', statuses);
};
cleanup();
setInterval(cleanup, 30 * 60 * 1000).unref();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e5 });

app.use(express.json({ limit: '400kb' }));
app.get('/', (req, res) => {
  if (!cookieDev(req.headers.cookie)) {
    res.cookie('pc_dev', crypto.randomBytes(16).toString('hex'), { maxAge: 5 * 365 * 24 * 3600 * 1000, httpOnly: true, sameSite: 'lax', path: '/' });
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PROFILE_CD = 3 * 24 * 60 * 60 * 1000; // 3 hari
const remainCd = (ts) => Math.max(0, PROFILE_CD - (Date.now() - (ts || 0)));
const cdMsg = (remain) => {
  const h = Math.ceil(remain / 3600000);
  const d = Math.floor(h / 24), hh = h % 24;
  return d > 0 ? `Bisa diubah lagi dalam ${d} hari ${hh} jam` : `Bisa diubah lagi dalam ${h} jam`;
};
// akun admin = Developer (nama dicadangkan, tidak bisa dipakai lewat ganti username)
const ADMIN_KEY = String(process.env.ADMIN_USER || 'estheryu').toLowerCase();
const isAdminKey = (k) => k === ADMIN_KEY;
// role tambahan yang diatur Developer: vip / owner (hanya badge)
const ROLES = ['vip', 'owner'];
const roleOfKey = (k) => (!isAdminKey(k) && users[k] && ROLES.includes(users[k].role)) ? users[k].role : '';
// peta badge untuk client: { usernameLowercase: { d: developer, v: centang biru, r: 'vip' | 'owner' | '' } }
const rolesMap = () => {
  const o = {};
  for (const k of Object.keys(users)) {
    const d = isAdminKey(k), v = d || !!users[k].verified, r = roleOfKey(k);
    if (d || v || r) o[k] = { d: d ? 1 : 0, v: v ? 1 : 0, r };
  }
  return o;
};
const pub = (key) => {
  const u = users[key];
  // backward compat: profileAt lama dianggap untuk keduanya
  const avatarAt = u.avatarAt != null ? u.avatarAt : (u.profileAt || 0);
  const nameAt = u.nameAt != null ? u.nameAt : (u.profileAt || 0);
  const nextAvatar = remainCd(avatarAt);
  const nextName = remainCd(nameAt);
  return {
    name: u.name,
    av: u.av,
    seen: u.seen || 0,
    joined: u.created || 0,
    admin: isAdminKey(key),
    verified: isAdminKey(key) || !!u.verified,
    u: u.name, // alias biar client lama/gagal parse tetap kebaca
    canEditAvatar: nextAvatar === 0,
    canEditName: nextName === 0,
    nextAvatar,
    nextName,
    // legacy fields
    canEdit: nextAvatar === 0 && nextName === 0,
    nextEdit: Math.max(nextAvatar, nextName),
    profileAt: Math.max(avatarAt, nameAt),
  };
};
const newSession = (key) => {
  const token = crypto.randomBytes(32).toString('hex');
  sess[token] = key;
  save('sess', sess);
  return { token, user: pub(key) };
};
const auth = (req, res, next) => {
  const token = req.headers['x-token'];
  const key = sess[token];
  if (!key || !users[key]) return res.status(401).json({ error: 'Sesi habis, masuk lagi' });
  if (users[key].banned) {
    delete sess[token];
    save('sess', sess);
    return res.status(403).json({ error: 'Akun kamu di-ban' + (users[key].banReason ? ': ' + users[key].banReason : '') });
  }
  req.key = key;
  next();
};
// hapus semua sesi + putuskan semua koneksi socket milik sebuah akun (dipakai saat ban)
const dropSockets = (key) => {
  for (const [, sock] of io.of('/').sockets) {
    if (sock.key === key) sock.disconnect(true);
  }
};
const kickUser = (key) => {
  for (const t of Object.keys(sess)) if (sess[t] === key) delete sess[t];
  save('sess', sess);
  dropSockets(key);
};
const checkAvatarCd = (key) => {
  const u = users[key];
  const ts = u.avatarAt != null ? u.avatarAt : (u.profileAt || 0);
  const r = remainCd(ts);
  return r > 0 ? cdMsg(r) : null;
};
const checkNameCd = (key) => {
  const u = users[key];
  const ts = u.nameAt != null ? u.nameAt : (u.profileAt || 0);
  const r = remainCd(ts);
  return r > 0 ? cdMsg(r) : null;
};
// pindah key username (untuk rename)
const renameUser = (oldKey, newKey, newName) => {
  const u = users[oldKey];
  u.name = newName;
  users[newKey] = u;
  if (oldKey !== newKey) delete users[oldKey];
  // sesi
  for (const t of Object.keys(sess)) if (sess[t] === oldKey) sess[t] = newKey;
  // dms pair key
  const ndms = {};
  for (const pk of Object.keys(dms)) {
    let [a, b] = pk.split('|');
    if (a === oldKey) a = newKey;
    if (b === oldKey) b = newKey;
    const npk = pairKey(a, b);
    ndms[npk] = (ndms[npk] || []).concat(dms[pk] || []);
  }
  // dedupe by id
  for (const pk of Object.keys(ndms)) {
    const seen = new Set();
    ndms[pk] = ndms[pk].filter((m) => (seen.has(m.id) ? false : (seen.add(m.id), true)));
  }
  Object.keys(dms).forEach((k) => delete dms[k]);
  Object.assign(dms, ndms);
  // reads
  if (reads[oldKey]) {
    reads[newKey] = Object.assign(reads[newKey] || {}, reads[oldKey]);
    delete reads[oldKey];
  }
  for (const k of Object.keys(reads)) {
    if (reads[k][oldKey] != null) {
      reads[k][newKey] = reads[k][oldKey];
      delete reads[k][oldKey];
    }
  }
  // statuses
  for (const s of statuses) {
    if (s.key === oldKey) { s.key = newKey; s.u = newName; }
    s.views = (s.views || []).map((v) => (v === oldKey ? newKey : v));
    s.likes = (s.likes || []).map((v) => (v === oldKey ? newKey : v));
  }
  save('users', users);
  save('sess', sess);
  save('dms', dms);
  save('reads', reads);
  save('statuses', statuses);
};

app.post('/api/register', limiter, (req, res) => {
  const u = String(req.body.username || '').trim();
  const p = String(req.body.password || '');
  if (!/^[A-Za-z0-9_]{3,16}$/.test(u)) return res.status(400).json({ error: 'Username 3-16 karakter (huruf, angka, _)' });
  if (p.length < 4 || p.length > 64) return res.status(400).json({ error: 'Password minimal 4 karakter' });
  const key = u.toLowerCase();
  const ids = reqIds(req);
  const fp = validFp(req.headers['x-fp']);
  if (blockedBy(ids, fp)) {
    return res.status(403).json({ error: 'Perangkat ini terkait akun yang di-band, tidak bisa daftar akun baru. Hubungi admin buat unband.' });
  }
  if (ONE_DEVICE) {
    const own = ownerOfDev(ids);
    if (own) {
      return res.status(403).json({
        error: users[own].banned
          ? 'Perangkat ini punya akun yang di-band, tidak bisa daftar akun baru. Hubungi admin buat unband.'
          : 'Perangkat ini sudah punya akun (' + users[own].name + '). 1 perangkat cuma bisa 1 akun, minta admin hapus akun lamamu dulu.',
      });
    }
  }
  if (users[key]) return res.status(409).json({ error: 'Username sudah dipakai' });
  const salt = crypto.randomBytes(16).toString('hex');
  users[key] = { name: u, salt, hash: hashPw(p, salt), avatar: validAvatar(req.body.avatar), av: Date.now(), created: Date.now() };
  bindDevice(key, ids, true);
  addFp(key, fp);
  save('users', users);
  res.json(newSession(key));
});

app.post('/api/login', limiter, (req, res) => {
  const u = String(req.body.username || '').trim().toLowerCase();
  const p = String(req.body.password || '');
  const user = users[u];
  if (!user) return res.status(401).json({ error: 'Username belum terdaftar' });
  if (user.banned) {
    bindDevice(u, reqIds(req), false);
    user.devs = [...new Set([...(user.devs || []), ...reqIds(req)])].slice(-12);
    addFp(u, req.headers['x-fp']);
    blkAdd(u);
    return res.status(403).json({ error: 'Akun kamu di-ban' + (user.banReason ? ': ' + user.banReason : '') });
  }
  const a = Buffer.from(hashPw(p, user.salt), 'hex');
  const b = Buffer.from(user.hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Password salah' });
  bindDevice(u, reqIds(req), false);
  addFp(u, req.headers['x-fp']);
  res.json(newSession(u));
});

app.get('/api/me', auth, (req, res) => res.json({ user: pub(req.key) }));

app.get('/api/user/:name', auth, (req, res) => {
  const k = String(req.params.name || '').trim().toLowerCase();
  if (!users[k]) return res.status(404).json({ error: 'Username tidak ditemukan' });
  if (k === req.key) return res.status(400).json({ error: 'Itu akun kamu sendiri' });
  res.json({ user: pub(k) });
});

app.post('/api/avatar', auth, (req, res) => {
  const cd = checkAvatarCd(req.key);
  if (cd) return res.status(429).json({ error: cd });
  const a = validAvatar(req.body.avatar);
  if (!a) return res.status(400).json({ error: 'Foto tidak valid' });
  const user = users[req.key];
  user.avatar = a;
  user.av = Date.now();
  user.avatarAt = Date.now();
  save('users', users);
  io.emit('avatar', { u: user.name, av: user.av });
  res.json({ av: user.av, user: pub(req.key) });
});

// ubah avatar dan/atau username — cooldown terpisah 3 hari
app.post('/api/profile', auth, (req, res) => {
  const user = users[req.key];
  const oldKey = req.key;
  const oldName = user.name;
  let changed = false;
  let didAvatar = false;
  let didName = false;

  // avatar
  if (req.body.avatar !== undefined) {
    const cd = checkAvatarCd(req.key);
    if (cd) return res.status(429).json({ error: 'Avatar: ' + cd });
    const a = validAvatar(req.body.avatar);
    if (!a) return res.status(400).json({ error: 'Foto tidak valid' });
    user.avatar = a;
    user.av = Date.now();
    user.avatarAt = Date.now();
    changed = true;
    didAvatar = true;
  }

  // username
  let newName = req.body.username != null ? String(req.body.username).trim() : null;
  if (newName != null && newName !== oldName) {
    const cd = checkNameCd(req.key);
    if (cd) return res.status(429).json({ error: 'Username: ' + cd });
    if (!/^[A-Za-z0-9_]{3,16}$/.test(newName)) {
      return res.status(400).json({ error: 'Username 3-16 karakter (huruf, angka, _)' });
    }
    const newKey = newName.toLowerCase();
    if (isAdminKey(oldKey) && newKey !== oldKey) {
      return res.status(403).json({ error: 'Akun Developer tidak bisa ganti username' });
    }
    if (isAdminKey(newKey) && oldKey !== newKey) {
      return res.status(403).json({ error: 'Username ini dicadangkan' });
    }
    if (users[newKey] && newKey !== oldKey) {
      return res.status(409).json({ error: 'Username sudah dipakai' });
    }
    if (newKey === oldKey) {
      user.name = newName;
      for (const s of statuses) if (s.key === oldKey) s.u = newName;
      save('statuses', statuses);
    } else {
      renameUser(oldKey, newKey, newName);
      if (typeof online !== 'undefined' && online.has(oldKey)) {
        online.set(newKey, online.get(oldKey));
        online.delete(oldKey);
      }
      for (const [, sock] of io.of('/').sockets) {
        if (sock.key === oldKey) {
          sock.key = newKey;
          sock.leave('u:' + oldKey);
          sock.join('u:' + newKey);
        }
      }
      req.key = newKey;
    }
    users[req.key].nameAt = Date.now();
    changed = true;
    didName = true;
    io.emit('rename', { from: oldName, to: newName, av: users[req.key].av });
    io.emit('roles', rolesMap());
    io.emit('online', onlineList());
  }

  if (!changed) return res.status(400).json({ error: 'Tidak ada perubahan' });
  save('users', users);
  if (didAvatar) io.emit('avatar', { u: users[req.key].name, av: users[req.key].av });
  res.json({ ok: true, user: pub(req.key) });
});

app.post('/api/logout', auth, (req, res) => {
  delete sess[req.headers['x-token']];
  save('sess', sess);
  res.json({ ok: true });
});

// ----- status -----
const limitStatus = (req, res, next) => {
  const n = statuses.filter((s) => s.key === req.key && Date.now() - s.t <= DAY).length;
  if (n >= 20) return res.status(400).json({ error: 'Maksimal 20 status aktif' });
  next();
};
const addStatus = (req, res, data) => {
  const me = users[req.key];
  statuses.push(Object.assign({ id: crypto.randomBytes(8).toString('hex'), key: req.key, u: me.name, t: Date.now(), views: [] }, data));
  save('statuses', statuses);
  io.emit('status:update', { u: me.name });
  res.json({ ok: true });
};

app.post('/api/status/text', auth, limitStatus, (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 300);
  if (!text) return res.status(400).json({ error: 'Tulis sesuatu dulu' });
  const bg = Math.max(0, Math.min(5, parseInt(req.body.bg, 10) || 0));
  addStatus(req, res, { type: 'text', text, bg });
});

app.post('/api/status/media', auth, limitStatus,
  express.raw({ type: (r) => /^(image|video)\//.test(r.headers['content-type'] || ''), limit: MAXMEDIA }),
  (req, res) => {
    const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    const ext = EXT[mime];
    if (!ext) return res.status(400).json({ error: 'Format tidak didukung (jpg, png, webp, mp4, webm, mov)' });
    if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'File kosong' });
    let caption = '';
    try { caption = decodeURIComponent(String(req.headers['x-caption'] || '')); } catch (e) {}
    caption = caption.trim().slice(0, 200);
    const file = crypto.randomBytes(12).toString('hex') + '.' + ext;
    fs.writeFile(path.join(MEDIA, file), req.body, (e) => {
      if (e) return res.status(500).json({ error: 'Gagal menyimpan file' });
      addStatus(req, res, { type: mime.startsWith('video') ? 'video' : 'image', caption, file });
    });
  });

app.get('/api/statuses', auth, (req, res) => {
  const now = Date.now();
  const by = {};
  for (const s of statuses) {
    if (now - s.t > DAY || !users[s.key]) continue;
    const own = s.key === req.key;
    const it = { id: s.id, type: s.type, text: s.text, bg: s.bg, caption: s.caption, url: s.file ? '/media/' + s.file : null, t: s.t, seen: own || s.views.includes(req.key) };
    const likes = (s.likes || []).filter((k) => users[k]);
    if (own) {
      it.viewers = s.views.filter((k) => users[k]).map((k) => users[k].name);
      it.likes = likes.map((k) => users[k].name);
    } else {
      it.liked = likes.includes(req.key);
    }
    (by[s.key] = by[s.key] || []).push(it);
  }
  const groups = Object.keys(by).map((k) => {
    const items = by[k].sort((a, b) => a.t - b.t);
    return { u: users[k].name, av: users[k].av, items, allSeen: items.every((i) => i.seen) };
  });
  groups.sort((a, b) => (a.allSeen - b.allSeen) || (b.items[b.items.length - 1].t - a.items[a.items.length - 1].t));
  res.json({ groups });
});

app.post('/api/status/:id/view', auth, (req, res) => {
  const s = statuses.find((x) => x.id === req.params.id);
  if (s && s.key !== req.key && !s.views.includes(req.key)) { s.views.push(req.key); save('statuses', statuses); }
  res.json({ ok: true });
});

app.post('/api/status/:id/like', auth, (req, res) => {
  const s = statuses.find((x) => x.id === req.params.id);
  if (!s || Date.now() - s.t > DAY || !users[s.key]) return res.status(404).json({ error: 'Status sudah tidak tersedia' });
  if (s.key === req.key) return res.status(400).json({ error: 'Tidak bisa menyukai status sendiri' });
  s.likes = s.likes || [];
  const i = s.likes.indexOf(req.key);
  let liked;
  if (i >= 0) { s.likes.splice(i, 1); liked = false; }
  else {
    s.likes.push(req.key); liked = true;
    if (!s.views.includes(req.key)) s.views.push(req.key);
  }
  save('statuses', statuses);
  io.to('u:' + s.key).emit('status:like', { u: users[req.key].name, id: s.id, liked });
  res.json({ ok: true, liked, count: s.likes.length });
});

app.post('/api/status/:id/delete', auth, (req, res) => {
  const admin = isAdminKey(req.key); // admin boleh menghapus status siapa pun
  const i = statuses.findIndex((x) => x.id === req.params.id && (admin || x.key === req.key));
  if (i < 0) return res.status(404).json({ error: 'Status tidak ditemukan' });
  dropFile(statuses[i].file);
  statuses.splice(i, 1);
  save('statuses', statuses);
  io.emit('status:update', {});
  res.json({ ok: true });
});

// ----- stiker -----
const MAX_PACKS = 12;
const MAX_PACK_STK = 30;
const stkOut = (x) => ({ id: x.id, file: x.file, url: '/sticker/' + x.file });
const packOut = (p) => ({
  id: p.id,
  name: p.name,
  stickers: (p.stickers || []).map((f) => ({ file: f, url: '/sticker/' + f })),
  t: p.t || 0,
});
const ensureStk = (u) => {
  u.stickers = u.stickers || [];
  u.favStickers = u.favStickers || [];
  u.stickerPacks = u.stickerPacks || [];
};
app.get('/api/stickers', auth, (req, res) => {
  const u = users[req.key];
  ensureStk(u);
  res.json({
    stickers: u.stickers.map(stkOut),
    favorites: u.favStickers.filter((f) => validSticker(f)).map((f) => ({ file: f, url: '/sticker/' + f })),
    packs: u.stickerPacks.map(packOut),
    max: MAX_STK,
    maxPacks: MAX_PACKS,
  });
});
app.post('/api/stickers', auth,
  express.raw({ type: ['image/png', 'image/webp'], limit: 700 * 1024 }),
  (req, res) => {
    const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    const ext = mime === 'image/png' ? 'png' : mime === 'image/webp' ? 'webp' : null;
    const b = req.body;
    if (!ext || !Buffer.isBuffer(b) || b.length < 100) return res.status(400).json({ error: 'Gambar stiker tidak valid' });
    const okMagic = ext === 'png'
      ? b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
      : b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP';
    if (!okMagic) return res.status(400).json({ error: 'Format stiker tidak dikenali' });
    const u = users[req.key];
    ensureStk(u);
    if (u.stickers.length >= MAX_STK) return res.status(400).json({ error: 'Maksimal ' + MAX_STK + ' stiker, hapus dulu yang lama' });
    const file = crypto.randomBytes(12).toString('hex') + '.' + ext;
    fs.writeFile(path.join(STK, file), b, (e) => {
      if (e) return res.status(500).json({ error: 'Gagal menyimpan stiker' });
      const rec = { id: crypto.randomBytes(6).toString('hex'), file, t: Date.now() };
      u.stickers.unshift(rec);
      save('users', users);
      res.json({ ok: true, sticker: stkOut(rec) });
    });
  });
// simpan stiker dari chat orang lain ke koleksi sendiri
app.post('/api/stickers/add', auth, (req, res) => {
  const file = validSticker(req.body && req.body.file);
  if (!file) return res.status(400).json({ error: 'Stiker tidak ditemukan' });
  const u = users[req.key];
  ensureStk(u);
  if (u.stickers.some((x) => x.file === file)) return res.status(409).json({ error: 'Stiker ini sudah ada di koleksimu' });
  if (u.stickers.length >= MAX_STK) return res.status(400).json({ error: 'Maksimal ' + MAX_STK + ' stiker, hapus dulu yang lama' });
  const rec = { id: crypto.randomBytes(6).toString('hex'), file, t: Date.now() };
  u.stickers.unshift(rec);
  save('users', users);
  res.json({ ok: true, sticker: stkOut(rec) });
});
// favorit: on/off
app.post('/api/stickers/favorite', auth, (req, res) => {
  const file = validSticker(req.body && req.body.file);
  if (!file) return res.status(400).json({ error: 'Stiker tidak ditemukan' });
  const u = users[req.key];
  ensureStk(u);
  const on = !!(req.body && req.body.on);
  const i = u.favStickers.indexOf(file);
  if (on && i < 0) u.favStickers.unshift(file);
  if (!on && i >= 0) u.favStickers.splice(i, 1);
  if (u.favStickers.length > 40) u.favStickers.length = 40;
  save('users', users);
  res.json({ ok: true, on: u.favStickers.includes(file), favorites: u.favStickers.filter((f) => validSticker(f)).map((f) => ({ file: f, url: '/sticker/' + f })) });
});
// paket stiker
app.post('/api/stickers/packs', auth, (req, res) => {
  const name = String((req.body && req.body.name) || '').trim().slice(0, 24);
  if (!name) return res.status(400).json({ error: 'Nama paket wajib diisi' });
  const u = users[req.key];
  ensureStk(u);
  if (u.stickerPacks.length >= MAX_PACKS) return res.status(400).json({ error: 'Maksimal ' + MAX_PACKS + ' paket' });
  const pack = { id: crypto.randomBytes(6).toString('hex'), name, stickers: [], t: Date.now() };
  u.stickerPacks.push(pack);
  save('users', users);
  res.json({ ok: true, pack: packOut(pack) });
});
app.post('/api/stickers/packs/:id/rename', auth, (req, res) => {
  const name = String((req.body && req.body.name) || '').trim().slice(0, 24);
  if (!name) return res.status(400).json({ error: 'Nama paket wajib diisi' });
  const u = users[req.key];
  ensureStk(u);
  const p = u.stickerPacks.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Paket tidak ada' });
  p.name = name;
  save('users', users);
  res.json({ ok: true, pack: packOut(p) });
});
app.post('/api/stickers/packs/:id/add', auth, (req, res) => {
  const file = validSticker(req.body && req.body.file);
  if (!file) return res.status(400).json({ error: 'Stiker tidak ditemukan' });
  const u = users[req.key];
  ensureStk(u);
  const p = u.stickerPacks.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Paket tidak ada' });
  p.stickers = p.stickers || [];
  if (p.stickers.includes(file)) return res.status(409).json({ error: 'Stiker sudah ada di paket ini' });
  if (p.stickers.length >= MAX_PACK_STK) return res.status(400).json({ error: 'Paket penuh (maks ' + MAX_PACK_STK + ')' });
  p.stickers.push(file);
  save('users', users);
  res.json({ ok: true, pack: packOut(p) });
});
app.post('/api/stickers/packs/:id/remove', auth, (req, res) => {
  const file = String((req.body && req.body.file) || '');
  const u = users[req.key];
  ensureStk(u);
  const p = u.stickerPacks.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Paket tidak ada' });
  p.stickers = (p.stickers || []).filter((f) => f !== file);
  save('users', users);
  res.json({ ok: true, pack: packOut(p) });
});
app.post('/api/stickers/packs/:id/delete', auth, (req, res) => {
  const u = users[req.key];
  ensureStk(u);
  const i = u.stickerPacks.findIndex((x) => x.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'Paket tidak ada' });
  u.stickerPacks.splice(i, 1);
  save('users', users);
  res.json({ ok: true });
});
app.post('/api/stickers/:id/delete', auth, (req, res) => {
  const u = users[req.key];
  ensureStk(u);
  const i = u.stickers.findIndex((x) => x.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'Stiker tidak ditemukan' });
  const file = u.stickers[i].file;
  u.stickers.splice(i, 1);
  u.favStickers = u.favStickers.filter((f) => f !== file);
  u.stickerPacks.forEach((p) => { p.stickers = (p.stickers || []).filter((f) => f !== file); });
  save('users', users);
  res.json({ ok: true });
});
app.get('/sticker/:file', (req, res) => {
  if (!/^[a-f0-9]{24}\.(png|webp)$/.test(req.params.file)) return res.sendStatus(404);
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.sendFile(path.join(STK, req.params.file), (e) => { if (e && !res.headersSent) res.sendStatus(404); });
});
// bersihkan file stiker yang sudah tidak dipakai siapa pun (koleksi, global chat, dm, favorit, paket)
const cleanStickers = () => {
  const ref = new Set();
  for (const k of Object.keys(users)) {
    const u = users[k];
    (u.stickers || []).forEach((x) => ref.add(x.file));
    (u.favStickers || []).forEach((f) => ref.add(f));
    (u.stickerPacks || []).forEach((p) => (p.stickers || []).forEach((f) => ref.add(f)));
  }
  msgs.forEach((m) => { if (m.sticker) ref.add(m.sticker); });
  Object.values(dms).forEach((arr) => arr.forEach((m) => { if (m.sticker) ref.add(m.sticker); }));
  fs.readdir(STK, (e, files) => {
    if (e) return;
    const now = Date.now();
    files.forEach((f) => {
      if (ref.has(f)) return;
      const fp = path.join(STK, f);
      fs.stat(fp, (e2, stt) => { if (!e2 && now - stt.mtimeMs > 3600000) fs.unlink(fp, () => {}); });
    });
  });
};
setTimeout(cleanStickers, 15000).unref();
setInterval(cleanStickers, 6 * 3600000).unref();

app.get('/media/:file', (req, res) => {
  if (!/^[a-f0-9]{24}\.(jpg|png|webp|mp4|webm|mov|m4a|mp3|ogg|aac|wav)$/.test(req.params.file)) return res.sendStatus(404);
  if (voFiles.has(req.params.file)) {
    const tk = voTok.get(String(req.query.t || ''));
    if (!tk || tk.file !== req.params.file || tk.exp < Date.now()) return res.sendStatus(403);
    res.set('Cache-Control', 'no-store');
  } else {
    res.set('Cache-Control', 'private, max-age=3600');
  }
  res.sendFile(path.join(MEDIA, req.params.file), (e) => { if (e && !res.headersSent) res.sendStatus(404); });
});

// upload media untuk chat (foto / video / audio)
app.post('/api/chat/media', auth,
  express.raw({ type: (r) => /^(image|video|audio)\//.test(r.headers['content-type'] || ''), limit: MAXMEDIA }),
  (req, res) => {
    const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    const ext = EXT[mime];
    if (!ext) return res.status(400).json({ error: 'Format tidak didukung' });
    if (!Buffer.isBuffer(req.body) || req.body.length < 50) return res.status(400).json({ error: 'File kosong / terlalu kecil' });
    const kind = mime.startsWith('video') ? 'video' : mime.startsWith('audio') ? 'audio' : 'image';
    if (kind === 'audio' && req.body.length > 15 * 1024 * 1024) return res.status(400).json({ error: 'Audio maksimal 15 MB' });
    const file = crypto.randomBytes(12).toString('hex') + '.' + ext;
    fs.writeFile(path.join(MEDIA, file), req.body, (e) => {
      if (e) return res.status(500).json({ error: 'Gagal menyimpan file' });
      res.json({ ok: true, file, type: kind, url: '/media/' + file, mime });
    });
  });

// buka pesan sekali lihat (hanya penerima, sekali saja)
app.post('/api/chat/viewonce', auth, (req, res) => {
  const id = String((req.body && req.body.id) || '');
  const scope = (req.body && req.body.scope) === 'dm' ? 'dm' : 'global';
  let m = null, otherKey = null;
  if (scope === 'global') m = msgs.find((x) => x.id === id);
  else {
    const to = String((req.body && req.body.to) || '').trim().toLowerCase();
    if (!users[to]) return res.status(400).json({ error: 'Tidak valid' });
    otherKey = to;
    m = (dms[pairKey(req.key, to)] || []).find((x) => x.id === id);
  }
  if (!m || !m.viewOnce || !m.media) return res.status(404).json({ error: 'Pesan tidak ada' });
  const senderKey = String(m.u || '').toLowerCase();
  if (senderKey === req.key) return res.status(403).json({ error: 'Pengirim tidak bisa membuka ulang' });
  m.viewedBy = m.viewedBy || [];
  if (m.viewedBy.includes(req.key)) {
    return res.status(410).json({ error: 'Sudah dibuka sebelumnya', opened: true });
  }
  m.viewedBy.push(req.key);
  if (scope === 'global') { save('msgs', msgs); io.emit('msg:update', m); }
  else { save('dms', dms); io.to('u:' + req.key).to('u:' + otherKey).emit('msg:update', m); }
  voFiles.add(m.media.file);
  const token = crypto.randomBytes(18).toString('hex');
  voTok.set(token, { file: m.media.file, key: req.key, exp: Date.now() + 10 * 60 * 1000 });
  const url = '/media/' + m.media.file + '?t=' + token;
  res.json({ ok: true, url, type: m.media.type || mediaTypeOf(m.media.file), mime: m.media.mime || null });
});

// cari username untuk tag (@)
// ---------- tools RCH: react postingan channel WhatsApp lewat api-cloud.my.id ----------
// Kuota per hari (reset 00.00 WIB): free 3x, VIP 25x, Owner & Developer unlimited
const RCH_API = 'https://api-cloud.my.id/tools/rchv2';
const RCH_FREE = Number(process.env.RCH_FREE) || 3;
const RCH_VIP = Number(process.env.RCH_VIP) || 25;
const wibDay = () => new Date(Date.now() + 7 * 3600 * 1000).toISOString().slice(0, 10);
const rchLimit = (k) => {
  if (isAdminKey(k) || roleOfKey(k) === 'owner') return Infinity;
  return roleOfKey(k) === 'vip' ? RCH_VIP : RCH_FREE;
};
const rchUsed = (k) => { const r = users[k].rch; return r && r.day === wibDay() ? r.n : 0; };
const rchInfo = (k) => {
  const lim = rchLimit(k), used = rchUsed(k), unl = lim === Infinity;
  return {
    unlimited: unl, limit: unl ? null : lim, used, left: unl ? null : Math.max(0, lim - used),
    tier: isAdminKey(k) ? 'developer' : (roleOfKey(k) || 'free'),
  };
};
const rchBusy = new Set();
app.get('/api/rch/info', auth, (req, res) => res.json(rchInfo(req.key)));
app.post('/api/rch', auth, async (req, res) => {
  const k = req.key;
  const link = String((req.body && req.body.link) || '').trim();
  if (!/^https?:\/\/(www\.)?whatsapp\.com\/channel\/[A-Za-z0-9_-]+\/\d+$/.test(link)) {
    return res.status(400).json({ error: 'Link harus link postingan channel WhatsApp (whatsapp.com/channel/kode/nomor)' });
  }
  const list = String((req.body && req.body.emoji) || '').split(/[,，]/).map((x) => x.trim()).filter(Boolean);
  if (!list.length) return res.status(400).json({ error: 'Isi minimal 1 emoji' });
  if (list.length > 10 || list.some((x) => x.length > 16)) return res.status(400).json({ error: 'Emoji maksimal 10, pisahkan dengan koma' });
  if (rchBusy.has(k)) return res.status(429).json({ error: 'Tunggu proses sebelumnya selesai' });
  const lim = rchLimit(k);
  if (lim !== Infinity && rchUsed(k) >= lim) {
    return res.status(403).json({ error: 'Kuota hari ini habis (' + lim + 'x). Reset jam 00.00 WIB.', ...rchInfo(k) });
  }
  // kuota dipesan dulu supaya tidak bisa ditembus kirim berbarengan, dikembalikan kalau API gagal
  const day = wibDay();
  users[k].rch = { day, n: rchUsed(k) + 1 };
  save('users', users);
  rchBusy.add(k);
  const refund = () => {
    const r = users[k] && users[k].rch;
    if (r && r.day === day && r.n > 0) { r.n--; save('users', users); }
  };
  const ac = new AbortController();
  const tm = setTimeout(() => ac.abort(), 45000);
  try {
    const url = RCH_API + '?' + new URLSearchParams({ link, emoji: list.join(',') }).toString();
    const r = await fetch(url, { signal: ac.signal, headers: { Accept: 'application/json' } });
    const text = await r.text();
    let j = null;
    try { j = JSON.parse(text); } catch { /* bukan JSON */ }
    const failed = !r.ok || (j && (j.status === false || j.success === false || j.ok === false || (j.error && !j.result)));
    if (failed) {
      refund();
      const why = (j && (j.message || j.msg || (typeof j.error === 'string' && j.error))) || ('API membalas ' + r.status);
      return res.status(502).json({ error: String(why).slice(0, 200), ...rchInfo(k) });
    }
    res.json({ ok: true, result: j !== null ? j : text.slice(0, 1000), ...rchInfo(k) });
  } catch (e) {
    refund();
    res.status(502).json({ error: e && e.name === 'AbortError' ? 'API terlalu lama membalas, coba lagi' : 'Gagal menghubungi API', ...rchInfo(k) });
  } finally {
    clearTimeout(tm);
    rchBusy.delete(k);
  }
});

app.get('/api/users', auth, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 16);
  let list = Object.keys(users).filter((k) => k !== req.key);
  if (q) list = list.filter((k) => k.includes(q)).sort((a, b) => (b.startsWith(q) - a.startsWith(q)) || a.localeCompare(b));
  else list.sort((a, b) => (online.has(b) - online.has(a)) || a.localeCompare(b));
  res.json({
    users: list.slice(0, 8).map((k) => {
      const p = pub(k);
      return { name: p.name, u: p.name, av: p.av };
    }),
  });
});

const COLORS = ['#e8604c', '#3aa6a0', '#f2a93b', '#7a6bd1', '#4c8be8', '#d95f9b', '#6fae4f'];
app.get('/avatar/:name', (req, res) => {
  const key = String(req.params.name).toLowerCase();
  const user = users[key];
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  if (user && user.avatar) {
    const m = /^data:(image\/[a-z]+);base64,(.+)$/.exec(user.avatar);
    res.type(m[1]).send(Buffer.from(m[2], 'base64'));
    return;
  }
  const name = user ? user.name : '?';
  let h = 0;
  for (const c of name) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="${COLORS[h % COLORS.length]}"/><text x="50" y="50" dy=".35em" text-anchor="middle" font-family="Arial,sans-serif" font-weight="700" font-size="52" fill="#fff">${name[0].toUpperCase().replace(/[<>&]/g, '?')}</text></svg>`;
  res.type('image/svg+xml').send(svg);
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const big = err && err.type === 'entity.too.large';
  res.status(big ? 413 : err.status || 500).json({ error: big ? (String(req.path).startsWith('/api/stickers') ? 'Stiker terlalu besar' : 'File terlalu besar (maks 30 MB)') : 'Terjadi kesalahan' });
});

// ---------- Socket.io ----------
io.use((socket, next) => {
  const key = sess[socket.handshake.auth && socket.handshake.auth.token];
  if (!key || !users[key]) return next(new Error('auth'));
  bindDevice(key, idsOf(socket.handshake.auth && socket.handshake.auth.dev, socket.handshake.headers.cookie), false);
  addFp(key, socket.handshake.auth && socket.handshake.auth.fp);
  if (users[key].banned) return next(new Error('banned'));
  socket.key = key;
  next();
});

const online = new Map(); // key -> jumlah koneksi
const onlineList = () => [...online.keys()].map((k) => ({ u: users[k].name, av: users[k].av }));

io.on('connection', (socket) => {
  online.set(socket.key, (online.get(socket.key) || 0) + 1);
  socket.join('u:' + socket.key);
  const avs = {};
  for (const m of msgs) { const k = m.u.toLowerCase(); if (users[k]) avs[users[k].name] = users[k].av; }
  socket.emit('history', { msgs, avs, online: onlineList(), roles: rolesMap(), locked: meta.locked, lockedBy: meta.lockedBy });
  io.emit('online', onlineList());

  let last = 0;
  socket.on('msg', (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    const user = users[socket.key];
    if (user.muted) return reply({ error: 'Kamu di-mute di Global Chat' });
    if (meta.locked && !isAdminKey(socket.key)) return reply({ error: 'Global Chat sedang ditutup admin' });
    const now = Date.now();
    if (now - last < 600) return reply({ error: 'Pelan-pelan ya' });
    let text, replyId = null, forward = null, sticker = null, media = null, viewOnce = false;
    if (payload && typeof payload === 'object') {
      text = payload.text;
      replyId = payload.replyId || null;
      forward = payload.forward || null;
      viewOnce = !!payload.viewOnce;
      if (payload.sticker) {
        sticker = validSticker(payload.sticker);
        if (!sticker) return reply({ error: 'Stiker tidak valid' });
      }
      if (payload.media && payload.media.file) {
        const f = validMediaFile(payload.media.file);
        if (!f) return reply({ error: 'Media tidak valid' });
        const t = payload.media.type || mediaTypeOf(f);
        if (!t) return reply({ error: 'Tipe media tidak valid' });
        media = { file: f, type: t, mime: payload.media.mime || null };
      }
    } else {
      text = payload;
    }
    text = String(text || '').trim().slice(0, 500);
    if (sticker || media) text = text || '';
    if (sticker) text = '';
    if (!text && !sticker && !media) return reply({ error: 'Kosong' });
    if (viewOnce && !media) return reply({ error: 'Sekali lihat hanya untuk foto/video/audio' });
    if (viewOnce && media && media.type === 'audio') return reply({ error: 'Sekali lihat hanya untuk foto & video' });
    last = now;
    const m = { id: now.toString(36) + Math.random().toString(36).slice(2, 6), u: user.name, av: user.av, text, t: now };
    if (sticker) m.sticker = sticker;
    if (media) m.media = media;
    if (viewOnce) { m.viewOnce = true; m.viewedBy = []; voFiles.add(media.file); }
    if (replyId) {
      const src = msgs.find((x) => x.id === String(replyId));
      if (src) { m.reply = { id: src.id, u: src.u, text: stkPreview(src) }; if (src.sticker) m.reply.sticker = src.sticker; }
    }
    if (forward && forward.u && forward.text) {
      m.forward = { u: String(forward.u).slice(0, 32), text: String(forward.text).slice(0, 120) };
    }
    const mentions = [...new Set((text.match(/@([A-Za-z0-9_]{3,16})/g) || []).map((x) => x.slice(1).toLowerCase()))]
      .filter((k) => users[k]).slice(0, 10).map((k) => users[k].name);
    if (mentions.length) m.mentions = mentions;
    msgs.push(m);
    if (msgs.length > 200) msgs.splice(0, msgs.length - 200);
    save('msgs', msgs);
    io.emit('msg', m);
    reply({ ok: true });
  });

  // ----- chat pribadi -----
  socket.on('dm', (to, payload, ack) => {
    if (typeof payload === 'function') { ack = payload; payload = ''; }
    const reply = typeof ack === 'function' ? ack : () => {};
    const toKey = String(to || '').trim().toLowerCase();
    if (!users[toKey] || toKey === socket.key) return reply({ error: 'Penerima tidak valid' });
    const now = Date.now();
    if (now - last < 600) return reply({ error: 'Pelan-pelan ya' });
    let text, replyId = null, forward = null, sticker = null, statusId = null, media = null, viewOnce = false;
    if (payload && typeof payload === 'object') {
      text = payload.text;
      replyId = payload.replyId || null;
      forward = payload.forward || null;
      statusId = payload.statusId || null;
      viewOnce = !!payload.viewOnce;
      if (payload.sticker) {
        sticker = validSticker(payload.sticker);
        if (!sticker) return reply({ error: 'Stiker tidak valid' });
      }
      if (payload.media && payload.media.file) {
        const f = validMediaFile(payload.media.file);
        if (!f) return reply({ error: 'Media tidak valid' });
        const t = payload.media.type || mediaTypeOf(f);
        if (!t) return reply({ error: 'Tipe media tidak valid' });
        media = { file: f, type: t, mime: payload.media.mime || null };
      }
    } else {
      text = payload;
    }
    text = String(text || '').trim().slice(0, 500);
    if (sticker) text = '';
    if (!text && !sticker && !media) return reply({ error: 'Kosong' });
    if (viewOnce && !media) return reply({ error: 'Sekali lihat hanya untuk foto/video' });
    if (viewOnce && media && media.type === 'audio') return reply({ error: 'Sekali lihat hanya untuk foto & video' });
    // balasan untuk status: status harus masih aktif dan milik penerima
    let statusCtx = null;
    if (statusId) {
      const s = statuses.find((x) => x.id === String(statusId));
      if (!s || now - s.t > DAY || s.key !== toKey) return reply({ error: 'Status sudah tidak tersedia' });
      statusCtx = { id: s.id, type: s.type };
      if (s.type === 'text') { statusCtx.text = String(s.text || '').slice(0, 80); statusCtx.bg = s.bg || 0; }
      else { statusCtx.url = '/media/' + s.file; if (s.caption) statusCtx.text = String(s.caption).slice(0, 80); }
    }
    last = now;
    const me = users[socket.key];
    const m = { id: now.toString(36) + Math.random().toString(36).slice(2, 6), u: me.name, av: me.av, to: users[toKey].name, text, t: now };
    if (sticker) m.sticker = sticker;
    if (media) m.media = media;
    if (viewOnce) { m.viewOnce = true; m.viewedBy = []; voFiles.add(media.file); }
    if (statusCtx) m.status = statusCtx;
    const pk = pairKey(socket.key, toKey);
    if (replyId) {
      const src = (dms[pk] || []).find((x) => x.id === String(replyId));
      if (src) { m.reply = { id: src.id, u: src.u, text: stkPreview(src) }; if (src.sticker) m.reply.sticker = src.sticker; }
    }
    if (forward && forward.u && forward.text) {
      m.forward = { u: String(forward.u).slice(0, 32), text: String(forward.text).slice(0, 120) };
    }
    (dms[pk] = dms[pk] || []).push(m);
    if (dms[pk].length > 200) dms[pk].splice(0, dms[pk].length - 200);
    save('dms', dms);
    io.to('u:' + socket.key).to('u:' + toKey).emit('dm', m);
    reply({ ok: true });
  });

  socket.on('dm:history', (name, ack) => {
    if (typeof ack !== 'function') return;
    const k = String(name || '').trim().toLowerCase();
    if (!users[k]) return ack({ error: 'Tidak ditemukan' });
    ack({ msgs: dms[pairKey(socket.key, k)] || [], user: pub(k) });
  });

  // data profil lawan chat (halaman profil): status, terakhir dilihat, tanggal gabung, jumlah pesan
  socket.on('user:info', (name, ack) => {
    if (typeof ack !== 'function') return;
    const k = String(name || '').trim().toLowerCase();
    if (!users[k]) return ack({ error: 'Tidak ditemukan' });
    ack({
      name: users[k].name, av: users[k].av, online: online.has(k),
      seen: users[k].seen || 0, joined: users[k].created || 0,
      msgs: (dms[pairKey(socket.key, k)] || []).length,
    });
  });

  socket.on('dm:read', (name) => {
    const k = String(name || '').trim().toLowerCase();
    if (!users[k]) return;
    (reads[socket.key] = reads[socket.key] || {})[k] = Date.now();
    save('reads', reads);
  });

  socket.on('dm:list', (_, ack) => {
    if (typeof ack !== 'function') return;
    const out = [];
    for (const pk of Object.keys(dms)) {
      const [a, b] = pk.split('|');
      if (a !== socket.key && b !== socket.key) continue;
      const other = a === socket.key ? b : a;
      const arr = dms[pk];
      if (!users[other] || !arr.length) continue;
      const seen = (reads[socket.key] && reads[socket.key][other]) || 0;
      const unread = arr.filter((m) => m.u.toLowerCase() !== socket.key && m.t > seen).length;
      const lm = arr[arr.length - 1];
      const cp = users[socket.key].cp || {};
      if (cp.hid && cp.hid[other] && lm.t <= cp.hid[other]) continue; // kontak dihapus: muncul lagi kalau ada pesan baru
      out.push({
        u: users[other].name, av: users[other].av, text: lm.sticker ? 'Stiker' : lm.text, t: lm.t, unread,
        p: (cp.pin || []).includes(other), a: (cp.arc || []).includes(other),
      });
    }
    out.sort((x, y) => y.t - x.t);
    ack(out);
  });

  // pin / arsip / hapus kontak di daftar chat pribadi (tersimpan di server per akun)
  socket.on('conv:pref', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const k = String((data && data.u) || '').trim().toLowerCase();
    const act = data && data.act;
    const me = users[socket.key];
    if (!me || !users[k] || k === socket.key) return done({ error: 'User tidak ada' });
    const cp = me.cp = me.cp || {};
    cp.pin = cp.pin || []; cp.arc = cp.arc || []; cp.hid = cp.hid || {};
    const rm = (arr) => { const i = arr.indexOf(k); if (i >= 0) arr.splice(i, 1); };
    if (act === 'pin') {
      if (!cp.pin.includes(k)) {
        if (cp.pin.length >= 5) return done({ error: 'Maksimal 5 kontak yang di-pin' });
        cp.pin.push(k);
      }
      rm(cp.arc);
    } else if (act === 'unpin') rm(cp.pin);
    else if (act === 'arc') { if (!cp.arc.includes(k)) cp.arc.push(k); rm(cp.pin); }
    else if (act === 'unarc') rm(cp.arc);
    else if (act === 'del') { cp.hid[k] = Date.now(); rm(cp.pin); rm(cp.arc); }
    else return done({ error: 'Aksi tidak valid' });
    save('users', users);
    done({ ok: true });
  });

  // semua emoji dari keyboard boleh (bukan huruf/angka biasa), maksimal 1 reaksi per orang per pesan
  const EMOJI_RE = /\p{Extended_Pictographic}|\p{Regional_Indicator}|\u20e3/u;
  const validEmoji = (e) => typeof e === 'string' && e.length > 0 && e.length <= 24 && EMOJI_RE.test(e) && !/[\s<>&]/.test(e);
  const MAX_KINDS = 30;
  const isOwn = (m) => m && m.u && m.u.toLowerCase() === socket.key;

  socket.on('msg:edit', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const id = data && data.id;
    const text = String((data && data.text) || '').trim().slice(0, 500);
    if (!id || !text) return done({ error: 'Data tidak valid' });
    const m = msgs.find((x) => x.id === String(id));
    if (!m || !isOwn(m) || m.sticker) return done({ error: 'Tidak bisa diedit' });
    m.text = text;
    m.edited = Date.now();
    const mentions = [...new Set((text.match(/@([A-Za-z0-9_]{3,16})/g) || []).map((x) => x.slice(1).toLowerCase()))]
      .filter((k) => users[k]).slice(0, 10).map((k) => users[k].name);
    if (mentions.length) m.mentions = mentions; else delete m.mentions;
    save('msgs', msgs);
    io.emit('msg:update', m);
    done({ ok: true });
  });
  socket.on('msg:delete', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const i = msgs.findIndex((x) => x.id === String(data && data.id));
    if (i < 0 || !(isOwn(msgs[i]) || isAdminKey(socket.key))) return done({ error: 'Tidak bisa dihapus' });
    const id = msgs[i].id;
    msgs.splice(i, 1);
    save('msgs', msgs);
    io.emit('msg:delete', { id, scope: 'global' });
    done({ ok: true });
  });
  socket.on('msg:react', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const emoji = String((data && data.emoji) || '');
    if (!validEmoji(emoji)) return done({ error: 'Emoji tidak valid' });
    const m = msgs.find((x) => x.id === String(data && data.id));
    if (!m) return done({ error: 'Pesan tidak ada' });
    const name = users[socket.key].name;
    m.reactions = m.reactions || {};
    const had = (m.reactions[emoji] || []).includes(name);
    for (const e of Object.keys(m.reactions)) {
      m.reactions[e] = (m.reactions[e] || []).filter((n) => n !== name);
      if (!m.reactions[e].length) delete m.reactions[e];
    }
    if (!had && !m.reactions[emoji] && Object.keys(m.reactions).length >= MAX_KINDS) return done({ error: 'Terlalu banyak jenis reaksi' });
    if (!had) m.reactions[emoji] = (m.reactions[emoji] || []).concat(name);
    save('msgs', msgs);
    io.emit('msg:update', m);
    done({ ok: true });
  });

  socket.on('dm:edit', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const other = String((data && data.to) || '').trim().toLowerCase();
    const text = String((data && data.text) || '').trim().slice(0, 500);
    if (!other || !users[other] || !text) return done({ error: 'Data tidak valid' });
    const pk = pairKey(socket.key, other);
    const m = (dms[pk] || []).find((x) => x.id === String(data && data.id));
    if (!m || !isOwn(m) || m.sticker) return done({ error: 'Tidak bisa diedit' });
    m.text = text;
    m.edited = Date.now();
    save('dms', dms);
    io.to('u:' + socket.key).to('u:' + other).emit('msg:update', m);
    done({ ok: true });
  });
  socket.on('dm:delete', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const other = String((data && data.to) || '').trim().toLowerCase();
    if (!other || !users[other]) return done({ error: 'Data tidak valid' });
    const pk = pairKey(socket.key, other);
    const arr = dms[pk] || [];
    const i = arr.findIndex((x) => x.id === String(data && data.id));
    if (i < 0 || !isOwn(arr[i])) return done({ error: 'Tidak bisa dihapus' });
    const id = arr[i].id;
    arr.splice(i, 1);
    save('dms', dms);
    io.to('u:' + socket.key).to('u:' + other).emit('msg:delete', { id, scope: 'dm' });
    done({ ok: true });
  });
  socket.on('dm:react', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const other = String((data && data.to) || '').trim().toLowerCase();
    const emoji = String((data && data.emoji) || '');
    if (!validEmoji(emoji) || !other || !users[other]) return done({ error: 'Tidak valid' });
    const pk = pairKey(socket.key, other);
    const m = (dms[pk] || []).find((x) => x.id === String(data && data.id));
    if (!m) return done({ error: 'Pesan tidak ada' });
    const name = users[socket.key].name;
    m.reactions = m.reactions || {};
    const had = (m.reactions[emoji] || []).includes(name);
    for (const e of Object.keys(m.reactions)) {
      m.reactions[e] = (m.reactions[e] || []).filter((n) => n !== name);
      if (!m.reactions[e].length) delete m.reactions[e];
    }
    if (!had && !m.reactions[emoji] && Object.keys(m.reactions).length >= MAX_KINDS) return done({ error: 'Terlalu banyak jenis reaksi' });
    if (!had) m.reactions[emoji] = (m.reactions[emoji] || []).concat(name);
    save('dms', dms);
    io.to('u:' + socket.key).to('u:' + other).emit('msg:update', m);
    done({ ok: true });
  });

  // pin pesan: global hanya pemilik pesan, chat pribadi kedua peserta
  socket.on('msg:pin', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const m = msgs.find((x) => x.id === String(data && data.id));
    if (!m) return done({ error: 'Pesan tidak ada' });
    if (!isAdminKey(socket.key)) return done({ error: 'Hanya admin yang bisa pin pesan di Global Chat' });
    if (m.pinned) { delete m.pinned; delete m.pinnedBy; } else { m.pinned = Date.now(); m.pinnedBy = users[socket.key].name; }
    save('msgs', msgs);
    io.emit('msg:update', m);
    done({ ok: true, pinned: !!m.pinned });
  });
  socket.on('dm:pin', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    const other = String((data && data.to) || '').trim().toLowerCase();
    if (!other || !users[other]) return done({ error: 'Tidak valid' });
    const m = (dms[pairKey(socket.key, other)] || []).find((x) => x.id === String(data && data.id));
    if (!m) return done({ error: 'Pesan tidak ada' });
    if (m.pinned) { delete m.pinned; delete m.pinnedBy; } else { m.pinned = Date.now(); m.pinnedBy = users[socket.key].name; }
    save('dms', dms);
    io.to('u:' + socket.key).to('u:' + other).emit('msg:update', m);
    done({ ok: true, pinned: !!m.pinned });
  });

  // ---- panel admin: centang biru, mute, ban, tutup global chat ----
  socket.on('admin:users', (_, ack) => {
    if (typeof ack !== 'function') return;
    if (!isAdminKey(socket.key)) return ack({ error: 'Bukan admin' });
    const list = Object.keys(users).map((k) => ({
      u: users[k].name, av: users[k].av, d: isAdminKey(k),
      v: isAdminKey(k) || !!users[k].verified,
      r: roleOfKey(k),
      m: !!users[k].muted, b: !!users[k].banned, br: users[k].banReason || '',
    }));
    list.sort((a, b) => (b.d - a.d) || a.u.toLowerCase().localeCompare(b.u.toLowerCase()));
    ack({ users: list, locked: meta.locked, lockedBy: meta.lockedBy });
  });
  socket.on('admin:verify', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    if (!isAdminKey(socket.key)) return done({ error: 'Bukan admin' });
    const k = String((data && data.u) || '').trim().toLowerCase();
    if (!users[k]) return done({ error: 'User tidak ada' });
    if (isAdminKey(k)) return done({ error: 'Developer selalu centang biru' });
    if (data && data.on) users[k].verified = true; else delete users[k].verified;
    save('users', users);
    io.emit('roles', rolesMap());
    done({ ok: true, v: !!users[k].verified });
  });
  // atur role VIP / Owner (kosong = hapus role)
  socket.on('admin:role', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    if (!isAdminKey(socket.key)) return done({ error: 'Bukan admin' });
    const k = String((data && data.u) || '').trim().toLowerCase();
    if (!users[k]) return done({ error: 'User tidak ada' });
    if (isAdminKey(k)) return done({ error: 'Developer tidak perlu role' });
    const role = String((data && data.role) || '').toLowerCase();
    if (role && !ROLES.includes(role)) return done({ error: 'Role tidak valid' });
    if (role) users[k].role = role; else delete users[k].role;
    save('users', users);
    io.emit('roles', rolesMap());
    done({ ok: true, r: roleOfKey(k) });
  });
  socket.on('admin:mute', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    if (!isAdminKey(socket.key)) return done({ error: 'Bukan admin' });
    const k = String((data && data.u) || '').trim().toLowerCase();
    if (!users[k]) return done({ error: 'User tidak ada' });
    if (isAdminKey(k)) return done({ error: 'Developer tidak bisa dimute' });
    if (data && data.on) users[k].muted = true; else delete users[k].muted;
    save('users', users);
    io.to('u:' + k).emit('you:muted', { muted: !!users[k].muted });
    done({ ok: true, muted: !!users[k].muted });
  });
  socket.on('admin:ban', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    if (!isAdminKey(socket.key)) return done({ error: 'Bukan admin' });
    const k = String((data && data.u) || '').trim().toLowerCase();
    if (!users[k]) return done({ error: 'User tidak ada' });
    if (isAdminKey(k)) return done({ error: 'Developer tidak bisa dibanned' });
    if (data && data.on) {
      users[k].banned = true;
      users[k].banReason = String((data && data.reason) || '').trim().slice(0, 140) || null;
      save('users', users);
      blkAdd(k);
      // sesi dibiarkan: saat user buka web lagi, server balas "di-ban" lalu client pindah ke halaman daftar
      io.to('u:' + k).emit('you:banned', { reason: users[k].banReason || '' });
      dropSockets(k);
    } else {
      delete users[k].banned;
      delete users[k].banReason;
      delete meta.blk[k];
      save('meta', meta);
      save('users', users);
    }
    done({ ok: true, banned: !!users[k].banned });
  });
  socket.on('admin:delete', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    if (!isAdminKey(socket.key)) return done({ error: 'Bukan admin' });
    const k = String((data && data.u) || '').trim().toLowerCase();
    if (!users[k]) return done({ error: 'User tidak ada' });
    if (isAdminKey(k)) return done({ error: 'Akun Developer tidak bisa dihapus' });
    const name = users[k].name;
    kickUser(k);
    // pesan global
    const gone = msgs.filter((x) => x.u && x.u.toLowerCase() === k).map((x) => x.id);
    if (gone.length) {
      for (let i = msgs.length - 1; i >= 0; i--) if (msgs[i].u && msgs[i].u.toLowerCase() === k) msgs.splice(i, 1);
      save('msgs', msgs);
      gone.forEach((id) => io.emit('msg:delete', { id, scope: 'global' }));
    }
    // status
    let sch = false;
    for (let i = statuses.length - 1; i >= 0; i--) {
      if (statuses[i].key === k) { dropFile(statuses[i].file); statuses.splice(i, 1); sch = true; }
    }
    if (sch) { save('statuses', statuses); io.emit('status:update', {}); }
    // chat pribadi + penanda baca
    for (const pk of Object.keys(dms)) if (pk.split('|').includes(k)) delete dms[pk];
    delete reads[k];
    for (const r of Object.keys(reads)) if (reads[r] && reads[r][k] != null) delete reads[r][k];
    delete users[k];
    online.delete(k);
    save('users', users); save('dms', dms); save('reads', reads);
    io.emit('roles', rolesMap());
    io.emit('online', onlineList());
    done({ ok: true, name });
  });
  socket.on('admin:lock', (data, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    if (!isAdminKey(socket.key)) return done({ error: 'Bukan admin' });
    meta.locked = !!(data && data.on);
    meta.lockedBy = meta.locked ? users[socket.key].name : null;
    save('meta', meta);
    io.emit('global:lock', { locked: meta.locked, by: meta.lockedBy });
    done({ ok: true, locked: meta.locked });
  });

  // ---- indikator mengetik (bubble chat) ----
  socket.on('typing', (data) => {
    const scope = data && data.scope === 'dm' ? 'dm' : 'global';
    const name = users[socket.key].name;
    if (scope === 'global') {
      socket.broadcast.emit('typing', { u: name, scope: 'global' });
    } else {
      const toKey = String((data && data.to) || '').trim().toLowerCase();
      if (!users[toKey] || toKey === socket.key) return;
      io.to('u:' + toKey).emit('typing', { u: name, scope: 'dm', to: users[socket.key].name });
    }
  });

  socket.on('disconnect', () => {
    const n = (online.get(socket.key) || 1) - 1;
    if (n > 0) online.set(socket.key, n);
    else {
      online.delete(socket.key);
      if (users[socket.key]) {
        users[socket.key].seen = Date.now();
        save('users', users);
        io.emit('seen', { u: users[socket.key].name, t: users[socket.key].seen });
      }
    }
    io.emit('online', onlineList());
  });
});

voScan();
server.listen(PORT, '0.0.0.0', () => console.log('THERCAY jalan di port ' + PORT));
