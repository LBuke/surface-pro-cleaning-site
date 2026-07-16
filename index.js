'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'data.json');
const UPLOAD_DIR = path.join(ROOT, 'uploads');

// ---- defaults for first run ----
const DEFAULT_USER = 'admin';
const DEFAULT_PASS = 'changeme';

// -------------------------------------------------------------------
// Data layer: a single JSON file, held in memory, written atomically.
// -------------------------------------------------------------------
let db;

function saveDb() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE); // atomic replace, avoids half-written files
}

function loadDb() {
  if (fs.existsSync(DATA_FILE)) {
    db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return;
  }
  // First run: seed the default admin + a stable session secret.
  db = {
    sessionSecret: crypto.randomBytes(32).toString('hex'),
    user: {
      username: DEFAULT_USER,
      passwordHash: bcrypt.hashSync(DEFAULT_PASS, 12),
    },
    images: [],
  };
  saveDb();
  console.log(`[init] Seeded data.json with default login  ${DEFAULT_USER} / ${DEFAULT_PASS}`);
  console.log('[init] Log in and change the password from the admin page.');
}

loadDb();
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// -------------------------------------------------------------------
// App / session
// -------------------------------------------------------------------
app.disable('x-powered-by');
app.set('trust proxy', 1); // behind nginx + Cloudflare; needed for secure cookies

app.use(session({
  name: 'sid',
  secret: db.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',              // set only over https (production behind nginx)
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  },
}));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Auth gate for API + pages
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(401).json({ error: 'not authenticated' });
  }
  return res.redirect('/login');
}

function requireAuthApi(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'not authenticated' });
}

// -------------------------------------------------------------------
// Tiny in-memory login throttle (per IP). Resets on restart — fine here.
// -------------------------------------------------------------------
const attempts = new Map(); // ip -> { count, first }
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 10;

function throttled(ip) {
  const rec = attempts.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.first > WINDOW_MS) { attempts.delete(ip); return false; }
  return rec.count >= MAX_ATTEMPTS;
}
function noteFailure(ip) {
  const rec = attempts.get(ip);
  if (!rec || Date.now() - rec.first > WINDOW_MS) {
    attempts.set(ip, { count: 1, first: Date.now() });
  } else {
    rec.count += 1;
  }
}

// -------------------------------------------------------------------
// Uploads (multer) — images only, random safe filenames, 10 MB cap.
// -------------------------------------------------------------------
const ALLOWED_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif']);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    let ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) ext = '.jpg';
    cb(null, crypto.randomBytes(16).toString('hex') + ext);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (file.mimetype.startsWith('image/') && ALLOWED_EXT.has(ext)) return cb(null, true);
    cb(new Error('Only image files are allowed (jpg, png, webp, gif).'));
  },
});

// -------------------------------------------------------------------
// Static assets
// -------------------------------------------------------------------
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d' }));
app.use(express.static(path.join(ROOT, 'public')));

// -------------------------------------------------------------------
// Public API — gallery feed
// -------------------------------------------------------------------
app.get('/api/images', (req, res) => {
  // newest first
  const list = [...db.images].reverse().map(img => ({
    id: img.id,
    url: '/uploads/' + img.file,
    caption: img.caption || '',
  }));
  res.json(list);
});

// -------------------------------------------------------------------
// Auth
// -------------------------------------------------------------------
app.get('/login', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/admin');
  res.sendFile(path.join(ROOT, 'views', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (throttled(ip)) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }
  const { username, password } = req.body || {};
  const ok =
    typeof username === 'string' &&
    typeof password === 'string' &&
    username === db.user.username &&
    bcrypt.compareSync(password, db.user.passwordHash);

  if (!ok) {
    noteFailure(ip);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  attempts.delete(ip);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'session error' });
    req.session.user = db.user.username;
    res.json({ ok: true });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) return res.json({ user: req.session.user });
  res.status(401).json({ error: 'not authenticated' });
});

// -------------------------------------------------------------------
// Admin page + protected actions
// -------------------------------------------------------------------
app.get('/admin', requireAuth, (req, res) => {
  res.sendFile(path.join(ROOT, 'views', 'admin.html'));
});

app.post('/api/upload', requireAuthApi, (req, res) => {
  upload.single('image')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No file received.' });
    const caption = (req.body.caption || '').toString().slice(0, 120);
    const entry = {
      id: crypto.randomBytes(8).toString('hex'),
      file: req.file.filename,
      caption,
      uploadedAt: new Date().toISOString(),
    };
    db.images.push(entry);
    saveDb();
    res.json({ ok: true, image: { id: entry.id, url: '/uploads/' + entry.file, caption } });
  });
});

app.post('/api/images/:id/delete', requireAuthApi, (req, res) => {
  const idx = db.images.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  const [removed] = db.images.splice(idx, 1);
  saveDb();
  // best-effort remove the file from disk
  fs.promises.unlink(path.join(UPLOAD_DIR, removed.file)).catch(() => {});
  res.json({ ok: true });
});

app.post('/api/change-password', requireAuthApi, (req, res) => {
  const { current, next } = req.body || {};
  if (typeof current !== 'string' || typeof next !== 'string') {
    return res.status(400).json({ error: 'Missing fields.' });
  }
  if (!bcrypt.compareSync(current, db.user.passwordHash)) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }
  if (next.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }
  db.user.passwordHash = bcrypt.hashSync(next, 12);
  saveDb();
  res.json({ ok: true });
});

// -------------------------------------------------------------------
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Listening on http://127.0.0.1:${PORT}`);
});
