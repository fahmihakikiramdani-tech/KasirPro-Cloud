
'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const isProduction = process.env.NODE_ENV === 'production';

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL || 'admin@example.com'
).trim().toLowerCase();

const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '');
const COOKIE_SECRET = String(process.env.COOKIE_SECRET || '');
const DATABASE_URL = String(process.env.DATABASE_URL || '');

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL belum diatur.');
}

if (
  isProduction &&
  (ADMIN_PASSWORD.length < 16 || COOKIE_SECRET.length < 32)
) {
  throw new Error(
    'Atur ADMIN_PASSWORD minimal 16 karakter dan COOKIE_SECRET minimal 32 karakter.'
  );
}

// Gunakan Supabase Transaction Pooler untuk deployment serverless.
// Jangan memasukkan DATABASE_URL langsung ke kode.
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 1,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 10000,
  ssl: { rejectUnauthorized: false }
});

pool.on('error', (err) => {
  console.error('Kesalahan koneksi PostgreSQL:', err.message);
});

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 150,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

const COOKIE_NAME = 'kasirpro_session';
const SESSION_DAYS = 30;
const MAX_DEVICES = 2;

function now() {
  return new Date().toISOString();
}

function makeId() {
  return crypto.randomUUID();
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

// HMAC membuat token sesi terikat pada secret server.
function tokenHash(token) {
  return crypto
    .createHmac('sha256', COOKIE_SECRET || 'development-only-secret')
    .update(String(token))
    .digest('hex');
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  return aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function getCookie(req, name) {
  const header = req.headers.cookie || '';

  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return '';
      }
    }
  }

  return '';
}

function setSessionCookie(res, token) {
  const options = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`
  ];

  if (isProduction) options.push('Secure');

  res.setHeader('Set-Cookie', options.join('; '));
}

function clearSessionCookie(res) {
  const options = [
    `${COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0'
  ];

  if (isProduction) options.push('Secure');

  res.setHeader('Set-Cookie', options.join('; '));
}

function getDeviceIdentifier(req) {
  const body = req.body || {};

  return String(
    body.deviceId ||
    body.device_id ||
    body.deviceToken ||
    req.get('x-device-id') ||
    ''
  ).trim().slice(0, 200);
}

function getDeviceLabel(req) {
  return String(
    (req.body && req.body.deviceLabel) ||
    req.get('user-agent') ||
    'Unknown device'
  ).slice(0, 200);
}

function validPassword(password) {
  return typeof password === 'string' &&
    password.length >= 8 &&
    password.length <= 128;
}

function validEmail(email) {
  return email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function transaction(callback) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {}
    throw err;
  } finally {
    client.release();
  }
}


async function createSession(client, user, req) {
  const deviceIdentifier = getDeviceIdentifier(req);

  if (!deviceIdentifier) {
    const err = new Error(
      'ID perangkat belum tersedia. Aplikasi harus mengirim deviceId.'
    );
    err.status = 400;
    throw err;
  }

  const deviceHash = hash(deviceIdentifier);

  // Kunci baris akun agar dua login bersamaan tidak melewati batas.
  await client.query(
    'SELECT id FROM users WHERE id = $1 FOR UPDATE',
    [user.id]
  );

  // Cari perangkat yang sama.
  const existing = await client.query(
    `SELECT id, revoked
     FROM devices
     WHERE user_id = $1 AND device_hash = $2
     FOR UPDATE`,
    [user.id, deviceHash]
  );

  let device;

  if (existing.rowCount > 0) {
    device = existing.rows[0];

    // Jika perangkat sudah dicabut, jangan aktifkan kembali otomatis.
    if (device.revoked) {
      const err = new Error(
        'Akses perangkat ini sudah dicabut. Gunakan perangkat yang diizinkan atau hubungi admin.'
      );
      err.status = 403;
      throw err;
    }

    await client.query(
      `UPDATE devices
       SET last_seen = NOW(), label = $3
       WHERE id = $1 AND user_id = $2`,
      [device.id, user.id, getDeviceLabel(req)]
    );
  } else {
    // Hanya customer yang dibatasi maksimal 2 perangkat aktif.
    if (user.role !== 'admin') {
      const count = await client.query(
        `SELECT COUNT(*)::int AS total
         FROM devices
         WHERE user_id = $1
           AND revoked = FALSE`,
        [user.id]
      );

      if (count.rows[0].total >= MAX_DEVICES) {
        const err = new Error(
          'Batas 2 perangkat aktif tercapai. Logout dari salah satu perangkat terlebih dahulu.'
        );
        err.status = 403;
        throw err;
      }
    }

    const inserted = await client.query(
      `INSERT INTO devices
       (id, user_id, device_hash, label, created_at, last_seen, revoked)
       VALUES ($1, $2, $3, $4, NOW(), NOW(), FALSE)
       RETURNING id`,
      [makeId(), user.id, deviceHash, getDeviceLabel(req)]
    );

    device = inserted.rows[0];
  }

  const token = randomToken();

  await client.query(
    `INSERT INTO sessions
     (token_hash, user_id, device_id, created_at, last_seen, revoked)
     VALUES ($1, $2, $3, NOW(), NOW(), FALSE)`,
    [tokenHash(token), user.id, device.id]
  );

  return { token, deviceId: device.id };
}



async function getUser(req) {
  const token = getCookie(req, COOKIE_NAME);
  if (!token) return null;

  const result = await pool.query(
    `SELECT
       u.id, u.email, u.role, u.active,
       s.token_hash, s.device_id
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     JOIN devices d ON d.id = s.device_id
     WHERE s.token_hash = $1
       AND s.revoked = FALSE
       AND d.revoked = FALSE
       AND u.active = TRUE
     LIMIT 1`,
    [tokenHash(token)]
  );

  if (result.rowCount === 0) return null;

  await pool.query(
    'UPDATE sessions SET last_seen = NOW() WHERE token_hash = $1',
    [result.rows[0].token_hash]
  );

  await pool.query(
    'UPDATE devices SET last_seen = NOW() WHERE id = $1',
    [result.rows[0].device_id]
  );

  const row = result.rows[0];

  return {
    id: row.id,
    email: row.email,
    role: row.role,
    deviceId: row.device_id
  };
}

async function requireUser(req, res, next) {
  try {
    const user = await getUser(req);

    if (!user) {
      clearSessionCookie(res);
      return res.status(401).json({
        error: 'Silakan login kembali.'
      });
    }

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

async function requireAdmin(req, res, next) {
  try {
    const user = await getUser(req);

    if (!user) {
      clearSessionCookie(res);
      return res.status(401).json({ error: 'Login admin diperlukan.' });
    }

    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Akses admin ditolak.' });
    }

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

function makeLicenseCode() {
  return 'KPR-' +
    crypto.randomBytes(4).toString('hex').toUpperCase() +
    '-' +
    crypto.randomBytes(4).toString('hex').toUpperCase();
}

function normalizeLicenseCode(value) {
  return String(value || '').trim().toUpperCase();
}

// Halaman statis berada dalam folder public/.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/app', async (req, res, next) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.redirect('/');
    }

    res.sendFile(path.join(__dirname, 'public', 'kasirpro.html'));
  } catch (err) {
    next(err);
  }
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch {
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

// Registrasi akun.
app.post('/api/register', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password;

    if (!validEmail(email)) {
      return res.status(400).json({ error: 'Format email tidak valid.' });
    }

    if (!validPassword(password)) {
      return res.status(400).json({
        error: 'Password harus 8–128 karakter.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
       (id, email, password_hash, role, created_at, active)
       VALUES ($1, $2, $3, 'customer', NOW(), FALSE)
       ON CONFLICT (email) DO NOTHING
       RETURNING id, email, role`,
      [makeId(), email, passwordHash]
    );

    if (result.rowCount === 0) {
      return res.status(409).json({ error: 'Email sudah terdaftar.' });
    }

    res.status(201).json({
      ok: true,
      user: result.rows[0]
    });
  } catch (err) {
    next(err);
  }
});

// Login pengguna.
app.post('/api/login', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password;

    if (!email || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email dan password wajib diisi.' });
    }

    const result = await pool.query(
      `SELECT id, email, password_hash, role, active
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );

    const user = result.rows[0];

    if (
  !user ||
  !await bcrypt.compare(password, user.password_hash)
) {
  return res.status(401).json({
    error: 'Email atau password salah.'
  });
}

if (!user.active) {
  return res.status(403).json({
    error: 'Akun belum aktif. Silakan selesaikan aktivasi lisensi terlebih dahulu.'
  });
}

const licenseResult = await pool.query(
  `SELECT id, status, expires_at
   FROM licenses
   WHERE user_id = $1
   LIMIT 1`,
  [user.id]
);

const license = licenseResult.rows[0];

if (
  !license ||
  license.status !== 'active' ||
  (license.expires_at && new Date(license.expires_at) <= new Date())
) {
  return res.status(403).json({
    error: 'Lisensi belum aktif atau sudah kedaluwarsa.'
  });
}
    const session = await transaction((client) =>
      createSession(client, user, req)
    );

    setSessionCookie(res, session.token);

    res.json({
      ok: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    next(err);
  }
});

// Aktivasi lisensi untuk akun yang sudah login.

app.post('/api/activate', async (req, res, next) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const code = normalizeLicenseCode(
    req.body.code || req.body.licenseCode || req.body.license_code || ''
  );
  const deviceId = String(req.body.deviceId || '').trim();

  if (!email || !password) {
    return res.status(400).json({
      error: 'Email dan kata sandi wajib diisi.'
    });
  }

  if (!deviceId) {
    return res.status(400).json({
      error: 'Identitas perangkat tidak ditemukan. Muat ulang halaman.'
    });
  }

  try {
    const result = await transaction(async client => {
      const userResult = await client.query(
        `SELECT id, email, password_hash, role, active
         FROM users
         WHERE email = $1
         FOR UPDATE`,
        [email]
      );

      const user = userResult.rows[0];

      if (!user || !await bcrypt.compare(password, user.password_hash)) {
        throw Object.assign(
          new Error('Email atau kata sandi salah.'),
          { status: 401 }
        );
      }

      // Periksa apakah akun sudah mempunyai lisensi.
      const existingResult = await client.query(
        `SELECT id, status, expires_at
         FROM licenses
         WHERE user_id = $1
         LIMIT 1
         FOR UPDATE`,
        [user.id]
      );

      if (existingResult.rowCount > 0) {
        const existing = existingResult.rows[0];

        if (
          existing.status !== 'active' ||
          (existing.expires_at &&
            new Date(existing.expires_at) <= new Date())
        ) {
          throw Object.assign(
            new Error(
              'Lisensi akun tidak aktif atau kedaluwarsa. Hubungi admin.'
            ),
            { status: 403 }
          );
        }

        // Lisensi sudah aktif: pulihkan status akun jika sebelumnya
        // gagal diperbarui, lalu buat sesi login.
        await client.query(
          `UPDATE users SET active = TRUE WHERE id = $1`,
          [user.id]
        );

        const session = await createSession(
          client,
          { ...user, active: true },
          req
        );

        return {
          token: session.token,
          user: {
            id: user.id,
            email: user.email,
            role: user.role
          },
          message: 'Lisensi akun sudah aktif. Berhasil masuk.'
        };
      }

      if (!code) {
        throw Object.assign(
          new Error('Masukkan kode aktivasi lisensi.'),
          { status: 400 }
        );
      }

      // Kunci baris kode supaya tidak dapat dipakai dua kali bersamaan.
      const licenseResult = await client.query(
        `SELECT id, status, user_id, expires_at
         FROM licenses
         WHERE code_hash = $1
         FOR UPDATE`,
        [hash(code)]
      );

      const license = licenseResult.rows[0];

      if (!license) {
        throw Object.assign(
          new Error('Kode lisensi tidak valid.'),
          { status: 400 }
        );
      }

      if (license.status !== 'unused' || license.user_id) {
        throw Object.assign(
          new Error('Kode lisensi sudah digunakan atau tidak aktif.'),
          { status: 409 }
        );
      }

      if (
        license.expires_at &&
        new Date(license.expires_at) <= new Date()
      ) {
        throw Object.assign(
          new Error('Kode lisensi sudah kedaluwarsa.'),
          { status: 400 }
        );
      }

      await client.query(
        `UPDATE licenses
         SET status = 'active',
             user_id = $2,
             activated_at = NOW()
         WHERE id = $1`,
        [license.id, user.id]
      );

      await client.query(
        `UPDATE users SET active = TRUE WHERE id = $1`,
        [user.id]
      );

      const session = await createSession(
        client,
        { ...user, active: true },
        req
      );

      return {
        token: session.token,
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        },
        message: 'Lisensi berhasil diaktifkan.'
      };
    });

    setSessionCookie(res, result.token);

    return res.json({
      ok: true,
      message: result.message,
      user: result.user
    });
  } catch (err) {
    next(err);
  }
});

// Informasi akun aktif.
app.get('/api/me', requireUser, async (req, res, next) => {
  try {
    const license = await pool.query(
      `SELECT status, activated_at, expires_at
       FROM licenses
       WHERE user_id = $1
       LIMIT 1`,
      [req.user.id]
    );

    res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        role: req.user.role
      },
      license: license.rows[0] || null
    });
  } catch (err) {
    next(err);
  }
});

// Sinkronisasi data cloud.
app.get('/api/data', requireUser, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT payload, updated_at, version
       FROM cloud_data
       WHERE user_id = $1
       LIMIT 1`,
      [req.user.id]
    );

    if (result.rowCount === 0) {
      return res.json({
        data: {},
        payload: {},
        updated_at: null,
        version: 0
      });
    }

    const row = result.rows[0];

    res.json({
      data: row.payload,
      payload: row.payload,
      updated_at: row.updated_at,
      version: row.version
    });
  } catch (err) {
    next(err);
  }
});

app.put('/api/data', requireUser, async (req, res, next) => {
  try {
    const payload = req.body.payload !== undefined
      ? req.body.payload
      : req.body.data;

    if (
      payload === undefined ||
      payload === null ||
      typeof payload !== 'object'
    ) {
      return res.status(400).json({
        error: 'Kirim data JSON pada properti payload atau data.'
      });
    }

    const serialized = JSON.stringify(payload);

    if (Buffer.byteLength(serialized, 'utf8') > 900000) {
      return res.status(413).json({ error: 'Data terlalu besar.' });
    }

    const result = await pool.query(
      `INSERT INTO cloud_data
       (user_id, payload, updated_at, version)
       VALUES ($1, $2::jsonb, NOW(), 1)
       ON CONFLICT (user_id)
       DO UPDATE SET
         payload = EXCLUDED.payload,
         updated_at = NOW(),
         version = cloud_data.version + 1
       RETURNING payload, updated_at, version`,
      [req.user.id, serialized]
    );

    res.json({
      ok: true,
      data: result.rows[0].payload,
      payload: result.rows[0].payload,
      updated_at: result.rows[0].updated_at,
      version: result.rows[0].version
    });
  } catch (err) {
    next(err);
  }
});

// Logout.

// Logout dan lepaskan slot perangkat.
app.post('/api/logout', async (req, res, next) => {
  try {
    const token = getCookie(req, COOKIE_NAME);

    if (token) {
      await transaction(async (client) => {
        // Cari sesi dan perangkat yang sedang digunakan.
        const result = await client.query(
          `SELECT device_id
           FROM sessions
           WHERE token_hash = $1
           FOR UPDATE`,
          [tokenHash(token)]
        );

        if (result.rowCount > 0) {
          const deviceId = result.rows[0].device_id;

          // Akhiri semua sesi pada perangkat ini.
          await client.query(
            `UPDATE sessions
             SET revoked = TRUE
             WHERE device_id = $1`,
            [deviceId]
          );

          // Lepaskan perangkat agar slot bisa digunakan kembali.
          await client.query(
            `UPDATE devices
             SET revoked = TRUE
             WHERE id = $1`,
            [deviceId]
          );
        }
      });
    }

    clearSessionCookie(res);

    return res.json({
      ok: true,
      message: 'Berhasil logout. Slot perangkat telah dilepaskan.'
    });
  } catch (err) {
    next(err);
  }
});
// Login admin menggunakan kredensial dari environment variables.
app.post('/api/admin/login', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password;

    if (
      !ADMIN_PASSWORD ||
      !safeEqual(email, ADMIN_EMAIL) ||
      typeof password !== 'string' ||
      !safeEqual(password, ADMIN_PASSWORD)
    ) {
      return res.status(401).json({ error: 'Kredensial admin salah.' });
    }

    const admin = await transaction(async (client) => {
      let result = await client.query(
        `SELECT id, email, role, active
         FROM users
         WHERE email = $1
         FOR UPDATE`,
        [ADMIN_EMAIL]
      );

      if (result.rowCount === 0) {
        const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

        result = await client.query(
          `INSERT INTO users
           (id, email, password_hash, role, created_at, active)
           VALUES ($1, $2, $3, 'admin', NOW(), TRUE)
           RETURNING id, email, role, active`,
          [makeId(), ADMIN_EMAIL, passwordHash]
        );
      } else {
        await client.query(
          `UPDATE users SET role = 'admin', active = TRUE
           WHERE id = $1`,
          [result.rows[0].id]
        );

        result = await client.query(
          `SELECT id, email, role, active FROM users WHERE id = $1`,
          [result.rows[0].id]
        );
      }

      return result.rows[0];
    });

    const session = await transaction((client) =>
      createSession(client, admin, req)
    );

    setSessionCookie(res, session.token);

    res.json({
      ok: true,
      user: {
        id: admin.id,
        email: admin.email,
        role: 'admin'
      }
    });
  } catch (err) {
    next(err);
  }
});

// Membuat lisensi baru. Kode mentah hanya ditampilkan saat dibuat.
app.post('/api/admin/licenses', requireAdmin, async (req, res, next) => {
  try {
    const count = Number(req.body.count || 1);

    if (!Number.isInteger(count) || count < 1 || count > 100) {
      return res.status(400).json({
        error: 'Jumlah lisensi harus berupa angka bulat 1–100.'
      });
    }

    let expiresAt = null;

    if (req.body.expiresAt || req.body.expires_at) {
      const parsed = new Date(req.body.expiresAt || req.body.expires_at);

      if (Number.isNaN(parsed.getTime())) {
        return res.status(400).json({ error: 'Tanggal kedaluwarsa tidak valid.' });
      }

      expiresAt = parsed.toISOString();
    }

    const licenses = await transaction(async (client) => {
      const created = [];

      for (let i = 0; i < count; i++) {
        const code = makeLicenseCode();

        const result = await client.query(
          `INSERT INTO licenses
           (id, code_hash, code_hint, status, created_at, expires_at)
           VALUES ($1, $2, $3, 'unused', NOW(), $4)
           RETURNING id, status, created_at, expires_at`,
          [makeId(), hash(code), code.slice(-4), expiresAt]
        );

        created.push({
          ...result.rows[0],
          code
        });
      }

      return created;
    });

    res.status(201).json({ ok: true, licenses });
  } catch (err) {
    next(err);
  }
});

// Daftar lisensi tanpa mengungkap kode lengkap.
app.get('/api/admin/licenses', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, code_hint, status, created_at, activated_at, user_id, expires_at
       FROM licenses
       ORDER BY created_at DESC
       LIMIT 500`
    );

    res.json({ licenses: result.rows });
  } catch (err) {
    next(err);
  }
});

// Daftar pengguna.
app.get('/api/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT
         u.id, u.email, u.role, u.active, u.created_at,
         (SELECT COUNT(*)::int
          FROM devices d
          WHERE d.user_id = u.id AND d.revoked = FALSE) AS active_devices,
         (SELECT l.status
          FROM licenses l
          WHERE l.user_id = u.id
          LIMIT 1) AS license_status
       FROM users u
       ORDER BY u.created_at DESC
       LIMIT 500`
    );

    res.json({ users: result.rows });
  } catch (err) {
    next(err);
  }
});

// Menonaktifkan akun pengguna dan semua session miliknya.
app.post('/api/admin/users/:id/revoke', requireAdmin, async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({
        error: 'Admin tidak dapat menonaktifkan akunnya sendiri.'
      });
    }

    const result = await transaction(async (client) => {
      const user = await client.query(
        'UPDATE users SET active = FALSE WHERE id = $1 RETURNING id',
        [req.params.id]
      );

      if (user.rowCount === 0) {
        const err = new Error('Pengguna tidak ditemukan.');
        err.status = 404;
        throw err;
      }

      await client.query(
        'UPDATE sessions SET revoked = TRUE WHERE user_id = $1',
        [req.params.id]
      );

      return { ok: true };
    });

    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Mencabut akses satu perangkat beserta session terkait.
app.post('/api/admin/devices/:id/revoke', requireAdmin, async (req, res, next) => {
  try {
    const result = await transaction(async (client) => {
      const device = await client.query(
        `UPDATE devices
         SET revoked = TRUE
         WHERE id = $1
         RETURNING id`,
        [req.params.id]
      );

      if (device.rowCount === 0) {
        const err = new Error('Perangkat tidak ditemukan.');
        err.status = 404;
        throw err;
      }

      await client.query(
        'UPDATE sessions SET revoked = TRUE WHERE device_id = $1',
        [req.params.id]
      );

      return { ok: true };
    });

    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Endpoint tidak dikenal.
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Endpoint API tidak ditemukan.' });
});

// Penanganan error.
app.use((err, req, res, next) => {
  console.error('Request error:', err.message);

  if (res.headersSent) return next(err);

  const status = Number(err.status) || 500;

  res.status(status).json({
    error: status >= 500
      ? 'Terjadi kesalahan server.'
      : err.message
  });
});

// Vercel menggunakan export app; untuk menjalankan lokal gunakan node server.js.
if (require.main === module) {
  const PORT = Number(process.env.PORT || 3000);

  app.listen(PORT, () => {
    console.log(`KasirPro berjalan di port ${PORT}`);
  });
}

module.exports = app;
