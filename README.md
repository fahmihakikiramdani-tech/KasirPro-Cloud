# KasirPro Cloud License — MVP

Implementasi awal untuk:
- pendaftaran customer dengan email + password
- kode aktivasi acak yang hanya bisa ditebus satu kali (hash disimpan di DB)
- lisensi permanen
- maksimum 2 perangkat aktif per customer
- login/logout berbasis sesi cookie HttpOnly
- panel admin membuat kode, melihat lisensi/customer, mencabut akses
- endpoint cloud data per customer dan bridge snapshot localStorage untuk versi HTML POS

## Jalankan lokal

Memerlukan Node.js 20+ dan npm.

```bash
cp .env.example .env
# Isi ADMIN_EMAIL, ADMIN_PASSWORD (min 16 karakter), COOKIE_SECRET (acak min 32 karakter)
npm install
set -a; . ./.env; set +a
npm start
```

Buka `http://localhost:3000`. Panel admin: `http://localhost:3000/admin`. Login admin memakai kredensial dari environment. Admin baru dibuat saat login admin pertama berhasil. Jangan gunakan password contoh.

## Deployment (Render atau server Node dengan disk persisten)

1. Unggah folder ini ke repo privat milikmu.
2. Buat Web Service Node, build command `npm install`, start command `npm start`.
3. Tambahkan environment variables `NODE_ENV=production`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` (minimal 16 karakter), `COOKIE_SECRET` (minimal 32 karakter acak), `DB_PATH=/var/data/kasirpro.sqlite`.
4. Pasang persistent disk pada `/var/data`; SQLite harus berada di disk persisten. Tanpa disk persisten data lisensi bisa hilang saat redeploy/restart.
5. Aktifkan HTTPS. Cookie sesi hanya secure di production.
6. Buka `/admin`, login admin, buat kode. Kode lengkap hanya ditampilkan sekali; simpan dengan aman dan kirim satu kode per customer.
7. Customer buka halaman utama, daftar, lalu buka tab Aktivasi dan masukkan kode.

## Cara kerja

- Kode aktivasi dihasilkan menggunakan `crypto.randomBytes`; database hanya menyimpan SHA-256 hash dan petunjuk enam karakter akhir.
- Penukaran kode menggunakan transaksi SQLite dan conditional update agar kode tidak bisa ditebus dua kali.
- Password disimpan dengan bcrypt; token sesi disimpan dalam bentuk hash dan dikirim ke browser lewat cookie HttpOnly.
- Lisensi permanen berarti tidak ada tanggal kedaluwarsa. Admin tetap dapat mencabut lisensi/akun.
- ID perangkat dibuat browser-side dan server hanya menyimpan hash ID perangkat. Ini membatasi penggunaan normal ke dua browser/perangkat terdaftar, bukan fingerprint perangkat yang tidak dapat dipalsukan.
- Data cloud saat ini disimpan sebagai snapshot JSON per akun. Bridge menyinkronkan localStorage POS ke cloud dengan pola last-write-wins; bukan sinkronisasi kolaboratif real-time. Hindari membuka akun yang sama aktif di dua perangkat saat mengedit data bersamaan.

## Catatan sebelum penggunaan komersial

Ini adalah MVP fondasi, bukan audit keamanan produksi. Untuk deployment berbayar skala besar, disarankan migrasi PostgreSQL, email verification dan password reset, CSRF protection yang sesuai, backup database otomatis, audit log, pemantauan, serta konflik sinkronisasi berbasis versi. Tambahkan kebijakan privasi dan syarat layanan. Kode aktivasi yang tampil di admin hanya muncul sekali; jangan refresh sebelum disalin.

## Endpoint utama
- `POST /api/register`
- `POST /api/activate`
- `POST /api/login`
- `POST /api/logout`
- `GET /api/me`
- `GET/PUT /api/data`
- `POST /api/admin/login`
- `POST /api/admin/licenses`
- `GET /api/admin/licenses`
- `GET /api/admin/users`
- `POST /api/admin/users/:id/revoke`

Lisensi dan akun harus selalu divalidasi server-side. Jangan menaruh secret admin di HTML atau menganggap file HTML lokal sebagai perlindungan lisensi.
