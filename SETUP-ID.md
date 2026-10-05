# Cara Instal Legacy Staff sampai jadi

## 1. Buat project Supabase baru
Nama yang disarankan: `legacy-staff`.

Setelah project siap:
1. Buka SQL Editor.
2. Jalankan seluruh isi `supabase/migrations/01_legacy_staff.sql`.
3. Buka Authentication > Users.
4. Buat user Admin Staff dengan email dan password Anda.
5. Buka SQL Editor lagi dan jalankan `supabase/CREATE_ADMIN_EXAMPLE.sql` setelah mengganti email contoh dengan email Admin yang baru dibuat.

## 2. Ambil API project Supabase
Dari Project Connect / Settings > API Keys, ambil:
- Project URL
- Publishable key (`sb_publishable_...`)
- Secret key (`sb_secret_...`)

Jangan pernah commit Secret key ke GitHub dan jangan masukkan Secret key ke HTML/JavaScript browser.

## 3. Buat repository GitHub baru
Nama disarankan: `legacy-staff`.

Dengan GitHub Desktop:
1. File > Add Local Repository atau Create New Repository.
2. Arahkan ke folder project ini.
3. Commit semua file.
4. Publish repository.

## 4. Deploy Cloudflare Worker
Dari Terminal di folder project:

```bash
npm install
npx wrangler login
npx wrangler deploy
```

Setelah Worker pertama kali tercipta, simpan secrets:

```bash
npx wrangler secret put SUPABASE_URL
npx wrangler secret put SUPABASE_PUBLISHABLE_KEY
npx wrangler secret put SUPABASE_SECRET_KEY
```

Masukkan masing-masing value saat diminta. Setelah itu deploy lagi:

```bash
npx wrangler deploy
```

## 5. Pasang custom domain SEBELUM mendaftarkan biometrik
Sangat penting untuk WebAuthn/Passkey.

Di Cloudflare:
Workers & Pages > legacy-staff > Settings > Domains & Routes > Add > Custom Domain.

Contoh domain:
`staff.legacy.sch.id`

Setelah domain aktif, selalu gunakan domain ini untuk Admin dan pendaftaran biometrik.
Jangan mendaftarkan Passkey di URL `workers.dev` lalu pindah domain, karena Passkey terikat ke RP ID/domain tempat credential dibuat.

## 6. Login Admin
Buka:
`https://staff.legacy.sch.id/`

Login menggunakan user yang dibuat di Supabase Authentication.

## 7. Tambahkan Staff
Menu Staff > Tambah Staff.
Isi minimal:
- Kode Staff, misalnya `STF-001`
- Nama
- Jabatan
- Status Aktif

## 8. Daftarkan Face ID / Touch ID
Pada row Staff pilih `Daftar Biometrik`.
Aplikasi menghasilkan link berlaku 30 menit.
Kirim link tersebut ke HP milik staff.

Staff membuka link dari `staff.legacy.sch.id`, lalu menekan Daftarkan Face ID / Touch ID.

Satu staff boleh memiliki lebih dari satu Passkey/perangkat.
Admin dapat menekan Reset untuk mencabut semua Passkey staff tersebut.

## 9. Absensi harian
Staff membuka:
`https://staff.legacy.sch.id/attendance.html`

Masukkan Kode Staff > Verifikasi Biometrik.
- Verifikasi pertama pada hari itu = Jam Masuk.
- Verifikasi kedua = Jam Pulang.
- Setelah masuk + pulang lengkap, verifikasi berikutnya hanya menampilkan status bahwa absensi sudah lengkap.

Waktu absensi menggunakan timezone Asia/Jakarta.

## 10. Koreksi oleh Admin
Admin dapat membuka menu Absensi dan membuat/mengedit data manual untuk:
- Izin
- Sakit
- Cuti
- Alpa
- Koreksi jam masuk/pulang

Data manual ditandai sebagai verifikasi `Admin`, sedangkan data Passkey ditandai `Biometrik`.

## 11. Install di iPhone sebagai PWA
Buka `https://staff.legacy.sch.id/attendance.html` di Safari.
Share > Add to Home Screen.

## Batas keamanan penting
Aplikasi tidak menerima atau menyimpan sidik jari, Face ID, iris, atau foto wajah. WebAuthn hanya mengirim bukti kriptografi bahwa user verification pada perangkat berhasil.
