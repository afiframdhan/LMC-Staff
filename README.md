# Legacy Staff

Aplikasi terpisah dari Legacy LMS untuk manajemen karyawan dan absensi biometrik.

## Fitur
- Supabase project sendiri, terpisah dari siswa/guru
- Login Admin memakai Supabase Auth
- Data Staff dan jabatan
- Absensi masuk/pulang dengan Face ID / Touch ID / Windows Hello melalui WebAuthn/Passkey
- Multi-device Passkey dan reset credential oleh Admin
- Koreksi manual Izin/Sakit/Cuti/Alpa
- Ringkasan kehadiran
- Audit aktivitas Admin
- PWA untuk shortcut di HP

## Cloudflare secrets
Gunakan key modern Supabase 2026:
- `SUPABASE_URL`
- `SUPABASE_PUBLISHABLE_KEY`
- `SUPABASE_SECRET_KEY`

Kode tetap kompatibel dengan `SUPABASE_ANON_KEY` dan `SUPABASE_SERVICE_ROLE_KEY` legacy bila diperlukan.

Baca `SETUP-ID.md` untuk instalasi lengkap.
