-- Legacy Staff: Face Recognition untuk HP Kantor / Kiosk
-- Jalankan setelah 02_kiosk_attendance.sql

alter table public.staff_employees
  add column if not exists face_descriptor jsonb,
  add column if not exists face_enrolled_at timestamptz,
  add column if not exists face_model text;

alter table public.staff_attendance
  add column if not exists face_match_distance numeric;

alter table public.staff_attendance
  drop constraint if exists staff_attendance_verification_method_check;

alter table public.staff_attendance
  add constraint staff_attendance_verification_method_check
  check (verification_method in ('admin','webauthn','kiosk','face'));

-- Descriptor wajah adalah template biometrik (128 angka), bukan foto mentah.
-- RLS tetap aktif dan akses aplikasi melalui Cloudflare Worker / service role.
