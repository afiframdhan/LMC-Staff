-- Legacy Staff: Kiosk Attendance (office-device only)
-- Jalankan setelah 01_legacy_staff.sql

alter table public.staff_employees
  add column if not exists photo_url text;

alter table public.staff_attendance
  drop constraint if exists staff_attendance_verification_method_check;

alter table public.staff_attendance
  add constraint staff_attendance_verification_method_check
  check (verification_method in ('admin','webauthn','kiosk'));

create table if not exists public.staff_kiosk_devices (
  kiosk_id uuid primary key default gen_random_uuid(),
  device_name text not null,
  token_hash text not null unique,
  active boolean not null default true,
  created_by text,
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create index if not exists idx_staff_kiosk_active on public.staff_kiosk_devices(active, created_at desc);
alter table public.staff_kiosk_devices enable row level security;

-- Akses tetap hanya melalui Cloudflare Worker / service role.
