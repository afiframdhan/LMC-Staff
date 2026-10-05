create extension if not exists pgcrypto;

create table if not exists public.staff_admins (
  admin_id uuid primary key default gen_random_uuid(),
  email text not null unique,
  full_name text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.staff_employees (
  staff_id uuid primary key default gen_random_uuid(),
  employee_code text not null unique,
  full_name text not null,
  position text not null,
  email text,
  phone text,
  joined_on date,
  ended_on date,
  status text not null default 'Aktif' check (status in ('Aktif','Cuti','Nonaktif')),
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.staff_attendance (
  attendance_id uuid primary key default gen_random_uuid(),
  staff_id uuid not null references public.staff_employees(staff_id) on delete cascade,
  staff_name_snapshot text not null,
  position_snapshot text,
  attendance_date date not null,
  status text not null default 'Hadir' check (status in ('Hadir','Izin','Sakit','Alpa','Cuti')),
  check_in time,
  check_out time,
  notes text,
  verification_method text not null default 'admin' check (verification_method in ('admin','webauthn')),
  biometric_credential_id text,
  biometric_verified_at timestamptz,
  recorded_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(staff_id, attendance_date)
);

create table if not exists public.staff_biometric_enrollments (
  enrollment_id uuid primary key default gen_random_uuid(),
  staff_id uuid not null references public.staff_employees(staff_id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_by text,
  created_at timestamptz not null default now()
);

create table if not exists public.staff_webauthn_credentials (
  credential_id text primary key,
  staff_id uuid not null references public.staff_employees(staff_id) on delete cascade,
  public_key_spki text not null,
  algorithm integer not null,
  sign_count bigint not null default 0,
  transports jsonb not null default '[]'::jsonb,
  device_label text,
  active boolean not null default true,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.staff_webauthn_challenges (
  challenge_id uuid primary key default gen_random_uuid(),
  staff_id uuid not null references public.staff_employees(staff_id) on delete cascade,
  purpose text not null check (purpose in ('register','authenticate')),
  challenge text not null unique,
  origin text not null,
  rp_id text not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.staff_audit_logs (
  audit_id uuid primary key default gen_random_uuid(),
  actor_email text,
  action text not null,
  entity_type text,
  entity_id text,
  details jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_staff_attendance_date on public.staff_attendance(attendance_date desc);
create index if not exists idx_staff_attendance_staff on public.staff_attendance(staff_id, attendance_date desc);
create index if not exists idx_staff_credentials_staff on public.staff_webauthn_credentials(staff_id);
create index if not exists idx_staff_challenges_staff on public.staff_webauthn_challenges(staff_id, created_at desc);
create index if not exists idx_staff_audit_created on public.staff_audit_logs(created_at desc);

alter table public.staff_admins enable row level security;
alter table public.staff_employees enable row level security;
alter table public.staff_attendance enable row level security;
alter table public.staff_biometric_enrollments enable row level security;
alter table public.staff_webauthn_credentials enable row level security;
alter table public.staff_webauthn_challenges enable row level security;
alter table public.staff_audit_logs enable row level security;

-- Sengaja tidak membuat policy untuk anon/authenticated.
-- Semua akses data aplikasi melewati Cloudflare Worker menggunakan service_role.
