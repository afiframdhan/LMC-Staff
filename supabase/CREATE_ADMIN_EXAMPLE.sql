-- Jalankan SETELAH membuat user Admin di Supabase Authentication > Users.
-- Ganti email di bawah sesuai email user Auth yang dibuat.
insert into public.staff_admins (email, full_name, active)
values ('admin@legacy.sch.id', 'Admin Legacy', true)
on conflict (email) do update
set full_name = excluded.full_name,
    active = true,
    updated_at = now();
