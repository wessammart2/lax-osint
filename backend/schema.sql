-- ============================================================
-- LAX OSINT — مخطط قاعدة بيانات Supabase (الإصدار الإنتاجي)
-- التشغيل: Supabase Dashboard → SQL Editor → New query → Run
-- ⚠️ يشمل drop للجداول: تشغيله أكثر من مرة يمسح الجداول ويعيد إنشاءها (بيانات نظيفة).
-- ============================================================

-- ١) تفعيل إضافة التشفير (لـ crypt bcrypt للأدمن)
create extension if not exists pgcrypto;

-- ============================================================
-- ٢) إنشاء الجداول
-- ============================================================

drop table if exists public.admin_logs cascade;
drop table if exists public.search_logs cascade;
drop table if exists public.activation_codes cascade;
drop table if exists public.users cascade;
drop table if exists public.admins cascade;

-- جدول المستخدمين (بدون كلمة مرور — يديرها GoTrue في auth.users بـ bcrypt)
create table public.users (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null unique,
  searches_today integer not null default 0,      -- عداد البحوث اليومية
  last_search_date date,                           -- تاريخ آخر بحث (لتصفير العداد)
  is_pro boolean not null default false,           -- حالة الاشتراك البرو
  pro_until timestamptz,                           -- تاريخ انتهاء البرو
  disabled boolean not null default false,         -- تعطيل الحساب
  created_at timestamptz not null default now()
);

-- جدول أكواد التفعيل (صيغة الكود: XXXX-XXXX-XXXXX-XXX)
create table public.activation_codes (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  used boolean not null default false,             -- هل استُخدم الكود؟
  used_by uuid references public.users (id) on delete set null,
  activated_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

-- جدول سجل البحوث
create table public.search_logs (
  id bigint generated always as identity primary key,
  user_id uuid references public.users (id) on delete cascade,
  search_type text not null,                       -- username / email / phone / name
  query text not null,
  results_count integer not null default 0,
  created_at timestamptz not null default now()
);

-- جدول بيانات الأدمن (password_hash: bcrypt عبر pgcrypto)
create table public.admins (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now()
);

-- جدول سجل أنشطة الأدمن (مطلوب من لوحة الأدمن logs)
create table public.admin_logs (
  id bigint generated always as identity primary key,
  admin_id uuid references public.admins (id) on delete set null,
  action text not null,                            -- login / create_codes / ...
  detail jsonb,
  ip text,
  created_at timestamptz not null default now()
);

-- ============================================================
-- ٣) إدراج الأدمن الافتراضي بأمان (bcrypt مباشر عبر PostgreSQL)
-- ============================================================
insert into public.admins (username, password_hash)
values ('kalilax', crypt('kalilax122313', gen_salt('bf')))
on conflict (username) do nothing;

-- ============================================================
-- ٤) الدوال والـ Triggers
-- ============================================================

-- إنشاء سجل في users عند تسجيل مستخدم جديد عبر GoTrue
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.users (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- زيادة عداد البحوث (يعيد التصفير عند تغير اليوم)
create or replace function public.increment_searches(p_uid uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if (select last_search_date from public.users where id = p_uid)
     is distinct from current_date then
    update public.users
       set searches_today = 1, last_search_date = current_date
     where id = p_uid;
  else
    update public.users
       set searches_today = searches_today + 1
     where id = p_uid;
  end if;
end;
$$;

-- ============================================================
-- ٥) أمان مستوى الصف (RLS)
-- ============================================================
alter table public.users enable row level security;
alter table public.activation_codes enable row level security;
alter table public.search_logs enable row level security;
alter table public.admins enable row level security;
alter table public.admin_logs enable row level security;

-- المستخدم: يقرأ صفّه فقط (أي تعديل يمر عبر الباك إند بالمفتاح service_role)
create policy "users_select_own"
  on public.users for select
  to authenticated
  using (auth.uid() = id);

-- activation_codes / search_logs / admins / admin_logs:
-- لا سياسات للعميل إطلاقًا (ممنوعة بفعل RLS) — تُدار حصريًا من الباك إند
-- عبر مفتاح service_role الذي يتجاوز RLS تلقائيًا.

-- ============================================================
-- ٦) فهارس
-- ============================================================
create index if not exists idx_activation_codes_code on public.activation_codes (code);
create index if not exists idx_search_logs_user on public.search_logs (user_id);
create index if not exists idx_users_email on public.users (email);