-- Gelato Control: схема базы, версия 2 (роли на уровне базы).
-- Выполнить в Supabase → SQL Editor → New query → Run. Повторный запуск безопасен.

-- 1. Таблица документов (все коллекции программы: ops, items, whs, cfg, members, ...)
create table if not exists public.docs (
  coll       text        not null,
  id         text        not null,
  data       jsonb       not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (coll, id)
);

alter table public.docs enable row level security;
-- Права на таблицу: только вошедшие пользователи; анонимным доступа нет
revoke all on public.docs from anon;
grant select, insert, update, delete on public.docs to authenticated;
alter table public.docs replica identity full;

do $$ begin
  alter publication supabase_realtime add table public.docs;
exception when duplicate_object then null;
end $$;

-- 2. Роль текущего пользователя: берётся из cfg/main.roles[uid]. Если роли нет, но есть запись участника — «seller».
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select coalesce(
    (select d.data->'roles'->>auth.uid()::text from public.docs d where d.coll = 'cfg' and d.id = 'main'),
    case when exists (select 1 from public.docs m where m.coll = 'members' and m.id = auth.uid()::text)
         then 'seller' end
  );
$$;

-- 3. Какие типы операций (ops.type) может проводить роль (ТЗ, раздел 17)
create or replace function public.op_allowed(r text, t text) returns boolean
language sql immutable as $$
  select case
    when r in ('owner', 'admin') then true
    when r = 'acct'   then t in ('buy', 'spay', 'exp', 'epay', 'cpay', 'payout', 'mtr', 'asset', 'cdiff', 'ret', 'open')
    when r in ('prod', 'packer') then t in ('prod', 'pack', 'move', 'wo', 'inv', 'open')
    when r = 'store'  then t in ('buy', 'move', 'wo', 'inv', 'open', 'ret')
    when r = 'seller' then t in ('sale', 'shift', 'ret', 'cdiff')   -- cdiff: недостача/излишек при открытии и закрытии смены
    else false
  end;
$$;

-- 4. Чтение: участник видит справочники и журнал операций; архив — владелец, админ, бухгалтер.
create or replace function public.can_read(c text, i text, t text) returns boolean
language sql stable security definer set search_path = public as $$
  select case
    when c = 'members' and i = auth.uid()::text then true
    when not exists (select 1 from public.docs m where m.coll = 'members' and m.id = auth.uid()::text) then false
    when c = 'ops'     then true   -- все участники видят все операции (остатки считаются по общему журналу); писать — по роли
    when c = 'archive' then public.my_role() in ('owner', 'admin', 'acct')
    else true
  end;
$$;

-- 5. Запись: операции — по типу; справочники и настройки — владелец/админ; свою запись участника — сам.
create or replace function public.can_write(c text, i text, t text) returns boolean
language sql stable security definer set search_path = public as $$
  select case
    when c = 'members' then i = auth.uid()::text or public.my_role() in ('owner', 'admin')
    when c = 'ops'     then public.op_allowed(public.my_role(), t)
    when c = 'archive' then public.my_role() = 'owner'
    when c = 'cfg'     then public.my_role() = 'owner'
    when c in ('accounts', 'expcats', 'templates', 'pays')
                       then public.my_role() in ('owner', 'admin', 'acct')
    else public.my_role() in ('owner', 'admin')
  end;
$$;

-- 6. Политики
drop policy if exists docs_select on public.docs;
drop policy if exists docs_insert on public.docs;
drop policy if exists docs_update on public.docs;
drop policy if exists docs_delete on public.docs;

create policy docs_select on public.docs for select to authenticated
  using (public.can_read(coll, id, data->>'type'));

create policy docs_insert on public.docs for insert to authenticated
  with check (public.can_write(coll, id, data->>'type'));

create policy docs_update on public.docs for update to authenticated
  using (public.can_write(coll, id, data->>'type'))
  with check (public.can_write(coll, id, data->>'type'));

create policy docs_delete on public.docs for delete to authenticated
  using (public.can_write(coll, id, data->>'type'));

-- 7. Первичная настройка владельца (выполнить ОДИН раз, после создания его учётной записи в Authentication → Users).
--    Вместо <UUID-ВЛАДЕЛЬЦА> вставить id пользователя из Authentication → Users.
--
--    insert into public.docs (coll, id, data)
--      values ('cfg', 'main', '{"roles": {}}') on conflict (coll, id) do nothing;
--    update public.docs
--      set data = jsonb_set(data, '{roles}', coalesce(data->'roles', '{}'::jsonb) || jsonb_build_object('<UUID-ВЛАДЕЛЬЦА>', 'owner'))
--      where coll = 'cfg' and id = 'main';
--
--    Владелец при первом входе сам создаст свою запись в members (политика members разрешает это только для себя).
