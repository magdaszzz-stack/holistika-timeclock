-- =====================================================================
--  Holistika Time Clock — database setup
--  Paste this whole file into Supabase → SQL Editor → New query → Run.
--  Safe to run once on a new, empty project.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- Tables ----------------------------------------------------

create table employees (
  id                    uuid primary key default gen_random_uuid(),
  name                  text not null,
  role                  text not null default '',
  full_time             boolean not null default false,
  pin_hash              text not null,
  active                boolean not null default true,
  start_date            date not null default (now() at time zone 'America/Los_Angeles')::date,
  sick_balance_start    numeric not null default 0,   -- sick hours available on start_date (from PayEntry)
  sick_used_year_start  numeric not null default 0,   -- sick hours already used this calendar year before start_date
  vac_balance_start     numeric not null default 0,   -- vacation hours available on start_date
  created_at            timestamptz not null default now()
);

create table shifts (
  id              uuid primary key default gen_random_uuid(),
  employee_id     uuid not null references employees(id),
  work_date       date not null,
  clock_in        timestamptz not null,
  clock_out       timestamptz,
  meal1_start     timestamptz,
  meal1_end       timestamptz,
  meal2_start     timestamptz,
  meal2_end       timestamptz,
  meal_answer     text check (meal_answer in ('yes','no','waived','n/a')),
  rest_answer     text check (rest_answer in ('yes','no','n/a')),
  times_accurate  boolean,
  edited          boolean not null default false,
  created_at      timestamptz not null default now()
);
create index shifts_emp_date on shifts(employee_id, work_date);

create table messages (
  id           uuid primary key default gen_random_uuid(),
  employee_id  uuid not null references employees(id),
  shift_id     uuid references shifts(id),
  items        jsonb not null default '[]',
  body         text not null default '',
  status       text not null default 'new' check (status in ('new','handled')),
  created_at   timestamptz not null default now(),
  handled_by   text,
  handled_at   timestamptz
);

create table fix_requests (
  id           uuid primary key default gen_random_uuid(),
  employee_id  uuid not null references employees(id),
  shift_id     uuid not null references shifts(id),
  field        text not null check (field in ('clock_in','clock_out','meal1_start','meal1_end','meal2_start','meal2_end')),
  new_time     timestamptz not null,
  reason       text not null,
  status       text not null default 'pending' check (status in ('pending','approved','declined')),
  created_at   timestamptz not null default now(),
  decided_by   text,
  decided_at   timestamptz
);

create table leave (
  id           uuid primary key default gen_random_uuid(),
  employee_id  uuid not null references employees(id),
  leave_date   date not null,
  kind         text not null check (kind in ('sick','vacation')),
  hours        numeric not null check (hours > 0),
  note         text not null default '',
  voided       boolean not null default false,
  created_by   text,
  created_at   timestamptz not null default now()
);

create table audit_log (
  id           bigint generated always as identity primary key,
  at           timestamptz not null default now(),
  actor        text not null,
  employee_id  uuid references employees(id),
  shift_id     uuid references shifts(id),
  field        text not null,
  old_value    text,
  new_value    text,
  reason       text not null
);

create table managers (
  user_id  uuid primary key references auth.users(id),
  name     text not null
);

create table pin_attempts (
  id           bigint generated always as identity primary key,
  employee_id  uuid not null,
  at           timestamptz not null default now(),
  ok           boolean not null
);

-- ---------- Records that can never be edited or deleted ---------------

create function _locked() returns trigger language plpgsql as $$
begin
  raise exception 'This record is permanent and cannot be changed or deleted.';
end $$;

create trigger audit_log_no_update before update or delete on audit_log
  for each row execute function _locked();
create trigger audit_log_no_truncate before truncate on audit_log
  for each statement execute function _locked();
create trigger shifts_no_delete before delete on shifts
  for each row execute function _locked();
create trigger shifts_no_truncate before truncate on shifts
  for each statement execute function _locked();

-- ---------- Helpers (not callable from the app directly) --------------

create function _today() returns date language sql stable as $$
  select (now() at time zone 'America/Los_Angeles')::date
$$;

create function _la_ts(d date, hm text) returns timestamptz language sql immutable as $$
  select case when hm is null or hm = '' then null
              else (d + hm::time) at time zone 'America/Los_Angeles' end
$$;

create function _fmt(t timestamptz) returns text language sql stable as $$
  select case when t is null then null
              else to_char(t at time zone 'America/Los_Angeles', 'Mon DD HH12:MI AM') end
$$;

create function is_manager() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from managers where user_id = auth.uid())
$$;

create function _actor() returns text
language sql stable security definer set search_path = public as $$
  select coalesce((select name from managers where user_id = auth.uid()), 'Manager')
$$;

create function _require_manager() returns void
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_manager() then raise exception 'Manager login required.'; end if;
end $$;

-- Returns NULL when the PIN is right, otherwise an error message.
-- Five wrong PINs in 15 minutes locks that person out for 15 minutes.
create function _pin_error(p_emp uuid, p_pin text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare h text; fails int;
begin
  select count(*) into fails from pin_attempts
   where employee_id = p_emp and not ok and at > now() - interval '15 minutes';
  if fails >= 5 then return 'Too many wrong PINs. Try again in 15 minutes.'; end if;
  select pin_hash into h from employees where id = p_emp and active;
  if h is null then return 'Employee not found.'; end if;
  if crypt(coalesce(p_pin,''), h) <> h then
    insert into pin_attempts(employee_id, ok) values (p_emp, false);
    return 'That PIN doesn''t match. Try again.';
  end if;
  return null;
end $$;

-- ---------- Staff actions (PIN required) ------------------------------

create function staff_list() returns table(id uuid, name text)
language sql stable security definer set search_path = public as $$
  select id, name from employees where active order by name
$$;

create function staff_status(p_emp uuid, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare err text;
begin
  err := _pin_error(p_emp, p_pin);
  if err is not null then return jsonb_build_object('error', err); end if;
  return jsonb_build_object(
    'ok', true,
    'now', now(),
    'today', _today(),
    'name', (select name from employees where id = p_emp),
    'open', (select to_jsonb(s) from shifts s where employee_id = p_emp and clock_out is null
              order by clock_in desc limit 1),
    'recent', coalesce((select jsonb_agg(to_jsonb(r) order by r.clock_in desc) from (
                select * from shifts where employee_id = p_emp order by clock_in desc limit 14) r), '[]')
  );
end $$;

create function staff_punch(p_emp uuid, p_pin text, p_action text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare err text; s shifts;
begin
  err := _pin_error(p_emp, p_pin);
  if err is not null then return jsonb_build_object('error', err); end if;
  select * into s from shifts where employee_id = p_emp and clock_out is null
   order by clock_in desc limit 1;

  if p_action = 'in' then
    if s.id is not null and s.work_date = _today() then
      return jsonb_build_object('error', 'You are already clocked in.');
    end if;
    insert into shifts(employee_id, work_date, clock_in) values (p_emp, _today(), now());
    return jsonb_build_object('ok', true);
  end if;

  if s.id is null then return jsonb_build_object('error', 'You are not clocked in.'); end if;

  if p_action = 'meal_start' then
    if s.meal1_start is null then update shifts set meal1_start = now() where id = s.id;
    elsif s.meal1_end is not null and s.meal2_start is null then update shifts set meal2_start = now() where id = s.id;
    else return jsonb_build_object('error', 'You are already on lunch.'); end if;
  elsif p_action = 'meal_end' then
    if s.meal1_start is not null and s.meal1_end is null then update shifts set meal1_end = now() where id = s.id;
    elsif s.meal2_start is not null and s.meal2_end is null then update shifts set meal2_end = now() where id = s.id;
    else return jsonb_build_object('error', 'You are not on lunch.'); end if;
  else
    return jsonb_build_object('error', 'Unknown action.');
  end if;
  return jsonb_build_object('ok', true);
end $$;

create function staff_clock_out(p_emp uuid, p_pin text, p_meal_answer text, p_rest_answer text,
                                p_accurate boolean, p_items jsonb, p_message text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare err text; s shifts;
begin
  err := _pin_error(p_emp, p_pin);
  if err is not null then return jsonb_build_object('error', err); end if;
  select * into s from shifts where employee_id = p_emp and clock_out is null
   order by clock_in desc limit 1;
  if s.id is null then return jsonb_build_object('error', 'You are not clocked in.'); end if;
  if (s.meal1_start is not null and s.meal1_end is null) or (s.meal2_start is not null and s.meal2_end is null) then
    return jsonb_build_object('error', 'End your lunch before clocking out.');
  end if;
  update shifts set clock_out = now(), meal_answer = p_meal_answer, rest_answer = p_rest_answer,
                    times_accurate = p_accurate
   where id = s.id;
  if jsonb_array_length(coalesce(p_items,'[]')) > 0 or coalesce(trim(p_message),'') <> '' then
    insert into messages(employee_id, shift_id, items, body)
    values (p_emp, s.id, coalesce(p_items,'[]'), coalesce(trim(p_message),''));
  end if;
  return jsonb_build_object('ok', true, 'shift_id', s.id);
end $$;

create function staff_request_fix(p_emp uuid, p_pin text, p_shift uuid, p_field text,
                                  p_time text, p_reason text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare err text; d date;
begin
  err := _pin_error(p_emp, p_pin);
  if err is not null then return jsonb_build_object('error', err); end if;
  select work_date into d from shifts where id = p_shift and employee_id = p_emp;
  if d is null then return jsonb_build_object('error', 'Shift not found.'); end if;
  if coalesce(trim(p_reason),'') = '' then return jsonb_build_object('error', 'Please give a reason.'); end if;
  insert into fix_requests(employee_id, shift_id, field, new_time, reason)
  values (p_emp, p_shift, p_field, _la_ts(d, p_time), trim(p_reason));
  return jsonb_build_object('ok', true);
end $$;

-- ---------- Manager actions (manager login required, all logged) ------

create function manager_save_employee(p_id uuid, p_name text, p_role text, p_full_time boolean,
    p_pin text, p_active boolean, p_start_date date, p_sick_balance_start numeric,
    p_sick_used_year_start numeric, p_vac_balance_start numeric) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare new_id uuid; old_row jsonb; new_row jsonb;
begin
  perform _require_manager();
  if coalesce(trim(p_name),'') = '' then raise exception 'Name is required.'; end if;
  if p_pin is not null and p_pin !~ '^[0-9]{4,6}$' then raise exception 'PIN must be 4 to 6 digits.'; end if;

  if p_id is null then
    if p_pin is null then raise exception 'A PIN is required for a new employee.'; end if;
    insert into employees(name, role, full_time, pin_hash, active, start_date,
                          sick_balance_start, sick_used_year_start, vac_balance_start)
    values (trim(p_name), coalesce(p_role,''), p_full_time, crypt(p_pin, gen_salt('bf')), coalesce(p_active,true),
            coalesce(p_start_date, _today()), coalesce(p_sick_balance_start,0),
            coalesce(p_sick_used_year_start,0), coalesce(p_vac_balance_start,0))
    returning id into new_id;
    insert into audit_log(actor, employee_id, field, old_value, new_value, reason)
    values (_actor(), new_id, 'Employee added', null, trim(p_name), 'New employee');
    return new_id;
  end if;

  select to_jsonb(e) - 'pin_hash' - 'created_at' into old_row from employees e where id = p_id;
  if old_row is null then raise exception 'Employee not found.'; end if;
  update employees set name = trim(p_name), role = coalesce(p_role,''), full_time = p_full_time,
         active = coalesce(p_active,true), start_date = coalesce(p_start_date, start_date),
         sick_balance_start = coalesce(p_sick_balance_start,0),
         sick_used_year_start = coalesce(p_sick_used_year_start,0),
         vac_balance_start = coalesce(p_vac_balance_start,0),
         pin_hash = case when p_pin is null then pin_hash else crypt(p_pin, gen_salt('bf')) end
   where id = p_id;
  select to_jsonb(e) - 'pin_hash' - 'created_at' into new_row from employees e where id = p_id;
  if old_row <> new_row then
    insert into audit_log(actor, employee_id, field, old_value, new_value, reason)
    values (_actor(), p_id, 'Employee details', old_row::text, new_row::text, 'Updated employee details');
  end if;
  if p_pin is not null then
    insert into audit_log(actor, employee_id, field, old_value, new_value, reason)
    values (_actor(), p_id, 'PIN', '(hidden)', '(hidden)', 'PIN changed');
  end if;
  return p_id;
end $$;

-- p_changes: {"clock_in": "2026-10-14T15:05:00Z", "meal_answer": "no", ...}  (null clears a time)
create function manager_edit_shift(p_shift uuid, p_changes jsonb, p_reason text, p_actor_note text default null)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare k text; v jsonb; newtxt text; oldtxt text; changed boolean; n int := 0; emp uuid;
        time_fields text[] := array['clock_in','clock_out','meal1_start','meal1_end','meal2_start','meal2_end'];
        answer_fields text[] := array['meal_answer','rest_answer'];
begin
  perform _require_manager();
  if coalesce(trim(p_reason),'') = '' then raise exception 'A reason is required for every change.'; end if;
  select employee_id into emp from shifts where id = p_shift;
  if emp is null then raise exception 'Shift not found.'; end if;

  for k, v in select key, value from jsonb_each(p_changes) loop
    newtxt := case when jsonb_typeof(v) = 'null' then null else v #>> '{}' end;
    if newtxt = '' then newtxt := null; end if;
    if k = any(time_fields) then
      if k = 'clock_in' and newtxt is null then raise exception 'Clock-in time cannot be blank.'; end if;
      execute format('select %I is distinct from $1::timestamptz, _fmt(%I) from shifts where id = $2', k, k)
        into changed, oldtxt using newtxt, p_shift;
      if changed then
        execute format('update shifts set %I = $1::timestamptz where id = $2', k) using newtxt, p_shift;
        insert into audit_log(actor, employee_id, shift_id, field, old_value, new_value, reason)
        values (_actor() || coalesce(' ' || p_actor_note, ''), emp, p_shift, k, coalesce(oldtxt,'(blank)'),
                coalesce(_fmt(newtxt::timestamptz),'(blank)'), trim(p_reason));
        n := n + 1;
      end if;
    elsif k = any(answer_fields) then
      execute format('select %I is distinct from $1, %I from shifts where id = $2', k, k)
        into changed, oldtxt using newtxt, p_shift;
      if changed then
        execute format('update shifts set %I = $1 where id = $2', k) using newtxt, p_shift;
        insert into audit_log(actor, employee_id, shift_id, field, old_value, new_value, reason)
        values (_actor() || coalesce(' ' || p_actor_note, ''), emp, p_shift, k, coalesce(oldtxt,'(no answer)'),
                coalesce(newtxt,'(no answer)'), trim(p_reason));
        n := n + 1;
      end if;
    else
      raise exception 'The field "%" cannot be edited.', k;
    end if;
  end loop;
  if n > 0 then update shifts set edited = true where id = p_shift; end if;
  return jsonb_build_object('ok', true, 'changes', n);
end $$;

create function manager_add_shift(p_emp uuid, p_date date, p_in text, p_out text, p_meal_start text,
    p_meal_end text, p_meal_answer text, p_rest_answer text, p_reason text) returns uuid
language plpgsql security definer set search_path = public as $$
declare new_id uuid;
begin
  perform _require_manager();
  if coalesce(trim(p_reason),'') = '' then raise exception 'A reason is required.'; end if;
  if coalesce(p_in,'') = '' then raise exception 'Clock-in time is required.'; end if;
  insert into shifts(employee_id, work_date, clock_in, clock_out, meal1_start, meal1_end,
                     meal_answer, rest_answer, edited)
  values (p_emp, p_date, _la_ts(p_date, p_in), _la_ts(p_date, p_out), _la_ts(p_date, p_meal_start),
          _la_ts(p_date, p_meal_end), nullif(p_meal_answer,''), nullif(p_rest_answer,''), true)
  returning id into new_id;
  insert into audit_log(actor, employee_id, shift_id, field, old_value, new_value, reason)
  values (_actor(), p_emp, new_id, 'Shift added', null,
          concat_ws(' ', 'In', p_in, '· Out', coalesce(nullif(p_out,''),'—'),
                    '· Lunch', coalesce(nullif(p_meal_start,''),'—'), '-', coalesce(nullif(p_meal_end,''),'—')),
          trim(p_reason));
  return new_id;
end $$;

create function manager_decide_request(p_id uuid, p_approve boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r fix_requests; who text;
begin
  perform _require_manager();
  select * into r from fix_requests where id = p_id and status = 'pending';
  if r.id is null then raise exception 'Request not found or already decided.'; end if;
  update fix_requests set status = case when p_approve then 'approved' else 'declined' end,
         decided_by = _actor(), decided_at = now() where id = p_id;
  if p_approve then
    select split_part(name, ' ', 1) into who from employees where id = r.employee_id;
    perform manager_edit_shift(r.shift_id, jsonb_build_object(r.field, r.new_time),
                               'Employee request: ' || r.reason, '(approved ' || who || '''s request)');
  end if;
  return jsonb_build_object('ok', true);
end $$;

create function manager_handle_message(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  perform _require_manager();
  update messages set status = 'handled', handled_by = _actor(), handled_at = now() where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

create function manager_add_leave(p_emp uuid, p_date date, p_kind text, p_hours numeric, p_note text) returns uuid
language plpgsql security definer set search_path = public as $$
declare new_id uuid;
begin
  perform _require_manager();
  insert into leave(employee_id, leave_date, kind, hours, note, created_by)
  values (p_emp, p_date, p_kind, p_hours, coalesce(p_note,''), _actor()) returning id into new_id;
  insert into audit_log(actor, employee_id, field, old_value, new_value, reason)
  values (_actor(), p_emp, 'Time off added', null, p_kind || ' ' || p_hours || ' hrs on ' || p_date,
          coalesce(nullif(trim(p_note),''), 'Recorded time off'));
  return new_id;
end $$;

create function manager_void_leave(p_id uuid, p_reason text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare l leave;
begin
  perform _require_manager();
  if coalesce(trim(p_reason),'') = '' then raise exception 'A reason is required.'; end if;
  select * into l from leave where id = p_id and not voided;
  if l.id is null then raise exception 'Entry not found.'; end if;
  update leave set voided = true where id = p_id;
  insert into audit_log(actor, employee_id, field, old_value, new_value, reason)
  values (_actor(), l.employee_id, 'Time off removed', l.kind || ' ' || l.hours || ' hrs on ' || l.leave_date,
          '(removed)', trim(p_reason));
  return jsonb_build_object('ok', true);
end $$;

-- ---------- Security: who can see and do what --------------------------

alter table employees    enable row level security;
alter table shifts       enable row level security;
alter table messages     enable row level security;
alter table fix_requests enable row level security;
alter table leave        enable row level security;
alter table audit_log    enable row level security;
alter table managers     enable row level security;
alter table pin_attempts enable row level security;

-- Managers can read everything (except PIN codes). Nobody can write to tables
-- directly; every change goes through the functions above, which log it.
create policy mgr_read on employees    for select to authenticated using (is_manager());
create policy mgr_read on shifts       for select to authenticated using (is_manager());
create policy mgr_read on messages     for select to authenticated using (is_manager());
create policy mgr_read on fix_requests for select to authenticated using (is_manager());
create policy mgr_read on leave        for select to authenticated using (is_manager());
create policy mgr_read on audit_log    for select to authenticated using (is_manager());
create policy mgr_read on managers     for select to authenticated using (is_manager());

revoke all on all tables in schema public from anon, authenticated;
grant select on shifts, messages, fix_requests, leave, audit_log, managers to authenticated;
grant select (id, name, role, full_time, active, start_date, sick_balance_start,
              sick_used_year_start, vac_balance_start, created_at) on employees to authenticated;

revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function staff_list(), staff_status(uuid,text), staff_punch(uuid,text,text),
  staff_clock_out(uuid,text,text,text,boolean,jsonb,text), staff_request_fix(uuid,text,uuid,text,text,text)
  to anon, authenticated;
grant execute on function is_manager(),
  manager_save_employee(uuid,text,text,boolean,text,boolean,date,numeric,numeric,numeric),
  manager_edit_shift(uuid,jsonb,text,text), manager_add_shift(uuid,date,text,text,text,text,text,text,text),
  manager_decide_request(uuid,boolean), manager_handle_message(uuid),
  manager_add_leave(uuid,date,text,numeric,text), manager_void_leave(uuid,text)
  to authenticated;

-- Done. Next: create the manager login (see the setup guide, step 2).
