-- Holistika Time Clock — update 2: signed meal waivers
-- California only allows skipping lunch (shifts of 6 hours or less) when the employee
-- has signed a meal waiver. This lets the manager record who has one on file.
-- Paste into Supabase → SQL Editor → New query → Run.

alter table employees add column if not exists meal_waiver boolean not null default false;
grant select (meal_waiver) on employees to authenticated;

drop function if exists manager_save_employee(uuid,text,text,boolean,text,boolean,date,numeric,numeric,numeric);

create function manager_save_employee(p_id uuid, p_name text, p_role text, p_full_time boolean,
    p_pin text, p_active boolean, p_start_date date, p_sick_balance_start numeric,
    p_sick_used_year_start numeric, p_vac_balance_start numeric, p_meal_waiver boolean default false) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare new_id uuid; old_row jsonb; new_row jsonb;
begin
  perform _require_manager();
  if coalesce(trim(p_name),'') = '' then raise exception 'Name is required.'; end if;
  if p_pin is not null and p_pin !~ '^[0-9]{4,6}$' then raise exception 'PIN must be 4 to 6 digits.'; end if;

  if p_id is null then
    if p_pin is null then raise exception 'A PIN is required for a new employee.'; end if;
    insert into employees(name, role, full_time, pin_hash, active, start_date,
                          sick_balance_start, sick_used_year_start, vac_balance_start, meal_waiver)
    values (trim(p_name), coalesce(p_role,''), p_full_time, crypt(p_pin, gen_salt('bf')), coalesce(p_active,true),
            coalesce(p_start_date, _today()), coalesce(p_sick_balance_start,0),
            coalesce(p_sick_used_year_start,0), coalesce(p_vac_balance_start,0), coalesce(p_meal_waiver,false))
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
         meal_waiver = coalesce(p_meal_waiver,false),
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

revoke execute on function manager_save_employee(uuid,text,text,boolean,text,boolean,date,numeric,numeric,numeric,boolean) from public, anon;
grant execute on function manager_save_employee(uuid,text,text,boolean,text,boolean,date,numeric,numeric,numeric,boolean) to authenticated;

create or replace function staff_status(p_emp uuid, p_pin text) returns jsonb
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
    'meal_waiver', (select meal_waiver from employees where id = p_emp),
    'balances', _balances(p_emp),
    'open', (select to_jsonb(s) from shifts s where employee_id = p_emp and clock_out is null
              order by clock_in desc limit 1),
    'recent', coalesce((select jsonb_agg(to_jsonb(r) order by r.clock_in desc) from (
                select * from shifts where employee_id = p_emp order by clock_in desc limit 14) r), '[]')
  );
end $$;
