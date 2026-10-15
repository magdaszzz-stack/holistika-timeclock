-- Holistika Time Clock — update 1: show staff their own sick and vacation balance
-- Paste into Supabase → SQL Editor → New query → Run.

create or replace function _balances(p_emp uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  with e as (select * from employees where id = p_emp),
  worked as (
    select coalesce(sum(
      extract(epoch from (s.clock_out - s.clock_in))
      - coalesce(extract(epoch from (s.meal1_end - s.meal1_start)), 0)
      - coalesce(extract(epoch from (s.meal2_end - s.meal2_start)), 0)
    ) / 3600, 0) as hrs
    from shifts s, e
    where s.employee_id = p_emp and s.clock_out is not null and s.work_date >= e.start_date
  ),
  used as (
    select coalesce(sum(hours) filter (where kind = 'sick'), 0) as sick,
           coalesce(sum(hours) filter (where kind = 'vacation'), 0) as vac
    from leave l, e
    where l.employee_id = p_emp and not l.voided and l.leave_date >= e.start_date
  )
  select jsonb_build_object(
    'full_time', e.full_time,
    'sick', round(greatest(0, least(80, e.sick_balance_start + worked.hrs / 30 - used.sick))::numeric, 2),
    'vacation', case when e.full_time then
      round((e.vac_balance_start + 40.0 * greatest(0, _today() - e.start_date) / 365 - used.vac)::numeric, 2)
      else null end)
  from e, worked, used
$$;

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
    'balances', _balances(p_emp),
    'open', (select to_jsonb(s) from shifts s where employee_id = p_emp and clock_out is null
              order by clock_in desc limit 1),
    'recent', coalesce((select jsonb_agg(to_jsonb(r) order by r.clock_in desc) from (
                select * from shifts where employee_id = p_emp order by clock_in desc limit 14) r), '[]')
  );
end $$;

revoke execute on function _balances(uuid) from public, anon, authenticated;
