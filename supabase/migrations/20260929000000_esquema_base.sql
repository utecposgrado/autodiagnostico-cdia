-- Esquema base: resultados, admins, clave de respuestas y calificación en el servidor.
-- La clave de respuestas (privado.clave) NO se incluye: se carga aparte (ver README).

create schema if not exists privado;
revoke all on schema privado from public, anon, authenticated;

-- Clave de respuestas (una sola fila). El esquema privado no se expone por la API.
create table if not exists privado.clave (
  id integer primary key default 1 check (id = 1),
  datos jsonb not null
);

-- Correos autorizados para el panel de administración.
create table if not exists public.admins (
  email text primary key check (email = lower(email)),
  creado_en timestamptz not null default now()
);

create table if not exists public.resultados (
  id bigint generated always as identity primary key,
  creado_en timestamptz not null default now(),
  nombre text not null,
  lenguaje text not null,
  experiencia text not null,
  puntaje_parte1 integer not null,
  puntaje_reto1 integer not null,
  puntaje_total integer not null,
  respuestas_parte1 jsonb not null,
  respuestas_reto1 jsonb not null,
  email text not null,
  inicio timestamptz,
  fin timestamptz,
  duracion_seg integer
);

create index if not exists resultados_creado_en_idx on public.resultados (creado_en desc);

create or replace function public.es_admin()
returns boolean
language sql
stable security definer
set search_path to ''
as $$
  select exists (
    select 1 from public.admins
    where email = lower(coalesce((select auth.jwt() ->> 'email'), ''))
  );
$$;

alter table public.admins enable row level security;
alter table public.resultados enable row level security;

create policy "usuario ve su propia fila de admin" on public.admins
  for select to authenticated
  using (email = lower((select auth.jwt() ->> 'email')));

create policy "admins leen resultados" on public.resultados
  for select to authenticated
  using ((select public.es_admin()));

create policy "admins borran resultados" on public.resultados
  for delete to authenticated
  using ((select public.es_admin()));

-- La llama el formulario: califica en el servidor y guarda el resultado.
create or replace function public.enviar_evaluacion(p jsonb)
returns jsonb
language plpgsql
security definer
set search_path to ''
as $$
declare
  k jsonb;
  v_nombre text := btrim(coalesce(p ->> 'nombre', ''));
  v_email text := lower(btrim(coalesce(p ->> 'email', '')));
  v_lenguaje text := btrim(coalesce(p ->> 'lenguaje', ''));
  v_experiencia text := btrim(coalesce(p ->> 'experiencia', ''));
  r1 jsonb := coalesce(p -> 'respuestasParteI', '[]'::jsonb);
  rr1 jsonb := coalesce(p -> 'respuestasReto1', '{}'::jsonb);
  v_fin timestamptz := now();          -- la hora de fin la pone el servidor
  v_inicio timestamptz;
  s1 int; s2 int;
begin
  if v_nombre = '' or v_lenguaje = '' or v_experiencia = ''
     or length(v_nombre) > 200 or length(v_lenguaje) > 100 or length(v_experiencia) > 100 then
    raise exception 'Datos personales inválidos';
  end if;
  if length(v_email) > 254 or v_email !~ '^[^\s@]+@[^\s@]+\.[^\s@]+$' then
    raise exception 'Correo electrónico inválido';
  end if;
  if jsonb_typeof(r1) <> 'array' or jsonb_array_length(r1) > 50
     or jsonb_typeof(rr1) <> 'object' or length(rr1::text) > 500 then
    raise exception 'Respuestas inválidas';
  end if;

  -- Hora de inicio enviada por el navegador; se descarta si no es plausible
  -- (futura o de hace más de 24 h).
  begin
    v_inicio := (p ->> 'inicio')::timestamptz;
  exception when others then
    v_inicio := null;
  end;
  if v_inicio is not null and (v_inicio > v_fin + interval '1 minute' or v_inicio < v_fin - interval '24 hours') then
    v_inicio := null;
  end if;

  select datos into k from privado.clave where id = 1;

  select count(*) * 4 into s1
  from jsonb_array_elements(k -> 'parte1') with ordinality as c(ok, i)
  where r1 -> (c.i::int - 1) = c.ok;

  select coalesce(sum((c.pts #>> '{}')::int), 0) into s2
  from jsonb_each(k -> 'reto1_pts') as c(id, pts)
  where rr1 -> c.id = k -> 'reto1' -> c.id;

  insert into public.resultados (nombre, email, lenguaje, experiencia,
    puntaje_parte1, puntaje_reto1, puntaje_total, respuestas_parte1, respuestas_reto1,
    inicio, fin, duracion_seg)
  values (v_nombre, v_email, v_lenguaje, v_experiencia, s1, s2, s1 + s2, r1, rr1,
    v_inicio, v_fin, greatest(0, extract(epoch from (v_fin - v_inicio)))::int);

  return jsonb_build_object('parte1', s1, 'reto1', s2, 'total', s1 + s2,
    'duracion_seg', greatest(0, extract(epoch from (v_fin - v_inicio)))::int);
end;
$$;

-- Clave para el detalle por pregunta del panel (solo admins).
create or replace function public.clave_para_admin()
returns jsonb
language plpgsql
stable security definer
set search_path to ''
as $$
begin
  if not public.es_admin() then
    raise exception 'No autorizado' using errcode = '42501';
  end if;
  return (select datos from privado.clave where id = 1);
end;
$$;

revoke all on function public.es_admin() from public, anon;
revoke all on function public.clave_para_admin() from public, anon;
revoke all on function public.enviar_evaluacion(jsonb) from public;
grant execute on function public.es_admin() to authenticated;
grant execute on function public.clave_para_admin() to authenticated;
grant execute on function public.enviar_evaluacion(jsonb) to anon, authenticated;
