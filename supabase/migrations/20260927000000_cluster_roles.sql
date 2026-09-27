create table if not exists public.cluster_workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 90),
  region text not null default '',
  country text not null default '',
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table if not exists public.cluster_memberships (
  cluster_id uuid not null references public.cluster_workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('lsa', 'individual')),
  created_at timestamptz not null default now(),
  primary key (cluster_id, user_id)
);

create table if not exists public.cluster_workspace_data (
  cluster_id uuid primary key references public.cluster_workspaces(id) on delete cascade,
  data jsonb not null default '{"records":{}}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.cluster_invitations (
  id uuid primary key default gen_random_uuid(),
  cluster_id uuid not null references public.cluster_workspaces(id) on delete cascade,
  email text not null check (char_length(email) between 3 and 320),
  role text not null check (role in ('lsa', 'individual')),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '14 days',
  accepted_at timestamptz,
  accepted_by uuid references auth.users(id) on delete set null
);

create index if not exists cluster_memberships_user_idx on public.cluster_memberships(user_id);
create index if not exists cluster_invitations_email_idx on public.cluster_invitations(lower(email));

create or replace function public.is_cluster_lsa(target_cluster uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.cluster_memberships membership
    where membership.cluster_id = target_cluster
      and membership.user_id = (select auth.uid())
      and membership.role = 'lsa'
  );
$$;

create or replace function public.is_cluster_member(target_cluster uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.cluster_memberships membership
    where membership.cluster_id = target_cluster
      and membership.user_id = (select auth.uid())
  );
$$;

alter table public.cluster_workspaces enable row level security;
alter table public.cluster_memberships enable row level security;
alter table public.cluster_workspace_data enable row level security;
alter table public.cluster_invitations enable row level security;

create policy "Members can read their cluster profiles"
on public.cluster_workspaces for select to authenticated
using (exists (
  select 1 from public.cluster_memberships membership
  where membership.cluster_id = id and membership.user_id = (select auth.uid())
));

create policy "LSA members can update their cluster profiles"
on public.cluster_workspaces for update to authenticated
using (public.is_cluster_lsa(id))
with check (public.is_cluster_lsa(id));

create policy "LSA members can delete their cluster profiles"
on public.cluster_workspaces for delete to authenticated
using (public.is_cluster_lsa(id));

create policy "Members can read cluster memberships"
on public.cluster_memberships for select to authenticated
using (public.is_cluster_member(cluster_id));

create policy "Members can read shared cluster data"
on public.cluster_workspace_data for select to authenticated
using (exists (
  select 1 from public.cluster_memberships membership
  where membership.cluster_id = cluster_id and membership.user_id = (select auth.uid())
));

create policy "LSA members can create shared cluster data"
on public.cluster_workspace_data for insert to authenticated
with check (public.is_cluster_lsa(cluster_id));

create policy "LSA members can update shared cluster data"
on public.cluster_workspace_data for update to authenticated
using (public.is_cluster_lsa(cluster_id))
with check (public.is_cluster_lsa(cluster_id));

create policy "LSA members can read cluster invitations"
on public.cluster_invitations for select to authenticated
using (
  public.is_cluster_lsa(cluster_id)
  or lower(email) = lower(coalesce((select auth.jwt()) ->> 'email', ''))
);

create policy "LSA members can create cluster invitations"
on public.cluster_invitations for insert to authenticated
with check (public.is_cluster_lsa(cluster_id) and created_by = (select auth.uid()));

create policy "LSA members can revoke cluster invitations"
on public.cluster_invitations for delete to authenticated
using (public.is_cluster_lsa(cluster_id));

create or replace function public.create_cluster_workspace(
  cluster_name text,
  cluster_region text default '',
  cluster_country text default ''
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_cluster_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Sign in is required to create a cluster.' using errcode = '42501';
  end if;

  insert into public.cluster_workspaces(name, region, country, created_by)
  values (trim(cluster_name), coalesce(trim(cluster_region), ''), coalesce(trim(cluster_country), ''), auth.uid())
  returning id into new_cluster_id;

  insert into public.cluster_memberships(cluster_id, user_id, role)
  values (new_cluster_id, auth.uid(), 'lsa');

  insert into public.cluster_workspace_data(cluster_id, data)
  values (new_cluster_id, '{"records":{}}'::jsonb);

  return new_cluster_id;
end;
$$;

create or replace function public.create_cluster_invitation(
  target_cluster uuid,
  invite_email text,
  invite_role text default 'individual'
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  invitation_id uuid;
begin
  if not public.is_cluster_lsa(target_cluster) then
    raise exception 'Only an LSA member can invite people.' using errcode = '42501';
  end if;
  if invite_role not in ('lsa', 'individual') then
    raise exception 'Choose an LSA or individual account.' using errcode = '22023';
  end if;
  if trim(coalesce(invite_email, '')) = '' then
    raise exception 'Enter the invitee email address.' using errcode = '22023';
  end if;

  insert into public.cluster_invitations(cluster_id, email, role, created_by)
  values (target_cluster, lower(trim(invite_email)), invite_role, auth.uid())
  returning id into invitation_id;

  return invitation_id;
end;
$$;

create or replace function public.accept_cluster_invitation(invitation_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  invitation public.cluster_invitations%rowtype;
  signed_in_email text;
begin
  if auth.uid() is null then
    raise exception 'Sign in is required to accept an invitation.' using errcode = '42501';
  end if;
  signed_in_email := lower(coalesce((select auth.jwt()) ->> 'email', ''));
  select * into invitation
  from public.cluster_invitations pending
  where pending.id = invitation_id
    and pending.accepted_at is null
    and pending.expires_at > now()
    and lower(pending.email) = signed_in_email;

  if not found then
    raise exception 'This invitation is invalid, expired, or belongs to another email address.' using errcode = '22023';
  end if;

  insert into public.cluster_memberships(cluster_id, user_id, role)
  values (invitation.cluster_id, auth.uid(), invitation.role)
  on conflict (cluster_id, user_id) do nothing;

  update public.cluster_invitations pending
  set accepted_at = now(), accepted_by = auth.uid()
  where pending.id = invitation.id;

  return invitation.cluster_id;
end;
$$;

revoke all on function public.is_cluster_lsa(uuid) from public, anon;
revoke all on function public.is_cluster_member(uuid) from public, anon;
revoke all on function public.create_cluster_workspace(text, text, text) from public, anon;
revoke all on function public.create_cluster_invitation(uuid, text, text) from public, anon;
revoke all on function public.accept_cluster_invitation(uuid) from public, anon;
grant execute on function public.is_cluster_lsa(uuid) to authenticated;
grant execute on function public.is_cluster_member(uuid) to authenticated;
grant execute on function public.create_cluster_workspace(text, text, text) to authenticated;
grant execute on function public.create_cluster_invitation(uuid, text, text) to authenticated;
grant execute on function public.accept_cluster_invitation(uuid) to authenticated;
grant select on public.cluster_workspaces, public.cluster_memberships, public.cluster_workspace_data, public.cluster_invitations to authenticated;
grant insert, update, delete on public.cluster_workspaces, public.cluster_memberships, public.cluster_workspace_data, public.cluster_invitations to authenticated;
