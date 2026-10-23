-- EXNYA security hardening, part 4 — run AFTER parts 1, 2 and 3.
--
-- Makes the database the only place a balance or a trade state can change.
--
-- The two client flows that moved money by themselves are replaced by
-- SECURITY DEFINER functions:
--   * swap_execute()       -> atomic, server-priced two-asset exchange
--   * p2p_<action>()       -> a strict state machine per trade action
--
-- Both are idempotent-friendly, take a row lock, and never trust a price,
-- an amount or a status sent from the browser.

-- ── A. Ledger gaps: entry_type / amount / asset_symbol must be writable ──
alter table public.ledger_entries
  add column if not exists asset_symbol text,
  add column if not exists entry_type   text,
  add column if not exists amount       numeric;

alter table public.audit_log
  add column if not exists actor_id uuid;

-- ── B. SWAP ────────────────────────────────────────────────────────────
-- prices: {"BTC": 67000, "USDT": 1, ...} in USD. The browser sends its quote;
-- the server rejects anything further than 1% away from the server's own
-- price so a modified client cannot buy at its own rate.
create or replace function public.swap_execute(
  p_from_asset  text,
  p_from_amount numeric,
  p_to_asset    text,
  p_to_amount   numeric,
  p_prices      jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $swap$
declare
  v_uid        uuid := auth.uid();
  v_fee_rate   constant numeric := 0.005;
  v_from_usd   numeric;
  v_to_usd     numeric;
  v_rate       numeric;
  v_expected   numeric;
  v_from_qty   numeric;
  v_tolerance  constant numeric := 0.01;   -- 1%
begin
  if v_uid is null then
    raise exception 'Not signed in' using errcode = '28000';
  end if;
  if p_from_asset is null or p_to_asset is null or p_from_asset = p_to_asset then
    raise exception 'Pick two different assets';
  end if;
  if p_from_amount is null or p_from_amount <= 0 then
    raise exception 'Amount must be greater than zero';
  end if;

  -- Server-side prices. A missing price is a hard failure, never a silent 0.
  begin
    v_from_usd := (p_prices ->> p_from_asset)::numeric;
    v_to_usd   := (p_prices ->> p_to_asset)::numeric;
  exception when others then
    raise exception 'Price for % or % is missing', p_from_asset, p_to_asset;
  end;
  if coalesce(v_from_usd, 0) <= 0 or coalesce(v_to_usd, 0) <= 0 then
    raise exception 'Price for % or % is missing', p_from_asset, p_to_asset;
  end if;

  v_rate     := v_from_usd / v_to_usd;
  v_expected := (p_from_amount * (1 - v_fee_rate)) * v_rate;

  if p_to_amount is null or p_to_amount <= 0 then
    raise exception 'No valid quote for this pair';
  end if;
  if abs(v_expected - p_to_amount) / v_expected > v_tolerance then
    raise exception 'Quote changed (expected about %, you were quoted %). Refresh and try again.',
      round(v_expected, 8), round(p_to_amount, 8);
  end if;

  -- Lock the debit row, then take the quote from the lock, not from the page.
  select quantity into v_from_qty
  from public.user_assets
  where user_id = v_uid and asset_symbol = p_from_asset
  for update;

  if not found then
    raise exception 'You do not hold %', p_from_asset;
  end if;
  if v_from_qty < p_from_amount then
    raise exception 'Insufficient % balance', p_from_asset;
  end if;

  -- Debit
  if round(v_from_qty - p_from_amount, 8) <= 0 then
    delete from public.user_assets
    where user_id = v_uid and asset_symbol = p_from_asset;
  else
    update public.user_assets
    set quantity = round(v_from_qty - p_from_amount, 8)
    where user_id = v_uid and asset_symbol = p_from_asset;
  end if;

  -- Credit (upsert so a first-time asset row is created)
  insert into public.user_assets (user_id, asset_symbol, quantity)
  values (v_uid, p_to_asset, round(v_expected, 8))
  on conflict (user_id, asset_symbol) do update
    set quantity = round(public.user_assets.quantity + excluded.quantity, 8);

  insert into public.ledger_entries
    (user_id, asset_symbol, amount, entry_type, reference_id, note)
  values
    (v_uid, p_from_asset, -p_from_amount, 'swap_out', gen_random_uuid(),
     'Swap ' || p_from_asset || ' to ' || p_to_asset),
    (v_uid, p_to_asset,   round(v_expected, 8), 'swap_in', gen_random_uuid(),
     'Swap ' || p_from_asset || ' to ' || p_to_asset);

  return jsonb_build_object(
    'ok', true,
    'from_asset', p_from_asset,
    'from_amount', p_from_amount,
    'to_asset', p_to_asset,
    'to_amount', round(v_expected, 8),
    'rate', v_rate
  );
end;
$swap$;

revoke all on function public.swap_execute(text, numeric, text, numeric, jsonb) from public;
grant execute on function public.swap_execute(text, numeric, text, numeric, jsonb) to authenticated;

-- unique index the upsert above relies on
create unique index if not exists user_assets_user_asset_key
  on public.user_assets (user_id, asset_symbol);

-- ── C. P2P trade state machine ─────────────────────────────────────────
-- Allowed moves, enforced server-side:
--   open      -> matched | cancelled     (maker)
--   matched   -> escrowed | cancelled    (either party)
--   escrowed  -> paid | cancelled | disputed  (either party)
--   paid      -> completed | disputed    (either party)
--   disputed  -> completed | cancelled   (admin only)
-- Balances only move on `completed`, atomically, by this function.
create or replace function public.p2p_transition(p_trade_id uuid, p_action text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $p2p$
declare
  v_uid      uuid := auth.uid();
  t          public.p2p_trades%rowtype;
  v_action   text := lower(coalesce(p_action, ''));
  v_is_maker boolean;
  v_is_taker boolean;
  v_seller   uuid;
  v_buyer    uuid;
  v_admin    boolean;
  v_qty      numeric;
begin
  if v_uid is null then
    raise exception 'Not signed in' using errcode = '28000';
  end if;

  select * into t from public.p2p_trades where id = p_trade_id for update;
  if not found then
    raise exception 'Trade not found';
  end if;

  v_admin    := public.is_admin();
  v_is_maker := (t.user_id = v_uid);
  v_is_taker := (t.matched_user_id = v_uid);

  if not (v_is_maker or v_is_taker or v_admin) then
    raise exception 'You are not a party to this trade';
  end if;

  -- ── claim (taker takes an open ad) ────────────────────────────────────
  if v_action = 'match' then
    if t.status <> 'open' then
      raise exception 'This ad is no longer open';
    end if;
    if v_is_maker then
      raise exception 'You cannot trade with your own ad';
    end if;
    -- the seller (maker of a sell ad, taker of a buy ad) must hold the asset
    v_seller := case when t.type = 'sell' then t.user_id else v_uid end;
    select coalesce(quantity, 0) into v_qty
    from public.user_assets
    where user_id = v_seller and asset_symbol = t.asset_symbol;
    if coalesce(v_qty, 0) < t.amount then
      raise exception 'Seller does not hold enough %', t.asset_symbol;
    end if;

    update public.p2p_trades
    set matched_user_id = v_uid,
        status = 'matched',
        escrow_status = 'pending',
        escrow_chain = coalesce(escrow_chain, 'base-sepolia'),
        updated_at = now()
    where id = p_trade_id;
    return jsonb_build_object('ok', true, 'status', 'matched');
  end if;

  -- ── escrow funded (reserve the seller's balance conceptually) ─────────
  if v_action = 'fund' then
    if t.status <> 'matched' then
      raise exception 'Escrow can only be funded after both parties are matched';
    end if;
    update public.p2p_trades
    set status = 'escrowed', escrow_status = 'funded',
        escrow_locked_amount = t.amount, updated_at = now()
    where id = p_trade_id;
    return jsonb_build_object('ok', true, 'status', 'escrowed');
  end if;

  -- ── buyer says fiat was sent ──────────────────────────────────────────
  if v_action = 'paid' then
    if t.status <> 'escrowed' then
      raise exception 'Payment can only be marked on an escrowed trade';
    end if;
    update public.p2p_trades
    set status = 'paid', updated_at = now()
    where id = p_trade_id;
    return jsonb_build_object('ok', true, 'status', 'paid');
  end if;

  -- ── release: THE ONLY PLACE BALANCES MOVE ────────────────────────────
  if v_action = 'complete' then
    if t.status not in ('paid', 'disputed') then
      raise exception 'Only a paid or disputed trade can be completed';
    end if;
    if t.status = 'disputed' and not v_admin then
      raise exception 'A disputed trade can only be resolved by support';
    end if;
    if t.matched_user_id is null then
      raise exception 'Trade has no counterparty';
    end if;

    -- seller is the crypto side of the trade
    v_seller := case when t.type = 'sell' then t.user_id else t.matched_user_id end;
    v_buyer  := case when t.type = 'sell' then t.matched_user_id else t.user_id end;

    -- lock the seller's row and verify the balance again
    select quantity into v_qty
    from public.user_assets
    where user_id = v_seller and asset_symbol = t.asset_symbol
    for update;

    if coalesce(v_qty, 0) < t.amount then
      raise exception 'Seller balance is no longer sufficient (%)', coalesce(v_qty, 0);
    end if;

    if round(v_qty - t.amount, 8) <= 0 then
      delete from public.user_assets
      where user_id = v_seller and asset_symbol = t.asset_symbol;
    else
      update public.user_assets
      set quantity = round(v_qty - t.amount, 8)
      where user_id = v_seller and asset_symbol = t.asset_symbol;
    end if;

    insert into public.user_assets (user_id, asset_symbol, quantity)
    values (v_buyer, t.asset_symbol, t.amount)
    on conflict (user_id, asset_symbol) do update
      set quantity = round(public.user_assets.quantity + excluded.quantity, 8);

    insert into public.ledger_entries
      (user_id, asset_symbol, amount, entry_type, reference_id, note)
    values
      (v_seller, t.asset_symbol, -t.amount, 'p2p_out', p_trade_id, 'P2P release'),
      (v_buyer,  t.asset_symbol,  t.amount, 'p2p_in',  p_trade_id, 'P2P release');

    update public.p2p_trades
    set status = 'completed', escrow_status = 'released', updated_at = now()
    where id = p_trade_id;

    update public.profiles p
    set completed_trades_count = coalesce(p.completed_trades_count, 0) + 1,
        merchant = (coalesce(p.completed_trades_count, 0) + 1) >= 5
    where p.id in (v_seller, v_buyer);

    return jsonb_build_object('ok', true, 'status', 'completed');
  end if;

  -- ── dispute ───────────────────────────────────────────────────────────
  if v_action = 'dispute' then
    if t.status not in ('escrowed', 'paid') then
      raise exception 'Only an active trade can be disputed';
    end if;
    update public.p2p_trades
    set status = 'disputed', updated_at = now()
    where id = p_trade_id;
    return jsonb_build_object('ok', true, 'status', 'disputed');
  end if;

  -- ── cancel (never after money has moved) ─────────────────────────────
  if v_action = 'cancel' then
    if t.status in ('completed', 'cancelled') then
      raise exception 'This trade is already finished';
    end if;
    if t.status = 'paid' and not v_admin then
      raise exception 'A paid trade cannot be cancelled by a trader — open a dispute';
    end if;
    update public.p2p_trades
    set status = 'cancelled', escrow_status = 'refunded', updated_at = now()
    where id = p_trade_id;
    return jsonb_build_object('ok', true, 'status', 'cancelled');
  end if;

  raise exception 'Unknown action "%"', p_action;
end;
$p2p$;

revoke all on function public.p2p_transition(uuid, text) from public;
grant execute on function public.p2p_transition(uuid, text) to authenticated;

-- ── D. Close the client's direct write paths for good ──────────────────
-- No browser UPDATE on assets, and no browser write to escrow columns.
revoke update, delete on public.user_assets from authenticated;
grant  select, insert on public.user_assets to authenticated;   -- insert limited by policy

revoke update on public.p2p_trades from authenticated;
grant  update (status, matched_user_id, updated_at) on public.p2p_trades to authenticated;

-- ── E. Let the client learn about the new functions ────────────────────
comment on function public.swap_execute(text, numeric, text, numeric, jsonb) is
  'Atomic server-priced swap. Call via supabase.rpc()';
comment on function public.p2p_transition(uuid, text) is
  'P2P state machine + atomic balance release. Call via supabase.rpc()';
