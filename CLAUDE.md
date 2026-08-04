# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`silvana-bot-sipal` — a headless trading bot that farms the **DAY_TRADER** daily quest on
[Silvana](https://app.silvana.one) / Supanova (Canton Network). It logs in with a self-held
passkey, signs Canton transactions through a Privy TEE embedded wallet, and swaps tokens in
a loop until the daily earn-hub task is full.

There is **no build, no lint, no test suite**. The only dependency is `node-cron`. Everything
is native Node (`https`, `crypto`, `net`, `tls`, `zlib`) so the whole bot is portable to a bare
VPS with `npm install && node index.js`.

## Commands

```bash
npm install                  # only installs node-cron
node index.js                # interactive menu (options 0-9), then dashboard + daily cron
node index.js once            # fetch balances + render dashboard once, exit (no swap)
node index.js swap            # force ONE DAY_TRADER session, exit
node index.js register        # one-time: print browser Console script to enrol a passkey
node index.js paste           # resume `register` if the paste step was interrupted
node index.js wallets         # list Privy wallets per account, flag which matches partyId
node index.js pin <walletId>  # pin a privyWalletId into session.json
node index.js balance [idx|all]                        # read-only: every instrument, unlocked/locked/UTXO count
node index.js transfer <idx> <token> <amt|max> <dest> [go]   # any instrument; omit `go` for a dry run
node index.js help            # full subcommand list
```

Diagnostics / dry-runs (these cost 0 CC and auto-clean the proposals they create):

```bash
node index.js feecheck [ceth|usdcx|edelceth] [sell|buy] [amt]
node index.js proposals       # read-only list of active settlements (find stuck ones)
node index.js cleanup         # reject stuck proposals that hold 0 locked funds
node index.js diag
node index.js terminal        [idx] [MARKET]        # read-only probe of /terminal
node index.js terminal-order  [idx] [go] [buy|sell] # probe submitOrder (dry unless `go`)
node index.js terminal-hist   [idx]
node index.js terminal-swap   [idx] [buy|sell] [go] # one full terminal swap
```

`swap-debug.log` is appended automatically on any `prepare_transaction` / `submit_prepared`
failure (see `logDebug`, [index.js:2578](index.js#L2578)) — read it first when a swap breaks.

## Layout

Deliberately a **single file**. `index.js` is ~5,600 lines split by `// ====` banner comments;
navigate with `sed -n 'A,Bp'` / `grep -n` rather than reading it whole.

| Lines | Section |
| --- | --- |
| 31–350 | Path & config loader, `SWAP` / `M8` / `PAIRS` globals |
| 351–540 | Native HTTP w/ cookie jar, gzip/br, proxy CONNECT tunnel |
| 486–540 | Proxy pool (sticky-deterministic per email) |
| 540–612 | Passkey (WebAuthn ES256 assertion) |
| 566–612 | React Server Components ("flight") parser |
| 613–800 | Privy embedded wallet — HPKE decrypt + authorization signature |
| 800–978 | `CantonClient` + `buildMultiCallAccept` transaction assembler |
| 979–1338 | `SilvanaClient` — passkey login, earn-hub, server actions, RFQ, terminal |
| 1339–1410 | `session.json` store |
| 1411–1654 | Privy OTP login / refresh, TTY prompt & key-nav |
| 1654–2060 | `swapOnce` — the atomic RFQ swap |
| 2060–2282 | `terminalSwapOnce` / `settleTerminalProposal` — CLOB swap (mode 8) |
| 2282–2780 | ANSI dashboard + per-account tick |
| 2823–4350 | DAY_TRADER engine and EDELx↔cETH ping-pong engine |
| 4349–4570 | Daily scheduler, web-dashboard push |
| 4572–5570 | `runMain`, passkey register/paste, CLI dispatch |

### Files at runtime

| File | Committed | Role |
| --- | --- | --- |
| `config.json` | yes | all tunables; keys prefixed `_help*` are inline docs, not settings |
| `accounts.json` | **no** | `{accounts:[{label,email,privyEmail}]}` — the only hand-written input |
| `session.json` | **no** | everything generated: passkey private key, `userServiceCid`, `partyId`, `privyWalletId`, Silvana cookies, Privy tokens, fee/spread accumulators |
| `proxy.txt` | **no** | one HTTP proxy URL per line |
| `action_ids.json` | generated | cache of discovered Next.js server-action IDs |
| `swap-debug.log` | **no** | auto-appended request/response dumps |

`.gitignore` already covers the secrets. `session.json` holds a raw private key — never print
or commit it.

## Architecture

### Two identities per account

Silvana and Supanova are separate logins that must be reconciled:

1. **Silvana** — a *custom passkey* whose private key lives in `session.json`, so the bot can
   complete WebAuthn assertions with no Touch ID. Enrolment is the only manual step
   (`node index.js register` prints a script you paste into the browser Console while already
   logged in). Yields a cookie jar.
2. **Privy / Supanova** — email OTP (`privyEmail`, falling back to `email`) → access token →
   `supaMe()` → `partyId`. The token doubles as the Canton bearer *and* is now required as a
   Bearer header on Silvana server actions.

`buildSwapClients` ([index.js:2884](index.js#L2884)) is the single entry point that wires both
together and returns `{sv, privy, canton, partyId}`. It also self-heals: if `partyId` changed
(user rebound a wallet) it invalidates the cached `userServiceCid` and `privyWalletId`.

Tokens live ~1 hour but a swap session runs for hours. Two independent timers keep them alive
(`keepAliveAll`, `refreshExpiringTokens`), and `CantonClient.token` / `sv.bearer` are stored as
**functions** that re-read `session.json`, not as captured strings — a static string silently
turns into `active_contracts → []` after a refresh.

### Signing

Privy wallets are stellar (ed25519) keys held in a TEE. `PrivyWallet.authenticate()` does an
HPKE handshake to unwrap a short-lived authorization key; `rawSign()` then signs the Canton
prepared-transaction hash with an RFC-8785 (JCS) canonicalized authorization signature.

A Privy account can hold several stellar wallets while Canton binds `partyId` to exactly one
key. On `BAD SIGNATURE` the code rotates through `walletCandidates` re-signing the *same* hash
(no re-prepare), then persists the winner via `onWalletPicked`.

### Server action IDs are volatile — this drives a lot of the design

Silvana is a Next.js app; every swap step is a `next-action` RPC whose ID is a build hash that
changes on each redeploy (roughly daily). The hardcoded IDs in `SWAP.actionIds` are **fallbacks
only**. The stable thing is the *function name*, so `ACTION_NAME` ([index.js:987](index.js#L987))
maps a logical key → the exported function name, and `discoverActionIds()` scrapes
`/_next/static/chunks/*.js` from both `/swap` and `/terminal` for
`createServerReference)("<id>", …, "<functionName>")` and rebuilds the map.

Three layers of recovery, in cost order:
- `loadActionIds()` at startup reads the `action_ids.json` cache.
- `ensureActionIds()` at session start probes two volatile IDs; a 404 triggers a full rescan
  (throttled to one scan per 30 s).
- `SilvanaClient._selfHeal` re-discovers mid-run when any action 404s;
  `discoverActionByProbe` handles the awkward cases (e.g. `getAllocFactory`) by probing
  candidate IDs with the real body and matching the response shape.

If a swap suddenly fails after a Silvana redeploy, this is almost always the cause — check
that discovery resolved every key in the `critical` list, not that the fallback hashes are current.

### The swap pipeline

`swapOnce(ctx, direction, quantity)` ([index.js:1671](index.js#L1671)):

```
estimateFee (fee gate #1, before anything on-chain)
  → rfqStream        (SSE; retries rfqMaxTries × rfqRetryMs when liquidity is absent)
  → pick cheapest quote → fee gate #2 (still before any proposal exists)
  → acceptQuote      → proposalId
  → recordEvent (preconfirmation)  →  pollProposal
  → getMultiCall / prepareDvpFee (fee gate #3, the real feeCtx)
  → prepareTransfer  (sell)  |  getAllocFactory (buy)
  → buildMultiCallAccept → canton.prepareTransaction
  → privy.rawSign → canton.submitPrepared → queryCompletion
```

Both fee gates before `acceptQuote` exist so a fee spike aborts **without** leaving a stuck
`DvpProposal` on-chain. Stuck proposals lock balance, so several routines exist to clear them:
`cleanupStaleProposals`, `drainStaleDvpProposals`, `withdrawStuckAllocations`,
`cancelPendingForFresh`.

Supanova rejects `limit`/`pageSize` on `active_contracts` (returns empty) and caps results at
200 — hence the periodic proposal draining rather than pagination.

### Transfers go through the Supanova **wallet** API, not Silvana

Silvana is the trading platform and has no wallet at all (`/wallet` and `/portfolio` are 404, and
the bundle exposes no send action). The wallet is a separate product at `app.supanova.app`, and its
transfer endpoints sit **outside** `/canton/api/` — which is why probing `/canton/api/transfer*`
returns 404 and led an earlier attempt to conclude, wrongly, that transfers were impossible:

```
POST /canton/transfers/prepare_transfer   {receiverPartyId, amount, instrumentId, instrumentAdmin?, memo?} -> {hash}
GET  /canton/transfers/calculate_transfer_fee?partyId=&instrumentId=&instrumentAdmin=
GET  /canton/transfers/pending_incoming_transfers
POST /canton/transfers/prepare_response_to_incoming_transfer
POST /canton/transfers/prepare_withdraw_transfer
```

`transferToken()` uses the first two: ask the fee, POST `prepare_transfer`, sign the returned hash
with `privy.rawSign`, then `submit_prepared` + `queryCompletion` exactly like a swap. The server
assembles the Daml command and pays the fee itself, so none of the MultiCall machinery is involved
and **any** instrument works — CC, EDELx, cETH.

Two things that cost real time to discover:
- `calculate_transfer_fee` needs the `x-canton-node-id` header like every other Canton call, and its
  fields are `supaFee` / `amuletTransferFee` — not `feeCC`/`fee`/`amount`.
- The fee is a flat **16 CC per transfer**, identical for CC, EDELx and cETH. Verified live: sending
  1 CC moved the balance 939.7347 → 922.7347. That is ~13× a swap's fee, so batching matters.

Do not rebuild this as a raw Canton command. That path was tried and is a dead end: a bare
`ExerciseCommand` makes the server append its own fee command and Canton answers
`Preparing multiple commands is currently not supported`, while wrapping it in `Execute_MultiCall`
fails the same way because our MultiCall does not pay the fee, and `buildFeeTransferDataAction`
returns `null` for every non-DvP `feeType`.

### Pairs and the `SWAP` global

`PAIRS` defines `usdcx` / `ceth` / `edelx`; `setActivePair()` mutates the global `SWAP`. The
subtlety is base/quote orientation: `CC-USDCx` has base = CC (`CC→USDCx` is `sell`) while
`cETH-CC` and `EDELx-CC` have base = the token (`CC→token` is `buy`). `getPrice` returns
quote-per-base, so cETH/EDELx prices are inverted before being fed to `estimateFee`.

**Mutating `SWAP` is not safe under parallelism.** Mode 8 flips leg direction per account, so
it passes the leg through `ctx.leg` per call instead; `swapOnce` reads
`ctx.leg.{market,baseIsCC,tokenToToken,tokenId,tokenLabel,tokenAdmin}` and only falls back to
the global when absent. Any new token↔token flow must do the same.

### Two engines

`SESSION_ENGINE` (`'daytrader'` | `'pingpong'`) selects which runs at the scheduled hour:

- **daytrader** (menu 0/1) — `runDayTraderSession` → `_accountSwapOnce`. Reads the DAY_TRADER
  task count from the API each iteration rather than counting locally, so it cannot overshoot
  (`allowOvercap` opts out). `closeWithCC` forces swap 9 to sell and swap 10 to buy back all
  USDCx so the day ends holding CC.
- **pingpong / mode 8** (menu 8) — `runEdelCethSession` → `runEdelCethAccount`, using the CLOB
  `/terminal` endpoint (`submitOrder`, tighter spread) instead of RFQ. All of its knobs live in
  `config.json → mode8`, notably `minNetUsd` (a round-trip PnL gate measured in EDELx terms;
  negative = allowed loss) and the day/night split: past `dayEndHour` the fee and net gates are
  ignored so the task still completes before it resets at 07:00 WIB.

A terminal order can be split across several makers into N `DvpProposal`s. Chunks worth less
than `mode8.minUsd` are cancelled **before any signing** (so dust costs 0 CC); the rest are
settled sequentially, threading `consumedAmuletCids` forward so successive fee payments don't
fight over the same CC UTXO.

#### Order pricing: the book, never `getPrice`

`EDELx-cETH` is a **synthetic `cross_rate` market** — `/api/markets` gives it
`price_feeds: {base_pair: EDELx-USDCx, operation: divide, quote_pair: cETH-USDCx}`.
`getPrice('EDELx-cETH')` therefore returns `source: "Calculated"`, not a traded price, and it
was measured live sitting **+3.6 % above `bestBid`**. Pricing an order off it puts a limit SELL
*above* the bid (can never match) and makes BUY overpay ~5 %. Always price from
`SilvanaClient.orderbookDepth()` → `GET /api/orderbook-depth/{market}?depth=20&lpOnly=1`.
The `lpOnly` variant is mandatory because the bot sends `requirements.lpOnly: true` — the full
book contains levels its orders cannot match. `tick_size` is `1e-10`; round with `tickPrice()`
(up for BUY, down for SELL) — plain `fmt10` breaks once a price drops below `1e-6` because
`Number.toString()` switches to exponential notation.

#### Resting orders must always be cancelled

`mode8.orderTif` is `GTD` (FOK killed almost every order). The trap that FOK hid: **a resting
order stays alive in the book after it matches.** If its settlement is later cancelled — a
fee-gate abort, a dust chunk — the surviving order is re-matched by the LP and a fresh `PENDING`
settlement appears, repeatedly. Observed live: one order spawned three orphan proposals before it
was killed. So `terminalSwapOnce` calls `cancelOrder` unconditionally once proposals are
collected, not only on partial fill. `node index.js cancel-order <orderId>` kills a stuck one by
hand.

`GTD` over plain `GTC` closes the crash window: if the process dies between `submitOrder` and
`cancelOrder`, a GTC order lives forever and nothing can find it again, whereas GTD expires by
itself. The server honours it — verified with `node index.js tif-probe <idx> GTD <ttlSec>`, which
rests an order 5× above the ask (impossible to match, so zero CC) and then uses `cancelOrder` as
the probe: `failed_precondition … status Expired` proves it self-destructed. TTL is forced to at
least `orderWaitSec + 30` so the order cannot die while proposals are still being polled.

`/api/orders?mine=true` reports `0` even while an order is demonstrably still live, so it cannot
be used to confirm an order is dead — `cancelOrder` returning
`failed_precondition … status Filled` is the reliable signal.

#### `/api/settlement-proposals` needs `partyId`

Without the `partyId` query param the endpoint returns `proposals: []` silently — not an error.
That is why `cleanup` used to report 0 forever while early-stage settlements piled up.
`cleanupStaleProposals` only sees ledger `DvpProposal` contracts, so anything still at stage
&lt; 5 (`SETTLEMENT_STATUS_PENDING`) needs the REST sweep that `cleanup` and `terminalSwapOnce`
step 0 now perform. Note `createdAt` there is a protobuf `{seconds, nanos}`, not an ISO string.

### Resilience patterns worth preserving

Errors are tagged rather than string-matched at the call site: `e.transient`, `e.unauthorized`,
`e.feeSpike`, `e.insufficientFunds`, `e.noLiquidity`, `e.aborted`. Retry logic keys off these
flags plus `isProxyErr` / `isIpBlockErr` (which trigger `rotateProxy`).

Proxies are assigned deterministically per email (`sha1(email) % PROXIES.length`) so an account
keeps a stable IP with no stored mapping; `rotateProxy` bumps an in-memory offset that resets on
restart. (`proxy.example.txt` and `.gitignore` still mention a `proxy-assignments.json` — nothing
writes it any more.)

`maxStuckBeforeStop` halts new swaps after N submissions that don't move the DAY_TRADER counter
— this prevents locking the entire balance in pending settlements.

### Sequencer traffic is one shared bucket — back off globally, not per account

`SEQUENCER_NOT_ENOUGH_TRAFFIC_CREDIT: Member has insufficient traffic credit` is Canton's
sequencer rate limit, metered **per member (participant node), not per party**. Every account
sits on the same Supanova node (`partyId` hint `supa1`), so all of them draw from one bucket —
several accounts get rejected in the same second while others succeed. It refills on its own
over time; there is nothing to top up. `SEQUENCER_REQUEST_FAILED: Failed to send command`
appears alongside it and has the same cause.

Per-account backoff therefore does not work: while account A waits, B–E keep firing and the
bucket never refills. `completionErr()` tags these as `e.trafficLimit` and both engines route
them to the **global** gate (`TRAFFIC` / `trafficPenalize` / `waitTrafficGate`), which
`CantonClient.prepareTransaction` awaits — so every account stops submitting together. Backoff
is 30 s per consecutive hit (cap 5 min), decayed by `trafficRelax()` on each successful swap,
with a random 0–5 s jitter on release so the accounts don't resume in lockstep and drain it again.

The tag also keeps these errors out of the generic `hardErrs` path, whose client rebuild and
action-id rescan are pure waste here — the session and action IDs are fine, only the sequencer
is refusing.

There is no REST endpoint exposing the remaining credit (`/canton/api/traffic*` all 404); the
`costEstimation.totalTrafficCostEstimation` field in a `prepare_transaction` response
(~3900 per swap) is the only visible measure of what a transaction spends.

## Conventions

- Comments, log lines, and dashboard strings are **Indonesian**. Match that when editing; the
  comments carry hard-won protocol knowledge (which endpoints 400, which params are silently
  rejected, why a fallback exists) and are the real documentation — don't strip them.
- `config.json` documents itself with sibling `_help_*` keys. Adding a setting means adding its
  `_help_*` string too.
- Amounts are handled as decimal strings via `toScaled`/`fromScaled` (10 dp `BigInt`), never as
  floats. `fmt10()` normalizes before sending to Canton.
- New public constants (party IDs, template IDs, package IDs) are non-sensitive and belong in
  the `SWAP` object with a comment saying which HAR capture or frontend they came from.
- `global.__states` backs the dashboard. Subcommands that want clean stdout deliberately leave
  it unset so `render`/`logActivity` become no-ops, and log through a local `olog` instead.
