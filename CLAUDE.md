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

### Settlement fee has a cheap tier above ~$10 — size for it, not against it

The RFQ settlement fee is **flat per settlement** and **tiered by USD value**, not proportional to
trade size. Measured live on `EDELx-cETH` in one back-to-back sweep:

| target | qty EDELx | CC | USDCx | TUSDT |
| --- | --- | --- | --- | --- |
| $8 | 1218 | 19.97 | 1.8 | 0.9 |
| $9.5 | 1446 | 19.97 | 1.8 | 0.9 |
| $10.5 | 1599 | **6.66** | **0.6** | **0.3** |

So a swap just under $10 costs **three times** what a swap just over it costs. `mode8.feeTierMinUsd`
(default 10) raises the size to the threshold when the balance allows, and warns when it does not.

Two more things the same sweep settled:
- Fee does **not** scale with size within a tier — 600 and 1400 EDELx paid the same. Larger swaps are
  strictly more fee-efficient per dollar of volume.
- Absolute fees drift with network load over minutes (the UI's "Network load" indicator). The same
  1200 EDELx quote returned 0.9 TUSDT six times in a row within a minute, but 0.15 / 0.3 / 0.45 / 0.9
  at different times. The **ratio** CC : USDCx : TUSDT stays ~22 : 2 : 1, so a cap that is sane for one
  token is wildly wrong for another — `maxFeeCC` is denominated in whichever token `feeTokens` selects.

**Fee bisa dibaca TANPA quote.** `estimateAtomicFeeAction({partyId, marketId, feeTokens?})`
mengembalikan fee yang berlaku sekarang tanpa `quantity` sama sekali — ini yang dipakai UI
Silvana untuk menampilkan "Fee in ≈ $0.30" padahal kolom jumlahnya masih 0. Balasannya
`{success, feeUsd:"0.30", settlementFee:{instrumentId, amount, receiver, instrumentAdmin},
belowMinValue}`. `feeTokens` di sini juga **urutan preferensi**, dan dihilangkan = CC.
Terukur bersamaan: CC 6.66 ($0.60), USDCx 0.6 ($0.60), TUSDT 0.3 ($0.30), USD8 0.3 ($0.30).

Bedakan dari dua endpoint fee yang lain: `estimateSettlementFees` (`SWAP.actionIds.estimateFee`)
**wajib** `baseQuantity` + `price` — dipanggil tanpa itu jawabannya `Missing required fields`;
dan `requestQuotesV2` yang memang membuat RFQ. Jadi untuk sekadar memantau fee (menunggu fee
turun, menu batas fee), pakai `sv.feeNow()` yang membungkus `estimateAtomicFeeAction` — jangan
membuat quote hanya untuk melihat angkanya.

`feeTokens` accepts `CC`, `USDCx`, `TUSDT`; `USD8` and `EDELx` return no quote. The request name is not
the instrument id — `TUSDT` settles as instrument `tf-usdt`, so holdings lookups must go through
`FEE_TOKEN_INSTRUMENT` or they find nothing and blame the wrong token.

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

### Strategi 1 (menu 1) — rantai task harian dari satu token hub

Silvana sekarang punya beberapa DAY_TRADER harian sekaligus (`CETH_EDELX_DAY_TRADER`,
`HECTO_CETH_DAY_TRADER`, `HECTO_EDELX_DAY_TRADER`, plus `DAY_TRADER` umum yang ikut terisi
oleh swap apa pun). `s1RunTask` mengerjakannya berurutan dan selalu pulang ke satu token
**hub** (default cETH), jadi modal tidak tercecer di banyak token.

Yang perlu diketahui sebelum mengubahnya:

- **Progres task itu STRING.** `GET /api/earn-hub/tasks` mengembalikan `progress: "3/10"`,
  bukan `current`/`target` numerik. Membaca `it.current` menghasilkan `0` selamanya dan
  loop tidak pernah berhenti — `s1Progress()` mem-parse string itu seperti `parseDayTrader`.
- **Probe kuotasi fee harus bernilai di atas minimum order.** `feeQuotesUsd()` dulu
  bertanya dengan `quantity: '1'`; 1 EDELx ≈ $0.007 sehingga server tidak menjawab sama
  sekali dan semua kandidat tampak "gak ada quote". Ukurannya sekarang dihitung dari nilai
  USD dibagi harga base.
- **`feeTokens` adalah URUTAN PREFERENSI, bukan daftar untuk dibandingkan.** Dikirim
  `["TUSDT","USD8","USDCx","CC"]` server menjawab dengan yang **pertama** didukung market itu
  — terverifikasi live: kirim empat token, balasannya tetap dua quote dan dua-duanya TUSDT;
  `["USD8","TUSDT"]` menghasilkan USD8. Jadi token fee ditentukan **di dalam quote**, tanpa
  satu pun panggilan pembanding, dan **membuang token yang saldonya habis dari daftar =
  otomatis pindah** ke token berikutnya. Urutan awalnya peringkat statis (stabil dulu: rasio
  CC:USDCx:TUSDT ~22:2:1) lalu dikoreksi dari fee yang benar-benar ditagih tiap quote.
  Jangan kembalikan pola "kutip tiap kandidat lalu bandingkan" — itu 4 RFQ per market
  hanya untuk memilih, dan tetap salah begitu saldonya habis di tengah jalan.
- **Batas fee disimpan PER TOKEN, bukan satu angka dan bukan USD.** Pada beban jaringan yang
  sama fee itu 6.66 CC / 0.6 USDCx / 0.3 TUSDT / 0.3 USD8 — satu angka yang ketat untuk TUSDT
  mustahil dipenuhi CC. Bentuknya map `{CC, USDCx, TUSDT, USD8}` di `swap.maxFeeTok`,
  `swap.hardMaxFeeTok`, `mode8.maxFeeTok`, dan `mode8.strategy1.maxFeeTok`.
  `effFeeCap(ctxCap, unit)` membaca yang cocok dengan token yang **benar-benar ditagih quote**
  (`feeUnit` dari `lpFees[0].instrumentId`), bukan token yang kebetulan aktif di config, dan
  jatuh balik ke `maxFeeCC` lama kalau map-nya kosong. `ctxCap` boleh map, angka (override
  per-call), atau null. **`Infinity` bukan berarti "belum diset"** — itu override sengaja mode
  8 malam; memperlakukannya sebagai kosong membuat mode malam justru lebih ketat dari siang.
- **Versi USD sudah dibuang.** `strategy1.maxFeeUsd` dulu dikonversi ke satuan token memakai
  harga live, sehingga batasnya ikut bergeser mengikuti harga dan tidak bisa diatur per token.
- **Batas fee strategi 1 TERPISAH dari `swap.maxFeeCC`.** Menu `w → Batas max fee` dulu hanya
  menyetel angka bersatuan token untuk daytrader/ping-pong; strategi 1 tidak membacanya sama
  sekali, sehingga menyetel `swap.maxFeeCC = 0.16` tidak berpengaruh dan fee 0.3 TUSDT tetap
  lolos (log-nya jujur: `batas 1`, yaitu `strategy1.maxFeeUsd` default). Menu itu sekarang
  menerima satu angka **USD**: strategi 1 memakainya apa adanya, engine lain dikonversi ke
  satuan token fee memakai harga live. Menu juga mengukur fee yang berlaku sekarang untuk
  tiap kandidat token sebelum bertanya, dan memperingatkan kalau batas barunya di bawah fee
  termurah saat itu — kalau tidak, semua swap ditolak diam-diam sampai fee turun.
- **`maxFeeCC` satuannya ikut token fee**, sehingga batas 5 (wajar untuk CC yang fee-nya
  ~6.66) sama sekali tidak mengikat untuk TUSDT yang fee-nya ~0.15. `strategy1.maxFeeUsd`
  dipatok dalam USD lalu dikonversi ke satuan token terpilih di awal tiap task.
- **Arah swap: tahan posisi lawan seukuran satu langkah, jangan menumpuk.** Aturan naif
  "kirim sisi yang saldonya paling besar" membuat bot membeli berkali-kali berturut-turut
  (modal $94 di hub, tiap beli hanya memindah $12, jadi hub tetap lebih besar sampai sisi
  lawan melewati separuh — terlihat 4x beli beruntun), lalu meninggalkan ~$50 di token lawan
  yang harus dipulangkan lewat satu swap tambahan. Aturan sekarang: jual balik begitu sisi
  bukan hub sudah di atas `rfqMinUsd`, kalau belum baru beli — hasilnya beli/jual bergantian.
  Jumlah swap tugas sama, tapi volume turun $172 → $124 per task dan swap pemulangan hilang:
  terhitung **$0.93/akun/hari** lebih murah pada dua task yang menyentuh hub. Task yang kedua
  sisinya bukan hub (HECTO-EDELx) tetap memakai aturan sisi terbesar — tidak ada sisi "pulang".
- **Swap terakhir menguras habis** — tapi HANYA kalau yang dikirim sisi bukan hub. Kalau yang
  dikirim justru hub, menguras berarti melempar seluruh modal ke token lawan lalu menariknya
  kembali: dua swap raksasa, spread dua kali.
- **Menguras lewat arah BELI tidak boleh disizing dari harga USD silang.** Saat yang dipegang
  token quote, `qty` diminta dalam satuan base, dan menghitungnya lewat harga USD kedua token
  meleset sebesar spread market — terukur di `HECTO-EDELx` melesetnya 1.7 %, jauh di atas
  bantalan 0.3 %, sehingga LP menagih 1491.67 EDELx padahal saldo 1466.82 dan swap terakhir
  gagal di 9/10. Sizing memakai **harga eksekusi terakhir di market itu, dikunci per arah**
  (`memo.px["<market>|buy"]`): harga jual dan harga beli berbeda persis sebesar spread, jadi
  memakai harga jual untuk menyusun beli overshoot lebih parah lagi (dihitung ulang dengan
  angka asli: 1525.09 vs 1463.48 yang muat).
  Cadangannya `e.insufficientBalance` yang membawa `tokenNeeded`/`tokenHave` — rasionya
  dipakai mengecilkan `qty` secara **persis** lalu langkah diulang (maks 3×). Kegagalan ini
  terjadi **sebelum penandatanganan**, jadi tidak ada proposal nyangkut dan tidak ada fee
  terbuang; menggugurkan akun karenanya adalah reaksi yang salah.
- **Fee di atas batas = TUNGGU, bukan gagal.** Fee bergerak ikut beban jaringan (terukur
  0.15 lalu 0.30 di hari yang sama), jadi swap yang ditolak sekarang biasanya lolos beberapa
  menit kemudian. `e.feeSpike` memicu `s1TungguFeeTurun()` yang **mem-poll fee** tiap
  `strategy1.feePollSec` (default 30 dtk) sampai turun ke bawah `maxFeeUsd`, lalu langkah yang
  sama diulang. **Tiap poll ditulis ke panel log akun** (`ctx.log`), tonggaknya saja ke SYSTEM:
  versi yang meredam log jadi 5 menit sekali membuat panel diam belasan menit dan botnya
  terlihat mati padahal sedang memantau — tapi mengirim semuanya ke SYSTEM juga salah, 15 akun
  yang sama-sama menunggu membanjiri panel utama tiap 30 detik — tanpa batas, berhentinya hanya lewat `q`/Ctrl+C. Sebelumnya ini menggugurkan
  akun sehingga seluruh putaran batal dan bot menganggur sampai reset besok. Swap di luar loop
  utama (seed dan pulang-ke-hub) memakai `s1SwapTungguFee()` supaya tidak jadi celah yang
  tetap menggugurkan akun.
- **Satu swap punya batas waktu** (`strategy1.swapTimeoutSec`, default 240 dtk). Tanpa itu
  RFQ/settle yang diam membekukan akun tanpa satu baris log pun dan dari luar terlihat macet.
  Lewat batas ditandai `transient` sehingga langkah yang sama diulang, bukan akun digugurkan.
  Detail langkah swap (`ctx.log`) dialirkan ke panel log **akun** lewat `logAkun()`, bukan
  dibuang dan bukan ke panel SYSTEM: dibuang membuat layar diam berpuluh detik saat swap
  berjalan, ke SYSTEM membuat panel utama tenggelam.
- **Error proxy bukan alasan menggugurkan akun.** `proxy connect timeout` / IP diblokir
  dirotasi (`rotateProxy`) lalu klien dibangun ulang lewat `ctx.rebuild()` dan langkah yang
  sama diulang — `langkah` sengaja tidak dinaikkan karena swapnya belum terjadi. Sebelumnya
  satu timeout mematikan akun di tengah task (terlihat sebagai "7/10 lalu GAGAL").
  Karena itu `ctx` tidak boleh di-clone di dalam `s1RunTask` dan `sv` selalu dibaca lewat
  `ctx.sv`: kalau tidak, rebuild menukar klien di objek yang salah dan retry-nya sia-sia.
- **Detail lama swap terakhir.** Saat sisa target tinggal 1 (9/10), seluruh saldo
  dilepas: kalau yang dikirim base dipakai saldo persisnya sehingga benar-benar nol; kalau
  yang dikirim quote disisakan 0.3% karena harga eksekusi RFQ bisa bergeser dan meminta
  lebih dari yang dipunya berakhir insufficient funds. Sisa di bawah `rfqMinUsd` dibiarkan
  jadi dust — memaksanya hanya membuat quote ditolak.
- **Task yang tidak menyentuh hub didanai lebih dulu** (`seedUsd`) dan setelah selesai
  **dua-duanya** dikembalikan ke hub, bukan hanya sisi lawan.

Biaya terukur satu putaran penuh 3 task pada satu akun: 29 swap, fee 4.35 TUSDT (29 × 0.15,
flat), modal cETH susut $77.70 → $73.48 termasuk spread. Durasi ~21 menit.

Menu 1 **tidak berhenti** setelah semua task penuh: task earn-hub reset tiap hari 07:00 WIB,
jadi setelah satu putaran bot menunggu sampai `schedule.hour`/`minute` berikutnya lalu jalan
lagi. Yang harus ikut hidup selama menunggu adalah `keepAliveAll` dan `refreshExpiringTokens`
— token Silvana/Privy umurnya ~1 jam sedangkan tunggunya belasan jam, jadi tanpa itu putaran
besok mulai dengan sesi mati. Tunggunya dipotong 30 detikan supaya `q` tetap responsif dan
sisa waktunya tampil di kolom TASK; satu `sleep` panjang membuat dashboard membisu dan tidak
bisa dihentikan. Daftar market di-fetch ulang tiap putaran karena bisa berubah antar hari.

Akun dijalankan **paralel** (`swap.loginConcurrency`) dan progresnya tampil di dashboard yang
**sama persis** dengan mode ping-pong: `SESSION_ENGINE = 'strategi1'` lalu `render(states)` —
`renderHeader` + `renderAccountsTable` + `renderFooter` + `renderActivityLog`. Jangan bikin
tabel sendiri; yang didapat gratis dari jalur ini adalah drop kolom otomatis saat terminal
sempit (`prio`), sorot baris terpilih, panel log per akun dengan navigasi ↑/↓, dan total
season di footer. Kolom khusus strategi (TASK/SWAP/TAHAP/TOTAL) ditambahkan lewat cabang
`SESSION_ENGINE === 'strategi1'` di `renderAccountsTable`, kolom saldonya dari `S1TOKENS`
(hub + kedua sisi tiap market task + token fee). POIN/ΔPOIN/STREAK disembunyikan di mode ini
karena strategi tidak menarik earn-hub stats tiap tick. Fee dan spread dibukukan lewat
`bumpDaily`, ember yang sama dengan engine lain, sehingga FEE/SN, FEE-TOK dan LOSS/SN terisi
tanpa jalur akuntansi kedua. Versi berurutan + cetak baris membuat 15 akun berarti 15 × ~20 menit dan hanya akun
yang sedang jalan yang terlihat. Harga USD di-cache 30 detik (`usdPriceOf`): tiap swap butuh
harga base dan quote, jadi tanpa cache satu putaran menembak ~64 request harga yang jawabannya
praktis sama.

### Spread: proporsional, sedangkan fee flat — ini yang menentukan ukuran swap

`rfqSpread()` mengukurnya tanpa biaya: mengutip **dua arah** pada ukuran base yang sama
persis lalu membandingkan harganya (`node index.js spread [market|all|strategi] [usd]`).
Ini spread **RFQ**, bukan `bestBid`/`bestAsk` orderbook — jalur strategi 1 dan swap 1x
lewat RFQ dan harga LP bisa jauh berbeda dari book.

Jangan mengukur spread dengan menilai tiap swap memakai harga pasar. `getPrice` memberi
harga `last` (dan untuk market `cross_rate` malah `"Calculated"`), dan diukur live harga
`last` EDELx praktis **sama dengan harga ask RFQ** — sehingga satu swap $12 yang jelas
merugi terbaca **rugi $0.00**. Acuannya sendiri bias. Yang dipakai `s1RunTask` adalah
biaya **bolak-balik dalam satuan hub**: di awal dan akhir task seluruh dana ada di hub,
jadi selisihnya biaya nyata dan tidak butuh harga acuan sama sekali.

Diukur live di `EDELx-cETH`, spread persentase **tidak berubah** terhadap ukuran
sementara fee tetap flat:

| ukuran | spread | biaya spread | fee | total/swap |
| --- | --- | --- | --- | --- |
| $10.5 | 2.020 % | $0.106 | $0.300 | **$0.406** |
| $12 | 2.020 % | $0.121 | $0.300 | $0.421 |
| $14 | 1.954 % | $0.137 | $0.300 | $0.437 |

Jadi dua gaya biaya itu tarik-menarik: **fee** menghukum swap kecil (flat, dan 3× lebih
mahal di bawah ambang ~$10), **spread** menghukum swap besar (proporsional). Titik
termurah adalah ukuran **sekecil mungkin yang masih di atas ambang tier $10** — bukan
swap besar seperti yang disarankan logika fee sendirian.

Spread berbeda jauh antar market, jadi memilih market itu keputusan biaya: diukur
bersamaan, `HECTO-cETH` 0.61 %, `EDELx-cETH` 2.02 %, `HECTO-EDELx` 4.05 %.

Model ini sudah dicocokkan dengan realisasi: satu putaran penuh 3 task diprediksi
9×$0.121 + 9×$0.037 + 11×$0.243 = **$4.10**, realisasinya **$4.22** (selisih 3 %).

### Kolom fee/loss di dashboard: harian vs season, CC vs token

Empat kolom itu dipakai bersama semua engine dan gampang disalahartikan:

| kolom | isi | reset |
| --- | --- | --- |
| `FEE/hr` | fee **hari ini** — namanya menyesatkan, bukan per jam | otomatis 07:00 WIB |
| `FEE/SN` | fee **CC** sejak awal season | manual, menu 5 → b |
| `FEE-TOK` | fee **non-CC** season (TUSDT/USD8) + satuannya | manual, sama |
| `LOSS$/hr` / `LOSS/SN` | spread USD harian / season | 07:00 WIB / manual |

Di `strategi1` susunannya berbeda: `FEE-TOK` dibuang (isinya sudah sama dengan `FEE/hr` yang
di mode itu menampilkan ember token), tempatnya dipakai `SPREAD/HARI` = `spreadToday`.
Kolom itu memang sudah ada sebagai `LOSS$/hr`, tapi prionya 3 sehingga hampir selalu didrop
duluan saat terminal sempit; di `strategi1` ia naik ke prio 2 dan `LOSS$/hr` disembunyikan
supaya tidak dobel.

`persistDaily` memisahkan ember CC (`feeToday`/`feeSeason`) dari ember non-CC
(`feeTokToday`/`feeTokSeason` + `feeTokUnit`) supaya angkanya tidak tertimbun jadi satu.
Konsekuensinya: strategi 1 membayar TUSDT/USD8, jadi kolom CC-nya **selalu 0** dan yang
bergerak `FEE-TOK`. Karena itu di `SESSION_ENGINE === 'strategi1'` kolom `FEE/hr` menampilkan
ember token (`feeTokToday` + unit), bukan CC — kalau tidak, kolomnya nol terus dan pembacanya
menyimpulkan bot tidak membayar fee.

Kolom `FEE/SN` yang besar (ratusan sampai ribuan CC) itu warisan sesi ping-pong/day-trader
sebelumnya, bukan biaya strategi 1.

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
