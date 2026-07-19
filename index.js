#!/usr/bin/env node
/**
 * SilvanaBot-Sipal — single-file edition.
 *
 *  - Login Privy (email OTP, sekali) → cache di session.json, auto-refresh.
 *  - Login Silvana via passkey kustom (private key di session.json).
 *  - Auto-swap "DAY_TRADER": baca progress dari API, swap CC↔USDCx sampai X/X, STOP.
 *    Anti-overcap (jumlah swap = target - current dari API). Ulang tiap jam terjadwal WIB.
 *  - Dashboard ANSI ringan, adaptif ke ukuran tmux.
 *
 *  STRUKTUR FILE (cuma 4, sisanya node_modules/package utk node-cron):
 *    index.js      — seluruh kode + ID/URL publik (tidak sensitif)
 *    config.json   — setelan: swap min/max, refresh dashboard, jam, proxy
 *    accounts.json — kredensial input: { accounts:[{label,email,privyEmail}] }
 *    session.json  — semua hasil generate: passkey, userServiceCid, cookie, token
 */

'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const net = require('net');
const tls = require('tls');
const zlib = require('zlib');
const { URL } = require('url');

// ============================================================================
//  Path & file loader
// ============================================================================
const ROOT = __dirname;
const CFG_PATH = path.join(ROOT, 'config.json');
const ACC_PATH = path.join(ROOT, 'accounts.json');
const SESS_PATH = path.join(ROOT, 'session.json');

function loadJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) {
    if (fallback !== undefined) return fallback;
    throw new Error(`Gagal baca ${p}: ${e.message}`);
  }
}
function saveJSON(p, obj) { fs.writeFileSync(p, JSON.stringify(obj, null, 2)); }

// ── Persist action IDs (auto-fetch) ──────────────────────────────────────────
// Simpan hasil discovery ke action_ids.json → rerun load dulu (gak scan bundle
// tiap kali). Cuma re-discover kalau validate bilang stale. loadActionIds di
// startup; saveActionIds tiap SWAP.actionIds berubah.
const ACTIONIDS_PATH = path.join(__dirname, 'action_ids.json');
function loadActionIds() {
  const d = loadJSON(ACTIONIDS_PATH, null);
  if (d && d.ids && typeof d.ids === 'object') {
    // cuma load key yg dikenal (cegah dead key garbage dari file lama nempel)
    for (const k of Object.keys(SWAP.actionIds)) if (d.ids[k]) SWAP.actionIds[k] = d.ids[k];
    return d;
  }
  return null;
}
function saveActionIds() {
  try { saveJSON(ACTIONIDS_PATH, { ids: { ...SWAP.actionIds }, savedAt: Date.now() }); } catch (_) { }
}

const CONFIG = loadJSON(CFG_PATH, {});
const ACCOUNTS = loadJSON(ACC_PATH, { accounts: [] }).accounts || [];

// ---- setelan dari config.json (minimal) ----
const REFRESH_SEC = Math.max(30, Number((CONFIG.dashboard || {}).refreshSec) || 300);
const SCHED = Object.assign({ hour: 7, minute: 0, timezone: 'Asia/Jakarta' }, CONFIG.schedule || {});
const SWAP_MIN = String((CONFIG.swap || {}).minCC || '5');
// "Rata kanan": swap sebanyak mungkin, tapi SELALU sisakan reserveCC unlocked
// (buat fee swap berikutnya + safety). Set di config.json swap.reserveCC.
const SWAP_RESERVE = String((CONFIG.swap || {}).reserveCC || '5');
// Mode swap (config.json swap.mode):
//   "maxReserve" (default): RATA KANAN tapi di-cap maxAmount per swap. Sisakan
//                           reserveCC, skip kalau hasil < minCC. Sisa di-swap iterasi berikut.
//   "minmax":               tiap swap pilih amount ACAK antara minAmount..maxAmount.
//                           Tetap sisakan reserveCC (CC floor, sama kayak maxReserve).
const SWAP_MODE = String((CONFIG.swap || {}).mode || 'maxReserve').toLowerCase();
// let (bukan const) — bisa diubah live dari dashboard tool "set modal" + persist.
let SWAP_MIN_AMOUNT = Number((CONFIG.swap || {}).minAmount || SWAP_MIN);
let SWAP_MAX_AMOUNT = Number((CONFIG.swap || {}).maxAmount || 0); // 0 = tak terbatas
const PROXY_ENABLED = (CONFIG.proxy || {}).enabled !== false;
const PROXY_FILE = path.join(ROOT, (CONFIG.proxy || {}).file || 'proxy.txt');
const PROXY_LIST = (PROXY_ENABLED && fs.existsSync(PROXY_FILE))
  ? fs.readFileSync(PROXY_FILE, 'utf8').split(/\r?\n/)
  : [];

// ---- ID & URL publik (aman di-share; tidak sensitif) ----
const UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36';
const REQ = { timeoutMs: 20000, retry: 2, retryDelayMs: 2500 };

const PRIVY_APP_ID = 'cm338ijv804mhhgvacdxsayxu';
const PRIVY_CLIENT_ID = 'client-WY5dQwQyixARYCtWLMzJnVKpgX1kt796M1vUk7smkFEy5';
const PRIVY_CA_ID = '7cc8de2f-2849-4a08-8960-e51f40741cda';
const PRIVY_BASE = 'https://auth.privy.io';
const APP_BASE = 'https://app.silvana.one';
const SUPA = 'https://api.supanova.app/canton/api';
const RP_ID = 'silvana.one';

// Parameter swap (next-action & template ID = publik, dari frontend Silvana.
// Kalau swap mendadak gagal setelah Silvana redeploy frontend, update di sini).
const SWAP = {
  // === PAIR (di-set runtime via setActivePair; default usdcx) ===
  // market         : symbol RFQ/quote (CC-USDCx | cETH-CC).
  // tokenId        : id instrument token non-CC (match balance, uppercase).
  // tokenAdmin     : party admin registry token (fallback; admin asli diambil dari dvp terms).
  // baseIsCC       : true kalau base market = CC (RFQ quantity = CC). cETH base=cETH → false.
  // dirOpen/dirClose: arah market utk CC→token (open) & token→CC (close). Beda orientasi:
  //   CC-USDCx (base CC): open=sell, close=buy.  cETH-CC (base cETH): open=buy, close=sell.
  market: 'CC-USDCx',
  tokenId: 'USDCX',
  tokenLabel: 'USDCx',
  tokenAdmin: 'decentralized-usdc-interchain-rep::12208115f1e168dd7e792320be9c4ca720c751a02a3053c7606e1c1cd3dad9bf60ef',
  baseIsCC: true,
  // token↔token (EDELx↔cETH, opsi 8): neither leg CC. Di-set true oleh setEdelCethLeg,
  // di-reset false oleh setActivePair. Ubah holdingsByToken meta di swapOnce.
  tokenToToken: false,
  dirOpen: 'sell',
  dirClose: 'buy',
  pairKey: 'usdcx',
  dsoPartyId: 'DSO::1220b1431ef217342db44d516bb9befde802be7d8899637d290895fa58880f19accc',
  usdcxAdmin: 'decentralized-usdc-interchain-rep::12208115f1e168dd7e792320be9c4ca720c751a02a3053c7606e1c1cd3dad9bf60ef',
  synchronizerId: 'global-domain::1220b1431ef217342db44d516bb9befde802be7d8899637d290895fa58880f19accc',
  feeBufferCC: '10',
  minUsdcxToBuy: '0.5',
  rfqMaxTries: 5, rfqRetryMs: 30000, quoteTimeoutSec: 25,
  pollIntervalMs: 2000, pollMaxTries: 40,
  completionPollMs: 2000, completionMaxTries: 30,
  delayBetweenSwapsSec: 5,
  // Cooldown random setelah swap sukses sebelum cek DAY_TRADER ulang.
  // Tujuan: anti-overcap karena server butuh waktu update count.
  postSwapDelayMinSec: 10,
  postSwapDelayMaxSec: 20,
  // Tunggu max berapa detik kalau ada settlement aktif (counterparty belum
  // allocate) sebelum lanjut buka posisi baru. Default 4 menit. Setelah ini,
  // bot lanjut walau ada yang masih in-progress (asumsi stale/dead).
  activeSettlementWaitSec: 120,
  // === FEE PROTECTION ===
  // Kalau fee swap (CC) > maxFeeCC, JANGAN swap (walau DAY_TRADER belum kelar).
  // Tunggu feeSpikeWaitSec lalu cek ulang, retry SAMPAI fee turun (infinity).
  // Fee naik biasanya karena network Canton lagi sibuk → transient.
  maxFeeCC: Number((CONFIG.swap || {}).maxFeeCC) || 3.5,
  feeSpikeWaitSec: Number((CONFIG.swap || {}).feeSpikeWaitSec) || 300,
  // 2 swap submit tapi DAY_TRADER gak naik → STOP submit swap baru (cegah balance
  // ke-lock SEMUA di settlement pending). Poll DAY_TRADER tiap stuckPollSec sampai
  // naik (pending akhirnya settle & unlock), baru lanjut swap lagi.
  maxStuckBeforeStop: Number((CONFIG.swap || {}).maxStuckBeforeStop) || 2,
  stuckPollSec: Number((CONFIG.swap || {}).stuckPollSec) || 300,
  // closeWithCC: tutup hari pegang CC. Swap ke-9 (remaining<=2) dipaksa sell
  // (restock USDCx) → swap ke-10 (remaining<=1) dipaksa buy SEMUA USDCx jadi CC
  // (floor=minAmount, max BEBAS). Default ON; set false di config buat matiin.
  closeWithCC: (CONFIG.swap || {}).closeWithCC !== false,
  // === DAILY TARGET ===
  // dailySwapCount: target jumlah swap per hari (default 10 = sesuai DAY_TRADER).
  // allowOvercap: kalau true, boleh swap LEBIH dari batas DAY_TRADER API (mis. 15
  //   swap walau task cuma 10/10). Verifikasi DAY_TRADER tetap jalan (di-log),
  //   tapi tidak gate stop. Counter swap pakai settle on-chain saat overcap.
  //   Default false (aman, anti-overcap).
  allowOvercap: (CONFIG.swap || {}).allowOvercap === true,
  // Auto-cancel settlement nyangkut tiap sesi. Default OFF (cancelSettlement masih
  // gagal). Bersihin manual dulu; set true di config kalau cancel udah fix.
  autoCancelStale: (CONFIG.swap || {}).autoCancelStale === true,
  dailySwapCount: Math.max(1, Number((CONFIG.swap || {}).dailySwapCount) || 10),
  // === PARALLEL (config swap.parallel; cuma dihormati opsi 0/1) ===
  // parallel=true → swap SEMUA akun barengan, `concurrency` sekaligus. Default seq.
  parallel: (CONFIG.swap || {}).parallel === true,
  concurrency: Math.max(1, Number((CONFIG.swap || {}).concurrency) || 3),
  privyAppId: PRIVY_APP_ID, privyClientId: PRIVY_CLIENT_ID,
  actionIds: {
    // FALLBACK saja — di-refresh tiap sesi via discoverActionIds() (parse bundle
    // by NAMA FUNGSI, lihat ACTION_NAME). execSettle gone (Canton prepare→submit).
    // listProposals + getConsumedHoldings DIHAPUS: gak dipakai swap core
    //   (listProposals → REST /api/settlement-proposals; getConsumedHoldings unused).
    estimateFee: '4074ab0f8f8520c7db51cdc9553113534d890eb95e',
    acceptQuote: '40a1adcd089f85984250205b5ea4e17f06a40dbeba',
    recordEvent: '40e87910772c03d8a7421cfb88978ac8f2cd4c456b',
    pollProposal: '40394b3565003b5772b75a4d82bdd88f26fe3af6a0',
    getMultiCall: '402effcb926d81e596e8d19b4f5a645a5b604a03ed',
    prepareDvpFee: '406963e108efd714c3b12143bae33345c88035c129',
    prepareTransfer: '40163cbb1aa5dc6248b427f0f118e2d90fea196a3d',
    // FALLBACK saja — semua di-refresh via discoverActionIds (parse bundle by
    // NAMA FUNGSI). getAllocFactory=getAllocationFactory, cancelSettlement=
    // cancelSettlementAction (lewat /swap, bukan /terminal).
    getAllocFactory: '603f6b19e6cca00e786c9be09a1042e21308027cd1',
    cancelSettlement: '403c0a394eb2f07997e27fc2d2b981533c564272e8',
    // FALLBACK — di-refresh via discoverActionIds (by nama). Buat withdraw alloc.
    getDsoInfo: '00dd839eb2f450e60e92b6e868e52f2ecf9999af98',
    getOpenRound: '00719f372227f711c798857cecf801de3b40bbe809',
    // TERMINAL (mode 8 CLOB) — di-refresh via discoverActionIds. submitOrder=place
    // market/limit order; cancelOrder=batal order; submitPreconfirmation=setuju
    // settlement (pengganti recordEvent preconfirmation di terminal); getSettlementHistory
    // → consumedAmuletCids (exclude CC UTXO biar fee split gak rebutan). Nama STABIL,
    // hash ganti tiap redeploy (fallback = deploy 2026-07-14).
    submitOrder: '40301abd1de5f1b536a589e3f888ef7707802b51e5',
    cancelOrder: '4022f5e5f5c6ab32b7939cc75a192f6e4738cf1379',
    submitPreconfirmation: '40b97b1d16dd581c9ad4f2fad40e5e71cd39e3cdb3',
    getSettlementHistory: '4067fe2fd14e778bd08be31aa9a3cd4fedb68c78f2',
  },
  // Package ID untuk Splice.Api.Token.AllocationInstructionV1 — dipakai
  // saat membangun ExerciseCommand AllocationFactory_Allocate.
  allocationInstructionPackageId: '275064aacfe99cea72ee0c80563936129563776f67415ef9f13e4297eecbc520',
  // catatan: actionIds (di bawah) + templateIds SHARED antar pair (sama persis).
  templateIds: {
    dvpProposal: '#utility-settlement-app-v1:Utility.Settlement.App.V1.Model.Dvp:DvpProposal',
    amulet: '#splice-amulet:Splice.Amulet:Amulet',
    allocationFactory: '#utility-registry-app-v0:Utility.Registry.App.V0.Service.AllocationFactory:AllocationFactory',
    instrumentConfiguration: '#utility-registry-v0:Utility.Registry.V0.Configuration.Instrument:InstrumentConfiguration',
  },
};

// ── Mode 8 (ping-pong EDELx↔cETH) config — SEMUA knob opsi 8 di config.json "mode8" ──────────
// Fallback ke swap.edelCeth* / swap.maxFeeCC / schedule.timezone lama biar config lama tetap jalan.
// Siang (dayStartHour..dayEndHour WIB): net gate (minNetUsd) + fee gate (maxFeeCC). Malam: trabas.
const _m8 = CONFIG.mode8 || {};
const _m8sw = CONFIG.swap || {};
const _m8num = (v, d) => (v === '' || v == null || Number.isNaN(Number(v))) ? d : Number(v);
const M8 = {
  dayStartHour: _m8num(_m8.dayStartHour, 7),
  dayEndHour: _m8num(_m8.dayEndHour, 23),
  timezone: _m8.timezone || (CONFIG.schedule || {}).timezone || 'Asia/Jakarta',
  nightForce: _m8.nightForce !== false,
  maxFeeCC: _m8num(_m8.maxFeeCC, _m8num(_m8sw.maxFeeCC, 3.5)),
  // minNetUsd: null/'' = gate mati. NEGATIF = allowed-loss, POSITIF = cari profit, 0 = break-even.
  minNetUsd: (_m8.minNetUsd === '' || _m8.minNetUsd == null || Number.isNaN(Number(_m8.minNetUsd))) ? null : Number(_m8.minNetUsd),
  netWaitSec: _m8num(_m8.netWaitSec, _m8num(_m8sw.feeSpikeWaitSec, 300)),
  cleanupEveryChecks: Math.max(0, Math.floor(_m8num(_m8.cleanupEveryChecks, 100))),
  usdAmount: _m8num(_m8.usdAmount, _m8num(_m8sw.edelCethUsdAmount, 10.1)),
  minUsd: _m8num(_m8.minUsd, _m8num(_m8sw.edelCethMinUsd, 10)),
  reduceRelax: _m8num(_m8.reduceRelax, _m8num(_m8sw.edelCethReduceRelax, 0.003)),
  reduceMinFactor: _m8num(_m8.reduceMinFactor, _m8num(_m8sw.edelCethReduceMinFactor, 0.5)),
  // Haircut FIXED (terminal fee tetap = maker 0.1%). Ganti reduce ADAPTIF RFQ lama:
  // rf = 1 − haircut, dipakai pre-reduce max-dump + estimasi net-gate. Default 0.001 (0.1%).
  haircut: _m8num(_m8.haircut, 0.001),
  // Aggressive cross market order (FOK): BUY price = ref×(1+cross), SELL = ref×(1−cross).
  // PENTING sizing BUY: order dibayar cETH di ref×(1+cross) → size edelxQty di harga ORDER
  // (bagi 1+cross), BUKAN di ref. Kalau enggak, cost cETH 2% > saldo → insufficient → retry
  // −1% tiap swap (bug). Default 0.02 (2%). Turunin buat spread lebih ketat (risiko gak fill).
  orderCross: _m8num(_m8.orderCross, 0.02),
  taskCode: String(_m8.taskCode || _m8sw.edelCethTaskCode || '').toUpperCase(),
  // allowOvercap (kayak opsi 0/1): false = stop pas task 'EDELx-cETH Daily Trader'
  // penuh (10/10). true = boleh swap LEBIH dari task target sampai dailySwapCount
  // total swap sesi (task tetap capped 10, dihitung pakai counter swap lokal).
  allowOvercap: (_m8.allowOvercap != null ? _m8.allowOvercap === true : (_m8sw.allowOvercap === true)),
  dailyCap: Math.max(1, _m8num(_m8.dailySwapCount, _m8num(_m8sw.dailySwapCount, 10))),
};
// Jam sekarang (0–23) di timezone tz. Pola sama msUntilNext (Intl.DateTimeFormat TZ).
function nowHourInTz(tz) {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz || 'Asia/Jakarta', hour12: false, hour: '2-digit' }).formatToParts(new Date());
  let h = Number((parts.find(p => p.type === 'hour') || {}).value); if (h === 24) h = 0;
  return Number.isFinite(h) ? h : new Date().getHours();
}
// true = "malam trabas" aktif (di luar jam siang) → net + fee gate diabaikan. false pas siang / nightForce off.
function mode8IsNight() {
  if (!M8.nightForce) return false;
  const h = nowHourInTz(M8.timezone);
  return h >= M8.dayEndHour || h < M8.dayStartHour;
}

// Definisi pair yg didukung. Nilai token-specific dari HAR (folder jual_cc =
// USDCx, cc-eth = cETH). Logic swap SAMA; cuma orientasi base/quote beda:
//   CC-USDCx : base=CC  → CC→USDCx = 'sell', USDCx→CC = 'buy'  (RFQ qty = CC).
//   cETH-CC  : base=cETH → CC→cETH = 'buy',  cETH→CC = 'sell'  (RFQ qty = cETH).
// price (bid/ask) di KEDUA market = "jumlah token per 1 CC" (invariant) → buyCap
// & konversi qty seragam. admin token asli tetap diambil dari dvp terms saat swap.
const PAIRS = {
  usdcx: {
    pairKey: 'usdcx', market: 'CC-USDCx', tokenId: 'USDCX', tokenLabel: 'USDCx',
    tokenAdmin: 'decentralized-usdc-interchain-rep::12208115f1e168dd7e792320be9c4ca720c751a02a3053c7606e1c1cd3dad9bf60ef',
    baseIsCC: true, dirOpen: 'sell', dirClose: 'buy',
  },
  ceth: {
    pairKey: 'ceth', market: 'cETH-CC', tokenId: 'CETH', tokenLabel: 'cETH',
    tokenAdmin: 'cethMain-1::12200350ba6e96e3b701c3048b5aa013a8c1c08833e8ebf54339cff581055c29003a',
    baseIsCC: false, dirOpen: 'buy', dirClose: 'sell',
  },
  // EDELx-CC (base=EDELx, quote=CC), sama orientasi kayak cETH. CC→EDELx = 'buy'.
  // tokenAdmin fallback dari HAR /api/instruments (edel-registrar); admin ASLI tetap
  // diambil dari dvp terms saat swap. Dipakai opsi 7 (one-shot CC→EDELx).
  edelx: {
    pairKey: 'edelx', market: 'EDELx-CC', tokenId: 'EDELX', tokenLabel: 'EDELx',
    tokenAdmin: 'edel-registrar::122085b19d439b7e68abf7c94c3d9949f9e23aef3f1d4835ccbcb0993ed96fb53432',
    baseIsCC: false, dirOpen: 'buy', dirClose: 'sell',
  },
};
// Set pair aktif (mutate SWAP). Dipanggil dari menu / CLI sebelum sesi swap.
function setActivePair(key) {
  const p = PAIRS[key] || PAIRS.usdcx;
  SWAP.pairKey = p.pairKey; SWAP.market = p.market; SWAP.tokenId = p.tokenId;
  SWAP.tokenLabel = p.tokenLabel; SWAP.tokenAdmin = p.tokenAdmin;
  SWAP.baseIsCC = p.baseIsCC; SWAP.dirOpen = p.dirOpen; SWAP.dirClose = p.dirClose;
  SWAP.tokenToToken = false;
  return p;
}

// EDELx↔cETH (opsi 8, token↔token). market EDELx-cETH, base=EDELx, quote=cETH.
// deliver='EDELx' → SELL (EDELx→cETH). deliver='cETH' → BUY (cETH→EDELx). Set SWAP.tokenId
// = token yg KITA SERAHKAN (dipakai swapOnce buat cari holding + holdingsByToken meta).
const EDEL_CETH = {
  market: 'EDELx-cETH',
  edelxAdmin: 'edel-registrar::122085b19d439b7e68abf7c94c3d9949f9e23aef3f1d4835ccbcb0993ed96fb53432',
  cethAdmin: 'cethMain-1::12200350ba6e96e3b701c3048b5aa013a8c1c08833e8ebf54339cff581055c29003a',
};
// Mutate global SWAP (buat feecheck single-thread). JANGAN dipakai di engine parallel.
function setEdelCethLeg(deliver) {
  const { leg } = edelCethLeg(deliver);
  SWAP.market = leg.market; SWAP.baseIsCC = leg.baseIsCC; SWAP.tokenToToken = leg.tokenToToken;
  SWAP.tokenId = leg.tokenId; SWAP.tokenLabel = leg.tokenLabel; SWAP.tokenAdmin = leg.tokenAdmin;
  return deliver === 'EDELx' ? 'sell' : 'buy';
}
// NON-mutating: balikin {direction, leg} buat di-pass via ctx.leg ke swapOnce. WAJIB
// dipakai engine ping-pong (parallel) — SWAP global di-share antar akun → race.
function edelCethLeg(deliver) {
  const isEdel = deliver === 'EDELx';
  return {
    direction: isEdel ? 'sell' : 'buy',
    leg: {
      market: EDEL_CETH.market, baseIsCC: false, tokenToToken: true,
      tokenId: isEdel ? 'EDELX' : 'CETH',
      tokenLabel: isEdel ? 'EDELx' : 'cETH',
      tokenAdmin: isEdel ? EDEL_CETH.edelxAdmin : EDEL_CETH.cethAdmin,
    },
  };
}

// ---- UI constants ----
const MIN_ACTIVITY_LINES = 4;
// View panel log: 0 = SYSTEM (semua log), 1..N = akun ke-(selView-1). Navigasi ↑/↓.
let selView = 0;
// Flag parallel swap aktif (di-set di menu, cuma opsi 0/1 + config swap.parallel).
let parallelSwapActive = false;

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
// Map paralel dgn batas konkurensi. Jaga urutan hasil = urutan input. Error per
// item → undefined (gak gagalin yg lain). Dipakai biar discovery (fetch chunk +
// probe action) jalan barengan, bukan satu-satu (jauh lebih cepat).
async function mapLimit(items, limit, fn) {
  const ret = new Array(items.length);
  let i = 0;
  const n = Math.max(1, Math.min(limit, items.length));
  const workers = Array.from({ length: n }, async () => {
    while (i < items.length) { const idx = i++; try { ret[idx] = await fn(items[idx], idx); } catch (_) { ret[idx] = undefined; } }
  });
  await Promise.all(workers);
  return ret;
}

// ============================================================================
//  HTTP (native, + cookie jar, gzip/br, proxy CONNECT tunnel)
// ============================================================================
function tunnelThroughProxy(proxy, targetHost, targetPort, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: proxy.host, port: proxy.port });
    sock.setTimeout(timeoutMs, () => { sock.destroy(new Error('proxy connect timeout')); });
    let connectReq = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
    if (proxy.auth) connectReq += `Proxy-Authorization: Basic ${Buffer.from(proxy.auth, 'utf8').toString('base64')}\r\n`;
    connectReq += 'Proxy-Connection: keep-alive\r\n\r\n';
    sock.once('error', reject);
    let buf = '';
    const onData = (chunk) => {
      buf += chunk.toString('latin1');
      const end = buf.indexOf('\r\n\r\n');
      if (end < 0) return;
      sock.removeListener('data', onData);
      const status = buf.split('\r\n')[0] || '';
      if (!/^HTTP\/1\.[01]\s+2\d\d/.test(status)) { sock.destroy(); return reject(new Error(`proxy CONNECT failed: ${status.trim() || 'no response'}`)); }
      const tlsSock = tls.connect({ socket: sock, servername: targetHost, ALPNProtocols: ['http/1.1'] }, () => resolve(tlsSock));
      tlsSock.once('error', reject);
    };
    sock.on('data', onData);
    sock.on('connect', () => sock.write(connectReq));
  });
}

// Tag error jaringan sementara (timeout/reset/hangup) sbg e.transient → dipungut
// semua retry yg cek e.transient (loop swap L3073, engine ping-pong). BUKAN proxy
// connect timeout (itu diurus isProxyErr + rotate, jangan retry proxy sama).
function tagTransient(e) {
  const m = (e && e.message) || String(e);
  if (/Request timeout|socket hang ?up|ECONNRESET|ETIMEDOUT|EAI_AGAIN/i.test(m)) { try { e.transient = true; } catch (_) { } }
  return e;
}
function request(method, urlStr, opts = {}) {
  const { headers = {}, body = null, jar = null, timeoutMs = REQ.timeoutMs, proxy = null } = opts;
  return new Promise((resolve, _reject) => {
    const reject = (e) => _reject(tagTransient(e));
    const u = new URL(urlStr);
    const isHttps = u.protocol === 'https:';
    const targetHost = u.hostname;
    const targetPort = u.port ? Number(u.port) : (isHttps ? 443 : 80);
    const finalHeaders = { ...headers };
    if (jar && jar.size && jar.size()) { const c = jar.toHeader(); if (c) finalHeaders['Cookie'] = c; }
    if (!finalHeaders['Accept-Encoding'] && !finalHeaders['accept-encoding']) finalHeaders['Accept-Encoding'] = 'gzip, deflate, br';
    if (body && !finalHeaders['Content-Type'] && !finalHeaders['content-type']) finalHeaders['Content-Type'] = 'application/json';
    if (body) finalHeaders['Content-Length'] = Buffer.byteLength(body);
    const reqPath = u.pathname + u.search;
    const onResponse = (res) => {
      if (jar && res.headers['set-cookie']) jar.ingest(res.headers['set-cookie']);
      const chunks = [];
      res.on('data', d => chunks.push(d));
      res.on('end', () => {
        let b = Buffer.concat(chunks);
        const enc = (res.headers['content-encoding'] || '').toLowerCase();
        try {
          if (enc === 'gzip') b = zlib.gunzipSync(b);
          else if (enc === 'deflate') b = zlib.inflateSync(b);
          else if (enc === 'br') b = zlib.brotliDecompressSync(b);
        } catch (_) { }
        const text = b.toString('utf8');
        let json = null; try { json = text ? JSON.parse(text) : null; } catch (_) { }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    };
    if (!proxy) {
      const lib = isHttps ? https : http;
      const req = lib.request({ method, hostname: targetHost, port: targetPort, path: reqPath, headers: finalHeaders }, onResponse);
      req.on('error', reject);
      req.setTimeout(timeoutMs, () => req.destroy(new Error('Request timeout')));
      if (body) req.write(body);
      req.end();
      return;
    }
    if (isHttps) {
      tunnelThroughProxy(proxy, targetHost, targetPort, timeoutMs).then((sock) => {
        const req = https.request({ method, hostname: targetHost, port: targetPort, path: reqPath, headers: finalHeaders, createConnection: () => sock }, onResponse);
        req.on('error', reject);
        req.setTimeout(timeoutMs, () => req.destroy(new Error('Request timeout')));
        if (body) req.write(body);
        req.end();
      }).catch(reject);
      return;
    }
    const reqOpts = { method, hostname: proxy.host, port: proxy.port, path: urlStr, headers: { ...finalHeaders, Host: targetHost } };
    if (proxy.auth) reqOpts.headers['Proxy-Authorization'] = `Basic ${Buffer.from(proxy.auth, 'utf8').toString('base64')}`;
    const req = http.request(reqOpts, onResponse);
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error('Request timeout')));
    if (body) req.write(body);
    req.end();
  });
}

async function withRetry(fn, label, opts = {}) {
  const tries = (opts.retry ?? 1) + 1;
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try { return await fn(); }
    catch (e) { lastErr = e; if (e && e.rateLimit) break; if (i < tries - 1) await sleep(opts.delayMs || 2000); }
  }
  throw new Error(`${label} gagal: ${lastErr && lastErr.message}`);
}

// ============================================================================
//  Cookie jar
// ============================================================================
class CookieJar {
  constructor(initial) {
    this.map = new Map();
    if (initial && typeof initial === 'object') for (const [k, v] of Object.entries(initial)) this.map.set(k, v);
  }
  ingest(setCookieHeader) {
    if (!setCookieHeader) return;
    const arr = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    for (const raw of arr) {
      if (typeof raw !== 'string') continue;
      const first = raw.split(';')[0];
      const eq = first.indexOf('=');
      if (eq <= 0) continue;
      const name = first.slice(0, eq).trim();
      const value = first.slice(eq + 1).trim();
      if (!name) continue;
      const lower = raw.toLowerCase();
      if (value === '' || /max-age=0\b/.test(lower) || /expires=[^;]*1970/.test(lower)) { this.map.delete(name); continue; }
      this.map.set(name, value);
    }
  }
  toHeader() { return this.map.size ? [...this.map.entries()].map(([k, v]) => `${k}=${v}`).join('; ') : ''; }
  toObject() { return Object.fromEntries(this.map); }
  size() { return this.map.size; }
  clear() { this.map.clear(); }
}

// ============================================================================
//  Proxy pool (list dari config.json, sticky deterministik per email)
// ============================================================================
const PROXIES = (() => {
  if (!PROXY_ENABLED) return [];
  const list = [];
  for (const raw of PROXY_LIST) {
    const s = String(raw || '').trim();
    if (!s || s.startsWith('#')) continue;
    try {
      const norm = s.includes('://') ? s : `http://${s}`;
      const u = new URL(norm);
      if (!/^https?:$/.test(u.protocol)) continue;
      list.push({
        key: norm, host: u.hostname,
        port: u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80),
        auth: u.username ? `${decodeURIComponent(u.username)}:${decodeURIComponent(u.password || '')}` : null,
      });
    } catch (_) { }
  }
  return list;
})();
function pickProxy(email) {
  if (!PROXIES.length) return null;
  const hash = parseInt(crypto.createHash('sha1').update(String(email)).digest('hex').slice(0, 8), 16);
  return PROXIES[hash % PROXIES.length];
}

// Proxy rotation — keyed on canonical account email (state.email).
// Offset reset tiap bot restart. Naik 1 setiap proxy error terdeteksi.
const _proxyOffset = {};
function getProxy(email) {
  if (!PROXIES.length) return null;
  const off = _proxyOffset[email] || 0;
  const hash = parseInt(crypto.createHash('sha1').update(String(email)).digest('hex').slice(0, 8), 16);
  return PROXIES[(hash + off) % PROXIES.length];
}
function rotateProxy(email) {
  if (PROXIES.length <= 1) return getProxy(email);
  _proxyOffset[email] = ((_proxyOffset[email] || 0) + 1) % PROXIES.length;
  return getProxy(email);
}
function isProxyErr(e) {
  const m = (e && e.message) || String(e);
  return /proxy connect timeout|proxy CONNECT failed/i.test(m);
}
// IP proxy ke-block WAF/Cloudflare (Privy/Silvana) → 403 balikin halaman HTML, bukan JSON.
// Beda dari 401/403-JSON (auth beneran). Rotate ke IP baru biasanya fix. Dipakai login-loop
// buat rotate proxy (bukan langsung mati). Cek: status 403/429/503 + body HTML/challenge.
function isIpBlockErr(e) {
  const m = (e && e.message) || String(e);
  return /status=(403|429|503)/.test(m) && /<!doctype html|<html|cloudflare|just a moment|attention required|access denied/i.test(m);
}

// ============================================================================
//  Passkey (WebAuthn assertion, ES256)
// ============================================================================
function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function buildAssertion({ challenge, rpId, origin, credId, userHandle, privateJwk }) {
  const clientData = { type: 'webauthn.get', challenge, origin, crossOrigin: false };
  const clientDataJSON = Buffer.from(JSON.stringify(clientData), 'utf8');
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
  const keyObj = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const signer = crypto.createSign('SHA256');
  signer.update(Buffer.concat([authenticatorData, clientDataHash]));
  signer.end();
  const signatureDer = signer.sign(keyObj);
  return {
    id: credId, rawId: credId, type: 'public-key',
    response: {
      clientDataJSON: b64u(clientDataJSON),
      authenticatorData: b64u(authenticatorData),
      signature: b64u(signatureDer),
      userHandle: userHandle || undefined,
    },
  };
}

// ============================================================================
//  React Server Components (flight) parser untuk server actions /swap
// ============================================================================
function parseFlight(payload) {
  const chunks = {}; let i = 0; const n = payload.length;
  while (i < n) {
    const colon = payload.indexOf(':', i);
    if (colon < 0) break;
    const id = payload.slice(i, colon); let p = colon + 1;
    if (payload[p] === 'T') {
      const comma = payload.indexOf(',', p);
      const len = parseInt(payload.slice(p + 1, comma), 16);
      const start = comma + 1;
      chunks[id] = { type: 'text', value: payload.slice(start, start + len) };
      i = start + len; if (payload[i] === '\n') i++;
    } else {
      let end = payload.indexOf('\n', p); if (end < 0) end = n;
      const text = payload.slice(p, end);
      let val; try { val = JSON.parse(text); } catch (_) { val = { type: 'raw', value: text }; }
      chunks[id] = { type: 'model', value: val }; i = end + 1;
    }
  }
  return chunks;
}
function resolveRefs(value, chunks, seen = new Set()) {
  if (typeof value === 'string') {
    if (value === '$undefined') return undefined;
    if (value.startsWith('$$')) return value.slice(1);
    if (value[0] === '$') {
      let ref = value.slice(1); if (ref[0] === '@') ref = ref.slice(1);
      if (chunks[ref] !== undefined) { if (seen.has(ref)) return chunks[ref].value; seen.add(ref); return resolveRefs(chunks[ref].value, chunks, seen); }
      return value;
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(v => resolveRefs(v, chunks, seen));
  if (value && typeof value === 'object') { const out = {}; for (const k of Object.keys(value)) out[k] = resolveRefs(value[k], chunks, seen); return out; }
  return value;
}
function actionResult(payload) {
  const chunks = parseFlight(payload);
  const meta = chunks['0'] && chunks['0'].value;
  if (meta && typeof meta === 'object' && typeof meta.a === 'string') return resolveRefs(meta.a, chunks);
  if (chunks['1']) return resolveRefs(chunks['1'].value, chunks);
  return null;
}

// ============================================================================
//  Privy embedded-wallet (TEE) signing — HPKE + authorization signature
// ============================================================================
const PW_EXPIRY_MS = 1_800_000;
const PW_SDK = 'react-auth:3.26.0';
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

function jcs(value) {
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
}
function hmacSha256(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }
function hkdfExpand(prk, info, length) {
  const out = []; let t = Buffer.alloc(0), i = 1, total = 0;
  while (total < length) { t = hmacSha256(prk, Buffer.concat([t, info, Buffer.from([i])])); out.push(t); total += t.length; i++; }
  return Buffer.concat(out).slice(0, length);
}
function i2osp(n, len) { const b = Buffer.alloc(len); b.writeUIntBE(n, 0, len); return b; }
const HPKE_LABEL = Buffer.from('HPKE-v1');
function labeledExtract(suiteId, salt, label, ikm) { return hmacSha256(salt, Buffer.concat([HPKE_LABEL, suiteId, Buffer.from(label), ikm])); }
function labeledExpand(suiteId, prk, label, info, length) { return hkdfExpand(prk, Buffer.concat([i2osp(length, 2), HPKE_LABEL, suiteId, Buffer.from(label), info]), length); }
function rawPointToPublicKey(point65) { return crypto.createPublicKey({ key: Buffer.concat([P256_SPKI_PREFIX, point65]), format: 'der', type: 'spki' }); }
function publicKeyToRawPoint(keyObject) { const der = keyObject.export({ format: 'der', type: 'spki' }); return der.slice(der.length - 65); }
const HPKE_AEAD = { 'aes-256-gcm': { id: 0x0002, Nk: 32, Nn: 12, cipher: 'aes-256-gcm' }, 'aes-128-gcm': { id: 0x0001, Nk: 16, Nn: 12, cipher: 'aes-128-gcm' }, 'chacha20-poly1305': { id: 0x0003, Nk: 32, Nn: 12, cipher: 'chacha20-poly1305' } };
function hpkeOpen(recipientPriv, enc, ct, opts = {}) {
  const aead = HPKE_AEAD[opts.aead || 'chacha20-poly1305'];
  const info = opts.info != null ? Buffer.from(opts.info) : Buffer.alloc(0);
  const aad = opts.aad != null ? Buffer.from(opts.aad) : Buffer.alloc(0);
  const kemId = 0x0010;
  const kemSuite = Buffer.concat([Buffer.from('KEM'), i2osp(kemId, 2)]);
  const hpkeSuite = Buffer.concat([Buffer.from('HPKE'), i2osp(kemId, 2), i2osp(0x0001, 2), i2osp(aead.id, 2)]);
  const peerPub = rawPointToPublicKey(enc);
  const dh = crypto.diffieHellman({ privateKey: recipientPriv, publicKey: peerPub });
  const pkRm = publicKeyToRawPoint(crypto.createPublicKey(recipientPriv));
  const eaePrk = labeledExtract(kemSuite, Buffer.alloc(0), 'eae_prk', dh);
  const sharedSecret = labeledExpand(kemSuite, eaePrk, 'shared_secret', Buffer.concat([enc, pkRm]), 32);
  const pskIdHash = labeledExtract(hpkeSuite, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0));
  const infoHash = labeledExtract(hpkeSuite, Buffer.alloc(0), 'info_hash', info);
  const ksContext = Buffer.concat([Buffer.from([0x00]), pskIdHash, infoHash]);
  const secret = labeledExtract(hpkeSuite, sharedSecret, 'secret', Buffer.alloc(0));
  const key = labeledExpand(hpkeSuite, secret, 'key', ksContext, aead.Nk);
  const baseNonce = labeledExpand(hpkeSuite, secret, 'base_nonce', ksContext, aead.Nn);
  const tag = ct.slice(ct.length - 16), bodyCt = ct.slice(0, ct.length - 16);
  const decipher = crypto.createDecipheriv(aead.cipher, key, baseNonce, { authTagLength: 16 });
  decipher.setAuthTag(tag); if (aad.length) decipher.setAAD(aad);
  return Buffer.concat([decipher.update(bodyCt), decipher.final()]);
}
function loadAuthzKey(plaintext) {
  const str = plaintext.toString('utf8');
  if (str.includes('PRIVATE KEY')) return crypto.createPrivateKey({ key: str, format: 'pem' });
  if (/^[A-Za-z0-9+/=\s]+$/.test(str.trim())) {
    try {
      const der = Buffer.from(str.trim(), 'base64'); if (der.length > 40) {
        try { return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }); } catch (_) { }
        try { return crypto.createPrivateKey({ key: der, format: 'der', type: 'sec1' }); } catch (_) { }
      }
    } catch (_) { }
  }
  try { return crypto.createPrivateKey({ key: plaintext, format: 'der', type: 'pkcs8' }); } catch (_) { }
  try { return crypto.createPrivateKey({ key: plaintext, format: 'der', type: 'sec1' }); } catch (_) { }
  throw new Error(`tidak bisa parse authorization key (len=${plaintext.length})`);
}
function authorizationSignature(authzKey, { url, method, body, appId, expiry }) {
  const payload = { version: 1, url, method, headers: { 'privy-app-id': appId, 'privy-request-expiry': expiry }, body };
  return crypto.sign('sha256', Buffer.from(jcs(payload), 'utf8'), { key: authzKey, dsaEncoding: 'der' }).toString('base64');
}
function genEphemeral() {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spkiB64 = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64');
  return { privateKey, spkiB64 };
}
function privyWalletHeaders(caId, accessToken, origin = APP_BASE) {
  return {
    'User-Agent': UA, 'Accept': 'application/json', 'Content-Type': 'application/json',
    'Origin': origin, 'Referer': origin + '/',
    'privy-app-id': PRIVY_APP_ID, 'privy-client-id': PRIVY_CLIENT_ID, 'privy-client': PW_SDK,
    ...(caId ? { 'privy-ca-id': caId } : {}),
    ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}),
  };
}
/**
 * Pilih wallet Privy yg cocok untuk Canton party tertentu.
 * Urutan prioritas:
 *   1. ID eksplisit (`preferredWalletId` dari session.json — cache hasil sukses).
 *   2. Fingerprint heuristic: namespace partyId (`1220<hex>`) cocok sha256 pubkey
 *      lewat 1 dari beberapa skema encoding Canton.
 *   3. Fallback: stellar wallet pertama (perilaku lama).
 *
 * Privy user bisa punya >1 stellar wallet (bind ulang) → tanpa logic ini bot
 * salah pilih → raw_sign sukses tapi Canton tolak (pubkey beda → sig invalid).
 */
function pickPrivyWallet(wallets, preferredId, partyId) {
  if (!wallets || !wallets.length) return null;
  const stellars = wallets.filter(w => w.chain_type === 'stellar');
  const pool = stellars.length ? stellars : wallets;
  if (preferredId) {
    const hit = pool.find(w => w.id === preferredId);
    if (hit) return hit;
  }
  if (partyId) {
    const ns = String(partyId).split('::')[1] || '';
    if (ns.startsWith('1220') && ns.length === 68) {
      const target = ns.slice(4); // 32-byte hex
      const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
      for (const w of pool) {
        const pkHex = String(w.public_key || '');
        if (!pkHex) continue;
        const full = Buffer.from(pkHex, 'hex'); // 33b w/ prefix
        const raw = full.length === 33 ? full.slice(1) : full; // 32b
        const candidates = [
          sha(raw),
          sha(full),
          sha(Buffer.concat([Buffer.from([0x00]), raw])),
          sha(Buffer.concat([Buffer.from([0x12, 0x20]), raw])),     // protobuf field 2 (bytes,len=32)
          sha(Buffer.concat([Buffer.from([0x08, 0x00, 0x12, 0x20]), raw, Buffer.from([0x18, 0x01])])), // SigningPublicKey{format:RAW,public_key,scheme:ED25519}
        ];
        if (candidates.includes(target)) return w;
      }
    }
  }
  return pool[0];
}

class PrivyWallet {
  constructor({ accessToken, timeoutMs = REQ.timeoutMs, proxy = null, preferredWalletId = null, partyId = null } = {}) {
    this.accessToken = accessToken; this.timeoutMs = timeoutMs; this.proxy = proxy;
    this.preferredWalletId = preferredWalletId; this.partyId = partyId;
    this.caId = crypto.randomUUID(); this.wallet = null; this.authzKey = null; this.authzExpiresAt = 0;
    this.walletCandidates = [];
  }
  async authenticate() {
    if (this.authzKey && Date.now() < this.authzExpiresAt - 15_000) return this.wallet;
    const eph = genEphemeral();
    const r = await request('POST', `${PRIVY_BASE}/api/v1/wallets/authenticate`, {
      headers: privyWalletHeaders(this.caId, this.accessToken, PRIVY_BASE),
      body: JSON.stringify({ encryption_type: 'HPKE', recipient_public_key: eph.spkiB64, user_jwt: '' }),
      timeoutMs: this.timeoutMs, proxy: this.proxy,
    });
    if (r.status !== 200 || !r.json || !r.json.encrypted_authorization_key) {
      const e = new Error(`wallets/authenticate status=${r.status} body=${(r.text || '').slice(0, 200)}`);
      if (r.status === 401 || r.status === 403) e.unauthorized = true; throw e;
    }
    const eak = r.json.encrypted_authorization_key;
    const plaintext = hpkeOpen(eph.privateKey, Buffer.from(eak.encapsulated_key, 'base64'), Buffer.from(eak.ciphertext, 'base64'), {});
    this.authzKey = loadAuthzKey(plaintext);
    this.authzExpiresAt = r.json.expires_at || (Date.now() + 4 * 60_000);
    this.walletCandidates = (r.json.wallets || []).filter(w => w.chain_type === 'stellar');
    this.wallet = pickPrivyWallet(r.json.wallets, this.preferredWalletId, this.partyId);
    return this.wallet;
  }
  async rawSign(hashHex) {
    await this.authenticate();
    if (!this.wallet) throw new Error('tidak ada wallet untuk raw_sign');
    const url = `${PRIVY_BASE}/api/v1/wallets/${this.wallet.id}/raw_sign`;
    const expiry = String(Date.now() + PW_EXPIRY_MS);
    const bodyObj = { params: { hash: hashHex.startsWith('0x') ? hashHex : '0x' + hashHex } };
    const authSig = authorizationSignature(this.authzKey, { url, method: 'POST', body: bodyObj, appId: PRIVY_APP_ID, expiry });
    const r = await request('POST', url, {
      headers: { ...privyWalletHeaders(this.caId, this.accessToken), 'privy-authorization-signature': authSig, 'privy-request-expiry': expiry },
      body: JSON.stringify(bodyObj), timeoutMs: this.timeoutMs, proxy: this.proxy,
    });
    if (r.status !== 200 || !r.json || !r.json.data || !r.json.data.signature) {
      const e = new Error(`raw_sign status=${r.status} body=${(r.text || '').slice(0, 200)}`);
      if (r.status === 401 || r.status === 403) e.unauthorized = true; throw e;
    }
    return r.json.data.signature;
  }
  // Pindah ke wallet stellar berikutnya yg belum dicoba. Recovery BAD SIGNATURE:
  // Canton mengikat partyId ke SATU key; kalau pickPrivyWallet salah tebak,
  // rotasi ke kandidat lain satu2nya jalan tanpa re-config akun. Return wallet
  // baru, atau null kalau semua kandidat sudah dicoba.
  nextWallet() {
    const pool = (this.walletCandidates && this.walletCandidates.length)
      ? this.walletCandidates : (this.wallet ? [this.wallet] : []);
    if (!pool.length) return null;
    if (!this._triedWalletIds) this._triedWalletIds = new Set();
    if (this.wallet) this._triedWalletIds.add(this.wallet.id);
    const next = pool.find(w => !this._triedWalletIds.has(w.id));
    if (!next) return null;
    this.wallet = next;
    this._triedWalletIds.add(next.id);
    return next;
  }
}

// ============================================================================
//  Canton / Supanova client + perakit prepare_transaction (MultiCall)
// ============================================================================
function supaHeaders(token) {
  return {
    'User-Agent': UA, 'Accept': 'application/json, text/plain, */*',
    'Origin': APP_BASE, 'Referer': APP_BASE + '/',
    'x-canton-node-id': 'mainnet-supa', 'x-supa-app-id': 'silvana-order-book', 'x-supa-sdk': '0.2.44',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}
async function supaMe(token, proxy) {
  const r = await request('GET', `${SUPA}/me`, { headers: supaHeaders(token), timeoutMs: REQ.timeoutMs, proxy });
  return { status: r.status, data: r.json };
}
async function supaBalances(token, proxy) {
  const r = await request('GET', `${SUPA}/balances`, { headers: supaHeaders(token), timeoutMs: REQ.timeoutMs, proxy });
  if (r.status === 401) { const e = new Error('balances 401'); e.unauthorized = true; throw e; }
  if (r.status >= 400) throw new Error(`balances status=${r.status}`);
  return r.json;
}
class CantonClient {
  // token bisa berupa string statis ATAU fungsi () => token (live dari session).
  constructor({ token, timeoutMs = REQ.timeoutMs, proxy = null } = {}) { this._token = token; this.timeoutMs = timeoutMs; this.proxy = proxy; }
  get token() { return typeof this._token === 'function' ? this._token() : this._token; }
  set token(v) { this._token = v; }
  _opts(extra) { return { headers: supaHeaders(this.token), timeoutMs: this.timeoutMs, proxy: this.proxy, ...extra }; }
  // Query active contracts by INTERFACE id (mis. Allocation, Holding) — WAJIB pakai
  // param `interfaceIds=` (templateIds= balik 400 buat interface). Verified: diag
  // interfaceIds=Allocation → 200 rows. Dipakai withdraw allocation nyangkut.
  async activeContractsByInterface(interfaceId) {
    const r = await request('GET', `${SUPA}/active_contracts?interfaceIds=${encodeURIComponent(interfaceId)}`, this._opts());
    if (r.status === 401) { const e = new Error('active_contracts(iface) 401'); e.unauthorized = true; throw e; }
    if (r.status >= 400) throw new Error(`active_contracts(iface) status=${r.status}`);
    return Array.isArray(r.json) ? r.json : [];
  }
  async activeContracts(templateId, opts = {}) {
    // CATATAN: supanova TOLAK param limit/pageSize (bikin respons KOSONG) — jangan
    // tambah. Default cap 200; reduksi via cleanup (cancel) kalau DvpProposal numpuk.
    // Primary: try templateIds (plural) — works for DvpProposal, Amulet
    const r = await request('GET', `${SUPA}/active_contracts?templateIds=${encodeURIComponent(templateId)}`, this._opts());
    if (r.status === 401) { const e = new Error('active_contracts 401'); e.unauthorized = true; throw e; }
    if (r.status >= 400) throw new Error(`active_contracts status=${r.status}`);
    let list = Array.isArray(r.json) ? r.json : [];
    // Kalau kosong dan ada filterModule, fallback ke templateId (singular, unfiltered) + filter client-side
    if (!list.length && opts.filterModule) {
      const r2 = await request('GET', `${SUPA}/active_contracts?templateId=${encodeURIComponent(templateId)}`, this._opts());
      if (r2.status >= 200 && r2.status < 400 && Array.isArray(r2.json)) {
        list = r2.json.filter(c => c.templateId && c.templateId.includes(opts.filterModule));
      }
    }
    return list;
  }
  async prepareTransaction(body) {
    const r = await request('POST', `${SUPA}/prepare_transaction`, this._opts({ body: JSON.stringify(body) }));
    if (r.status === 401) { const e = new Error('prepare_transaction 401'); e.unauthorized = true; throw e; }
    if (r.status !== 200 && r.status !== 201) {
      // dump auto ke swap-debug.log tiap kali gagal — gak perlu env var
      logDebug('prepare_transaction REQUEST', body);
      logDebug(`prepare_transaction RESPONSE status=${r.status}`, r.text);
      const msg = r.text || '';
      const e = new Error(`prepare_transaction status=${r.status} body=${msg.slice(0, 400)}`);
      // Transient: contract sudah dikonsumsi/replaced di antara query & submit (race).
      // Solusi: retry dengan holding fresh.
      if (/CONTRACT_NOT_FOUND|Contract could not be found/i.test(msg)) e.transient = true;
      // Quote/RFQ kedaluwarsa juga transient
      if (/quote\s*(stale|expired)|RFQ.*(expired|stale)/i.test(msg)) e.transient = true;
      // Saldo CC unlocked gak cukup (fee swap pakai CC, besarnya tergantung server).
      // Bukan transient: retry instan gak guna — perlu nunggu settlement unlock CC.
      if (/InsufficientFunds|ITR_Insufficient/i.test(msg)) {
        e.insufficientFunds = true;
        const mm = msg.match(/missingAmount\s*=\s*([0-9.]+)/);
        if (mm) e.missingAmount = mm[1];
      }
      throw e;
    }
    return r.json;
  }
  async submitPrepared({ hash, signature }) {
    const r = await request('POST', `${SUPA}/submit_prepared`, this._opts({ body: JSON.stringify({ hash, signature }) }));
    if (r.status === 401) { const e = new Error('submit_prepared 401'); e.unauthorized = true; throw e; }
    if (r.status !== 200 && r.status !== 201) {
      logDebug('submit_prepared REQUEST', { hash, signature });
      logDebug(`submit_prepared RESPONSE status=${r.status}`, r.text);
      throw new Error(`submit_prepared status=${r.status} body=${(r.text || '').slice(0, 300)}`);
    }
    return r.json;
  }
  async queryCompletion(submissionId) {
    const r = await request('GET', `${SUPA}/query_completion?submissionId=${encodeURIComponent(submissionId)}`, this._opts());
    if (r.status >= 400 && r.status !== 304) throw new Error(`query_completion status=${r.status}`);
    return r.json;
  }
}
function toScaled(s) { const [i, f = ''] = String(s).split('.'); const frac = (f + '0'.repeat(10)).slice(0, 10); const neg = i.startsWith('-'); const ii = neg ? i.slice(1) : i; const v = BigInt((ii || '0') + frac); return neg ? -v : v; }
function fromScaled(v) { const neg = v < 0n; let a = neg ? -v : v; const s = a.toString().padStart(11, '0'); return (neg ? '-' : '') + s.slice(0, -10) + '.' + s.slice(-10); }
function addDp(a, b) { return fromScaled(toScaled(a) + toScaled(b)); }
function fmt10(s) { return fromScaled(toScaled(s)); }
function b64HashToHex(b64) { return '0x' + Buffer.from(b64, 'base64').toString('hex'); }
function sigHexToB64(hex) { return Buffer.from(hex.replace(/^0x/, ''), 'hex').toString('base64'); }
// Normalisasi signature dari Privy raw_sign ke base64 untuk submit_prepared.
// Privy kadang balikin hex (0x..), kadang hex polos, kadang sudah base64.
// Tanpa ini, base64 yg di-hex-decode jadi byte ngawur → Canton tolak "bad signature".
function sigToB64(sig) {
  const s = String(sig || '');
  if (s.startsWith('0x')) return Buffer.from(s.slice(2), 'hex').toString('base64');
  if (/[^0-9a-fA-F]/.test(s)) return s; // ada char non-hex → sudah base64
  return Buffer.from(s, 'hex').toString('base64');
}
// Ekstrak total fee swap (CC) dari hasil server action estimateFee / prepareDvpFee.
// Silvana pakai field feeAmountCC + counterpartFeeAmountCC. Kalau gak ketemu,
// coba field total tunggal. Return Number CC, atau null kalau gak yakin
// (FAIL-OPEN: jangan blokir swap cuma karena gagal parse — gate feeCtx tetap jaga).
function extractFeeCC(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const d = (obj.data && typeof obj.data === 'object') ? obj.data : obj;
  // estimateFee: {estimatedDvpFee, estimatedAllocationFee, estimatedTotalFee} (verified HAR)
  if (d.estimatedTotalFee != null && Number.isFinite(Number(d.estimatedTotalFee))) return Number(d.estimatedTotalFee);
  if (d.estimatedDvpFee != null || d.estimatedAllocationFee != null) {
    const sum = Number(d.estimatedDvpFee || 0) + Number(d.estimatedAllocationFee || 0);
    if (Number.isFinite(sum)) return sum;
  }
  // prepareDvpFee feeCtx: {feeAmountCC, counterpartFeeAmountCC}
  if (d.feeAmountCC != null || d.counterpartFeeAmountCC != null) {
    const sum = Number(d.feeAmountCC || 0) + Number(d.counterpartFeeAmountCC || 0);
    if (Number.isFinite(sum)) return sum;
  }
  for (const k of ['totalFeeCC', 'totalFee', 'feeCC', 'fee']) {
    if (d[k] != null && Number.isFinite(Number(d[k]))) return Number(d[k]);
  }
  return null;
}

function buildMultiCallAccept(p) {
  const now = p.now || new Date();
  const dso = p.dso, amulet = { admin: dso, id: 'Amulet' }, proposalId = p.proposalId, al = p.allocate;
  const feeRequestedAt = now.toISOString();
  const feeExecuteBefore = new Date(now.getTime() + 24 * 3600 * 1000 + 10_000).toISOString();
  const totalFee = addDp(p.feeCtx.feeAmountCC, p.feeCtx.counterpartFeeAmountCC);
  const feeContextValues = { ...p.feeCtx.choiceContextData.values };
  delete feeContextValues['featured-app-right'];
  const feeBatch = {
    tag: 'Op_BatchTransfer',
    value: {
      transferFactoryCid: p.feeCtx.externalPartyRules && p.feeCtx.externalPartyRules.contract_id,
      expectedAdmin: dso, instrumentId: amulet, requestedAt: feeRequestedAt, executeBefore: feeExecuteBefore,
      extraArgs: { context: { values: feeContextValues }, meta: { values: {} } },
      transferTargets: [{ receiver: p.feeCtx.feeParty, amount: totalFee, description: `DVP ${fmt10(p.feeCtx.feeAmountCC)} CC + Allocation ${fmt10(p.feeCtx.counterpartFeeAmountCC)} CC processing fee ${proposalId}` }],
    },
  };
  const acceptDvp = {
    tag: 'Op_AcceptDvpAndAllocate',
    value: {
      userServiceCid: p.userServiceCid, dvpProposalCid: p.dvpProposalCid, allocationFactoryCid: al.factoryCid,
      expectedAdmin: al.instrument.admin, requestedAt: p.dvpTerms.createdAt,
      allocations: [{
        settlement: { executor: p.executor, settlementRef: { id: proposalId, cid: null }, requestedAt: p.dvpTerms.createdAt, allocateBefore: p.dvpTerms.allocateBefore, settleBefore: p.dvpTerms.settleBefore, meta: { values: {} } },
        transferLegId: al.legId,
        transferLeg: { sender: p.party, receiver: p.receiver, instrumentId: al.instrument, amount: fmt10(al.amount), meta: { values: {} } },
      }],
      allocateExtraArgs: [{ context: { values: al.contextValues }, meta: { values: {} } }],
      instrumentIds: [al.instrument],
    },
  };
  const referenced = new Set([p.multiCall.contractId, feeBatch.value.transferFactoryCid, al.factoryCid]);
  for (const vals of [feeContextValues, al.contextValues]) for (const k of Object.keys(vals || {})) { const v = vals[k]; if (v && v.tag === 'AV_ContractId' && v.value) referenced.add(v.value); }
  const multiCallDisclosed = { contractId: p.multiCall.contractId, createdEventBlob: p.multiCall.blob, templateId: p.multiCall.templateId, synchronizerId: p.multiCall.synchronizerId };
  const disclosed = []; const seen = new Set();
  for (const c of [multiCallDisclosed, ...(p.feeCtx.contextDisclosedContracts || []), ...(al.disclosed || [])]) {
    if (!c || !c.contractId || seen.has(c.contractId) || !referenced.has(c.contractId)) continue;
    seen.add(c.contractId); disclosed.push(c);
  }
  return {
    commands: [{ ExerciseCommand: { templateId: p.multiCall.templateId, contractId: p.multiCall.contractId, choice: 'Execute_MultiCall', choiceArgument: { sender: p.party, inputHoldings: p.inputHoldingCids, operations: [feeBatch, acceptDvp] } } }],
    disclosedContracts: disclosed,
    commandId: `multicall-accept-${proposalId}`,
  };
}

// ============================================================================
//  Silvana app client (passkey login, earn-hub, server actions, RFQ)
// ============================================================================
const SWAP_STATE_TREE = encodeURIComponent(JSON.stringify(['', { children: ['(app)', { children: ['swap', { children: ['__PAGE__', {}, null, null] }, null, null] }, null, null] }, null, null, true]));
// Map: bot key → NAMA FUNGSI server-action di bundle Silvana. Nama STABIL antar-
// redeploy (cuma hash id-nya ganti). discoverActionIds parse bundle
// createServerReference("<id>",…,"<nama>") → resolve id by nama ini. Definitif,
// gak perlu probe. listProposals = getSettlementProposals (udah hilang dari /swap
// bundle → pakai REST). getConsumedHoldings tak dipakai swapOnce.
const ACTION_NAME = {
  estimateFee: 'estimateSettlementFees',
  acceptQuote: 'acceptQuote',
  recordEvent: 'recordSettlementEventAction',
  pollProposal: 'getSettlementStatus',
  getMultiCall: 'getMulticallConfigAction',
  prepareDvpFee: 'buildFeeTransferDataAction',
  prepareTransfer: 'getTransferFactoryContextAction',
  getAllocFactory: 'getAllocationFactory',
  cancelSettlement: 'cancelSettlementAction',
  // Buat withdraw allocation nyangkut (unlock + archive proposal LOCKED yg cancel
  // gagal). getDsoInfo→amulet_rules, getOpenRound→open mining round (context withdraw).
  getDsoInfo: 'getDsoInfoAction',
  getOpenRound: 'getOpenMiningRoundAction',
  // TERMINAL (mode 8 CLOB). Nama ada di bundle /terminal (dan biasanya /swap via
  // buildManifest app-wide). discoverActionIds scan /swap+/terminal → resolve.
  submitOrder: 'submitOrder',
  cancelOrder: 'cancelOrder',
  submitPreconfirmation: 'submitPreconfirmation',
  getSettlementHistory: 'getSettlementHistory',
};
// recoverParty (party + userServiceCid) skrg lewat REST GET /api/parties/{id},
// bukan server action /connect lagi (lihat SilvanaClient.recoverParty).

class SilvanaClient {
  constructor({ jar, timeoutMs = REQ.timeoutMs, proxy = null, bearer = null } = {}) { this.jar = jar || new CookieJar(); this.timeoutMs = timeoutMs; this.proxy = proxy; this.bearer = bearer; }
  _hdr(extra = {}) { return { 'User-Agent': UA, 'Accept': 'application/json, text/plain, */*', 'Accept-Language': 'en-US,en;q=0.9,id;q=0.8', 'Origin': APP_BASE, 'Referer': APP_BASE + '/', ...extra }; }
  // Server action /swap & /connect skrg butuh Canton Bearer (supa identity token);
  // cookie aja gak cukup (Canton balik "Missing authentication. Use Bearer").
  get _bearerHdr() { const t = typeof this.bearer === 'function' ? this.bearer() : this.bearer; return t ? { 'Authorization': 'Bearer ' + t } : {}; }
  _opts(extra = {}) { return { jar: this.jar, timeoutMs: this.timeoutMs, proxy: this.proxy, ...extra }; }
  async passkeyLoginOptions(email) {
    const r = await request('POST', `${APP_BASE}/api/auth/passkey/login/options`, this._opts({ headers: this._hdr({ 'Referer': APP_BASE + '/login' }), body: JSON.stringify({ email }) }));
    if (r.status !== 200 || !r.json || !r.json.challenge) throw new Error(`login/options status=${r.status} body=${(r.text || '').slice(0, 200)}`);
    return r.json;
  }
  async passkeyLoginVerify({ email, credential, rememberMe = true }) {
    const r = await request('POST', `${APP_BASE}/api/auth/passkey/login/verify`, this._opts({ headers: this._hdr({ 'Referer': APP_BASE + '/login' }), body: JSON.stringify({ email, credential, rememberMe }) }));
    if (r.status !== 200 || !r.json) throw new Error(`login/verify status=${r.status} body=${(r.text || '').slice(0, 200)}`);
    return r.json;
  }
  async loginWithPasskey(pk) {
    const opts = await this.passkeyLoginOptions(pk.email);
    const allowed = (opts.allowCredentials || []).map(c => c.id);
    if (allowed.length && !allowed.includes(pk.credentialId)) throw new Error(`credentialId tidak terdaftar di server. Server expect: ${allowed.join(', ')}`);
    const credential = buildAssertion({ challenge: opts.challenge, rpId: opts.rpId || RP_ID, origin: APP_BASE, credId: pk.credentialId, userHandle: pk.userHandle, privateJwk: pk.privateJwk });
    const verified = await this.passkeyLoginVerify({ email: pk.email, credential, rememberMe: true });
    return { user: verified, options: opts };
  }
  async authMe() {
    const r = await request('GET', `${APP_BASE}/api/auth/me`, this._opts({ headers: this._hdr() }));
    if (r.status === 401) return { authenticated: false };
    if (r.status !== 200) throw new Error(`auth/me status=${r.status}`);
    return { authenticated: true, ...r.json };
  }
  async earnTasks(partyId) {
    const u = `${APP_BASE}/api/earn-hub/tasks` + (partyId ? `?partyId=${encodeURIComponent(partyId)}` : '');
    const r = await request('GET', u, this._opts({ headers: this._hdr({ 'Referer': APP_BASE + '/earn-hub' }) }));
    if (r.status === 401) { const e = new Error('tasks 401'); e.unauthorized = true; throw e; }
    if (r.status !== 200) throw new Error(`tasks status=${r.status}`);
    return r.json;
  }
  async earnStats() {
    // Earn-hub stats: { displayName, totalPoints, activityCount, totalVolume, achievements }
    const r = await request('GET', `${APP_BASE}/api/earn-hub/stats`, this._opts({ headers: this._hdr({ 'Referer': APP_BASE + '/earn-hub' }) }));
    if (r.status === 401) { const e = new Error('stats 401'); e.unauthorized = true; throw e; }
    if (r.status !== 200) throw new Error(`stats status=${r.status}`);
    return r.json;
  }
  async getPrice(symbol) {
    const r = await request('POST', `${APP_BASE}/api/swap`, this._opts({
      headers: this._hdr({ 'Content-Type': 'application/json', 'Referer': APP_BASE + '/swap' }),
      body: JSON.stringify({ op: 'price', symbol: symbol || 'CC-USDCx' }),
    }));
    if (r.status !== 200) return null;
    return (r.json && r.json.data) || null;
  }
  async swapAction(actionId, args, { timeoutMs, _healed } = {}) {
    const doReq = (id) => request('POST', `${APP_BASE}/swap`, this._opts({
      timeoutMs: timeoutMs || this.timeoutMs,
      headers: this._hdr({ 'Accept': 'text/x-component', 'Content-Type': 'text/plain;charset=UTF-8', 'Referer': APP_BASE + '/swap', 'next-action': id, 'next-router-state-tree': SWAP_STATE_TREE, ...this._bearerHdr }),
      body: JSON.stringify(args || []),
    }));
    let r = await doReq(actionId);
    // ── SELF-HEAL: 404 = next-action ID stale (Silvana redeploy harian) → auto
    //    re-discover SEMUA id, lalu retry SEKALI pakai id baru utk action yg sama.
    //    Bikin SEMUA action auto-fetch on-demand — gak ada 404 yg lolos.
    if (r.status === 404 && !_healed && this.partyId) {
      actionIdsVerified = false;
      const name = Object.keys(SWAP.actionIds).find(n => SWAP.actionIds[n] === actionId);
      logDebug(`swapAction 404 → self-heal discover (action=${name || '?'} id=${actionId.slice(0, 10)})`, '');
      const healed = await this._selfHeal(name).catch(() => null);
      if (healed && healed !== actionId) {
        return this.swapAction(healed, args, { timeoutMs, _healed: true });
      }
    }
    if (r.status === 401 || r.status === 403) { const e = new Error(`swapAction ${actionId} status=${r.status}`); e.unauthorized = true; logDebug(`swapAction ${actionId} ${r.status}`, r.text || ''); throw e; }
    if (r.status !== 200) {
      if (r.status === 404) actionIdsVerified = false;
      logDebug(`swapAction ${actionId} ${r.status}`, r.text || '');
      const e = new Error(`swapAction ${actionId} status=${r.status} body=${(r.text || '').slice(0, 160)}`);
      // 404 = action ID stale (Silvana redeploy) → self-heal udah reset actionIdsVerified; tandain
      // RETRYABLE biar loop swap re-discover + ulang, JANGAN stop. 5xx = server sementara → retry juga.
      if (r.status === 404) { e.staleAction = true; e.transient = true; }
      else if (r.status >= 500) e.transient = true;
      throw e;
    }
    return actionResult(r.text || '');
  }
  // Cari id BARU utk action yg 404: re-discover dari bundle (by nama fungsi —
  // reliable, nemu SEMUA termasuk prepareDvpFee). Throttle 15s. Balikin id baru
  // utk `name`.
  async _selfHeal(name) {
    if (Date.now() - lastDiscoverMs >= 15000) {
      lastDiscoverMs = Date.now();
      const res = await this.discoverActionIds().catch(() => null);
      if (res && res.changed && res.changed.length) { saveActionIds(); logActivity(`auto-fetch: ${res.changed.length} ID di-refresh (self-heal)`, COLOR.green); }
    }
    return name ? SWAP.actionIds[name] : null;
  }

  /**
   * Probe mentah 1 next-action (tanpa throw). Balikin status + raw RSC text +
   * value baris "1:" (kalau JSON). Dipakai discoverActionIds buat fingerprint
   * tanpa kehilangan raw text (blob prepareDvpFee ada di baris "2:T...").
   */
  async _probeAction(actionId, args, timeoutMs = 9000) {
    try {
      const r = await request('POST', `${APP_BASE}/swap`, this._opts({
        timeoutMs,
        headers: this._hdr({ 'Accept': 'text/x-component', 'Content-Type': 'text/plain;charset=UTF-8', 'Referer': APP_BASE + '/swap', 'next-action': actionId, 'next-router-state-tree': SWAP_STATE_TREE, ...this._bearerHdr }),
        body: JSON.stringify(args || []),
      }));
      const text = r.text || '';
      const line1 = text.split('\n').find(l => l.startsWith('1:'));
      let val = null;
      if (line1) { try { val = JSON.parse(line1.slice(2)); } catch (_) { } }
      return { status: r.status, text, val };
    } catch (_) { return { status: 0, text: '', val: null }; }
  }

  /**
   * Cek apakah SWAP.actionIds masih current. Probe estimateFee DAN prepareDvpFee
   * (dua-duanya volatile + sering luput dari action_ids.json yg ke-save sebagian).
   * id valid → 200 (walau body error); stale → 404 "Server action not found".
   * Kalau SALAH SATU 404 → anggap stale → trigger discovery (refresh semua).
   */
  async validateActionIds(partyId) {
    if (!partyId) return false;
    const a = await this._probeAction(SWAP.actionIds.estimateFee, [partyId]);
    if (a.status !== 200) return false;
    const b = await this._probeAction(SWAP.actionIds.prepareDvpFee, [partyId]);
    if (b.status === 404) return false; // prepareDvpFee stale → discover ulang
    return true;
  }

  /**
   * Auto-discover next-action IDs dari bundle JS Silvana, FINGERPRINT-BASED.
   *
   * Silvana redeploy ~harian → hash next-action berubah + urutan bundle acak,
   * JADI mapping by-order (fetch_id.js lama) tidak reliable. Tapi nama RPC di
   * pesan error server STABIL antar-deploy. Strategi:
   *   1. Scan semua chunk /_next → kumpulkan kandidat ID 0x40/0x60.
   *   2. Probe tiap kandidat dgn [partyId], cocokkan signature (nama RPC/shape).
   *   3. prepareDvpFee + getConsumedHoldings balik null ke probe [partyId] →
   *      pass-2: probe pakai proposalId asli dari listProposals; prepareDvpFee
   *      balik blob fee-context (CgMyL / baris "2:T"), getConsumedHoldings balik
   *      {consumedAmuletCids}.
   * Mutasi SWAP.actionIds in-place. Tidak butuh urutan bundle sama sekali.
   *
   * @param {string} partyId
   * @returns {{ok:boolean, changed:string[], found:string[], missing:string[]}}
   */
  // Scan bundle JS /swap → daftar kandidat next-action ID (0x40/0x60). Fetch chunk
  // PARALEL (8 sekaligus). Dipakai discoverActionIds + discoverActionByProbe.
  async _scanSwapBundleIds() {
    const page = await request('GET', `${APP_BASE}/swap`, this._opts({
      headers: this._hdr({ 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8', 'Referer': APP_BASE + '/' }),
    }));
    const html = page.text || '';
    const chunkUrls = new Set();
    let m;
    const reChunk = /\/_next\/static\/chunks\/[^"' \n\r]+\.js/g;
    while ((m = reChunk.exec(html)) !== null) chunkUrls.add(m[0]);
    const buildMatch = html.match(/"buildId"\s*:\s*"([^"]+)"/);
    if (buildMatch) {
      try {
        const bm = await request('GET', `${APP_BASE}/_next/static/${buildMatch[1]}/_buildManifest.js`, this._opts({ timeoutMs: 8000 }));
        for (const cc of ((bm.text || '').match(/static\/chunks\/[^"'\\]+\.js/g) || [])) chunkUrls.add('/_next/' + cc);
      } catch (_) { }
    }
    const ids = [], seen = new Set();
    const chunkTexts = await mapLimit([...chunkUrls], 8, url =>
      request('GET', `${APP_BASE}${url}`, this._opts({ headers: this._hdr({ 'Referer': APP_BASE + '/swap' }), timeoutMs: 12000 }))
        .then(r => r.status === 200 ? (r.text || '') : '').catch(() => ''));
    for (const txt of chunkTexts) {
      const re = /["']([46][0-9a-f]{41})["']/g;
      while ((m = re.exec(txt)) !== null) { if (!seen.has(m[1])) { seen.add(m[1]); ids.push(m[1]); } }
    }
    return ids;
  }

  /**
   * Cari 1 action yg balik BLOB factory ("CgMyL"/"2:T") buat body tertentu.
   * Dipakai discover prepareDvpFee just-in-time (body butuh proposalId ASLI yg
   * cuma ada saat swap) tanpa bergantung listProposals (yg udah mati). Skip id
   * yg udah kepetakan biar gak salah ambil. Balikin id atau null.
   * @param {Array} probeBody  body persis yg mau dikirim (mis. dvpFee args)
   * @param {Set<string>} skipIds  id yg udah dipakai action lain
   */
  async discoverActionByProbe(probeBody, isMatch, skipIds = new Set()) {
    const ids = await this._scanSwapBundleIds();
    const cands = await mapLimit(ids.filter(id => !skipIds.has(id)), 6, id => this._probeAction(id, probeBody).then(r => ({ id, r })));
    for (const c of cands) { if (c && c.r && isMatch(c.r)) return c.id; }
    return null;
  }
  // prepareDvpFee/prepareTransfer balik BLOB factory ("CgMyL"/"2:T").
  static _isBlob(r) { return /CgMyL/.test(r.text) || /^2:T/m.test(r.text); }
  // getAllocFactory balik {success, factory:{factoryId, choiceContext}}.
  static _isAllocFactory(r) { return !!(r.val && r.val.factory && r.val.factory.factoryId); }

  async discoverActionIds() {
    // Parse bundle JS: createServerReference)("<id>", x.callServer, void 0,
    // x.findSourceMapURL, "<functionName>") → map NAMA FUNGSI (stabil antar-
    // redeploy) ke action id. Cara yg BENAR — bundle expose id↔nama langsung.
    // GAK perlu probe / proposal / blob / auth. Tiap redeploy nama tetap, hash
    // ganti → regex nemu hash baru. (Metode dari bot temen, terbukti 20 SA.)
    // Scan bundle /swap DAN /terminal — submitOrder/cancelOrder/submitPreconfirmation
    // cuma di chunk /terminal (gak ke-list di page /swap). Union chunkUrls dua page
    // → semua ACTION_NAME (swap + terminal) ke-resolve. _buildManifest app-wide biasanya
    // sudah nyakup terminal, tapi fetch /terminal jaga-jaga.
    const chunkUrls = new Set();
    let m;
    const reChunk = /\/_next\/static\/chunks\/[a-f0-9]+\.js/g;
    for (const path of ['/swap', '/terminal']) {
      const page = await request('GET', `${APP_BASE}${path}`, this._opts({ headers: this._hdr({ 'Accept': 'text/html,*/*;q=0.8', 'Referer': APP_BASE + '/' }) })).catch(() => ({ text: '' }));
      const html = page.text || '';
      while ((m = reChunk.exec(html)) !== null) chunkUrls.add(m[0]);
      const bm = html.match(/"buildId"\s*:\s*"([^"]+)"/);
      if (bm) { try { const b = await request('GET', `${APP_BASE}/_next/static/${bm[1]}/_buildManifest.js`, this._opts({ timeoutMs: 8000 })); for (const cc of ((b.text || '').match(/static\/chunks\/[a-f0-9]+\.js/g) || [])) chunkUrls.add('/_next/' + cc); } catch (_) { } }
    }
    const texts = await mapLimit([...chunkUrls], 8, url => request('GET', `${APP_BASE}${url}`, this._opts({ headers: this._hdr({ 'Referer': APP_BASE + '/swap' }), timeoutMs: 12000 })).then(r => r.status === 200 ? (r.text || '') : '').catch(() => ''));
    const name2id = {};
    const reSA = /createServerReference\)\("([0-9a-f]{42})",\s*\w+\.callServer,\s*void\s*0,\s*\w+\.findSourceMapURL,\s*"([a-zA-Z]+)"/g;
    for (const t of texts) { let mm; while ((mm = reSA.exec(t)) !== null) name2id[mm[2]] = mm[1]; }

    const changed = [], found = [], missing = [];
    for (const [key, fn] of Object.entries(ACTION_NAME)) {
      const id = name2id[fn];
      if (id) { found.push(key); if (SWAP.actionIds[key] !== id) { SWAP.actionIds[key] = id; changed.push(key); } }
      else missing.push(key);
    }
    const critical = ['estimateFee', 'acceptQuote', 'recordEvent', 'pollProposal', 'getMultiCall', 'prepareDvpFee', 'prepareTransfer'];
    const missingCritical = critical.filter(k => !name2id[ACTION_NAME[k]]);
    const ok = missingCritical.length === 0;
    if (!ok) logDebug(`discoverActionIds INCOMPLETE — missing ${missingCritical.join(',')} | bundle SA: ${Object.keys(name2id).join(',')}`, '');
    return { ok, changed, found, missing, missingCritical };
  }

  /**
   * Recover party + userServiceCid dari on-chain UserService.
   * BUKAN server action /connect lagi (itu udah mati) — sekarang REST endpoint
   * stabil: GET /api/parties/{partyId} → {success, party:{userServiceCid,...}}.
   * Auth cookie (jar). Tahan redeploy (gak ada hash next-action).
   */
  async recoverParty(partyId) {
    if (!partyId) throw new Error('partyId required');
    const r = await request('GET', `${APP_BASE}/api/parties/${encodeURIComponent(partyId)}`, this._opts({
      headers: this._hdr({ 'Accept': '*/*', 'Referer': APP_BASE + '/connect?returnTo=/swap', ...this._bearerHdr }),
    }));
    if (r.status === 401 || r.status === 403) { const e = new Error(`parties status=${r.status}`); e.unauthorized = true; throw e; }
    if (r.status !== 200) throw new Error(`parties status=${r.status} body=${(r.text || '').slice(0, 160)}`);
    let j = r.json; if (!j) { try { j = JSON.parse(r.text); } catch (_) { } }
    if (j && j.success && j.party && j.party.userServiceCid) return j.party;
    return null;
  }

  /**
   * List settlement proposals (V2) lewat REST GET /api/settlement-proposals.
   * Pengganti server action listProposals yg udah mati. Cookie auth, stabil
   * (gak ada hash). Balikin array proposal {proposalId, buyer, seller, status,
   * createdAt, ...}.
   */
  async listSettlementProposals() {
    const r = await request('GET', `${APP_BASE}/api/settlement-proposals`, this._opts({
      headers: this._hdr({ 'Accept': '*/*', 'Referer': APP_BASE + '/swap', ...this._bearerHdr }),
    }));
    if (r.status !== 200) return [];
    let j = r.json; if (!j) { try { j = JSON.parse(r.text); } catch (_) { } }
    return (j && Array.isArray(j.proposals)) ? j.proposals : [];
  }

  /**
   * Batalin settlement nyangkut (V2). cancelSettlementAction id dari bundle
   * (discoverActionIds). Lewat /swap (swapAction, ada self-heal 404). Body:
   * {proposalId, partyId, reason} -> {success:true}.
   */
  async cancelSettlement(proposalId, partyId, reason = 'Cancelled by user') {
    return this.swapAction(SWAP.actionIds.cancelSettlement, [{ proposalId, partyId, reason }]).catch(e => ({ _err: (e && e.message) || String(e) }));
  }

  // ── TERMINAL (CLOB, mode 8) ── lewat /swap swapAction (self-heal 404). submitOrder
  // terbukti live (probe): Referer /swap OK utk action terminal (id yg nentuin route).
  async submitOrder(payload) {
    // payload: {partyId, marketId, orderType:'buy'|'sell', price, quantity, timeInForce, requirements?, onlyLiquidityProviders?, expiresAt?}
    return this.swapAction(SWAP.actionIds.submitOrder, [payload]);
  }
  async cancelOrder(orderId, partyId) {
    return this.swapAction(SWAP.actionIds.cancelOrder, [{ orderId, partyId }]).catch(e => ({ _err: (e && e.message) || String(e) }));
  }
  // Setuju settlement (terminal). Pengganti recordEvent-preconfirmation → trigger LP/orderbook
  // majuin proposal ke stage DvpProposal (dvpProposalCid muncul).
  async submitPreconfirmation(proposalId, partyId, accept = true) {
    return this.swapAction(SWAP.actionIds.submitPreconfirmation, [{ proposalId, settlementId: proposalId, partyId, accept }]);
  }
  // consumedAmuletCids buat exclude CC UTXO yg lagi dipakai fee transfer settlement lain
  // (anti "Waiting for an unlocked CC balance" pas split multi-settlement).
  async settlementHistory(proposalId, partyId) {
    return this.swapAction(SWAP.actionIds.getSettlementHistory, [{ proposalId, partyId }]).catch(() => null);
  }
  // Proposal(s) hasil 1 order (>1 kalau split ke banyak maker). REST, cookie+Bearer.
  async proposalsByOrderId(partyId, orderId) {
    const u = `${APP_BASE}/api/settlement-proposals?partyId=${encodeURIComponent(partyId)}&orderId=${encodeURIComponent(orderId)}&includeClosed=1`;
    const r = await request('GET', u, this._opts({ headers: this._hdr({ 'Accept': '*/*', 'Referer': APP_BASE + '/terminal', ...this._bearerHdr }) }));
    if (r.status !== 200) return [];
    let j = r.json; if (!j) { try { j = JSON.parse(r.text); } catch (_) { } }
    return (j && Array.isArray(j.proposals)) ? j.proposals : [];
  }

  async rfqStream({ partyId, marketId, direction, quantity }, { timeoutMs } = {}) {
    const r = await request('POST', `${APP_BASE}/api/rfq/stream`, this._opts({
      timeoutMs: timeoutMs || this.timeoutMs,
      headers: this._hdr({ 'Accept': '*/*', 'Content-Type': 'application/json', 'Referer': APP_BASE + '/swap' }),
      body: JSON.stringify({ partyId, marketId, direction, quantity }),
    }));
    if (r.status !== 200) throw new Error(`rfq/stream status=${r.status} body=${(r.text || '').slice(0, 160)}`);
    const out = { rfqId: null, quotes: [], rejections: [], done: false };
    for (const blk of (r.text || '').split(/\n\n+/)) {
      const ev = (blk.match(/^event:\s*(.+)$/m) || [])[1];
      const dataLine = (blk.match(/^data:\s*(.+)$/m) || [])[1];
      if (!ev || !dataLine) continue;
      let data; try { data = JSON.parse(dataLine); } catch (_) { continue; }
      if (ev === 'initiated') out.rfqId = data.rfqId;
      else if (ev === 'quote') out.quotes.push(data);
      else if (ev === 'rejection') out.rejections.push(data);
      else if (ev === 'done') out.done = true;
    }
    return out;
  }
}

// ============================================================================
//  Session store (session.json) — per-akun: passkey, userServiceCid, cookie, privy
// ============================================================================
function loadStore() { return loadJSON(SESS_PATH, {}); }
function saveStore(d) { saveJSON(SESS_PATH, d); }
function acctSession(email) { return loadStore()[email] || {}; }
function patchAcctSession(email, patch) { const s = loadStore(); s[email] = { ...(s[email] || {}), ...patch }; saveStore(s); return s[email]; }
function getPasskey(email) { return acctSession(email).passkey || null; }
function getUserServiceCid(email) { return acctSession(email).userServiceCid || null; }
// Haircut mode 8 = FIXED (M8.haircut, default 0.1%) — terminal fee tetap (maker 0.1%),
// gak ada learning adaptif lagi. getEdelCethReduce/setEdelCethReduce DIHAPUS.
// Modal round-trip mode 8 (anchor EDELx): USD-value EDELx yg dikeluarin pas BUKA posisi
// (leg EDELx→cETH). Dipakai net gate — pas TUTUP (cETH→EDELx) cek EDELx yg balik >= modal + minNetUsd.
// null kalau belum ada posisi (cold-start / orphan cETH) → caller dump bootstrap tanpa gate.
function getEdelCethRoundUsd(email) {
  const v = Number(acctSession(email).edelCethRoundUsd);
  return (v > 0) ? v : null;
}
function setEdelCethRoundUsd(email, usd) {
  if (!(Number(usd) > 0)) return;
  patchAcctSession(email, { edelCethRoundUsd: Number(usd) });
}
// Anchor QTY EDELx round-trip: EDELx yg BENERAN keluar pas BUKA (EDELx→cETH). Dipakai
// pas TUTUP (cETH→EDELx) buat hitung loss = modal − balik (nangkep spread+fee+haircut).
function getEdelCethRoundEdelx(email) {
  const v = Number(acctSession(email).edelCethRoundEdelx);
  return (v > 0) ? v : null;
}
function setEdelCethRoundEdelx(email, qty) {
  patchAcctSession(email, { edelCethRoundEdelx: Number(qty) > 0 ? Number(qty) : 0 });
}
function loadCookies(email) { return acctSession(email).silvanaCookies || {}; }
function saveCookies(email, obj) { const c = { ...obj }; delete c.geo_status; patchAcctSession(email, { silvanaCookies: c }); }
function silvanaAccessExpMs(email) {
  const c = loadCookies(email);
  const tok = c.access_token; if (!tok) return 0;
  return decodeJwtExp(tok);
}

function decodeJwtExp(jwt) {
  try { const j = JSON.parse(Buffer.from(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); return j.exp ? j.exp * 1000 : 0; } catch (_) { return 0; }
}
function getValidPrivySession(email) {
  const s = acctSession(email).privy;
  if (!s || !s.privy_access_token || !s.token) return null;
  let expMs = s.expMs || decodeJwtExp(s.privy_access_token);
  let idExp = s.identityExpMs || decodeJwtExp(s.token);
  const exps = [expMs, idExp].filter(x => x > 0);
  const minExp = exps.length ? Math.min(...exps) : 0;
  // Refresh 10 menit sebelum benar-benar expired (1 iterasi swap bisa ~7 menit,
  // jadi token harus dijamin hidup sepanjang iterasi).
  const SAFETY_MS = 600_000;
  if (Date.now() + SAFETY_MS >= minExp) return null;
  return s;
}
function putPrivySession(email, payload) {
  const prev = acctSession(email).privy || {};
  const newToken = (payload.token === null) ? null : (payload.token || prev.token);
  const privy = {
    privy_access_token: payload.privy_access_token,
    token: newToken,
    refresh_token: payload.refresh_token || prev.refresh_token,
    expMs: decodeJwtExp(payload.privy_access_token),
    identityExpMs: newToken ? decodeJwtExp(newToken) : null,
    privyUserId: (payload.user && payload.user.id) || prev.privyUserId,
    savedAt: Date.now(),
  };
  patchAcctSession(email, { privy });
  return privy;
}

// ============================================================================
//  Privy OTP login / refresh
// ============================================================================
const privyHeaders = () => ({
  'User-Agent': UA, 'Accept': 'application/json', 'Origin': APP_BASE, 'Referer': APP_BASE + '/',
  'privy-app-id': PRIVY_APP_ID, 'privy-ca-id': PRIVY_CA_ID, 'privy-client': PW_SDK, 'privy-client-id': PRIVY_CLIENT_ID,
});
async function privyInit(email, proxy) {
  const r = await request('POST', `${PRIVY_BASE}/api/v1/passwordless/init`, { headers: privyHeaders(), body: JSON.stringify({ email }), timeoutMs: REQ.timeoutMs, proxy });
  if (r.status === 429) { const e = new Error('init OTP rate-limited (429). Tunggu ~5 menit.'); e.rateLimit = true; throw e; }
  if (r.status !== 200 || !r.json || r.json.success !== true) throw new Error(`init OTP status=${r.status} body=${(r.text || '').slice(0, 200)}`);
  return true;
}
async function privyAuthenticate(email, code, proxy) {
  const r = await request('POST', `${PRIVY_BASE}/api/v1/passwordless/authenticate`, { headers: privyHeaders(), body: JSON.stringify({ email, code, mode: 'login-or-sign-up' }), timeoutMs: REQ.timeoutMs, proxy });
  if (r.status !== 200 || !r.json || !r.json.privy_access_token) throw new Error(`authenticate status=${r.status} body=${(r.text || '').slice(0, 200)}`);
  return r.json;
}
async function privyRefreshSession(refreshToken, accessToken, proxy) {
  const r = await request('POST', `${PRIVY_BASE}/api/v1/sessions`, {
    headers: { ...privyHeaders(), ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}) },
    body: JSON.stringify({ refresh_token: refreshToken }), timeoutMs: REQ.timeoutMs, proxy,
  });
  if (r.status !== 200 || !r.json || !r.json.privy_access_token) {
    const action = r.json && r.json.session_update_action;
    const err = new Error(`session refresh status=${r.status} action=${action || '-'}`);
    if (r.status === 400 || r.status === 401) err.unauthorized = true;
    if (action === 'clear' || (r.status === 200 && !(r.json && r.json.privy_access_token))) err.notRefreshable = true;
    throw err;
  }
  return r.json;
}

// Serialize OTP prompt secara GLOBAL. Banyak akun bisa butuh OTP barengan
// (tickAll/keepAlive paralel), tapi stdin cuma satu → readline tabrakan & prompt
// numpuk. Lock bikin init+prompt OTP antri 1-per-1 di manapun dipanggil.
let _otpChain = Promise.resolve();
function withOtpLock(fn) {
  const result = _otpChain.then(fn, fn);
  _otpChain = result.then(() => { }, () => { });
  return result;
}

// terminal prompt (OTP manual). SATU readline singleton dipakai ulang via
// rl.question — JANGAN create/close interface tiap prompt. Create/close berulang
// di process.stdin ninggalin buffer → interface berikut emit 'line' kosong instan
// → prompt cascade (keliatan parallel). Singleton + mutex = 1 prompt sungguhan.
let _rl = null;
function getRL() {
  if (!_rl) {
    _rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    _rl.on('close', () => { _rl = null; });
  }
  return _rl;
}
function prompt(question) {
  return new Promise((resolve) => {
    global.__paused = true;
    navPause();                                   // matiin raw nav biar readline cooked (OTP/menu)
    if (useColor) process.stdout.write('\x1b[?25h');
    getRL().question('\n\n' + question, (ans) => {
      global.__paused = false;
      navResume();                                // balikin raw nav setelah input selesai
      resolve((ans || '').trim());
    });
  });
}

// ── Navigasi keyboard dashboard (panah ↑/↓ pindah view log per-akun) ──────────
// Raw mode stdin → tangkap keypress tanpa Enter. selView 0=SYSTEM, 1..N=akun.
// Ctrl+C di raw mode TIDAK jadi SIGINT → handle manual di sini.
let _navOn = false;
function navPause() { try { if (_navOn && process.stdin.isTTY && process.stdin.setRawMode) process.stdin.setRawMode(false); } catch (_) { } }
function navResume() { try { if (_navOn && process.stdin.isTTY && process.stdin.setRawMode) process.stdin.setRawMode(true); } catch (_) { } }
function setupKeyNav() {
  if (_navOn || !process.stdin.isTTY) return;
  try {
    readline.emitKeypressEvents(process.stdin);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    _navOn = true;
  } catch (_) { return; }
  process.stdin.on('keypress', (str, key) => {
    if (!key) return;
    if (key.ctrl && key.name === 'c') { process.stdout.write('\n' + paint('bye 👋', COLOR.gray) + '\n'); process.exit(0); }
    if (global.__paused) return;                  // OTP/menu prompt aktif → jangan ganggu
    const n = (global.__states || []).length;
    if (n <= 0) return;
    if (key.name === 'up') { selView = (selView - 1 + (n + 1)) % (n + 1); scheduleRender(); }
    else if (key.name === 'down') { selView = (selView + 1) % (n + 1); scheduleRender(); }
  });
}

// Pastikan ada identity token Privy yang valid utk akun (refresh / OTP bila perlu).
// Disimpan di session.json[email].privy. OTP dikirim ke privyEmail.
async function ensurePrivyToken(state) {
  const email = state.email;
  const privyEmail = state.privyEmail || email;
  const proxy = getProxy(email);
  state.proxyHost = proxy ? `${proxy.host}:${proxy.port}` : null;

  const cached = getValidPrivySession(email);
  if (cached) { state.tokenExpMs = cached.expMs; state.identityExpMs = cached.identityExpMs; return cached.token; }

  const old = acctSession(email).privy;
  if (old && old.refresh_token) {
    const maxRetry = 20, baseDelay = 2000; let lastErr = null;
    // 401/400 (unauthorized) bisa transient (proxy/Privy hiccup) — retry beberapa
    // kali sebelum nyerah ke OTP. Cuma 'notRefreshable' (sesi di-clear) yg final.
    const MAX_UNAUTH = 4; let unauthCount = 0;
    let curProxy = proxy;
    for (let attempt = 1; attempt <= maxRetry; attempt++) {
      state.status = 'login'; state.message = `refresh privy (${attempt}/${maxRetry})`; render(global.__states);
      try {
        const fresh = await privyRefreshSession(old.refresh_token, old.privy_access_token, curProxy);
        const sess = putPrivySession(email, { ...fresh, token: fresh.token || old.token, refresh_token: fresh.refresh_token || old.refresh_token });
        state.tokenExpMs = sess.expMs; state.identityExpMs = sess.identityExpMs; state.message = '';
        return sess.token;
      } catch (e) {
        lastErr = e;
        if (e && e.notRefreshable) break; // sesi di-clear server → OTP wajib
        if (e && e.unauthorized) {
          if (++unauthCount >= MAX_UNAUTH) break; // 401 persisten → refresh mati → OTP
          curProxy = rotateProxy(email); // IP baru, mungkin 401 gara2 IP
          state.proxyHost = curProxy ? `${curProxy.host}:${curProxy.port}` : null;
          state.message = `refresh 401 → retry (${unauthCount}/${MAX_UNAUTH})`; render(global.__states);
        } else if (isProxyErr(e)) {
          curProxy = rotateProxy(email); // exit node mati (502/timeout) → ganti IP
          state.proxyHost = curProxy ? `${curProxy.host}:${curProxy.port}` : null;
          state.message = `proxy mati → ganti IP`; render(global.__states);
        }
        if (attempt < maxRetry) { await sleep(Math.min(30_000, baseDelay * Math.min(8, attempt))); }
      }
    }
    if (lastErr) { state.message = `refresh gagal: ${(lastErr.message || '').slice(0, 40)}`; render(global.__states); }
  }

  // OTP manual (IMAP dihapus) — serialize global biar prompt gak tabrakan paralel.
  return await withOtpLock(async () => {
    // Re-cek cache: bisa jadi sesi keisi sementara nunggu giliran lock.
    const cachedNow = getValidPrivySession(email);
    if (cachedNow) { state.tokenExpMs = cachedNow.expMs; state.identityExpMs = cachedNow.identityExpMs; return cachedNow.token; }
    state.status = 'login'; state.message = 'kirim OTP'; render(global.__states);
    // init OTP: 429 = rate-limit per IP. Rotate proxy (IP baru) & coba lagi.
    // PENTING: panggil privyInit LANGSUNG (jangan withRetry) — withRetry bungkus
    // error jadi Error baru & buang flag .rateLimit, bikin rotate gak pernah jalan.
    let initProxy = proxy;
    const MAX_ROT = Math.min(PROXIES.length || 1, 8);
    let transientLeft = REQ.retry || 2;
    for (let rot = 0; ; rot++) {
      try {
        await privyInit(privyEmail, initProxy);
        break;
      } catch (e) {
        if (e && e.rateLimit) {
          if (rot >= MAX_ROT - 1) throw e; // semua proxy kena limit → nyerah
          initProxy = rotateProxy(email);
          state.proxyHost = initProxy ? `${initProxy.host}:${initProxy.port}` : null;
          state.message = `429 → ganti proxy #${rot + 1}`; render(global.__states);
          continue;
        }
        if (isProxyErr(e)) { // exit node mati → ganti IP (jangan retry proxy sama)
          if (rot >= MAX_ROT - 1) throw e;
          initProxy = rotateProxy(email);
          state.proxyHost = initProxy ? `${initProxy.host}:${initProxy.port}` : null;
          state.message = `proxy mati → ganti IP #${rot + 1}`; render(global.__states);
          continue;
        }
        // error transient (network non-proxy) → retry proxy sama beberapa kali
        if (transientLeft-- > 0) { await sleep(REQ.retryDelayMs || 2000); rot--; continue; }
        throw e;
      }
    }
    let code;
    for (; ;) {
      code = await prompt(`OTP Privy untuk ${privyEmail} (4-8 digit): `);
      if (/^\d{4,8}$/.test(code)) break;
      process.stdout.write(paint('  format OTP salah, ulangi\n', COLOR.yellow));
    }
    const auth = await withRetry(() => privyAuthenticate(privyEmail, code, initProxy), 'authenticate', { retry: REQ.retry, delayMs: REQ.retryDelayMs });
    const sess = putPrivySession(email, auth);
    state.tokenExpMs = sess.expMs; state.identityExpMs = sess.identityExpMs; state.message = '';
    return sess.token;
  });
}

// Pastikan sesi Silvana (cookie) hidup; re-login passkey (dari session.json) bila perlu.
async function ensureSilvanaSession(state) {
  const email = state.email;
  const pk = getPasskey(email);
  if (!pk) return null;
  const proxy = getProxy(email);
  const _rawCookies = loadCookies(email);
  delete _rawCookies.geo_status; // never send geo_status=blocked — let server re-eval based on current IP
  const jar = new CookieJar(_rawCookies);
  let curProxy = proxy;
  let client = new SilvanaClient({ jar, timeoutMs: REQ.timeoutMs, proxy: curProxy });
  // Re-login silvana proaktif kalau sisa < 15 menit (margin lebar biar gak pernah
  // expired antar-sesi). authMe TIDAK nge-extend token; cuma re-login yg nge-renew,
  // jadi margin harus > interval keep-alive.
  const SAFETY_MS = 900_000;
  const exp = silvanaAccessExpMs(email);
  const stillFresh = exp && (exp - Date.now() > SAFETY_MS);
  if (stillFresh) {
    // authMe bisa flake (network/proxy) — retry transient dikit sebelum re-login.
    for (let i = 0; i < 3; i++) {
      try {
        const me = await client.authMe();
        if (me.authenticated && me.user) { state.silvanaUser = me.user.email || me.user.firstName || 'ok'; saveCookies(email, jar.toObject()); state.silvanaExpMs = silvanaAccessExpMs(email); return client; }
        break; // ke-auth tapi gak authenticated → token mati, lanjut re-login
      } catch (e) {
        if (i < 2) {
          if (isProxyErr(e)) { curProxy = rotateProxy(email); state.proxyHost = curProxy ? `${curProxy.host}:${curProxy.port}` : null; client = new SilvanaClient({ jar, timeoutMs: REQ.timeoutMs, proxy: curProxy }); }
          await sleep(REQ.retryDelayMs || 2000);
        }
      }
    }
  }
  // Re-login passkey: retry banyak + rotate proxy tiap gagal (transient/IP block).
  const privateJwk = (typeof pk.privateJwk === 'string') ? JSON.parse(pk.privateJwk) : pk.privateJwk;
  const MAX_LOGIN = 6; let lastErr = null;
  for (let attempt = 1; attempt <= MAX_LOGIN; attempt++) {
    state.status = 'login'; state.message = `silvana re-login passkey (${attempt}/${MAX_LOGIN})`; render(global.__states);
    jar.clear();
    try {
      const result = await client.loginWithPasskey({ email, credentialId: pk.credentialId, userHandle: pk.userHandle, privateJwk });
      state.silvanaUser = (result.user && (result.user.email || result.user.firstName)) || 'ok';
      saveCookies(email, jar.toObject());
      state.silvanaExpMs = silvanaAccessExpMs(email);
      state.message = '';
      return client;
    } catch (e) {
      lastErr = e;
      if (attempt < MAX_LOGIN) {
        curProxy = rotateProxy(email);
        state.proxyHost = curProxy ? `${curProxy.host}:${curProxy.port}` : null;
        client = new SilvanaClient({ jar, timeoutMs: REQ.timeoutMs, proxy: curProxy });
        await sleep(REQ.retryDelayMs || 2000);
      }
    }
  }
  throw new Error(`silvana login gagal: ${(lastErr && lastErr.message) || lastErr}`);
}

// ============================================================================
//  Swap atomik (1 swap: RFQ → accept → prepare → sign → submit)
// ============================================================================
function findDvpProposal(contracts, proposalId) {
  for (const c of contracts) {
    const t = c.createArgument && c.createArgument.terms;
    if (t && t.id === proposalId) { const ca = c.createArgument; return { cid: c.contractId, terms: t, executor: ca.operator, proposer: ca.proposer, counterparty: ca.counterparty, proposerIsBuyer: ca.proposerIsBuyer }; }
  }
  return null;
}
function selectCcHoldings(amulets, needDecStr) {
  const items = amulets.map(c => { const a = c.createArgument && c.createArgument.amount; return { cid: c.contractId, amt: a ? Number(a.initialAmount || a.amount || 0) : 0 }; }).sort((x, y) => y.amt - x.amt);
  const need = Number(needDecStr); const out = []; let sum = 0;
  for (const it of items) { out.push(it.cid); sum += it.amt; if (sum >= need) break; }
  if (!out.length) throw new Error('tidak ada holding CC (Amulet)');
  return out;
}

async function swapOnce(ctx, direction, quantityCC) {
  let { sv, privy, canton, partyId, userServiceCid, log = () => { }, shouldContinue, onWait } = ctx;
  if (!userServiceCid) throw new Error('userServiceCid belum ada — auto-discovery gagal, cek koneksi/passkey');
  // Pair-leg config: token↔token (mode 8) jalan PARALLEL x-akun tapi SWAP global di-share
  // → race (akun A set tokenId=EDELX, akun B timpa CETH → salah holdings). Jadi mode 8 pass
  // leg lewat ctx.leg (per-call, gak ke-share). Opsi 0/1 gak pass → fallback SWAP (aman,
  // semua akun pair sama). Field: market/baseIsCC/tokenToToken/tokenId/tokenLabel/tokenAdmin.
  const L = ctx.leg || {};
  const A = SWAP.actionIds, amount = String(quantityCC), dso = SWAP.dsoPartyId;
  // Batas fee per-call: ctx.maxFeeCC override (mode 8 malam → Infinity buat trabas). Mode
  // lain gak pass → fallback SWAP.maxFeeCC (perilaku lama, gak berubah).
  const feeCap = ctx.maxFeeCC != null ? Number(ctx.maxFeeCC) : Number(SWAP.maxFeeCC);
  const market = L.market || SWAP.market;
  const legBaseIsCC = L.baseIsCC != null ? L.baseIsCC : SWAP.baseIsCC;
  const legTokenToToken = L.tokenToToken != null ? L.tokenToToken : SWAP.tokenToToken;
  const legTokenId = L.tokenId || SWAP.tokenId;
  const legTokenLabel = L.tokenLabel || SWAP.tokenLabel;
  const legTokenAdmin = L.tokenAdmin || SWAP.tokenAdmin;
  const role = direction === 'sell' ? 'seller' : 'buyer';
  const dirID = direction === 'sell' ? 'jual CC' : 'beli CC';

  const price = await sv.getPrice(market).catch(() => null);
  // getPrice = quote-per-base. USDCx (base CC): USDCx/CC. cETH (base cETH): CC/cETH.
  // estimateFee `price` butuh "token per CC" → USDCx pakai apa adanya; cETH INVERT
  // (1/getPrice) krn base/quote kebalik. (HAR cc-eth: getPrice ask≈10332, est price≈0.0000967.)
  let px = '0';
  if (price) {
    const raw = Number(direction === 'sell' ? price.bid : price.ask);
    px = String(legBaseIsCC ? raw : (raw > 0 ? 1 / raw : 0));
  }
  // FEE PROTECTION (early gate): cek estimasi fee SEBELUM bikin proposal on-chain.
  // Kalau fee > maxFeeCC, batal di sini — gak ada DvpProposal nyangkut.
  const feeEst = await sv.swapAction(A.estimateFee, [{ partyId, marketId: market, baseQuantity: amount, price: px }]).catch(() => null);
  const estFeeCC = extractFeeCC(feeEst);
  if (estFeeCC != null) {
    log(`Estimasi fee ${dirID}: ${estFeeCC} CC (batas ${feeCap})`);
    if (estFeeCC > feeCap && !ctx.dryRun) {
      logDebug('fee spike (estimateFee) — abort sebelum proposal', { estFeeCC, max: feeCap, feeEst });
      const e = new Error(`fee ${estFeeCC} CC > batas ${feeCap} CC`);
      e.feeSpike = true; e.feeCC = estFeeCC;
      throw e;
    }
  } else {
    logDebug('estimateFee shape tak dikenal (fee gate andalkan feeCtx)', feeEst);
  }

  let rfq = null;
  const rfqTries = SWAP.rfqMaxTries, rfqDelay = SWAP.rfqRetryMs;
  for (let i = 1; i <= rfqTries; i++) {
    if (shouldContinue && !shouldContinue()) { const e = new Error('dibatalkan'); e.aborted = true; throw e; }
    rfq = await sv.rfqStream({ partyId, marketId: market, direction, quantity: amount }, { timeoutMs: SWAP.quoteTimeoutSec * 1000 }).catch(() => null);
    if (rfq && rfq.quotes.length) break;
    log(`Menunggu harga ${dirID}… (cek tiap ${Math.round(rfqDelay / 1000)}s)`);
    if (i < rfqTries) {
      // Refresh client di tengah wait panjang biar token gak expired (24/7 safe).
      // onWait return client baru kalau token di-refresh; pakai sv/canton terbaru.
      if (onWait) {
        try {
          const fresh = await onWait();
          if (fresh && fresh.sv) { sv = fresh.sv; canton = fresh.canton; privy = fresh.privy; }
        } catch (_) { }
      }
      await sleep(rfqDelay);
    }
  }
  if (!rfq || !rfq.rfqId) throw new Error('koneksi harga gagal');
  if (!rfq.quotes.length) { const e = new Error('likuiditas belum tersedia'); e.noLiquidity = true; throw e; }
  // Pilih quote fee TERMURAH (bisa >1 LP). estimatedTotalFee = angka fee yg
  // ditampilkan web sbg "Est. settlement fee".
  const quote = rfq.quotes.slice().sort((a, b) => {
    const fa = extractFeeCC(a); const fb = extractFeeCC(b);
    return (fa == null ? Infinity : fa) - (fb == null ? Infinity : fb);
  })[0];
  log(`Dapat harga ${dirID} memproses transaksi`);

  // FEE PROTECTION (quote gate): cek fee quote SEBELUM acceptQuote/preconfirmation.
  // Ini SEBELUM proposal dibuat → gak ada DvpProposal nyangkut kalau fee spike.
  const quoteFeeCC = extractFeeCC(quote);
  if (quoteFeeCC != null) {
    log(`Fee quote ${dirID} (${quote.lpName || 'LP'}): ${quoteFeeCC} CC (batas ${feeCap})`);
    if (quoteFeeCC > feeCap && !ctx.dryRun) {
      logDebug('fee spike (quote) — abort sebelum acceptQuote', { quoteFeeCC, max: feeCap, quote });
      const e = new Error(`fee ${quoteFeeCC} CC > batas ${feeCap} CC`);
      e.feeSpike = true; e.feeCC = quoteFeeCC;
      throw e;
    }
  }

  const acc = await sv.swapAction(A.acceptQuote, [{ partyId, rfqId: rfq.rfqId, quoteId: quote.quoteId || quote.id }]);
  if (!acc || !acc.proposalId) throw new Error(`acceptQuote gagal: ${JSON.stringify(acc).slice(0, 120)}`);
  const proposalId = acc.proposalId;

  // recordEvent preconfirmation. PENTING: website SELALU sertakan metadata.holdingsByToken
  // = UTXO token yg kita commit (HAR cc-eth buyer & jual_cc seller: KEDUANYA {CC:[...]}).
  // Tanpa ini LP cETH gak majuin proposal stage 3→5 → poll dvpProposalCid timeout
  // (state stage 3 IDENTIK manual-success, beda cuma holdingsByToken). Open commit CC
  // (terbukti utk USDCx-sell & cETH-buy). Close (commit token) gak ada data HAR → biarin
  // spt semula (USDCx close jalan tanpa holdingsByToken) biar gak regresi.
  const meta = { accept: true, source: 'rfq_accept' };
  if (legTokenToToken) {
    // token↔token (EDELx↔cETH): LP butuh holdingsByToken = { CC:[fee utxo], <tokenKita>:[utxo] }
    // + totalByToken (HAR edel-ceth SELL: {CC:[543..], EDELx:[936..]}). Sertakan CC (fee) +
    // token yg KITA SERAHKAN (SWAP.tokenId di-set per-arah oleh engine ping-pong). Tanpa ini
    // LP gak majuin proposal (sama kayak cETH-buy tanpa CC meta → poll dvpProposalCid timeout).
    try {
      const bal = await supaBalances(ctx.identityToken || canton.token, ctx.proxy || null);
      const toks = (bal && bal.tokens) || [];
      const holdings = {}, totals = {};
      const add = (tk, key) => {
        const utxos = (tk && tk.unlockedUtxos || []).map(u => ({ cid: u.contractId, amount: fmt10(String(u.amount)) })).filter(x => x.cid);
        if (utxos.length) { holdings[key] = utxos; totals[key] = utxos.reduce((s, u) => s + Number(u.amount), 0); }
      };
      add(toks.find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === 'AMULET'), 'CC');
      const myTok = toks.find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === String(legTokenId).toUpperCase());
      if (myTok) add(myTok, (myTok.instrumentId && myTok.instrumentId.id) || legTokenLabel);
      if (Object.keys(holdings).length) { meta.holdingsByToken = holdings; meta.totalByToken = totals; }
    } catch (_) { }
  } else if (direction === SWAP.dirOpen) {
    try {
      const bal = await supaBalances(ctx.identityToken || canton.token, ctx.proxy || null);
      const ccTok = ((bal && bal.tokens) || []).find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === 'AMULET');
      const ccUtxos = (ccTok && ccTok.unlockedUtxos || [])
        .map(u => ({ cid: u.contractId, amount: fmt10(String(u.amount)) }))
        .filter(x => x.cid);
      if (ccUtxos.length) meta.holdingsByToken = { CC: ccUtxos };
    } catch (_) { }
  }
  // preconfirmation = trigger LP majuin proposal stage 3→5. Kalau GAGAL, proposal gak maju
  // → poll dvpProposalCid timeout. JANGAN telan senyap: surface ke panel biar ke-diagnosa.
  const recEvt = await sv.swapAction(A.recordEvent, [{ partyId, recordedByRole: role, eventType: `preconfirmation_${role}`, result: 'success', proposalId, metadata: meta }]).catch(e => ({ _err: (e && e.message) || String(e) }));
  if (recEvt && recEvt._err) log(`⚠ preconfirmation gagal: ${String(recEvt._err).slice(0, 140)} — LP mungkin gak majuin proposal`);

  let dvpCid = null;
  let lastPoll = null;
  for (let i = 0; i < SWAP.pollMaxTries; i++) {
    const st = await sv.swapAction(A.pollProposal, [{ settlementId: proposalId, partyId }]).catch(e => ({ _err: e && e.message }));
    lastPoll = st;
    if (st && typeof st.dvpProposalCid === 'string' && st.dvpProposalCid.startsWith('00')) { dvpCid = st.dvpProposalCid; break; }
    await sleep(SWAP.pollIntervalMs);
  }
  if (!dvpCid) {
    logDebug(`pollProposal final state for ${proposalId}`, lastPoll);
    throw new Error(`poll: dvpProposalCid timeout (last=${JSON.stringify(lastPoll).slice(0, 200)})`);
  }

  const multiCall = await sv.swapAction(A.getMultiCall, ['supa']);
  if (!multiCall || !multiCall.contractId) throw new Error('getMultiCall gagal');

  // Ambil DvpProposal ASLI dari ledger (active_contracts, filter by templateId
  // utility-settlement → cuma ~3 row, JAUH di bawah limit 200). Pakai terms-nya
  // VERBATIM (createdAt/allocateBefore/settleBefore presisi μs, amounts, proposer,
  // operator, proposerIsBuyer). Sintesis +6h/+12h yg lama bikin timestamp meleset
  // ~9s + presisi salah → allocation lock tapi DvP gak pernah match → gak settle.
  let dvp = null;
  let lastCount = 0;
  let lastAcErr = null;
  let unburied = false;
  for (let i = 0; i < SWAP.pollMaxTries; i++) {
    const list = await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(e => { lastAcErr = (e && e.message) || String(e); return []; });
    lastCount = (list || []).length;
    const hit = (list || []).find(c => c.contractId === dvpCid);
    if (hit && hit.createArgument && hit.createArgument.terms) {
      const ca = hit.createArgument;
      dvp = {
        cid: dvpCid,
        terms: ca.terms,                 // createdAt/allocateBefore/settleBefore/deliveries/payments ASLI
        executor: ca.operator,           // orderbook operator dari kontrak
        proposer: ca.proposer,           // LP / lawan kita
        counterparty: ca.counterparty,   // kita
        proposerIsBuyer: ca.proposerIsBuyer,
      };
      break;
    }
    // active_contracts CAP 200 (no pagination). Kalau proposal stale numpuk sampai
    // 200, cid FRESH kita ke-bury di balik yg lama → lookup gagal. DULU solusinya
    // ganti wallet (party baru = 0 proposal). GANTIIN: cleanup SEKALI (archive yg
    // 0-dana/tua >120s → count turun <200 → cid fresh kelihatan). Proposal fresh
    // kita age<120s → DI-SKIP cleanup (aman, gak ke-cancel sendiri).
    if (!unburied && lastCount >= 200) {
      unburied = true;
      log(`${lastCount} DvpProposal (cap supanova) — cid fresh ke-bury, bersihin proposal stale…`);
      const n = await cleanupStaleProposals(sv, canton, partyId, (m) => log(m), privy).catch(() => 0);
      log(`cleanup: ${n} proposal di-archive → cek ledger lagi`);
      continue; // re-fetch langsung tanpa delay
    }
    if (i === 0) log('Menunggu DvpProposal muncul di ledger…');
    await sleep(SWAP.pollIntervalMs);
  }
  if (!dvp) {
    logDebug(`DvpProposal lookup failed`, { proposalId, dvpCid, activeCount: lastCount, activeContractsError: lastAcErr });
    // activeCount:0 + error 401/unauthorized → token canton stale (bukan masalah
    // ledger). Kasih pesan jelas biar gak salah diagnosa.
    const tokenHint = (lastCount === 0 && lastAcErr) ? ` [active_contracts err: ${lastAcErr}]` : '';
    const e = new Error(`DvpProposal tidak ditemukan di ledger (dvpCid=${dvpCid.slice(0, 12)}.., active=${lastCount})${tokenHint}`);
    e.dvpStuck = true; // akun nyangkut (ledger penuh) → skip ke akun berikutnya
    throw e;
  }

  const deliv = dvp.terms.deliveries[0], pay = dvp.terms.payments[0], weAreBuyer = (direction === 'buy');
  const ourLeg = weAreBuyer ? { instrument: pay.instrument, amount: pay.amount, legId: '2' } : { instrument: deliv.instrument, amount: deliv.amount, legId: '1' };
  const receiver = dvp.proposer;
  // PATH ditentukan token YANG KITA SERAHKAN (bukan direction). weProvideCC = leg
  // kita = Amulet (CC) → bayar CC (cETH-buy / USDCx-sell). else → serahkan token
  // (USDCx-buy / cETH-sell). Bikin satu logic jalan utk kedua pair walau orientasi
  // base/quote kebalik. admin/id token diambil dari ourLeg.instrument (dvp terms).
  const weProvideCC = String((ourLeg.instrument && ourLeg.instrument.id) || '') === 'Amulet';

  const amulets = await canton.activeContracts(SWAP.templateIds.amulet);
  // Kalau kita bayar CC: butuh CC sebesar leg + fee. Kalau bayar token: CC cuma utk fee.
  const ccNeed = weProvideCC ? addDp(ourLeg.amount, SWAP.feeBufferCC) : SWAP.feeBufferCC;
  const inputHoldingCids = selectCcHoldings(amulets, ccNeed);

  const dvpFeeArgs = [{ partyId, feeType: 'dvp_contract', role, proposalId, inputHoldingCids }];
  let feeCtx = await sv.swapAction(A.prepareDvpFee, dvpFeeArgs).catch(e => ({ _err: (e && e.message) || String(e) }));
  // JUST-IN-TIME discover: kalau prepareDvpFee stale (404, redeploy) → scan bundle,
  // cari action yg balik blob fee-context buat body INI (proposalId asli udah ada
  // dari acceptQuote) → update SWAP.actionIds.prepareDvpFee → retry. Gak butuh
  // listProposals (mati). Ini bikin auto-fetch prepareDvpFee jalan tiap redeploy.
  if (!feeCtx || feeCtx._err || !feeCtx.choiceContextData) {
    const skip = new Set(Object.values(A).filter(id => id !== A.prepareDvpFee));
    const newId = await sv.discoverActionByProbe(dvpFeeArgs, SilvanaClient._isBlob, skip).catch(() => null);
    if (newId && newId !== A.prepareDvpFee) {
      log(`prepareDvpFee stale → ditemukan ID baru ${newId.slice(0, 10)}… (auto-fetch)`);
      SWAP.actionIds.prepareDvpFee = newId; saveActionIds();
      feeCtx = await sv.swapAction(newId, dvpFeeArgs).catch(e => ({ _err: (e && e.message) || String(e) }));
    }
  }
  if (!feeCtx || feeCtx._err || !feeCtx.choiceContextData) throw new Error(`prepareDvpFee gagal: ${(feeCtx && feeCtx._err) || 'no choiceContextData'}`);

  // FEE PROTECTION (authoritative): feeCtx punya angka fee CC sebenarnya.
  // Batalkan SEBELUM execSettle/prepare/submit → belum ada CC kebayar.
  const realFeeCC = Number(addDp(feeCtx.feeAmountCC || '0', feeCtx.counterpartFeeAmountCC || '0'));
  if (Number.isFinite(realFeeCC)) {
    log(`Fee ${dirID}: ${realFeeCC} CC (batas ${feeCap})`);
    if (realFeeCC > feeCap && !ctx.dryRun) {
      logDebug('fee spike (feeCtx) — abort sebelum submit', { realFeeCC, max: feeCap });
      // PROPOSAL udah dibuat (acceptQuote) tapi BELUM allocate (0 dana ke-lock) →
      // cancel SEKARANG biar gak nyangkut numpuk di ledger (cegah cap-200 → "Menunggu
      // DvpProposal" → ganti wallet). Best-effort, gak gagalin alur abort.
      await sv.cancelSettlement(proposalId, partyId).catch(() => { });
      const e = new Error(`fee ${realFeeCC} CC > batas ${feeCap} CC`);
      e.feeSpike = true; e.feeCC = realFeeCC;
      throw e;
    }
  }

  // DRY-RUN: stop SEBELUM execSettle/submit. Belum ada CC kebayar (cuma proposal
  // nyangkut, auto-expire 12 jam). Laporkan ke-3 angka fee buat verifikasi.
  if (ctx.dryRun) {
    const fees = { estFeeCC, quoteFeeCC, realFeeCC, lp: (quote && quote.lpName) || 'LP' };
    log(`[DRY-RUN] estimateFee=${estFeeCC} | quote(${fees.lp})=${quoteFeeCC} | feeCtx REAL=${realFeeCC} | batas=${feeCap}`);
    const e = new Error('dry-run: stop sebelum submit (0 CC kebayar)');
    e.dryRun = true; e.fees = fees;
    throw e;
  }

  // execSettle DIHAPUS (4th redeploy / swap_sell/30.har): action ini sudah gone
  // dari Silvana. Flow SELL skrg: prepareDvpFee → getConsumedHoldings →
  // prepareTransfer → getAllocFactory → prepare_transaction → submit_prepared.
  // Settlement di-trigger oleh submit_prepared (Canton RPC), bukan execSettle.

  const _now = new Date();
  const _totalFee = addDp(feeCtx.feeAmountCC || '0', feeCtx.counterpartFeeAmountCC || '0');
  const _prepTransferArgs = [{
    sender: partyId,
    receiver: feeCtx.feeParty,
    amount: _totalFee,
    instrumentId: { admin: dso, id: 'Amulet' },
    inputHoldingCids: [...inputHoldingCids],
    requestedAt: _now.toISOString(),
    executeBefore: new Date(_now.getTime() + 24 * 3600_000 + 10_000).toISOString(),
  }];
  let allocate;
  if (!weProvideCC) {
    // Kita SERAHKAN token (USDCx-buy / cETH-sell) — fetch holdings token + cek saldo.
    // admin token diambil dari ourLeg.instrument (dvp terms) → benar utk pair manapun.
    const tokenLabel = legTokenLabel, tokenId = legTokenId, tokenAdmin = (ourLeg.instrument && ourLeg.instrument.admin) || legTokenAdmin;
    const bal = await supaBalances(ctx.identityToken || canton.token, ctx.proxy || null);
    const tokenTok = ((bal && bal.tokens) || []).find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === tokenId);
    const tokenHoldings = (tokenTok && tokenTok.unlockedUtxos || []).map(u => u.contractId).filter(Boolean);
    if (!tokenHoldings.length) throw new Error(`tidak ada ${tokenLabel} holding untuk swap`);
    const totalToken = (tokenTok.unlockedUtxos || []).reduce((s, u) => s + Number(u.amount || 0), 0);
    const needToken = Number(ourLeg.amount);
    if (totalToken < needToken) {
      const e = new Error(`${tokenLabel} kurang: butuh ${needToken.toFixed(6)} hanya punya ${totalToken.toFixed(6)}`);
      e.insufficientBalance = true;
      e.tokenNeeded = needToken;
      e.tokenHave = totalToken;
      throw e;
    }
    for (const h of tokenHoldings) { if (!inputHoldingCids.includes(h)) inputHoldingCids.push(h); }
    const t = await sv.swapAction(A.prepareTransfer, _prepTransferArgs);
    logDebug('prepareTransfer (token) response', t);
    if (!t || !t.factoryId) throw new Error('prepareTransfer (token) gagal');
    // allocationFactory = factory TOKEN (bukan CC/Amulet ExternalPartyAmuletRules).
    // expectedAdmin = admin token dari dvp terms. getAllocFactory balik factory token.
    const allocFactArgs = [
      tokenAdmin,
      {
        allocation: {
          settlement: {
            executor: dvp.executor,
            settlementRef: { id: proposalId, cid: null },
            requestedAt: dvp.terms.createdAt,
            allocateBefore: dvp.terms.allocateBefore,
            settleBefore: dvp.terms.settleBefore,
            meta: { values: {} },
          },
          transferLegId: ourLeg.legId,
          transferLeg: {
            sender: partyId,
            receiver: dvp.proposer,
            instrumentId: ourLeg.instrument,
            amount: fmt10(ourLeg.amount),
            meta: { values: {} },
          },
        },
        inputHoldingCids: tokenHoldings,
        expectedAdmin: tokenAdmin,
        extraArgs: { context: { values: {} }, meta: { values: {} } },
        requestedAt: dvp.terms.createdAt,
      },
    ];
    let allocFact = await sv.swapAction(A.getAllocFactory, allocFactArgs).catch(e => ({ _err: (e && e.message) || String(e) }));
    // JUST-IN-TIME discover getAllocFactory (BUY) kalau stale (404, redeploy) →
    // scan bundle, cari action yg balik {factory:{factoryId}} buat body INI →
    // update + retry. Auto-fetch tiap redeploy tanpa update manual.
    if (!allocFact || allocFact._err || !allocFact.factory || !allocFact.factory.factoryId) {
      const skip = new Set(Object.values(A).filter(id => id !== A.getAllocFactory));
      const newId = await sv.discoverActionByProbe(allocFactArgs, SilvanaClient._isAllocFactory, skip).catch(() => null);
      if (newId && newId !== A.getAllocFactory) {
        log(`getAllocFactory stale → ditemukan ID baru ${newId.slice(0, 10)}… (auto-fetch)`);
        SWAP.actionIds.getAllocFactory = newId; saveActionIds();
        allocFact = await sv.swapAction(newId, allocFactArgs).catch(e => ({ _err: (e && e.message) || String(e) }));
      }
    }
    logDebug('getAllocFactory (buy) response', allocFact);
    if (!allocFact || allocFact._err || !allocFact.factory || !allocFact.factory.factoryId) throw new Error(`getAllocFactory (buy) gagal: ${(allocFact && allocFact._err) || 'no factory'}`);
    const _allocCtx = allocFact.factory.choiceContext || {};
    allocate = { instrument: ourLeg.instrument, amount: ourLeg.amount, legId: ourLeg.legId, factoryCid: allocFact.factory.factoryId, contextValues: (_allocCtx.choiceContextData && _allocCtx.choiceContextData.values) || {}, disclosed: _allocCtx.disclosedContracts || [] };
  } else {
    const t = await sv.swapAction(A.prepareTransfer, _prepTransferArgs);
    logDebug('prepareTransfer (sell) response', t);
    if (!t || !t.factoryId) throw new Error('prepareTransfer gagal');
    allocate = { instrument: ourLeg.instrument, amount: ourLeg.amount, legId: ourLeg.legId, factoryCid: t.factoryId, contextValues: t.choiceContextData.values, disclosed: t.disclosedContracts };
  }

  const body = buildMultiCallAccept({ party: partyId, inputHoldingCids, multiCall, userServiceCid, feeCtx, proposalId, dvpProposalCid: dvpCid, dvpTerms: dvp.terms, executor: dvp.executor, receiver, dso, allocate, now: _now });
  const prep = await canton.prepareTransaction(body);
  if (!prep || !prep.hash) throw new Error('gagal menyiapkan transaksi');

  log('Menandatangani & mengirim transaksi…');
  // Sign + submit dgn rotasi wallet pada BAD SIGNATURE. Canton ikat partyId ke
  // satu key stellar; kalau pickPrivyWallet salah tebak, rotasi ke kandidat lain.
  // Hash sama, cukup re-sign pakai key berbeda — tidak perlu prepare ulang.
  const hashHex = b64HashToHex(prep.hash);
  const sigMaxTries = Math.max(1, (privy.walletCandidates && privy.walletCandidates.length) || 1) + 1;
  let sub = null;
  for (let st = 1; st <= sigMaxTries; st++) {
    const sigRaw = await privy.rawSign(hashHex);
    try {
      sub = await canton.submitPrepared({ hash: prep.hash, signature: sigToB64(sigRaw) });
      // Wallet ini valid → persist biar run berikutnya langsung pakai (skip rotasi).
      if (ctx.onWalletPicked && privy.wallet) { try { ctx.onWalletPicked(privy.wallet.id); } catch (_) { } }
      break;
    } catch (e) {
      if (/bad signature/i.test((e && e.message) || '')) {
        const nxt = privy.nextWallet();
        if (nxt) { log(`BAD SIGNATURE → rotasi wallet ${nxt.id.slice(0, 8)}… (${st}/${sigMaxTries - 1})`); continue; }
        throw new Error('BAD SIGNATURE: semua wallet stellar dicoba, partyId terikat key yg tidak dimiliki Privy');
      }
      throw e;
    }
  }
  if (!sub || !sub.submissionId) throw new Error('gagal mengirim transaksi');

  let completion = null;
  for (let i = 0; i < SWAP.completionMaxTries; i++) {
    const q = await canton.queryCompletion(sub.submissionId).catch(() => null);
    if (q && q.status === 'completed') { completion = q; break; }
    if (q && (q.status === 'failed' || q.status === 'rejected')) throw new Error(`transaksi ${q.status}: ${q.message || ''}`);
    await sleep(SWAP.completionPollMs);
  }
  // Settlement di-finalize oleh submit_prepared (Canton RPC) di atas — tidak ada
  // execSettle lagi (gone sejak 4th redeploy).
  return { ok: true, direction, proposalId, submissionId: sub.submissionId, completed: !!completion, feeCC: Number.isFinite(realFeeCC) ? realFeeCC : null };
}

// ============================================================================
//  Terminal (CLOB) swap — mode 8. Ganti front-half RFQ (rfqStream+acceptQuote)
//  dengan submitOrder (spread ketat, fee taker 0.2% vs RFQ lebar). Order match →
//  1..N DvpProposal (split engine-side pas order nyapu >1 maker). Per proposal:
//    value(base×usdPerEdelx) ≥ minUsd → SETTLE (sign, reuse assembler swapOnce);
//    value < minUsd (dust leftover) → cancelSettlement (skip jam + hemat fee).
//  Settle SEKUENSIAL + excludeHoldingCids (consumedAmuletCids + CC fee cid dari
//  chunk sebelumnya) → fee CC gak rebutan UTXO ("Waiting for unlocked CC").
//  weProvideCC selalu false (mode 8 token↔token; fee CC batch terpisah).
// ============================================================================
async function terminalSwapOnce(ctx, side, edelxQty) {
  const { sv, log = () => { } } = ctx;
  if (!ctx.userServiceCid) throw new Error('userServiceCid belum ada — cek koneksi/passkey');
  const L = ctx.leg || {};
  const market = L.market || 'EDELx-cETH';
  const minUsd = Number(ctx.minUsd) || 0;
  const usdPerEdelx = Number(ctx.usdPerEdelx) || 0;

  // 0. FRESH: cancel SEMUA settlement pending kita di market ini SEBELUM order baru.
  //    Clean slate → gak ada dana ke-lock dari settlement lama (dust/gagal) → "Waiting
  //    for an unlocked balance" gak muncul. SKIP yg udah settle / dana kita udah alloc.
  try { await cancelPendingForFresh(ctx.sv, ctx.canton, ctx.partyId, market, log); } catch (_) { }

  // 1. Harga market order (cross agresif, sama frontend) + submitOrder FOK lpOnly.
  const pec = await sv.getPrice(market).catch(() => null);
  const ref = Number(pec && pec.last) || Number(ctx.cethPerEdelx) || 0;
  if (!(ref > 0)) throw new Error('harga EDELx-cETH belum ada');
  const cross = Number(M8.orderCross) || 0.02;
  const price = fmt10(String(ref * (side === 'buy' ? 1 + cross : 1 - cross)));
  const qtyStr = fmt10(String(edelxQty));
  log(`terminal ${side.toUpperCase()} ${qtyStr} EDELx @ ${price} cETH (FOK lpOnly)`);
  const ord = await sv.submitOrder({ partyId: ctx.partyId, marketId: market, orderType: side, price, quantity: qtyStr, timeInForce: 'FOK', requirements: { lpOnly: true } });
  if (!ord || ord.success === false || !ord.order) {
    const e = new Error(`submitOrder: ${(ord && (ord.error || ord.message)) || 'gagal'}`); e.noLiquidity = true; throw e;
  }
  const orderId = ord.order.orderId || ord.order.id;

  // 2. Proposal(s) hasil order (poll; split → >1). Order gak match (FOK kill / rest
  //    ACTIVE pas book kosong) → gak ada proposal → cancelOrder + noLiquidity (retry).
  let props = [];
  for (let i = 0; i < 14; i++) {
    props = (await sv.proposalsByOrderId(ctx.partyId, orderId).catch(() => [])).filter(p => p.buyer === ctx.partyId || p.seller === ctx.partyId);
    if (props.length) break;
    await sleep(2500);
  }
  if (!props.length) {
    await sv.cancelOrder(orderId, ctx.partyId).catch(() => { });
    const e = new Error('order gak match (book kosong / LP absen)'); e.noLiquidity = true; throw e;
  }
  log(`order ${orderId} → ${props.length} settlement${props.length > 1 ? ' (SPLIT)' : ''}`);

  // 3. Klasifikasi tiap chunk pakai minUsd (config mode8.minUsd). value = base×usdPerEdelx.
  //    SETTLED (auto) → skip. < minUsd (dust) → batch cancel. ≥ minUsd → antri settle.
  const consumed = new Set();  // CC UTXO cid yg udah dipakai fee → exclude di chunk berikut
  let settledCount = 0, dustCount = 0, dustEdelxTotal = 0, feeTotal = 0, lastErr = null;
  const toSettle = [], toCancel = [];
  for (const p of props) {
    if (/SETTLED/i.test(String(p.status || ''))) { settledCount++; continue; } // udah auto-settle
    const valUsd = Number(p.baseQuantity) * usdPerEdelx;
    if (valUsd < minUsd) toCancel.push({ p, valUsd }); else toSettle.push(p);
  }
  // PASS 1 — CANCEL SEMUA DUST DULU, SEBELUM sign apapun. Dust gak pernah masuk
  //   prepareDvpFee/prepareTransfer/sign → 0 fee CC buat chunk dust (permintaan user).
  //   dustEdelxTotal = jumlah EDELx chunk yg di-cancel (base EDELx utk buy/sell) → dipakai
  //   loss round-trip biar dust yg KETAHAN (bukan hilang) gak kehitung loss.
  for (const { p, valUsd } of toCancel) {
    log(`dust ${Number(p.baseQuantity).toFixed(2)} EDELx (~$${valUsd.toFixed(2)} < minUsd $${minUsd}) → cancelSettlement (sebelum sign, 0 fee)`);
    await sv.cancelSettlement(p.proposalId, ctx.partyId, 'dust chunk below minUsd').catch(() => { });
    dustCount++;
    dustEdelxTotal += Number(p.baseQuantity) || 0;
  }
  // PASS 2 — SETTLE chunk ≥ minUsd (besar dulu), sekuensial + excludeHoldingCids.
  //   Cuma chunk yg value USD ≥ minUsd (config) yg di-sign & bayar fee.
  toSettle.sort((a, b) => Number(b.baseQuantity) - Number(a.baseQuantity));
  for (const p of toSettle) {
    try {
      const r = await settleTerminalProposal(ctx, p, consumed);
      if (r && r.ok) { settledCount++; if (r.feeCC) feeTotal += r.feeCC; (r.consumed || []).forEach(c => consumed.add(c)); }
    } catch (e) {
      lastErr = e; log(`settle ${p.proposalId.slice(0, 12)}… gagal: ${(e && e.message) || e}`);
      if (e && e.feeSpike) throw e; // fee gate → bubble up (mode 8 tunggu)
    }
  }
  if (!settledCount) throw (lastErr || new Error('tidak ada chunk yg settle'));
  return { ok: true, direction: side, orderId, settled: settledCount, dust: dustCount, dustEdelx: dustEdelxTotal, feeCC: feeTotal || null };
}

// Settle SATU DvpProposal hasil order terminal. Mirror back-half swapOnce (getMultiCall
// → DvpProposal asli → prepareDvpFee(+fee gate) → prepareTransfer/getAllocFactory →
// buildMultiCallAccept → sign → submit). Beda: preconfirm pakai submitPreconfirmation
// (terminal) + fee CC exclude `consumedSet` (anti rebutan UTXO). Return consumed CC cid.
async function settleTerminalProposal(ctx, proposal, consumedSet) {
  const { sv, privy, canton, partyId, userServiceCid, log = () => { } } = ctx;
  const A = SWAP.actionIds, dso = SWAP.dsoPartyId;
  const proposalId = proposal.proposalId;
  const weAreBuyer = proposal.buyer === partyId;
  const role = weAreBuyer ? 'buyer' : 'seller';
  const L = ctx.leg || {};
  const legTokenId = L.tokenId || SWAP.tokenId;
  const legTokenLabel = L.tokenLabel || SWAP.tokenLabel;
  const legTokenAdmin = L.tokenAdmin || SWAP.tokenAdmin;
  const feeCap = ctx.maxFeeCC != null ? Number(ctx.maxFeeCC) : Number(SWAP.maxFeeCC);

  // 1. Preconfirm terminal: submitPreconfirmation + recordEvent(preconfirmation_role,
  //    holdingsByToken {CC,token}) → LP/orderbook majuin proposal → dvpProposalCid.
  const meta = { accept: true, source: 'order_match' };
  try {
    const bal = await supaBalances(ctx.identityToken || canton.token, ctx.proxy || null);
    const toks = (bal && bal.tokens) || [];
    const holdings = {}, totals = {};
    const add = (tk, key) => { const utxos = (tk && tk.unlockedUtxos || []).map(u => ({ cid: u.contractId, amount: fmt10(String(u.amount)) })).filter(x => x.cid); if (utxos.length) { holdings[key] = utxos; totals[key] = utxos.reduce((s, u) => s + Number(u.amount), 0); } };
    add(toks.find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === 'AMULET'), 'CC');
    const myTok = toks.find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === String(legTokenId).toUpperCase());
    if (myTok) add(myTok, (myTok.instrumentId && myTok.instrumentId.id) || legTokenLabel);
    if (Object.keys(holdings).length) { meta.holdingsByToken = holdings; meta.totalByToken = totals; }
  } catch (_) { }
  await sv.submitPreconfirmation(proposalId, partyId, true);
  await sv.swapAction(A.recordEvent, [{ partyId, recordedByRole: role, eventType: `preconfirmation_${role}`, result: 'success', proposalId, metadata: meta }]).catch(() => { });

  // 2. Poll dvpProposalCid.
  let dvpCid = null, lastPoll = null;
  for (let i = 0; i < SWAP.pollMaxTries; i++) {
    const st = await sv.swapAction(A.pollProposal, [{ settlementId: proposalId, partyId }]).catch(e => ({ _err: e && e.message }));
    lastPoll = st;
    if (st && typeof st.dvpProposalCid === 'string' && st.dvpProposalCid.startsWith('00')) { dvpCid = st.dvpProposalCid; break; }
    await sleep(SWAP.pollIntervalMs);
  }
  if (!dvpCid) throw new Error(`dvpProposalCid timeout (last=${JSON.stringify(lastPoll).slice(0, 160)})`);

  // 3. getMultiCall + DvpProposal ASLI dari ledger (terms verbatim).
  const multiCall = await sv.swapAction(A.getMultiCall, ['supa']);
  if (!multiCall || !multiCall.contractId) throw new Error('getMultiCall gagal');
  let dvp = null, unburied = false, lastCount = 0;
  for (let i = 0; i < SWAP.pollMaxTries; i++) {
    const list = await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(() => []);
    lastCount = (list || []).length;
    const hit = (list || []).find(c => c.contractId === dvpCid);
    if (hit && hit.createArgument && hit.createArgument.terms) { const ca = hit.createArgument; dvp = { cid: dvpCid, terms: ca.terms, executor: ca.operator, proposer: ca.proposer, counterparty: ca.counterparty, proposerIsBuyer: ca.proposerIsBuyer }; break; }
    if (!unburied && lastCount >= 200) { unburied = true; await cleanupStaleProposals(sv, canton, partyId, (m) => log(m), privy).catch(() => 0); continue; }
    await sleep(SWAP.pollIntervalMs);
  }
  if (!dvp) { const e = new Error(`DvpProposal tak ketemu (dvpCid=${dvpCid.slice(0, 12)}.., active=${lastCount})`); e.dvpStuck = true; throw e; }

  // 4. ourLeg + fee CC (exclude consumedSet + settlementHistory.consumedAmuletCids).
  const deliv = dvp.terms.deliveries[0], pay = dvp.terms.payments[0];
  const ourLeg = weAreBuyer ? { instrument: pay.instrument, amount: pay.amount, legId: '2' } : { instrument: deliv.instrument, amount: deliv.amount, legId: '1' };
  const receiver = dvp.proposer;
  const weProvideCC = String((ourLeg.instrument && ourLeg.instrument.id) || '') === 'Amulet'; // false utk mode8
  try { const h = await sv.settlementHistory(proposalId, partyId); (h && h.consumedAmuletCids || []).forEach(c => consumedSet.add(c)); } catch (_) { }
  const amuletsAll = await canton.activeContracts(SWAP.templateIds.amulet);
  const amulets = consumedSet.size ? amuletsAll.filter(c => !consumedSet.has(c.contractId)) : amuletsAll;
  const ccNeed = weProvideCC ? addDp(ourLeg.amount, SWAP.feeBufferCC) : SWAP.feeBufferCC;
  const inputHoldingCids = selectCcHoldings(amulets, ccNeed);
  const feeCcCids = [...inputHoldingCids]; // CC UTXO fee → di-exclude chunk berikut

  // 5. prepareDvpFee (+ fee gate; just-in-time discover kalau stale).
  const dvpFeeArgs = [{ partyId, feeType: 'dvp_contract', role, proposalId, inputHoldingCids }];
  let feeCtx = await sv.swapAction(A.prepareDvpFee, dvpFeeArgs).catch(e => ({ _err: (e && e.message) || String(e) }));
  if (!feeCtx || feeCtx._err || !feeCtx.choiceContextData) {
    const skip = new Set(Object.values(A).filter(id => id !== A.prepareDvpFee));
    const newId = await sv.discoverActionByProbe(dvpFeeArgs, SilvanaClient._isBlob, skip).catch(() => null);
    if (newId && newId !== A.prepareDvpFee) { SWAP.actionIds.prepareDvpFee = newId; saveActionIds(); feeCtx = await sv.swapAction(newId, dvpFeeArgs).catch(e => ({ _err: (e && e.message) || String(e) })); }
  }
  if (!feeCtx || feeCtx._err || !feeCtx.choiceContextData) throw new Error(`prepareDvpFee gagal: ${(feeCtx && feeCtx._err) || 'no choiceContextData'}`);
  const realFeeCC = Number(addDp(feeCtx.feeAmountCC || '0', feeCtx.counterpartFeeAmountCC || '0'));
  if (Number.isFinite(realFeeCC)) { log(`Fee: ${realFeeCC} CC (batas ${feeCap})`); if (realFeeCC > feeCap) { await sv.cancelSettlement(proposalId, partyId).catch(() => { }); const e = new Error(`fee ${realFeeCC} CC > batas ${feeCap} CC`); e.feeSpike = true; e.feeCC = realFeeCC; throw e; } }

  // 6. prepareTransfer / getAllocFactory → allocate.
  const _now = new Date();
  const _totalFee = addDp(feeCtx.feeAmountCC || '0', feeCtx.counterpartFeeAmountCC || '0');
  const _prepTransferArgs = [{ sender: partyId, receiver: feeCtx.feeParty, amount: _totalFee, instrumentId: { admin: dso, id: 'Amulet' }, inputHoldingCids: [...inputHoldingCids], requestedAt: _now.toISOString(), executeBefore: new Date(_now.getTime() + 24 * 3600_000 + 10_000).toISOString() }];
  let allocate;
  if (!weProvideCC) {
    const tokenAdmin = (ourLeg.instrument && ourLeg.instrument.admin) || legTokenAdmin;
    const bal = await supaBalances(ctx.identityToken || canton.token, ctx.proxy || null);
    const tokenTok = ((bal && bal.tokens) || []).find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === String(legTokenId).toUpperCase());
    const tokenHoldings = (tokenTok && tokenTok.unlockedUtxos || []).map(u => u.contractId).filter(Boolean);
    if (!tokenHoldings.length) throw new Error(`tidak ada ${legTokenLabel} holding`);
    const totalToken = (tokenTok.unlockedUtxos || []).reduce((s, u) => s + Number(u.amount || 0), 0);
    const needToken = Number(ourLeg.amount);
    if (totalToken < needToken) { await sv.cancelSettlement(proposalId, partyId).catch(() => { }); const e = new Error(`${legTokenLabel} kurang: butuh ${needToken.toFixed(6)} punya ${totalToken.toFixed(6)}`); e.insufficientBalance = true; e.tokenNeeded = needToken; e.tokenHave = totalToken; throw e; }
    for (const h of tokenHoldings) if (!inputHoldingCids.includes(h)) inputHoldingCids.push(h);
    const t = await sv.swapAction(A.prepareTransfer, _prepTransferArgs);
    if (!t || !t.factoryId) throw new Error('prepareTransfer (token) gagal');
    const allocFactArgs = [tokenAdmin, { allocation: { settlement: { executor: dvp.executor, settlementRef: { id: proposalId, cid: null }, requestedAt: dvp.terms.createdAt, allocateBefore: dvp.terms.allocateBefore, settleBefore: dvp.terms.settleBefore, meta: { values: {} } }, transferLegId: ourLeg.legId, transferLeg: { sender: partyId, receiver: dvp.proposer, instrumentId: ourLeg.instrument, amount: fmt10(ourLeg.amount), meta: { values: {} } } }, inputHoldingCids: tokenHoldings, expectedAdmin: tokenAdmin, extraArgs: { context: { values: {} }, meta: { values: {} } }, requestedAt: dvp.terms.createdAt }];
    let allocFact = await sv.swapAction(A.getAllocFactory, allocFactArgs).catch(e => ({ _err: (e && e.message) || String(e) }));
    if (!allocFact || allocFact._err || !allocFact.factory || !allocFact.factory.factoryId) {
      const skip = new Set(Object.values(A).filter(id => id !== A.getAllocFactory));
      const newId = await sv.discoverActionByProbe(allocFactArgs, SilvanaClient._isAllocFactory, skip).catch(() => null);
      if (newId && newId !== A.getAllocFactory) { SWAP.actionIds.getAllocFactory = newId; saveActionIds(); allocFact = await sv.swapAction(newId, allocFactArgs).catch(e => ({ _err: (e && e.message) || String(e) })); }
    }
    if (!allocFact || allocFact._err || !allocFact.factory || !allocFact.factory.factoryId) throw new Error(`getAllocFactory gagal: ${(allocFact && allocFact._err) || 'no factory'}`);
    const _allocCtx = allocFact.factory.choiceContext || {};
    allocate = { instrument: ourLeg.instrument, amount: ourLeg.amount, legId: ourLeg.legId, factoryCid: allocFact.factory.factoryId, contextValues: (_allocCtx.choiceContextData && _allocCtx.choiceContextData.values) || {}, disclosed: _allocCtx.disclosedContracts || [] };
  } else {
    const t = await sv.swapAction(A.prepareTransfer, _prepTransferArgs);
    if (!t || !t.factoryId) throw new Error('prepareTransfer gagal');
    allocate = { instrument: ourLeg.instrument, amount: ourLeg.amount, legId: ourLeg.legId, factoryCid: t.factoryId, contextValues: t.choiceContextData.values, disclosed: t.disclosedContracts };
  }

  // 7. build + sign (rotasi wallet on bad signature) + submit.
  const body = buildMultiCallAccept({ party: partyId, inputHoldingCids, multiCall, userServiceCid, feeCtx, proposalId, dvpProposalCid: dvpCid, dvpTerms: dvp.terms, executor: dvp.executor, receiver, dso, allocate, now: _now });
  const prep = await canton.prepareTransaction(body);
  if (!prep || !prep.hash) throw new Error('gagal menyiapkan transaksi');
  const hashHex = b64HashToHex(prep.hash);
  const sigMaxTries = Math.max(1, (privy.walletCandidates && privy.walletCandidates.length) || 1) + 1;
  let sub = null;
  for (let stx = 1; stx <= sigMaxTries; stx++) {
    const sigRaw = await privy.rawSign(hashHex);
    try { sub = await canton.submitPrepared({ hash: prep.hash, signature: sigToB64(sigRaw) }); if (ctx.onWalletPicked && privy.wallet) { try { ctx.onWalletPicked(privy.wallet.id); } catch (_) { } } break; }
    catch (e) { if (/bad signature/i.test((e && e.message) || '')) { const nxt = privy.nextWallet(); if (nxt) { log(`BAD SIGNATURE → rotasi wallet ${nxt.id.slice(0, 8)}…`); continue; } throw new Error('BAD SIGNATURE: semua wallet stellar dicoba'); } throw e; }
  }
  if (!sub || !sub.submissionId) throw new Error('gagal mengirim transaksi');
  for (let i = 0; i < SWAP.completionMaxTries; i++) {
    const q = await canton.queryCompletion(sub.submissionId).catch(() => null);
    if (q && q.status === 'completed') break;
    if (q && (q.status === 'failed' || q.status === 'rejected')) throw new Error(`transaksi ${q.status}: ${q.message || ''}`);
    await sleep(SWAP.completionPollMs);
  }
  return { ok: true, proposalId, feeCC: Number.isFinite(realFeeCC) ? realFeeCC : null, consumed: feeCcCids };
}

// ============================================================================
//  Dashboard (ANSI, adaptif tmux)
// ============================================================================
const useColor = process.stdout.isTTY !== false;
const c = (code) => useColor ? `\x1b[${code}m` : '';
const COLOR = { reset: c(0), dim: c(2), bold: c(1), red: c(31), green: c(32), yellow: c(33), blue: c(34), mag: c(35), cyan: c(36), white: c(37), gray: c(90) };
const paint = (txt, ...codes) => codes.join('') + txt + COLOR.reset;
function visLen(s) { return s.replace(/\x1b\[[0-9;]*m/g, '').length; }
function pad(s, w, side = 'right') {
  const len = visLen(s); if (len >= w) return s;
  const total = w - len;
  if (side === 'center') { const l = Math.floor(total / 2); return ' '.repeat(l) + s + ' '.repeat(total - l); }
  const sp = ' '.repeat(total);
  return side === 'right' ? s + sp : sp + s;
}

let W = 44, ROWS = 24;
function computeLayout() {
  const cols = process.stdout.columns || 0, rows = process.stdout.rows || 0;
  ROWS = rows > 0 ? rows : 24;
  W = cols > 0 ? Math.max(30, Math.min(cols, 160)) : 44;
}
const BOX = { tl: '╭', tr: '╮', bl: '╰', br: '╯', h: '─', v: '│', tee: '├', tee2: '┤' };
const line = () => paint(BOX.tl + BOX.h.repeat(W - 2) + BOX.tr, COLOR.cyan);
const endl = () => paint(BOX.bl + BOX.h.repeat(W - 2) + BOX.br, COLOR.cyan);
const sep = () => paint(BOX.tee + BOX.h.repeat(W - 2) + BOX.tee2, COLOR.gray);
function row(content) {
  let s = ' ' + content + ' ';
  if (visLen(s) > W - 2) {
    let out = '', len = 0, i = 0;
    while (i < s.length && len < W - 2 - 1) {
      if (s[i] === '\x1b') { const m = s.slice(i).match(/^\x1b\[[0-9;]*m/); if (m) { out += m[0]; i += m[0].length; continue; } }
      out += s[i]; len++; i++;
    }
    s = out + paint('…', COLOR.gray);
  }
  return paint(BOX.v, COLOR.cyan) + pad(s, W - 2) + paint(BOX.v, COLOR.cyan);
}
function clearScreen() { if (useColor) process.stdout.write('\x1b[2J\x1b[H'); }
function fmtNum(s, maxDp = 4) { if (s == null) return '-'; const n = Number(s); if (!isFinite(n)) return String(s); if (n === 0) return '0'; const t = (Math.abs(n) >= 1 ? n.toFixed(maxDp) : n.toFixed(6)); return t.includes('.') ? t.replace(/0+$/, '').replace(/\.$/, '') : t; }
// Sisa umur sesi → [teks, warna] (buat sel table; warna diterapkan saat render).
function expParts(expMs) {
  if (!expMs) return ['-', COLOR.gray];
  const ms = Number(expMs) - Date.now();
  if (ms <= 0) return ['expired', COLOR.red];
  const m = Math.round(ms / 60000);
  if (m < 60) return [m + 'm', m < 5 ? COLOR.yellow : COLOR.cyan];
  const h = Math.round(m / 60);
  if (h < 48) return [h + 'h', COLOR.cyan];
  return [Math.round(h / 24) + 'd', COLOR.cyan];
}
function renderHeader() {
  return [line(), row(paint(' SilvanaBot V1.10.1 Auto Swap ', COLOR.bold + COLOR.cyan)), row(paint(new Date().toLocaleString('id-ID'), COLOR.gray))].join('\n');
}
// Status akun → [teks, warna]. Dipakai sel STATUS di table.
function statusInfo(state) {
  const d = state.dayTrader;
  if (state.status === 'error') return ['● Error', COLOR.red];
  if (d && d.count >= d.target) return ['● Selesai', COLOR.green];
  if (dtSessionRunning) return ['● Swap', COLOR.yellow];
  if (state.status === 'login') return ['● Login', COLOR.yellow];
  if (state.status === 'ok') return ['● Aktif', COLOR.green];
  return ['● Siap', COLOR.gray];
}
// ── Helper kolom table (compact 2-baris/akun) ────────────────────────────────
function truncVis(s, w) { s = String(s); return s.length > w ? s.slice(0, Math.max(0, w - 1)) + '…' : s; }
function fmtThousand(n) { const x = Math.round(Number(n)); return Number.isFinite(x) ? x.toLocaleString('en-US') : '-'; }
// Fee season: <1000 → 1 desimal (123.4), >=1000 → ribuan bulat (12,345) biar muat kolom.
function fmtSeason(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v <= 0) return '0';
  return v >= 1000 ? fmtThousand(v) : v.toFixed(1);
}
function balOf(state, idUpper) {
  const t = (Array.isArray(state.balances) ? state.balances : []).find(b => String((b.instrumentId && b.instrumentId.id) || '').toUpperCase() === idUpper);
  if (!t) return null;
  const u = Number(t.totalUnlockedBalance ?? t.totalBalance ?? 0);
  const tot = Number(t.totalBalance ?? 0);
  return { unlocked: u, locked: Math.max(0, tot - u) };
}
// Grid akun: 1 baris/akun, kolom dipisah border │, ada header kolom. Lebar &
// set kolom dihitung SEKALI dari semua akun → align rapi. Kolom prioritas-rendah
// (prio besar) didrop SERAGAM kalau terminal sempit; AKUN nyerap sisa lebar.
function renderAccountsTable(states) {
  // Reset time-driven FEE/hr & LOSS$/hr tiap render (roll 00 UTC = 07 WIB) — jaga nilai
  // ke-nol walau 0 swap lewat rollover (bumpDaily gak kepanggil).
  if (Array.isArray(states)) for (const s of states) freshDaily(s);
  // TANPA pembatas kolom (no │/┬/┼/┴). Semua sel CENTER, compact (lebar natural),
  // blok di-center dalam frame. cell(s) → [teks polos, warna]. prio 0 = wajib.
  // Kolom token: mode 8 (ping-pong) → cETH + EDELx (pair yg di-swap). Selain itu →
  // 1 kolom token pair aktif (SWAP.tokenLabel: USDCx/cETH).
  const tokCell = (idUpper, ft) => (s) => { const b = balOf(s, idUpper); return [b ? ft(b.unlocked) + (b.locked > 1e-8 ? '+' + ft(b.locked) : '') : '-', COLOR.green]; };
  const tokenCols = SESSION_ENGINE === 'pingpong'
    ? [{ title: 'cETH', prio: 1, cap: 12, cell: tokCell('CETH', fmtCeth) }, { title: 'EDELx', prio: 1, cap: 12, cell: tokCell('EDELX', fmtEdelx) }]
    : [{ title: SWAP.tokenLabel, prio: 1, cap: 12, cell: tokCell(SWAP.tokenId, fmtForToken(SWAP.tokenId)) }];
  const COLS = [
    { title: 'AKUN', prio: 0, cap: 16, align: 'l', cell: s => [truncVis(s.label || '-', 16), COLOR.bold] },
    { title: 'STATUS', prio: 1, cap: 10, cell: s => statusInfo(s) },
    { title: 'SWAP', prio: 0, cap: 7, cell: s => [s.dayTrader ? `${s.dayTrader.count}/${s.dayTrader.target}` : '-', s.dayTrader && s.dayTrader.count >= s.dayTrader.target ? COLOR.green : COLOR.white] },
    { title: 'CC', prio: 1, cap: 12, cell: s => { const b = balOf(s, 'AMULET'); return [b ? fmtCC(b.unlocked) + (b.locked > 1e-8 ? '+' + fmtCC(b.locked) : '') : '-', COLOR.green]; } },
    ...tokenCols,
    { title: 'POIN', prio: 3, cap: 9, cell: s => [s.points != null ? fmtThousand(s.points) : '-', COLOR.mag] },
    // ΔPOIN = gain poin harian (segitiga ▲ naik / ▼ turun). Reset 0 tiap 07 WIB, persist.
    {
      title: 'ΔPOIN', prio: 3, cap: 10, cell: s => {
        const d = Number(s.pointsDiff);
        if (s.pointsDiff == null || !Number.isFinite(d)) return ['-', COLOR.gray];
        if (d > 0) return ['▲' + fmtThousand(d), COLOR.green];
        if (d < 0) return ['▼' + fmtThousand(-d), COLOR.red];
        return ['▲0', COLOR.gray];
      }
    },
    { title: 'STREAK', prio: 4, cap: 6, cell: s => [s.streak != null ? String(s.streak) : '-', COLOR.yellow] },
    { title: 'FEE/hr', prio: 3, cap: 8, cell: s => [Number(s.feeToday) > 0 ? Number(s.feeToday).toFixed(1) : '0', COLOR.yellow] },
    // SEASON = total fee CC kebakar seumur season (gak roll harian). Persist di
    // session.json → survive re-run. Reset cuma manual: menu 5 → b) reset season.
    { title: 'FEE/SN', prio: 2, cap: 11, cell: s => [fmtSeason(s.feeSeason), COLOR.mag] },
    { title: 'LOSS$/hr', prio: 3, cap: 9, cell: s => [Number(s.spreadToday) > 0 ? '$' + Number(s.spreadToday).toFixed(2) : '$0', COLOR.red] },
    // LOSS SEASON = total spread loss USD seumur season (mirror SEASON fee). Reset barengan.
    { title: 'LOSS/SN', prio: 2, cap: 11, cell: s => [Number(s.spreadSeason) > 0 ? '$' + fmtSeason(s.spreadSeason) : '$0', COLOR.red] },
    { title: 'SILV', prio: 2, cap: 8, cell: s => expParts(s.silvanaExpMs) },
    { title: 'SUPA', prio: 2, cap: 8, cell: s => expParts(s.tokenExpMs) },
  ];
  // Natural width = max(title, isi sel) di-cap per kolom.
  for (const c of COLS) {
    let w = c.title.length;
    for (const s of states) { const t = String(c.cell(s)[0]); if (t.length > w) w = t.length; }
    c.w = Math.min(c.cap, w);
  }
  // Fit compact: gap 2 spasi antar kolom, JANGAN distribusi slack (biar compact).
  // Drop prioritas-rendah kalau total > inner. inner = lebar konten (W-4).
  const inner = W - 4, GAP = 2;
  const total = arr => arr.reduce((a, c, i) => a + c.w + (i ? GAP : 0), 0);
  let kept = COLS.slice();
  while (kept.length > 2 && total(kept) > inner) {
    let di = -1;
    for (let i = 0; i < kept.length; i++) if (kept[i].prio > 0 && (di < 0 || kept[i].prio >= kept[di].prio)) di = i;
    if (di < 0) break;
    kept.splice(di, 1);
  }
  // Render: tiap sel di-center ke lebar kolom, gabung pakai GAP spasi, blok
  // di-center dalam inner. Header titles gray bold, baris data warna per sel.
  const gapStr = ' '.repeat(GAP);
  const blockW = total(kept);
  const leftPad = ' '.repeat(Math.max(0, Math.floor((inner - blockW) / 2)));
  const sideOf = a => a === 'l' ? 'right' : a === 'r' ? 'left' : 'center'; // l=rata kiri, r=rata kanan, default center
  const buildRow = (cellsTC, header, selected) => {
    const cells = kept.map((c, i) => {
      let [t, col] = cellsTC[i];
      t = String(t); if (visLen(t) > c.w) t = truncVis(t, c.w);
      return paint(pad(t, c.w, sideOf(c.align)), header ? COLOR.bold + COLOR.gray : (selected ? COLOR.bold + col : col));
    });
    const body = cells.join(gapStr);
    // Baris terpilih: marker ▸ (makan 2 kolom → potong 2 dari leftPad biar align).
    if (selected) return row(paint('▸ ', COLOR.bold + COLOR.cyan) + (leftPad.length >= 2 ? leftPad.slice(2) : '') + body);
    return row(leftPad + body);
  };
  const out = [sep()];
  out.push(buildRow(kept.map(c => [c.title, null]), true)); // header kolom (center)
  out.push(sep());
  states.forEach((s, i) => out.push(buildRow(kept.map(c => c.cell(s)), false, (selView - 1) === i))); // 1 baris/akun, sorot terpilih
  return out.join('\n');
}
function renderFooter(states) {
  const jam = String(SCHED.hour).padStart(2, '0') + ':' + String(SCHED.minute).padStart(2, '0');
  // Total season = agregat feeSeason (fee CC) + spreadSeason (loss USD) SEMUA akun.
  const st = Array.isArray(states) ? states : [];
  const seasonFee = st.reduce((a, s) => a + (Number(s.feeSeason) || 0), 0);
  const seasonLoss = st.reduce((a, s) => a + (Number(s.spreadSeason) || 0), 0);
  return [
    sep(),
    row(paint('Season fee total ', COLOR.gray) + paint(fmtSeason(seasonFee) + ' CC', COLOR.bold + COLOR.mag)
      + paint('   ·   loss ', COLOR.gray) + paint('$' + fmtSeason(seasonLoss), COLOR.bold + COLOR.red)
      + paint('   ·   reset: menu 5 → b', COLOR.gray)),
    row(paint('Jadwal harian ', COLOR.gray) + paint(jam + ' WIB', COLOR.cyan) + paint('   ·   Ctrl+C berhenti', COLOR.gray)),
  ].join('\n');
}
const ACTIVITY = []; const ACTIVITY_MAX = 1000;
const ACCT_LOG_MAX = 200;  // ring buffer per-akun (state.log)
// map label/email → index akun (route log per-akun). Lazy dari __states; reset null
// kalau states berubah. Cover label DAN email karena tag swap = label||email.
let _labelIdx = null;
function labelToIdx(label) {
  if (!_labelIdx) {
    _labelIdx = new Map();
    const st = global.__states || [];
    for (let i = 0; i < st.length; i++) {
      if (st[i].label) _labelIdx.set(st[i].label, i);
      if (st[i].email) _labelIdx.set(st[i].email, i);
    }
  }
  return _labelIdx.has(label) ? _labelIdx.get(label) : -1;
}
// Structured activity ring buffer — plain (no ANSI), untuk push ke web dashboard.
const DASH_ACTIVITY = []; const DASH_ACTIVITY_MAX = 200;
// Burn events — fee CC kebakar tiap swap sukses submit. Dashboard akumulasi
// jadi total All Time + Today (dedupe by ts server-side).
const BURN_EVENTS = []; const BURN_EVENTS_MAX = 200;
function recordBurn(feeCC, label) {
  const f = Number(feeCC);
  if (!Number.isFinite(f) || f <= 0) return;
  BURN_EVENTS.push({ ts: Date.now(), feeCC: f, label: String(label || '') });
  if (BURN_EVENTS.length > BURN_EVENTS_MAX) BURN_EVENTS.splice(0, BURN_EVENTS.length - BURN_EVENTS_MAX);
  logActivity(`[${label || 'swap'}] fee ${f.toFixed(4)} CC kebakar`, COLOR.yellow);
}
// ── Statistik harian per-akun (fee CC + spread loss USD). Persist ke session.json
// (survive re-run), reset otomatis tiap ganti hari. Boundary = tanggal UTC → roll di
// 00:00 UTC = 07:00 WIB, SAMA dengan reset task earn-hub (00 UTC) + daily loop scheduler
// (07 WIB). JANGAN pakai TZ Jakarta (roll 00 WIB = 17 UTC → misaligned 7 jam dari task).
function todayStr() {
  return new Date().toISOString().slice(0, 10);
}
// Tambah fee/spread hari ini ke session (source of truth), reset kalau ganti hari. Balikin total.
// feeSeason = akumulator fee CC SEUMUR SEASON: TANPA date-gate, jadi gak ikut roll 00 UTC.
// Tanggal season gak menentu (ditentuin Silvana) → reset cuma manual lewat menu 5b.
function persistDaily(email, feeCC, spreadUsd) {
  if (!email) return { feeToday: 0, spreadToday: 0, feeSeason: 0, spreadSeason: 0 };
  const today = todayStr();
  const s = acctSession(email);
  const same = s.statDate === today;
  const feeToday = (same ? Number(s.feeToday) || 0 : 0) + (Number(feeCC) || 0);
  const spreadToday = (same ? Number(s.spreadToday) || 0 : 0) + (Number(spreadUsd) || 0);
  const feeSeason = (Number(s.feeSeason) || 0) + (Number(feeCC) || 0);
  const spreadSeason = (Number(s.spreadSeason) || 0) + (Number(spreadUsd) || 0);
  patchAcctSession(email, { statDate: today, feeToday, spreadToday, feeSeason, spreadSeason });
  return { feeToday, spreadToday, feeSeason, spreadSeason };
}
// Wrapper: persist + update state buat dashboard live.
function bumpDaily(state, feeCC, spreadUsd) {
  if (!state || !state.email) return;
  const r = persistDaily(state.email, feeCC, spreadUsd);
  state.feeToday = r.feeToday; state.spreadToday = r.spreadToday;
  state.feeSeason = r.feeSeason; state.spreadSeason = r.spreadSeason; state.statDate = todayStr();
}
// Reset akumulator season 1 akun → 0 (session.json + state live kalau ada). Nol-in
// FEE dan LOSS season sekaligus (satu season = satu window). Balikin {fee, spread} lama.
function resetSeason(email) {
  if (!email) return { fee: 0, spread: 0 };
  const s = acctSession(email) || {};
  const prev = { fee: Number(s.feeSeason) || 0, spread: Number(s.spreadSeason) || 0 };
  patchAcctSession(email, { feeSeason: 0, spreadSeason: 0, seasonStart: Date.now() });
  const st = (global.__states || []).find(s => s.email === email);
  if (st) { st.feeSeason = 0; st.spreadSeason = 0; }
  return prev;
}
// Reset TIME-DRIVEN: dipanggil tiap render. Kalau hari (UTC) udah ganti tapi belum ada
// swap (bumpDaily gak kepanggil), state.feeToday/spreadToday nyangkut nilai kemarin →
// paksa 0 + persist. Tanpa ini FEE/hr & LOSS$/hr gak reset lewat 07 WIB kalau 0 swap.
// NB: feeSeason SENGAJA gak disentuh di sini (patchAcctSession = merge) — season
// bukan window harian, cuma reset manual lewat menu 5b.
function freshDaily(state) {
  if (!state || !state.email) return;
  const today = todayStr();
  if (state.statDate !== today) {
    state.feeToday = 0; state.spreadToday = 0; state.statDate = today;
    try { patchAcctSession(state.email, { statDate: today, feeToday: 0, spreadToday: 0 }); } catch (_) { }
  }
  // Diff POIN reset display ke 0 pas ganti hari; baseline di-rebase ke poin skrg pas
  // updatePointsDiff jalan lagi (baca pointsBaseDate ≠ today). Roll 00 UTC = 07 WIB.
  if ((acctSession(state.email) || {}).pointsBaseDate !== today) state.pointsDiff = 0;
}
// Diff POIN harian = gain sejak awal hari (baseline pointsBase, roll 00 UTC = 07 WIB).
// Persist base+diff → survive re-run. Ganti hari → baseline = poin saat itu, diff mulai 0.
function updatePointsDiff(state) {
  if (!state || !state.email || state.points == null) return;
  const today = todayStr();
  const s = acctSession(state.email) || {};
  let base = Number(s.pointsBase);
  if (s.pointsBaseDate !== today || !Number.isFinite(base)) {
    base = Number(state.points);   // hari baru → baseline = poin skrg, diff 0
    patchAcctSession(state.email, { pointsBaseDate: today, pointsBase: base, pointsDiff: 0 });
    state.pointsDiff = 0;
    return;
  }
  const diff = Number(state.points) - base;
  state.pointsDiff = diff;
  patchAcctSession(state.email, { pointsDiff: diff });
}
// Load stat harian dari session pas init state (reset kalau statDate ≠ hari ini).
// feeSeason/spreadSeason selalu diambil apa adanya → survive re-run bot.
function loadDaily(email) {
  const today = todayStr();
  const s = acctSession(email) || {};
  const feeSeason = Number(s.feeSeason) || 0;
  const spreadSeason = Number(s.spreadSeason) || 0;
  // pointsDiff cuma valid kalau baseline masih hari ini; beda hari → 0 (nunggu rebase).
  const pd = (s.pointsBaseDate === today && Number.isFinite(Number(s.pointsDiff))) ? Number(s.pointsDiff) : 0;
  if (s.statDate === today) return { feeToday: Number(s.feeToday) || 0, spreadToday: Number(s.spreadToday) || 0, feeSeason, spreadSeason, pointsDiff: pd, statDate: today };
  return { feeToday: 0, spreadToday: 0, feeSeason, spreadSeason, pointsDiff: pd, statDate: today };
}
function colorToType(color) {
  if (color === COLOR.green) return 'success';
  if (color === COLOR.red) return 'error';
  if (color === COLOR.yellow) return 'warn';
  return 'info';
}
const DEBUG_LOG_PATH = path.join(ROOT, 'swap-debug.log');
function logDebug(label, data) {
  try {
    const line = `[${new Date().toISOString()}] ${label}\n${typeof data === 'string' ? data : JSON.stringify(data, null, 2)}\n\n`;
    fs.appendFileSync(DEBUG_LOG_PATH, line);
  } catch (_) { }
}
function logActivity(msg, color) {
  const ts = new Date().toLocaleTimeString('id-ID');
  const lineStr = paint(ts + ' ', COLOR.gray) + (color ? paint(msg, color) : msg);
  ACTIVITY.push(lineStr);
  if (ACTIVITY.length > ACTIVITY_MAX) ACTIVITY.splice(0, ACTIVITY.length - ACTIVITY_MAX);
  // route ke buffer per-akun kalau msg diawali "[label]" (semua log swap pakai prefix)
  const mp = /^\[([^\]]+)\]/.exec(String(msg));
  if (mp) {
    const st = global.__states && global.__states[labelToIdx(mp[1])];
    if (st) {
      if (!Array.isArray(st.log)) st.log = [];
      st.log.push(lineStr);
      if (st.log.length > ACCT_LOG_MAX) st.log.splice(0, st.log.length - ACCT_LOG_MAX);
    }
  }
  // mirror ke buffer terstruktur (plain) untuk dashboard
  DASH_ACTIVITY.push({ ts: Date.now(), type: colorToType(color), category: 'bot', message: String(msg) });
  if (DASH_ACTIVITY.length > DASH_ACTIVITY_MAX) DASH_ACTIVITY.splice(0, DASH_ACTIVITY.length - DASH_ACTIVITY_MAX);
  if (global.__states) scheduleRender();
}
function renderActivityLog(maxLines) {
  const st = global.__states || [];
  const n = st.length;
  let title, buf;
  if (selView <= 0 || selView > n) { selView = Math.max(0, Math.min(selView, n)); title = '▎ aktivitas — SYSTEM (semua)'; buf = ACTIVITY; }
  else { const s = st[selView - 1]; title = '▎ log — ' + (s ? (s.label || s.email) : '?'); buf = (s && Array.isArray(s.log)) ? s.log : []; }
  const nav = paint(`  [↑/↓ ${selView}/${n}]`, COLOR.gray);
  const lines = [sep(), row(paint(title, COLOR.bold + COLOR.cyan) + nav)];
  const slice = buf.slice(-Math.max(1, maxLines));
  if (!slice.length) lines.push(row(paint('(belum ada aktivitas)', COLOR.gray)));
  else slice.forEach(l => lines.push(row(l)));
  lines.push(endl());
  return lines.join('\n');
}
function render(states) {
  if (global.__paused) return;
  if (!Array.isArray(states)) return; // dipanggil dari path non-dashboard (wallets/register) sebelum __states init
  computeLayout(); clearScreen();
  const out = [renderHeader()];
  out.push(renderAccountsTable(states));
  out.push(renderFooter(states));
  const used = out.join('\n').split('\n').length;
  const avail = Math.max(MIN_ACTIVITY_LINES, ROWS - used - 3);
  out.push(renderActivityLog(avail));
  process.stdout.write(out.join('\n') + '\n');
}
// Coalesce render biar ringan saat banyak log barengan (parallel swap N akun).
// Render sekarang, lalu max 1x / 80ms; render tertunda di-batch jadi 1.
let _renderTimer = null, _renderPending = false;
function scheduleRender() {
  if (_renderTimer) { _renderPending = true; return; }
  render(global.__states);
  _renderTimer = setTimeout(() => {
    _renderTimer = null;
    if (_renderPending) { _renderPending = false; scheduleRender(); }
  }, 80);
}

// ============================================================================
//  Tick dashboard data (balance + DAY_TRADER) — dipakai saat tidak swap
// ============================================================================
function parseDayTrader(tasksArr) {
  const arr = Array.isArray(tasksArr) ? tasksArr : (tasksArr && tasksArr.items) || [];
  const it = arr.find(t => String((t && t.code) || '').toUpperCase() === 'DAY_TRADER');
  if (!it) return null;
  const m = String(it.progress || '').match(/(\d+)\s*\/\s*(\d+)/);
  const current = m ? Number(m[1]) : (it.completed ? 10 : 0);
  const target = m ? Number(m[2]) : 10;
  return { current, target, completed: !!it.completed || current >= target };
}
// Task "EDELx-cETH Daily Trader" dari earn-hub (analog DAY_TRADER). Code PASTI dari
// task.har = CETH_EDELX_DAY_TRADER (title "EDELx-cETH Daily Trader", progress X/10).
// Prioritas: override config swap.edelCethTaskCode → code pasti → fuzzy (EDEL+CETH).
// Balikin {current,target,completed,code} atau null.
const EDEL_CETH_TASK_CODE = 'CETH_EDELX_DAY_TRADER';
function parseEdelCethTrader(tasksArr) {
  const arr = Array.isArray(tasksArr) ? tasksArr : (tasksArr && tasksArr.items) || [];
  const override = M8.taskCode || String((CONFIG.swap || {}).edelCethTaskCode || '').toUpperCase();
  const it = arr.find(t => {
    const code = String((t && t.code) || '').toUpperCase();
    if (override) return code === override;
    if (code === EDEL_CETH_TASK_CODE) return true;
    const name = String((t && (t.name || t.title || t.label || t.description)) || '').toUpperCase();
    const hay = code + ' ' + name;
    return /EDEL/.test(hay) && /C?ETH/.test(hay);
  });
  if (!it) return null;
  const m = String(it.progress || '').match(/(\d+)\s*\/\s*(\d+)/);
  const current = m ? Number(m[1]) : (it.completed ? 1 : 0);
  const target = m ? Number(m[2]) : 1;
  return { current, target, completed: !!it.completed || current >= target, code: it.code };
}
// Dump semua task code earn-hub (debug: cari code EDELx-cETH trader yg bener).
function dumpTaskCodes(tasksArr) {
  const arr = Array.isArray(tasksArr) ? tasksArr : (tasksArr && tasksArr.items) || [];
  return arr.map(t => `${(t && t.code) || '?'}${t && t.progress ? '(' + t.progress + ')' : ''}`).join(', ');
}
// Streak dari task MONTHLY_TRADER earn-hub. Robust ke nama field (streak/
// currentStreak/progress "X/Y"). Balikin angka streak atau null.
function parseMonthlyStreak(tasksArr) {
  const arr = Array.isArray(tasksArr) ? tasksArr : (tasksArr && tasksArr.items) || [];
  const it = arr.find(t => /MONTHLY/i.test(String((t && t.code) || '')));
  if (!it) return null;
  const num = v => { if (v == null) return null; const n = Number(String(v).replace(/,/g, '').trim()); return Number.isFinite(n) ? n : null; };
  for (const k of ['streak', 'currentStreak', 'dayStreak', 'consecutiveDays', 'streakDays', 'value', 'count']) {
    if (k in it) { const n = num(it[k]); if (n != null) return n; }
  }
  const m = String(it.progress || '').match(/(\d+)/); // "5/30" → 5
  if (m) return Number(m[1]);
  return it.completed ? 1 : 0;
}
// Format balance per token (desimal tetap, gak strip nol): CC = 1, USDCx = 1,
// cETH = 3, EDELx = 0.
function fmtCC(n) { const x = Number(n); return Number.isFinite(x) ? x.toFixed(1) : '-'; }
function fmtUSDC(n) { const x = Number(n); return Number.isFinite(x) ? x.toFixed(1) : '-'; }
function fmtCeth(n) { const x = Number(n); return Number.isFinite(x) ? x.toFixed(3) : '-'; }
function fmtEdelx(n) { const x = Number(n); return Number.isFinite(x) ? x.toFixed(0) : '-'; }
function fmtTok6(n) { const x = Number(n); return Number.isFinite(x) ? x.toFixed(6) : '-'; }
// Pilih formatter dari tokenId (USDCX/CETH/EDELX). Fallback fmtTok6.
function fmtForToken(idUpper) {
  const id = String(idUpper || '').toUpperCase();
  if (id === 'USDCX') return fmtUSDC;
  if (id === 'CETH') return fmtCeth;
  if (id === 'EDELX') return fmtEdelx;
  return fmtTok6;
}
// Unclaimed Points dari earn-hub (mis. 1,780.00). Cari di root + nested, robust ke nama field.
function extractUnclaimedPoints(tasks) {
  if (!tasks || typeof tasks !== 'object') return null;
  const num = v => { if (v == null) return null; const n = Number(String(v).replace(/,/g, '').trim()); return Number.isFinite(n) ? n : null; };
  const KEYS = ['unclaimedPoints', 'unclaimed_points', 'totalUnclaimedPoints', 'pointsUnclaimed', 'unclaimed', 'pointsBalance', 'availablePoints', 'points', 'totalPoints'];
  for (const k of KEYS) if (k in tasks) { const n = num(tasks[k]); if (n != null) return n; }
  for (const c of ['summary', 'earn', 'earnHub', 'rewards', 'data', 'pointsSummary', 'result']) {
    const o = tasks[c]; if (o && typeof o === 'object') for (const k of KEYS) if (k in o) { const n = num(o[k]); if (n != null) return n; }
  }
  let found = null;
  (function walk(o, d) {
    if (found != null || !o || typeof o !== 'object' || d > 4) return;
    for (const k of Object.keys(o)) {
      const v = o[k];
      if (/unclaim/i.test(k)) { const n = num(v); if (n != null) { found = n; return; } }
      if (v && typeof v === 'object') walk(v, d + 1);
    }
  })(tasks, 0);
  return found;
}
// Harga CC dalam USDCx (≈ USD). Diturunkan dari swap-quote getPrice (web.md §4e):
// mid (bid+ask)/2 dari market CC-USDCx. Cache + fail-open (jangan zero-kan harga live).
const CC_PRICE = { ccUsdcx: 0, ts: 0 };
async function fetchCcPrice(sv) {
  try {
    const p = await sv.getPrice(SWAP.market);
    if (!p) return;
    const bid = Number(p.bid), ask = Number(p.ask);
    let mid = 0;
    if (Number.isFinite(bid) && Number.isFinite(ask) && bid > 0 && ask > 0) mid = (bid + ask) / 2;
    else if (Number.isFinite(ask) && ask > 0) mid = ask;
    else if (Number.isFinite(bid) && bid > 0) mid = bid;
    if (mid > 0) { CC_PRICE.ccUsdcx = mid; CC_PRICE.ts = Date.now(); }
  } catch (_) { /* keep last cache */ }
}
async function tickAccount(state) {
  try {
    const proxy = pickProxy(state.privyEmail || state.email);
    const token = await ensurePrivyToken(state);
    state.status = 'fetching'; render(global.__states);
    try { const bal = await supaBalances(token, proxy); state.balances = (bal && bal.tokens) || []; } catch (_) { }
    const sv = await ensureSilvanaSession(state).catch(() => null);
    if (sv) {
      const me = await supaMe(token, proxy).catch(() => null);
      const partyId = me && me.data && me.data.partyId;
      const tasks = await sv.earnTasks(partyId).catch(() => null);
      // Mode 8 (ping-pong): SWAP kolom = task EDELx-cETH Daily Trader, bukan DAY_TRADER.
      const dt = SESSION_ENGINE === 'pingpong' ? parseEdelCethTrader(tasks && tasks.items) : parseDayTrader(tasks && tasks.items);
      if (dt) state.dayTrader = { count: dt.current, target: dt.target };
      const stk = parseMonthlyStreak(tasks && tasks.items);
      if (stk != null) state.streak = stk;
      const stats = await sv.earnStats().catch(() => null);
      const pts = (stats && stats.totalPoints != null && Number.isFinite(Number(stats.totalPoints)))
        ? Number(stats.totalPoints) : extractUnclaimedPoints(tasks);
      if (pts != null) { state.points = pts; updatePointsDiff(state); }
      // Earn-hub lengkap buat kolom dashboard table.
      if (stats && stats.totalVolume != null && Number.isFinite(Number(stats.totalVolume))) state.volume = Number(stats.totalVolume);
      if (stats && stats.activityCount != null && Number.isFinite(Number(stats.activityCount))) state.activity = Number(stats.activityCount);
      if (stats && stats.displayName) state.displayName = stats.displayName;
      await fetchCcPrice(sv);
    }
    state.status = 'ok'; state.message = '';
  } catch (e) { state.status = 'error'; state.message = (e && e.message) || String(e); }
  render(global.__states);
}
// Konkurensi login/keep-alive antar-akun. Tiap akun independen (proxy/cookie/
// privy sendiri) → aman paralel. Batasi biar gak overload proxy/rate-limit.
const ACCT_CONCURRENCY = Math.max(1, Number((CONFIG.swap || {}).loginConcurrency) || 5);
async function tickAll(states) { await mapLimit(states, ACCT_CONCURRENCY, s => tickAccount(s)); }

// ============================================================================
//  Keep-alive token (Privy/Supa + Silvana) — jalan TERUS walau quest selesai.
//  Lebih sering & ringan dari tickAll (gak fetch balance/tasks), khusus jaga
//  token gak expired antar-sesi. Per-akun try/catch biar 1 gagal gak blok lain.
// ============================================================================
async function keepAliveTokens(state) {
  try {
    await ensurePrivyToken(state);       // refresh Privy/Supa (update state.tokenExpMs)
    await ensureSilvanaSession(state);   // re-login Silvana kalau mendekati expired
    if (state.status === 'login') state.status = 'ok';
    if (/login|keep-alive/i.test(state.message || '')) state.message = '';
  } catch (e) {
    logActivity(`[${state.label || state.email}] keep-alive gagal: ${(e && e.message || e).toString().slice(0, 50)}`, COLOR.yellow);
  }
}
async function keepAliveAll(states) {
  if (dtSessionRunning) return;
  await mapLimit(states, ACCT_CONCURRENCY, s => dtSessionRunning ? null : keepAliveTokens(s));
  render(states);
}
// Token watcher — refresh Privy/Silvana BEGITU mendekati/expired, KAPANPUN (jalan
// walau dtSessionRunning, beda dari keepAlive yg ke-gate). Live token funcs
// (sv.bearer/canton.token) baca session → refresh otomatis ke-pick swap in-flight
// TANPA rebuild client. Per-akun guard __tokenBusy cegah refresh numpuk.
async function refreshExpiringTokens(states) {
  const now = Date.now();
  const SOON = 300_000; // sisa <5 mnt / expired → refresh proaktif
  await mapLimit(states, ACCT_CONCURRENCY, async (s) => {
    if (s.__tokenBusy) return;
    const supaStale = !s.tokenExpMs || (s.tokenExpMs - now < SOON);
    const silvStale = !s.silvanaExpMs || (s.silvanaExpMs - now < SOON);
    if (!supaStale && !silvStale) return;
    s.__tokenBusy = true;
    try {
      if (supaStale) await ensurePrivyToken(s);
      if (silvStale) await ensureSilvanaSession(s);
    } catch (e) {
      logActivity(`[${s.label || s.email}] token refresh gagal: ${((e && e.message) || e).toString().slice(0, 50)}`, COLOR.yellow);
    } finally { s.__tokenBusy = false; }
  });
}

// ============================================================================
//  DAY_TRADER engine — API-driven, anti-overcap (no local count file)
// ============================================================================
let dtSessionRunning = false;
// Sekali per-proses: true setelah action IDs diverifikasi/di-discover valid.
// Reset jadi false otomatis saat swapAction kena 404 (redeploy mid-run) →
// ensureActionIds di loop swap re-discover otomatis (self-heal mid-run).
let actionIdsVerified = false;
let lastDiscoverMs = 0; // throttle scan bundle (anti-hammer kalau discover gagal)

// Pastikan SWAP.actionIds current: validate murah (1 req) → kalau stale (404,
// Silvana redeploy) scan bundle & remap fingerprint. Dipanggil di session-start
// DAN tiap iterasi loop swap (murah kalau sudah verified). Aman dipanggil
// berulang. Throttle scan 30s biar gak hammer pas discover gagal (cookie dead).
async function ensureActionIds(sv, partyId, tag) {
  if (actionIdsVerified) return;
  try {
    if (await sv.validateActionIds(partyId)) {
      actionIdsVerified = true;
      logActivity(`[${tag}] action IDs valid ✓`, COLOR.gray);
      return;
    }
    if (Date.now() - lastDiscoverMs < 30000) return; // baru scan <30s lalu, tunggu
    lastDiscoverMs = Date.now();
    logActivity(`[${tag}] action ID stale (Silvana redeploy) → scan bundle…`, COLOR.yellow);
    const r = await sv.discoverActionIds();   // parse bundle by nama fungsi (no probe)
    if (r.changed.length) { logActivity(`[${tag}] action IDs di-refresh (${r.changed.length}): ${r.changed.join(', ')}`, COLOR.green); saveActionIds(); }
    actionIdsVerified = r.ok;
    if (!r.ok) logActivity(`[${tag}] discovery belum lengkap: ${r.missingCritical.join(', ')} (bundle berubah?) — auto-retry`, COLOR.yellow);
  } catch (e) {
    logActivity(`[${tag}] discovery action IDs gagal: ${(e && e.message) || e}`, COLOR.yellow);
  }
}
function makeStates() {
  return ACCOUNTS.map((a, i) => {
    const d = loadDaily(a.email);
    return { label: a.label || `akun-${i + 1}`, email: a.email, privyEmail: a.privyEmail || null, status: 'idle', message: '', balances: null, dayTrader: null, points: null, pointsDiff: d.pointsDiff, volume: null, activity: null, streak: null, log: [], feeToday: d.feeToday, spreadToday: d.spreadToday, feeSeason: d.feeSeason, spreadSeason: d.spreadSeason, statDate: d.statDate };
  });
}

/**
 * Ekstrak reason ringkas dari error swap (terutama prepare_transaction Canton).
 * Body Canton biasanya panjang 400+ char dengan stack trace; ambil bagian
 * "AssertionFailed (...): The requirement '...' was not met" saja.
 */
function shortSwapReason(err) {
  const m = (err && err.message) || String(err);
  // Pattern khusus yang sering: contract not found = race condition
  if (/CONTRACT_NOT_FOUND|Contract could not be found/i.test(m)) return 'contract dipakai/expired (retry)';
  if (/quote\s*(stale|expired)/i.test(m)) return 'quote stale (retry)';
  // Pattern Daml AssertionFailed
  const ar = m.match(/The requirement '([^']{0,180})' was not met/);
  if (ar) return ar[1];
  // Pattern lain: Canton client Error: ... message
  const ce = m.match(/Canton client Error[^"}]*?"message"\s*:\s*"([^"]{0,200})"/);
  if (ce) return ce[1];
  // Fallback: prepare_transaction status=N body=... → ambil "message"
  const j = m.match(/"message"\s*:\s*"([^"]{0,180})"/);
  if (j) return j[1];
  // Fallback potong di 80 char
  return m.length > 100 ? m.slice(0, 100) + '…' : m;
}
async function buildSwapClients(state) {
  const email = state.email;
  const proxy = getProxy(email);
  const identityToken = await ensurePrivyToken(state);
  const pat = (acctSession(email).privy || {}).privy_access_token;
  if (!pat) throw new Error('privy_access_token tidak ada di session');
  const sv = await ensureSilvanaSession(state);
  if (!sv) throw new Error('passkey belum di-set (paste dulu)');
  // Server action /swap & /connect skrg butuh Canton Bearer (supa identity token).
  // Pakai fungsi biar selalu baca token terbaru dari session (auto-refresh).
  sv.bearer = () => { try { return acctSession(email).privy.token || identityToken; } catch (_) { return identityToken; } };
  const me = await supaMe(identityToken, proxy);
  const partyId = me.data && me.data.partyId;
  if (!partyId) throw new Error('partyId tidak ditemukan');
  sv.partyId = partyId; // dipakai swapAction self-heal (auto re-discover on 404)

  // Invalidate cached userServiceCid kalau partyId user berubah (mis. bind wallet baru).
  // Tanpa ini, bot pakai userServiceCid party lama → swap finalize gagal silent.
  const cached = acctSession(email);
  if (cached.partyId && cached.partyId !== partyId) {
    patchAcctSession(email, { partyId, userServiceCid: null, privyWalletId: null });
    logActivity(`[${state.label || email}] partyId berubah → cache userServiceCid+walletId direset`, COLOR.yellow);
  } else if (!cached.partyId) {
    patchAcctSession(email, { partyId });
  }

  // Pilih Privy wallet yg cocok partyId (Privy bisa punya >1 stellar wallet).
  const preferredWalletId = acctSession(email).privyWalletId || null;
  const privy = new PrivyWallet({ accessToken: pat, timeoutMs: REQ.timeoutMs, proxy, preferredWalletId, partyId });
  await privy.authenticate();

  // Auto-cache walletId yg terpilih biar konsisten across runs.
  if (privy.wallet && privy.wallet.id && privy.wallet.id !== preferredWalletId) {
    patchAcctSession(email, { privyWalletId: privy.wallet.id });
    if (privy.walletCandidates.length > 1) {
      logActivity(`[${state.label || email}] Privy multi-wallet (${privy.walletCandidates.length}) → pakai ${privy.wallet.id.slice(0, 8)}…`, COLOR.gray);
    }
  }

  // Token LIVE (fungsi baca session terbaru) — JANGAN string statis. Kalau token
  // refresh/expired mid-sesi, string statis bikin canton 401 → active_contracts
  // []→ "DvpProposal lookup failed activeCount:0" walau /swap (pakai sv.bearer
  // live) masih jalan. Samain sumber token dgn sv.bearer.
  const canton = new CantonClient({ token: () => { try { return acctSession(email).privy.token || identityToken; } catch (_) { return identityToken; } }, timeoutMs: REQ.timeoutMs, proxy });
  return { sv, privy, canton, partyId, identityToken, proxy };
}

/**
 * Rebuild clients kalau token Privy (Supa) atau cookie Silvana mendekati/sudah
 * expired. Token Privy & Silvana lifetime ~1 jam; session swap bisa berjam-jam,
 * jadi tanpa ini token mati di tengah → 401.
 *
 * @param force  paksa rebuild (mis. setelah kena 401 mid-flight)
 */
async function ensureFreshClients(state, clients, { force = false } = {}) {
  const now = Date.now();
  const SOON_MS = 600_000; // refresh kalau sisa < 10 menit (1 iterasi bisa 6-7 menit)
  const supaExp = state.tokenExpMs || 0;
  const silvExp = state.silvanaExpMs || 0;
  const supaStale = !supaExp || (supaExp - now < SOON_MS);
  const silvStale = !silvExp || (silvExp - now < SOON_MS);
  if (!force && !supaStale && !silvStale) return clients;
  // rebuild (ensurePrivyToken & ensureSilvanaSession auto-refresh internal)
  return await buildSwapClients(state);
}
async function fetchDayTrader(sv, partyId) { const tasks = await sv.earnTasks(partyId); return parseDayTrader(tasks); }

/**
 * Cek SettlementProposal milik party yang masih in-progress.
 * Stage 9+ = settled (sukses). Stage <9 + tidak rejected = masih jalan.
 *
 * Returns array of "active" proposals dengan field tambahan:
 *   - stage, ageSec (umur sejak createdAt), needsAlloc (allocation belum ada)
 *
 * Param `staleMaxSec`: kalau proposal udah > waktu ini (default 5 menit) tapi
 * masih stage 5 (preconfirmed tapi gak allocated), kita anggap "stale/dead"
 * — counterparty atau diri kita sendiri timeout. Bisa diabaikan biar bot
 * lanjut buka posisi baru. Server akan auto-expire di settleBefore (12h).
 */
async function fetchActiveSettlements(sv, partyId, { staleMaxSec = 300, statusBudgetMs = 12000 } = {}) {
  const proposals = await sv.listSettlementProposals().catch(() => []);
  if (!proposals.length) return [];
  const now = Date.now();
  const out = [];
  for (const p of proposals) {
    if (p.buyer !== partyId && p.seller !== partyId) continue; // cuma punya kita
    // skip kalau sudah lebih dari budget waktu (cegah lookup ratusan)
    if (Date.now() - now > statusBudgetMs) break;
    const st = await sv.swapAction(SWAP.actionIds.pollProposal, [{ settlementId: p.proposalId, partyId }]).catch(() => null);
    if (!st) continue;
    const stage = st.stage || 0;
    const rejected = st.buyerRejected || st.sellerRejected;
    if (stage >= 9 || rejected) continue; // already settled or dead
    // FIX stuck: kalau SISI KITA sudah allocate (dana sudah terkunci utk settlement
    // ini), settlement bakal finalize sendiri — bukan "blocking" swap baru. Tanpa
    // skip ini, swap yg BARU SAJA sukses kita kerjakan terus kehitung "aktif" →
    // pre-check buang full wait-window tiap iterasi → bot keliatan stuck.
    const isBuyer = p.buyer === partyId;
    const ourAllocCid = isBuyer ? st.allocationBuyerCid : st.allocationSellerCid;
    if (ourAllocCid && ourAllocCid !== '$undefined') continue; // dana sudah committed
    const createdMs = Number(p.createdAt && p.createdAt.seconds) * 1000;
    const ageSec = createdMs ? Math.floor((Date.now() - createdMs) / 1000) : 0;
    if (ageSec > staleMaxSec) continue; // dianggap dead, server akan expire sendiri
    out.push({
      proposalId: p.proposalId,
      stage, ageSec,
      direction: p.buyer === partyId ? 'buy' : 'sell',
      amount: p.baseQuantity + ' CC',
      hasAlloc: st.allocationBuyerCid !== '$undefined' && st.allocationSellerCid !== '$undefined',
    });
  }
  return out;
}
// Interface templateId Allocation (Splice token standard).
const ALLOCATION_IFACE = '#splice-api-token-allocation-v1:Splice.Api.Token.AllocationV1:Allocation';
// contractId dari row active_contracts (flat {contractId} / wrapped contractEntry).
function _acContractId(c) {
  if (!c) return null;
  if (c.contractId) return c.contractId;
  const ce = c.contractEntry && c.contractEntry.JsActiveContract && c.contractEntry.JsActiveContract.createdEvent;
  return (ce && ce.contractId) || null;
}
// Normalisasi contract ref supanova → {templateId, contractId, createdEventBlob}
// (server balik snake_case template_id/contract_id/created_event_blob).
function _normContract(x) {
  if (!x) return null;
  return {
    templateId: x.template_id || x.templateId,
    contractId: x.contract_id || x.contractId,
    createdEventBlob: x.created_event_blob || x.createdEventBlob,
  };
}
/**
 * Withdraw SEMUA Allocation aktif milik party → UNLOCK dana + bikin DvpProposal
 * LOCKED bisa di-archive/cancel (yg cancelSettlement-nya FAILED gara2 dana ke-lock).
 * Pakai Canton choice `Allocation_Withdraw` + extraArgs {expire-lock:true, amulet-rules,
 * open-round}. Sumber: bot temen silvanjut (withdraw_allocation) — ini yg dia lakuin
 * buat atasi proposal nyangkut yg gak bisa di-cancel. Butuh privy (sign). Return jumlah.
 */
async function withdrawStuckAllocations(sv, canton, privy, partyId, log = () => { }) {
  if (!canton || !privy) return 0;
  // 1) Allocation nyangkut = dana kita ke-lock di proposal stuck. WAJIB query pakai
  //    interfaceIds= (templateIds= → 400). Verified diag: 200 alloc di akun stuck.
  const allocs = await canton.activeContractsByInterface(ALLOCATION_IFACE).catch((e) => { log(`  query alloc gagal: ${(e && e.message) || e}`, COLOR.red); return []; });
  const cids = [...new Set((allocs || []).map(_acContractId).filter(Boolean))];
  if (!cids.length) { log('  0 allocation aktif → gak ada dana ke-lock', COLOR.gray); return 0; }
  // 2) Context withdraw dari getDsoInfo (1 call): amulet_rules + latest_mining_round
  //    (getOpenRound action MATI 404 → pakai latest_mining_round dari getDsoInfo).
  try { const d = await sv.discoverActionIds(); if (d && d.changed && d.changed.length) saveActionIds(); } catch (_) { }
  const dso = await sv.swapAction(SWAP.actionIds.getDsoInfo, []).catch((e) => ({ _err: (e && e.message) || String(e) }));
  const ar = _normContract(dso && dso.amulet_rules && dso.amulet_rules.contract);
  const omr = _normContract(dso && dso.latest_mining_round && dso.latest_mining_round.contract);
  if (!ar || !ar.contractId || !omr || !omr.contractId) {
    log(`  withdraw GAGAL baca getDsoInfo (${cids.length} alloc nyangkut) — kirim swap-debug.log`, COLOR.red);
    logDebug('withdraw shape FAIL', { getDsoInfo: JSON.stringify(dso).slice(0, 1000), idDso: SWAP.actionIds.getDsoInfo });
    return 0;
  }
  log(`  ${cids.length} allocation nyangkut → withdraw (unlock dana)…`, COLOR.gray);
  let done = 0, fail = 0;
  const t0 = Date.now(), BUDGET_MS = 240000, MAX = 250;
  for (const cid of cids) {
    if (done + fail >= MAX || Date.now() - t0 > BUDGET_MS) { log(`  budget habis (${done} done) — run cleanup lagi buat sisanya`, COLOR.yellow); break; }
    const body = {
      commands: [{
        ExerciseCommand: {
          templateId: ALLOCATION_IFACE,
          contractId: cid,
          choice: 'Allocation_Withdraw',
          choiceArgument: {
            extraArgs: {
              context: {
                values: {
                  'expire-lock': { tag: 'AV_Bool', value: true },
                  'amulet-rules': { tag: 'AV_ContractId', value: ar.contractId },
                  'open-round': { tag: 'AV_ContractId', value: omr.contractId },
                },
              },
              meta: { values: {} },
            },
          },
        },
      }],
      disclosedContracts: [
        { templateId: omr.templateId, contractId: omr.contractId, createdEventBlob: omr.createdEventBlob, synchronizerId: SWAP.synchronizerId },
        { templateId: ar.templateId, contractId: ar.contractId, createdEventBlob: ar.createdEventBlob, synchronizerId: SWAP.synchronizerId },
      ],
    };
    try {
      const prep = await canton.prepareTransaction(body);
      if (!prep || !prep.hash) throw new Error('no hash');
      const hashHex = b64HashToHex(prep.hash);
      let sub = null;
      const tries = Math.max(1, (privy.walletCandidates && privy.walletCandidates.length) || 1) + 1;
      for (let st = 1; st <= tries; st++) {
        const sigRaw = await privy.rawSign(hashHex);
        try { sub = await canton.submitPrepared({ hash: prep.hash, signature: sigToB64(sigRaw) }); break; }
        catch (e) { if (/bad signature/i.test((e && e.message) || '')) { const nxt = privy.nextWallet(); if (nxt) continue; } throw e; }
      }
      if (sub && sub.submissionId) { done++; if (done % 10 === 0 || done === 1) log(`  withdraw ${done}/${cids.length}…`, COLOR.green); }
      else fail++;
    } catch (e) {
      fail++;
      if (fail <= 3) log(`  withdraw ${cid.slice(0, 14)}… gagal: ${((e && e.message) || e).toString().slice(0, 100)}`, COLOR.red);
    }
  }
  log(`  withdraw selesai: ${done} unlock, ${fail} gagal`, done ? COLOR.green : COLOR.yellow);
  return done;
}
/**
 * Cancel proposal nyangkut yg AMAN dibuang (V2): stage<9 (belum settle), alloc
 * sisi kita kosong (0 dana ke-lock), umur >90s (bukan in-flight). Sampah dari
 * abort fee-spike / settlement gak kelar / proposal LP yg gak kita ambil.
 * Cancel via cancelSettlement → DvpProposal di-archive → active_contracts gak
 * kena cap 200. Yg dana kita ke-LOCK gak bisa di-cancel → di-WITHDRAW (kalau privy
 * dikasih) biar dana unlock + proposal bisa archive. Return total (cancel+withdraw).
 */
async function cleanupStaleProposals(sv, canton, partyId, log = () => { }, privy = null) {
  // Clog = DvpProposal CONTRACTS di Canton (active_contracts cap 200), BUKAN REST
  // settlement-proposals (sering kosong) — itu kenapa cleanup lama 0 terus.
  // Ambil dari ledger, cancel yg AMAN → DvpProposal di-archive → count turun <200
  // → "DvpProposal lookup" jalan lagi. AMAN = punya kita, umur>120s, BELUM ada
  // allocation sama sekali (kedua sisi kosong → gak ada dana ke-lock).
  if (!canton) return 0;
  const list = await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(() => []);
  const totalDvp = (list || []).length;
  const cands = [];
  let pastExpiry = 0;
  for (const c of (list || [])) {
    const ca = c.createArgument, terms = ca && ca.terms;
    if (!terms || !terms.id) continue;
    const weProposed = ca.proposer === partyId;
    if (!weProposed && ca.counterparty !== partyId) continue;    // bukan punya kita
    const createdMs = Date.parse(terms.createdAt) || 0;
    const ageSec = createdMs ? (Date.now() - createdMs) / 1000 : 999999;
    if (ageSec < 120) continue;                                  // baru — mungkin in-flight, SKIP
    // sisi kita: kalau kita proposer → proposerIsBuyer; kalau counterparty → kebalikannya.
    const weAreBuyer = weProposed ? !!ca.proposerIsBuyer : !ca.proposerIsBuyer;
    const settleBeforeMs = Date.parse(terms.settleBefore) || 0;
    if (settleBeforeMs && settleBeforeMs < Date.now()) pastExpiry++; // udah lewat settleBefore
    cands.push({ proposalId: terms.id, ageSec, weAreBuyer });
  }
  cands.sort((a, b) => b.ageSec - a.ageSec);                      // tertua dulu (clear clog lama)
  log(`cleanup: ${totalDvp} DvpProposal aktif, ${cands.length} kandidat, ${pastExpiry} udah lewat settleBefore (harusnya auto-archive)`, COLOR.gray);
  // discover action ids (buat cancel + withdraw getDsoInfo/getOpenRound). Selalu,
  // walau cands kosong (mungkin masih ada allocation nyangkut buat di-withdraw).
  if (!actionIdsVerified) await ensureActionIds(sv, partyId, '(cleanup)').catch(() => { });
  // WITHDRAW DULU: unlock allocation nyangkut → dana balik + proposal LOCKED jadi
  // bisa di-cancel di loop bawah (dana kita ke-lock = penyebab cancel FAILED).
  let withdrawn = 0;
  if (privy) { withdrawn = await withdrawStuckAllocations(sv, canton, privy, partyId, log).catch(() => 0); }
  if (!cands.length) return withdrawn;
  let cancelled = 0, alreadyDone = 0, failed = 0;
  const t0 = Date.now(), BUDGET_MS = 120000, MAX = 120, ANCIENT = 3600;
  for (const p of cands) {
    if (cancelled >= MAX || Date.now() - t0 > BUDGET_MS) break;
    // Tua >1 jam = pasti mati (gak akan settle) → cancel LANGSUNG tanpa poll
    // (cepat, sekalian reclaim dana kalau ada yg ke-lock). Yg 120s–1h: poll dulu,
    // skip kalau SISI KITA udah allocate (dana kita ke-lock, mungkin masih jalan).
    if (p.ageSec < ANCIENT) {
      const st = await sv.swapAction(SWAP.actionIds.pollProposal, [{ settlementId: p.proposalId, partyId }]).catch(() => null);
      if (st) {
        if ((st.stage || 0) >= 9) continue;                      // settled — jangan sentuh
        const ourAlloc = p.weAreBuyer ? st.allocationBuyerCid : st.allocationSellerCid;
        if (ourAlloc && ourAlloc !== '$undefined') continue;     // dana KITA ke-lock — SKIP
      }
    }
    const r = await sv.cancelSettlement(p.proposalId, partyId);
    const emsg = ((r && (r._err || r.error || r.message)) || '').toString();
    if (r && !r._err && r.success !== false) {
      cancelled++;
      await sv.swapAction(SWAP.actionIds.recordEvent, [{ partyId, recordedByRole: 'buyer', eventType: 'cancel_buyer', result: 'cancelled', proposalId: p.proposalId, metadata: { source: 'cleanup' } }]).catch(() => { });
      log(`  cancelled ${p.proposalId.slice(0, 16)}… (${Math.round(p.ageSec)}s)`, COLOR.yellow);
    } else if (/only pending|already|status (Cancelled|Settled|Rejected|Completed)/i.test(emsg)) {
      // Udah Cancelled/Settled — cancel BUKAN alatnya. Yg cancelled-tapi-masih-aktif =
      // alloc kita masih ke-lock → di-clear lewat withdraw (di atas), bukan cancel.
      alreadyDone++;
    } else {
      if (failed === 0) logDebug('cancelSettlement gagal (full)', { proposalId: p.proposalId, resp: r });
      failed++;
      log(`  gagal cancel ${p.proposalId.slice(0, 16)}…: ${emsg.slice(0, 160) || 'unknown'}`, COLOR.red);
    }
  }
  if (alreadyDone) log(`  ${alreadyDone} proposal udah Cancelled/Settled (skip — clear lewat withdraw/expire)`, COLOR.gray);
  return cancelled + withdrawn;
}

// FRESH pre-swap: cancel SEMUA DvpProposal pending KITA di `market` SEBELUM order baru
// (mode 8 terminal). TANPA age-gate (beda cleanupStaleProposals yg >120s) — tiap swap
// baru wajib clean slate biar gak ada dana ke-lock dari settlement lama → "Waiting for
// an unlocked balance" gak pernah muncul. SKIP yg udah settled (stage≥9) atau SISI KITA
// udah allocate (dana ke-lock, lagi finalize — JANGAN nuke, biarin selesai). Cancel yg
// unallocated (0 dana lock) via cancelSettlement (server-action, gak butuh Canton sign).
async function cancelPendingForFresh(sv, canton, partyId, market, log = () => { }) {
  if (!canton) return 0;
  const list = await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(() => []);
  const wantInstr = String(market).toUpperCase().split('-'); // ['EDELX','CETH']
  const cands = [];
  for (const c of (list || [])) {
    const ca = c.createArgument, terms = ca && ca.terms;
    if (!terms || !terms.id) continue;
    const weProposed = ca.proposer === partyId;
    if (!weProposed && ca.counterparty !== partyId) continue;   // bukan punya kita
    // filter market by instrument kedua leg (EDELX + CETH). Skip pair lain (mis CC-USDCx).
    const inst = new Set();
    for (const d of (terms.deliveries || [])) if (d.instrument && d.instrument.id) inst.add(String(d.instrument.id).toUpperCase());
    for (const pm of (terms.payments || [])) if (pm.instrument && pm.instrument.id) inst.add(String(pm.instrument.id).toUpperCase());
    if (!wantInstr.every(x => inst.has(x))) continue;
    const weAreBuyer = weProposed ? !!ca.proposerIsBuyer : !ca.proposerIsBuyer;
    cands.push({ proposalId: terms.id, weAreBuyer });
  }
  if (!cands.length) return 0;
  let cancelled = 0;
  for (const p of cands) {
    const st = await sv.swapAction(SWAP.actionIds.pollProposal, [{ settlementId: p.proposalId, partyId }]).catch(() => null);
    if (st) {
      if ((st.stage || 0) >= 9) continue;                        // settled — jangan sentuh
      const ourAlloc = p.weAreBuyer ? st.allocationBuyerCid : st.allocationSellerCid;
      if (ourAlloc && ourAlloc !== '$undefined') continue;       // dana KITA ke-lock (finalize) — SKIP
    }
    const r = await sv.cancelSettlement(p.proposalId, partyId, 'fresh before new swap');
    if (r && !r._err && r.success !== false) {
      cancelled++;
      await sv.swapAction(SWAP.actionIds.recordEvent, [{ partyId, recordedByRole: p.weAreBuyer ? 'buyer' : 'seller', eventType: p.weAreBuyer ? 'cancel_buyer' : 'cancel_seller', result: 'cancelled', proposalId: p.proposalId, metadata: { source: 'fresh' } }]).catch(() => { });
    }
  }
  if (cancelled) log(`fresh: ${cancelled} settlement pending di-cancel (clean slate sebelum swap)`);
  return cancelled;
}
// ── accessor row active_contracts (flat snake/camel ATAU wrapped contractEntry) ──
function _acTemplateId(c) {
  if (!c) return null;
  if (c.templateId || c.template_id) return c.templateId || c.template_id;
  const ce = c.contractEntry && c.contractEntry.JsActiveContract && c.contractEntry.JsActiveContract.createdEvent;
  return (ce && ce.templateId) || null;
}
function _acBlob(c) {
  if (!c) return null;
  if (c.createdEventBlob || c.created_event_blob) return c.createdEventBlob || c.created_event_blob;
  const ce = c.contractEntry && c.contractEntry.JsActiveContract && c.contractEntry.JsActiveContract.createdEvent;
  return (ce && (ce.createdEventBlob || ce.created_event_blob)) || null;
}
function _acArg(c) {
  if (!c) return {};
  if (c.createArgument || c.create_argument) return c.createArgument || c.create_argument;
  const ce = c.contractEntry && c.contractEntry.JsActiveContract && c.contractEntry.JsActiveContract.createdEvent;
  return (ce && (ce.createArgument || ce.create_argument)) || {};
}
/**
 * ROBUST drain DvpProposal stale (penyebab cap-200 → "Menunggu DvpProposal").
 *
 * Beda dari cleanupStaleProposals (pakai cancelSettlement server-action yg sering
 * gagal & capped 120/2mnt 1-pass): ini ARCHIVE LANGSUNG di Canton via choice
 * `DvpProposal_Reject {reason}` pada contract-nya sendiri, lalu RE-FETCH berulang
 * sampai count<200 & gak ada expired lagi. active_contracts cap 200 → tiap putaran
 * yg di-archive ke-replace yg ke-201, jadi loop ngabisin backlog berapa pun banyaknya.
 *
 * AMAN: cuma yg PUNYA KITA (proposer/counterparty == party) & udah lewat settleBefore
 * (mati — gak akan settle). Withdraw allocation nyangkut DULU (unlock dana) biar
 * reject gak ketahan lock + dana balik. Butuh privy (buat raw_sign). Return jumlah
 * DvpProposal yg ke-reject + alloc yg ke-withdraw.
 *
 * templateId PER-CONTRACT (full package-id dari row), BUKAN '#name' (flaky) — Canton
 * reject '#'-form di prepare ("Invalid Daml-LF Package ID 0x23") & wajib match blob.
 */
async function drainStaleDvpProposals(sv, canton, privy, partyId, log = () => { }) {
  if (!canton) return 0;
  if (!privy) { log('drain: butuh privy (raw_sign) — skip', COLOR.yellow); return 0; }
  const TPL = SWAP.templateIds.dvpProposal;
  const REASON = 'expired cleanup';
  // unlock dana ke-lock dulu (allocation nyangkut) → dana balik + reject gak ketahan lock
  let withdrawn = 0;
  withdrawn = await withdrawStuckAllocations(sv, canton, privy, partyId, log).catch(() => 0);
  let rejected = 0, failed = 0, round = 0;
  const t0 = Date.now(), BUDGET_MS = 600000, MAX_ROUNDS = 60;
  while (round < MAX_ROUNDS && Date.now() - t0 < BUDGET_MS) {
    const list = await canton.activeContracts(TPL).catch(() => []);
    const n = (list || []).length;
    const cands = [];
    for (const c of (list || [])) {
      const ca = _acArg(c), terms = ca && ca.terms;
      if (!terms) continue;
      if (ca.proposer !== partyId && ca.counterparty !== partyId) continue; // bukan punya kita
      const settleBeforeMs = Date.parse(terms.settleBefore) || 0;
      if (!settleBeforeMs || settleBeforeMs >= Date.now()) continue;        // belum lewat settleBefore → SKIP (mungkin in-flight)
      const cid = _acContractId(c), tpl = _acTemplateId(c), blob = _acBlob(c);
      if (cid && tpl && blob) cands.push({ cid, tpl, blob });
    }
    log(`drain round ${round}: ${n} DvpProposal aktif, ${cands.length} expired (mati)`, COLOR.gray);
    if (n < 200 && !cands.length) { log('  ✓ cap-200 kebuka — gak ada stale lagi', COLOR.green); break; }
    if (!cands.length) { log('  gak ada kandidat expired lagi (sisanya mungkin in-flight) — stop', COLOR.yellow); break; }
    const rejectedAtRoundStart = rejected;
    for (const k of cands) {
      if (Date.now() - t0 > BUDGET_MS) { log('  budget habis — jalanin cleanup lagi buat sisanya', COLOR.yellow); break; }
      const body = {
        commands: [{ ExerciseCommand: { templateId: k.tpl, contractId: k.cid, choice: 'DvpProposal_Reject', choiceArgument: { reason: REASON } } }],
        disclosedContracts: [{ templateId: k.tpl, contractId: k.cid, createdEventBlob: k.blob, synchronizerId: SWAP.synchronizerId }],
      };
      try {
        const prep = await canton.prepareTransaction(body);
        if (!prep || !prep.hash) throw new Error('no hash');
        const hashHex = b64HashToHex(prep.hash);
        let sub = null;
        const tries = Math.max(1, (privy.walletCandidates && privy.walletCandidates.length) || 1) + 1;
        for (let st = 1; st <= tries; st++) {
          const sigRaw = await privy.rawSign(hashHex);
          try { sub = await canton.submitPrepared({ hash: prep.hash, signature: sigToB64(sigRaw) }); break; }
          catch (e) { if (/bad signature/i.test((e && e.message) || '') && privy.nextWallet && privy.nextWallet()) continue; throw e; }
        }
        if (sub && sub.submissionId) { rejected++; if (rejected % 25 === 0 || rejected === 1) log(`  reject ${rejected}…`, COLOR.green); }
        else failed++;
      } catch (e) {
        const msg = ((e && e.message) || e).toString();
        // CONTRACT_NOT_FOUND = ke-archive duluan (race) → harmless, lanjut
        if (!/CONTRACT_NOT_FOUND|could not be found/i.test(msg)) { failed++; if (failed <= 3) log(`  reject ${k.cid.slice(0, 14)}… gagal: ${msg.slice(0, 120)}`, COLOR.red); }
      }
    }
    if (rejected === rejectedAtRoundStart) { log('  ronde ini 0 progress (kandidat nolak terus) — stop biar gak spin', COLOR.yellow); break; }
    round++;
  }
  log(`drain selesai: ${rejected} DvpProposal di-reject, ${failed} gagal, ${withdrawn} alloc di-withdraw`, rejected ? COLOR.green : COLOR.yellow);
  return rejected + withdrawn;
}
// fetch saldo → update state.balances (utk dashboard) + return saldo TOKEN aktif
// (USDCx / cETH) unlocked. tokenId dari SWAP.tokenId (di-set per pair aktif).
async function refreshBalances(state, token, proxy) {
  try {
    const b = await supaBalances(token, proxy);
    if (b && b.tokens) state.balances = b.tokens;
    const t = (b && b.tokens || []).find(x => String((x.instrumentId && x.instrumentId.id) || '').toUpperCase() === SWAP.tokenId);
    return t ? Number(t.totalUnlockedBalance || t.totalBalance || 0) : 0;
  } catch (_) { return 0; }
}
// CC (Amulet) unlocked dari state.balances yg terakhir di-refresh.
function ccUnlockedFrom(state) {
  const t = (Array.isArray(state.balances) ? state.balances : []).find(x => String((x.instrumentId && x.instrumentId.id) || '').toUpperCase() === 'AMULET');
  return t ? Number(t.totalUnlockedBalance || t.totalBalance || 0) : 0;
}
// Unlocked balance token apapun (by instrumentId.id uppercase) dari state.balances.
function unlockedOf(state, idUpper) {
  const t = (Array.isArray(state.balances) ? state.balances : []).find(x => String((x.instrumentId && x.instrumentId.id) || '').toUpperCase() === String(idUpper).toUpperCase());
  return t ? Number(t.totalUnlockedBalance || t.totalBalance || 0) : 0;
}
// Swap 1 akun (di-extract dari runDayTraderSession biar bisa parallel/sequential).
// Body IDENTIK; `continue` level-akun → `return` (udah bukan di dalam for-loop).
// Outer catch RETHROW → dibungkus runAccountSwapSession (retry akun-level transient).
async function _accountSwapOnce(i) {
  const a = ACCOUNTS[i], tag = a.label || a.email;
  const state = (global.__states && global.__states[i]) || makeStates()[i];
  try {
    state.status = 'login'; render(global.__states);
    let clients;
    for (let _pb = 0; _pb <= Math.min(PROXIES.length - 1, 2); _pb++) {
      try { clients = await buildSwapClients(state); break; }
      catch (e) {
        if ((isProxyErr(e) || isIpBlockErr(e)) && PROXIES.length > 1 && _pb < Math.min(PROXIES.length - 1, 2)) {
          const np = rotateProxy(a.email);
          logActivity(`[${tag}] proxy error saat login → rotate ke ${np ? np.host + ':' + np.port : '-'}`, COLOR.yellow);
        } else { throw e; }
      }
    }
    let { sv, partyId, identityToken, proxy } = clients;
    state.status = 'ok';
    let userServiceCid = getUserServiceCid(a.email);
    if (!userServiceCid) {
      logActivity(`[${tag}] discovery party (one-time)…`, COLOR.cyan);
      try {
        const party = await sv.recoverParty(partyId);
        if (party && party.userServiceCid) {
          userServiceCid = party.userServiceCid;
          patchAcctSession(a.email, { userServiceCid });
          logActivity(`[${tag}] userServiceCid tersimpan ✓`, COLOR.green);
        } else {
          logActivity(`[${tag}] recoverParty: party tidak ditemukan on-chain`, COLOR.red);
        }
      } catch (e) {
        logActivity(`[${tag}] recoverParty gagal: ${(e && e.message) || e}`, COLOR.red);
      }
    }
    // AUTO-DISCOVER next-action IDs (Silvana redeploy ~harian re-hash semua ID).
    // Self-heal: validate murah → scan+remap fingerprint kalau stale. Juga
    // dipanggil ulang tiap iterasi loop swap (lihat di bawah) buat tangkap
    // redeploy MID-RUN (404 reset actionIdsVerified → re-discover otomatis).
    await ensureActionIds(sv, partyId, tag);

    await refreshBalances(state, identityToken, proxy); render(global.__states);

    // Auto-cancel settlement nyangkut: DIMATIKAN (cancelSettlement masih gagal).
    // Aktifin lagi via config.swap.autoCancelStale=true kalau udah fix. User
    // bersihin manual (browser) dulu, bot tinggal swap.
    if (SWAP.autoCancelStale) {
      const cleaned = await cleanupStaleProposals(sv, clients.canton, partyId, (m, c) => logActivity(`[${tag}] ${m}`, c), clients.privy).catch(e => { logActivity(`[${tag}] cleanup error: ${(e && e.message) || e}`, COLOR.yellow); return 0; });
      if (cleaned) logActivity(`[${tag}] cleanup ${cleaned} proposal nyangkut di-cancel`, COLOR.green);
    }

    const dt = await fetchDayTrader(sv, partyId);
    if (!dt) { logActivity(`[${tag}] DAY_TRADER tak terbaca dari API → tidak swap`, COLOR.yellow); return; }
    state.dayTrader = { count: dt.current, target: dt.target }; render(global.__states);
    // Effective target: dailySwapCount di-cap oleh dt.target kecuali allowOvercap=true.
    const apiCap = Number(dt.target) || 0;
    const dailyCap = Math.max(1, Number(SWAP.dailySwapCount) || apiCap);
    const effective = SWAP.allowOvercap ? dailyCap : Math.min(dailyCap, apiCap);
    const apiHit = dt.completed || dt.current >= apiCap;
    if (apiHit && !SWAP.allowOvercap) { logActivity(`[${tag}] DAY_TRADER ${dt.current}/${dt.target} sudah penuh ✓`, COLOR.green); return; }
    const need = Math.max(0, effective - dt.current);
    if (need <= 0) { logActivity(`[${tag}] dailySwapCount ${dailyCap} sudah terpenuhi (count ${dt.current}) ✓`, COLOR.green); return; }
    const overcapTag = SWAP.allowOvercap && dailyCap > apiCap ? ` (overcap → target ${effective})` : '';
    logActivity(`[${tag}] DAY_TRADER ${dt.current}/${dt.target}${overcapTag} — perlu ${need} swap lagi`, COLOR.cyan);

    // Anchor accounting ke API count. Optimistic visual tetap, tapi done counter
    // baru naik kalau DAY_TRADER beneran naik on-chain. Cegah silent-overcap
    // ketika LP lambat allocate (swap submit OK tapi DvP gak settle).
    const startApi = dt.current;
    // Default 3 (bukan 1): settle DvP + update counter earn-hub async, kadang
    // telat lewat cooldown. Anti-overcap tetap aman (dibatasi diff API count).
    const MAX_STUCK = Math.max(1, Number(SWAP.maxStuckBeforeStop) || 2);
    // CC unlocked gak cukup utk fee (banyak CC kelock di settlement pending).
    // Tunggu beberapa kali biar settlement settle & unlock CC; kalau tetap kurang
    // setelah MAX_LOW_FEE, stop sesi (perlu top-up CC / nunggu unlock lama).
    const MAX_LOW_FEE = Math.max(1, Number(SWAP.maxLowFeeBeforeStop) || 5);
    let stuck = 0;
    let lowFeeStreak = 0;
    let done = 0;
    while (done < need) {
      // Refresh token Privy/Silvana kalau mendekati expired (session bisa berjam-jam)
      try {
        const fresh = await ensureFreshClients(state, clients);
        if (fresh !== clients) {
          clients = fresh;
          ({ sv, partyId, identityToken, proxy } = clients);
          logActivity(`[${tag}] token di-refresh (Privy+Silvana)`, COLOR.gray);
          render(global.__states);
        }
      } catch (e) {
        logActivity(`[${tag}] refresh token gagal: ${(e && e.message) || e}`, COLOR.yellow);
      }

      // Self-heal MID-RUN: kalau redeploy bikin ID 404 di tengah loop,
      // swapAction set actionIdsVerified=false → re-discover SEBELUM swap
      // berikut (token udah di-refresh di atas → cookie fresh buat discovery).
      await ensureActionIds(sv, partyId, tag);

      const chk = await fetchDayTrader(sv, partyId).catch(() => null);
      if (chk) {
        state.dayTrader = { count: chk.current, target: chk.target }; render(global.__states);
        const chkApiHit = chk.completed || chk.current >= chk.target;
        if (chkApiHit && !SWAP.allowOvercap) { logActivity(`[${tag}] DAY_TRADER ${chk.current}/${chk.target} ✓ — berhenti`, COLOR.green); break; }
        if (chkApiHit && SWAP.allowOvercap) logActivity(`[${tag}] DAY_TRADER ${chk.current}/${chk.target} ✓ — lanjut overcap (${done + 1}/${need})`, COLOR.gray);
      }

      // Pre-check: kalau ada settlement yang lagi in-progress (counterparty
      // belum allocate), tunggu dulu sebelum buka posisi baru. Hindari
      // lock balance ganda + race condition di ledger.
      const activeWaitMaxSec = Math.max(60, Number(SWAP.activeSettlementWaitSec) || 240);
      const activeStartMs = Date.now();
      while (Date.now() - activeStartMs < activeWaitMaxSec * 1000) {
        const active = await fetchActiveSettlements(sv, partyId).catch(() => []);
        if (!active.length) break;
        const newest = active.sort((a, b) => a.ageSec - b.ageSec)[0];
        const remain = activeWaitMaxSec - Math.floor((Date.now() - activeStartMs) / 1000);
        logActivity(`[${tag}] ${active.length} settlement aktif (terbaru stage ${newest.stage}, ${newest.ageSec}s old). Tunggu ${remain}s lagi…`, COLOR.gray);
        render(global.__states);
        await sleep(15_000); // poll tiap 15 detik
      }
      // Setelah waitMax habis: kalau masih ada → anggap stuck, lanjut aja.
      // (Server akan expire di settleBefore = createdAt+12h, tidak akan
      // mengganggu swap baru kecuali balance benar2 terkunci semua.)
      const stillActive = await fetchActiveSettlements(sv, partyId).catch(() => []);
      if (stillActive.length) {
        logActivity(`[${tag}] ⚠ ${stillActive.length} settlement masih in-progress, lanjut swap baru`, COLOR.yellow);
      }

      const usdc = await refreshBalances(state, identityToken, proxy);
      render(global.__states);

      // "RATA KANAN": swap sebanyak mungkin, sisakan reserveCC unlocked.
      //  SELL (CC→USDCx): amount = ccUnlocked − reserve (CC dipakai utk leg + fee).
      //  BUY  (USDCx→CC): amount = kapasitas USDCx; tapi tetap butuh CC ≥ reserve
      //                   buat fee. CC leg-nya nambah, jadi reserve gak kepakai leg.
      const ccUnlocked = ccUnlockedFrom(state);
      const reserve = Math.max(0, Number(SWAP_RESERVE) || 0);
      const minSwap = Number(SWAP_MIN);
      const floor4 = (n) => Math.floor(Math.max(0, n) * 10000) / 10000;

      let ask = 0;
      try {
        const priceRes = await sv.getPrice(SWAP.market).catch(() => null);
        ask = (priceRes && Number(priceRes.ask)) || 0;
      } catch (_) { ask = 0; }

      const tokenBudget = usdc * 0.95;                            // buffer slippage/fee; kalau actual LP rate lebih mahal, auto-adjust di catch handler
      // ask = quote-per-base. USDCx (base CC): USDCx/CC → CC = budget/ask.
      // cETH (base cETH): CC/cETH → CC = budget*ask. Kapasitas CC dari saldo token.
      const buyCapCC = ask > 0 ? floor4(SWAP.baseIsCC ? tokenBudget / ask : tokenBudget * ask) : 0;
      const maxAmt = SWAP_MAX_AMOUNT > 0 ? SWAP_MAX_AMOUNT : Infinity;

      // Hitung amount per mode. KEDUA mode sisakan reserveCC (config swap.reserveCC,
      // default 5) sbg CC floor → jaminan fee buat reversal token→CC saat saldo tipis.
      //   maxReserve: rata kanan, sisakan reserveCC, di-cap maxAmount per swap.
      //   minmax:     amount ACAK [minAmount..maxAmount], tetap sisakan reserveCC.
      let maxSellCC, maxBuyCC, canSell, canBuy, modeLabel;
      if (SWAP_MODE === 'minmax') {
        // floor batas bawah = minAmount, batas atas = maxAmount (atau saldo).
        const lo = Math.max(0, SWAP_MIN_AMOUNT);
        const hi = SWAP_MAX_AMOUNT > 0 ? Math.max(lo, SWAP_MAX_AMOUNT) : lo;
        const target = floor4(lo + Math.random() * (hi - lo)); // acak per swap
        const sellCapCC = floor4(ccUnlocked - reserve);        // sisakan reserveCC buat fee reversal
        maxSellCC = floor4(Math.min(target, sellCapCC));
        maxBuyCC = floor4(Math.min(target, buyCapCC));
        canSell = sellCapCC >= lo && maxSellCC >= lo;
        canBuy = buyCapCC >= lo && maxBuyCC >= lo && ccUnlocked >= reserve;
        modeLabel = `minmax ${lo}..${SWAP_MAX_AMOUNT || '∞'} sisa ${reserve}`;
      } else {
        // maxReserve (default): rata kanan, cap maxAmount.
        maxSellCC = floor4(Math.min(ccUnlocked - reserve, maxAmt));
        maxBuyCC = floor4(Math.min(buyCapCC, maxAmt));
        canSell = maxSellCC >= minSwap;
        canBuy = maxBuyCC >= minSwap && ccUnlocked >= reserve; // perlu CC buat fee
        modeLabel = `maxReserve cap ${SWAP_MAX_AMOUNT || '∞'} sisa ${reserve}`;
      }

      let amountCC, direction;
      // closeWithCC: jamin hari berakhir pegang CC.
      //   remaining<=2 → restock token (buy penutup butuh token), TAPI cuma kalau
      //                  token TIPIS. Kalau token udah cukup buat close → close aja.
      //   remaining<=1 → paksa BUY semua token jadi CC (floor minAmount, max BEBAS).
      const remaining = need - done;
      // Swap penutup: abaikan cap minmax/maxReserve, ambil SEMUA token (rata kanan).
      // Floor tetap minAmount (config). closeBuyCC = kapasitas CC dari SELURUH token held.
      const closeBuyCC = floor4(buyCapCC);
      const closeFloor = Math.max(minSwap, SWAP_MODE === 'minmax' ? Number(SWAP_MIN_AMOUNT) : minSwap);
      let forcedDir = global.__forceDir || SWAP.forceDirection || null;
      let closeBuyAll = false;
      if (!forcedDir && SWAP.closeWithCC) {
        if (remaining <= 1) { forcedDir = 'buy'; closeBuyAll = true; }
        else if (remaining <= 2) {
          // BALANCE-AWARE: restock-open (beli token) cuma kalau token TIPIS. Kalau
          // udah punya token cukup buat close (closeBuyCC >= floor), langsung CLOSE —
          // hemat CC langka & gak stuck nunggu quote buy (kasus token-heavy/CC-light).
          forcedDir = (closeBuyCC >= closeFloor) ? 'buy' : 'sell';
        }
      }
      if (forcedDir === 'sell') { direction = 'sell'; amountCC = String(maxSellCC); logActivity(`[${tag}] arah dipaksa: open (restock ${SWAP.tokenLabel}, sisa ${remaining})`, COLOR.gray); }
      else if (forcedDir === 'buy') {
        direction = 'buy';
        if (closeBuyAll && closeBuyCC >= closeFloor) {
          amountCC = String(closeBuyCC); // habisin token, max bebas
          logActivity(`[${tag}] swap penutup: CLOSE semua ${SWAP.tokenLabel} (~${closeBuyCC} CC, floor ${closeFloor}) → tutup pegang CC`, COLOR.cyan);
        } else if (closeBuyAll) {
          // token < minAmount → gak bisa close valid. Fallback open biar gak stuck.
          if (canSell) { direction = 'sell'; amountCC = String(maxSellCC); logActivity(`[${tag}] swap penutup: ${SWAP.tokenLabel} ~${closeBuyCC} CC < min ${closeFloor} → fallback open`, COLOR.yellow); }
          else { direction = 'buy'; amountCC = String(maxBuyCC); logActivity(`[${tag}] swap penutup: ${SWAP.tokenLabel} kurang & open gak bisa, coba close seadanya`, COLOR.yellow); }
        } else {
          amountCC = String(maxBuyCC); logActivity(`[${tag}] arah dipaksa: buy (override)`, COLOR.gray);
        }
      }
      else if (canBuy) { direction = 'buy'; amountCC = String(maxBuyCC); }   // prefer buy → balik ke CC
      else if (canSell) { direction = 'sell'; amountCC = String(maxSellCC); }
      else {
        // Dua-duanya gak cukup. Banyak CC mungkin masih kelock di settlement →
        // tunggu sebentar lalu cek ulang; kalau tetap, stop sesi (server unlock sendiri).
        logActivity(`[${tag}] saldo gak cukup utk swap (CC unlocked ${floor4(ccUnlocked)}, ${SWAP.tokenLabel} ${SWAP.baseIsCC ? floor4(usdc) : usdc}, mode ${modeLabel}). Tunggu unlock…`, COLOR.yellow);
        lowFeeStreak++;
        if (lowFeeStreak >= MAX_LOW_FEE) { logActivity(`[${tag}] Stop sesi: saldo kurang setelah ${MAX_LOW_FEE}x. Tunggu settlement unlock / top-up.`, COLOR.red); break; }
        await sleep(Math.min(90, 30 * lowFeeStreak) * 1000);
        continue;
      }
      // === ADAPTER PAIR ===
      // `direction` di atas = INTENT (sell=open CC→token, buy=close token→CC) &
      // `amountCC` = CC. Konversi ke arah market + quantity RFQ sesuai pair aktif:
      //   USDCx (base CC): identity (arah sama, qty = CC).
      //   cETH  (base token): arah flip (open=buy/close=sell) & qty = CC*ask (token).
      // ask = quote-per-base (USDCx: USDCx/CC; cETH: CC/cETH). qty RFQ = jumlah BASE:
      //   USDCx base=CC → qty = CC (ccAmt). cETH base=cETH → qty = ccAmt / ask (CC÷(CC/cETH)).
      const toRfq = (intent, ccAmt) => {
        const md = (intent === 'sell') ? SWAP.dirOpen : SWAP.dirClose;
        const q = SWAP.baseIsCC ? String(ccAmt) : fmt10(String(ask > 0 ? Number(ccAmt) / ask : 0));
        return { md, q };
      };
      const { md: marketDir, q: rfqQty } = toRfq(direction, amountCC);
      if (!(Number(rfqQty) > 0)) {
        logActivity(`[${tag}] qty RFQ 0 (harga ${SWAP.tokenLabel} belum ada / saldo kurang) — tunggu…`, COLOR.yellow);
        await sleep(SWAP.delayBetweenSwapsSec * 1000);
        continue;
      }
      logActivity(`[${tag}] ${marketDir} ${rfqQty} ${SWAP.baseIsCC ? 'CC' : SWAP.tokenLabel} [${direction === 'sell' ? 'CC→' + SWAP.tokenLabel : SWAP.tokenLabel + '→CC'}] (${modeLabel})`, COLOR.gray);

      // Eksekusi swap + optimistic update progress + cooldown + refresh
      // handleSuccess: optimistic visual + cooldown + sync. TIDAK increment done.
      // Caller (di bawah) yg increment berdasar delta API count beneran.
      // Return realDt biar caller bisa cek apakah swap settle on-chain.
      const handleSuccess = async (label) => {
        const baseCount = (state.dayTrader && Number(state.dayTrader.count)) || 0;
        if (state.dayTrader) {
          state.dayTrader = {
            count: Math.min(state.dayTrader.target, baseCount + 1),
            target: state.dayTrader.target,
          };
        }
        logActivity(`[${tag}] Swap ${label} submitted ✓ menunggu settle…`, COLOR.green);
        render(global.__states);

        // Poll DAY_TRADER sampai CONFIRMED on-chain — INFINITE (user request).
        // res.ok = settlement tx udah submit+complete on-chain; ini cuma nunggu
        // counter earn-hub catch-up (bisa telat menit-an). Jangan nyerah di 5 cek.
        // Cek cepat awal [15s,20s,30s], lalu steady (default 30s) selamanya sampai:
        //   - count NAIK (settle ke-register), ATAU
        //   - overcap & count SATURATED (>=target → gak bakal naik lagi, settle pasti
        //     kelar via res.ok), ATAU
        //   - cap opsional SWAP.settleWaitMaxMin (default 0 = infinite).
        // Token di-refresh tiap iterasi (wait panjang → Privy token ~1jam expired).
        const SYNC_WAITS = [15000, 20000, 30000];
        const STEADY_MS = Math.max(10000, (Number(SWAP.settleSyncSec) || 30) * 1000);
        const MAX_WAIT_MS = Math.max(0, Number(SWAP.settleWaitMaxMin) || 0) * 60000;
        let realDt = null;
        const tStart = Date.now();
        for (let r = 0; ; r++) {
          const w = r < SYNC_WAITS.length ? SYNC_WAITS[r] : STEADY_MS;
          logActivity(`[${tag}] Sync DAY_TRADER… (cek ${r + 1}, tunggu ${Math.round(w / 1000)}s, sampai confirmed)`, COLOR.gray);
          await sleep(w);
          try {
            const fr = await ensureFreshClients(state, clients);
            if (fr !== clients) { clients = fr; ({ sv, partyId, identityToken, proxy } = clients); }
          } catch (_) { }
          realDt = await fetchDayTrader(sv, partyId).catch(() => null);
          if (realDt) state.dayTrader = { count: realDt.current, target: realDt.target };
          await refreshBalances(state, identityToken, proxy);
          render(global.__states);
          if (realDt && realDt.current > baseCount) break;                          // ✓ settle ke-register on-chain
          if (SWAP.allowOvercap && realDt && realDt.current >= realDt.target) break; // saturated — count gak bakal naik
          if (MAX_WAIT_MS && Date.now() - tStart > MAX_WAIT_MS) {                    // cap opsional (default OFF)
            logActivity(`[${tag}] settle belum ke-register ${Math.round(MAX_WAIT_MS / 60000)} mnt — lanjut (cap settleWaitMaxMin)`, COLOR.yellow);
            break;
          }
        }
        return realDt;
      };

      // Wrapper swap dengan auto-retry untuk transient errors (CONTRACT_NOT_FOUND,
      // quote stale). Holding cid bisa expired antara query → submit, tinggal
      // retry dengan fresh data.
      const TRANSIENT_MAX_RETRY = 3;
      const TRANSIENT_RETRY_DELAY_MS = 4000;
      const swapWithRetry = async (dir, amt, label) => {
        let lastErr = null;
        // onWait: dipanggil di tengah RFQ-wait panjang → refresh token kalau mau expired.
        // Return clients terbaru supaya swapOnce pakai sv/canton fresh.
        const onWait = async () => {
          try {
            const fresh = await ensureFreshClients(state, clients);
            if (fresh !== clients) {
              clients = fresh;
              ({ sv, partyId, identityToken, proxy } = clients);
              logActivity(`[${tag}] token di-refresh (saat nunggu harga)`, COLOR.gray);
              render(global.__states);
              return clients;
            }
          } catch (_) { }
          return null;
        };
        for (let attempt = 1; attempt <= TRANSIENT_MAX_RETRY; attempt++) {
          try {
            const res = await swapOnce({ ...clients, userServiceCid, onWait, log: (m) => logActivity(`[${tag}] ${m}`), onWalletPicked: (id) => { try { patchAcctSession(a.email, { privyWalletId: id }); } catch (_) { } } }, dir, amt);
            return res;
          } catch (e) {
            lastErr = e;
            // 401 mid-flight: token expired → rebuild clients & retry
            if (e && e.unauthorized && attempt < TRANSIENT_MAX_RETRY) {
              logActivity(`[${tag}] token expired mid-swap → refresh & retry`, COLOR.yellow);
              try {
                clients = await buildSwapClients(state);
                ({ sv, partyId, identityToken, proxy } = clients);
              } catch (re) {
                logActivity(`[${tag}] refresh gagal: ${(re && re.message) || re}`, COLOR.red);
              }
              await sleep(2000);
              continue;
            }
            if (e && e.transient && attempt < TRANSIENT_MAX_RETRY) {
              logActivity(`[${tag}] ${shortSwapReason(e)} — retry ${attempt}/${TRANSIENT_MAX_RETRY - 1}`, COLOR.yellow);
              await sleep(TRANSIENT_RETRY_DELAY_MS);
              continue;
            }
            if ((isProxyErr(e) || isIpBlockErr(e)) && PROXIES.length > 1 && attempt < TRANSIENT_MAX_RETRY) {
              const np = rotateProxy(a.email);
              logActivity(`[${tag}] proxy error → rotate ke ${np ? np.host + ':' + np.port : '-'} (retry ${attempt}/${TRANSIENT_MAX_RETRY - 1})`, COLOR.yellow);
              try {
                clients = await buildSwapClients(state);
                ({ sv, partyId, identityToken, proxy } = clients);
              } catch (re) {
                logActivity(`[${tag}] rebuild clients gagal: ${(re && re.message) || re}`, COLOR.red);
              }
              await sleep(2000);
              continue;
            }
            throw e;
          }
        }
        throw lastErr;
      };

      try {
        const beforeApi = (state.dayTrader && Number(state.dayTrader.count)) || 0;
        const label = direction === 'sell' ? `CC→${SWAP.tokenLabel}` : `${SWAP.tokenLabel}→CC`;
        const res = await swapWithRetry(marketDir, rfqQty, label);
        if (res && res.ok) {
          if (res.feeCC) { recordBurn(res.feeCC, tag); bumpDaily(state, res.feeCC, 0); }
          const realDt = await handleSuccess(label);
          if (realDt && realDt.current > beforeApi) {
            done = Math.max(done + 1, realDt.current - startApi);
            stuck = 0;
            lowFeeStreak = 0;
            logActivity(`[${tag}] ✓ confirmed on-chain (DAY_TRADER ${realDt.current}/${realDt.target})`, COLOR.green);
          } else if (SWAP.allowOvercap && realDt && realDt.current >= realDt.target) {
            // Sudah lewat batas API DAY_TRADER. Counter pakai settle on-chain
            // (res.ok = settlement settled by waitForSettlement). Verifikasi
            // DAY_TRADER tetap di-log walau gak naik.
            done++;
            stuck = 0;
            lowFeeStreak = 0;
            logActivity(`[${tag}] ✓ confirmed on-chain overcap ${done}/${need} (DAY_TRADER ${realDt.current}/${realDt.target} saturated)`, COLOR.green);
          } else {
            stuck++;
            logActivity(`[${tag}] ⚠ submitted tapi DAY_TRADER belum naik (LP lambat allocate) — stuck ${stuck}/${MAX_STUCK}`, COLOR.yellow);
            if (stuck >= MAX_STUCK) {
              // User: ${MAX_STUCK} swap submit tapi count gak naik → STOP submit
              // swap baru (cegah balance ke-lock SEMUA di settlement pending).
              // Cuma poll DAY_TRADER infinity sampai naik (pending akhirnya settle
              // & unlock balance), baru lanjut swap.
              const baseline = startApi + done;
              const pollS = Math.max(60, Number(SWAP.stuckPollSec) || 300);
              logActivity(`[${tag}] ${MAX_STUCK} swap nyangkut. STOP swap, tunggu settle. Poll DAY_TRADER tiap ${Math.round(pollS / 60)} mnt sampai naik (balance gak ke-lock semua)`, COLOR.yellow);
              for (; ;) {
                await sleep(pollS * 1000);
                try {
                  const fr = await ensureFreshClients(state, clients);
                  if (fr !== clients) { clients = fr; ({ sv, partyId, identityToken, proxy } = clients); }
                } catch (_) { }
                const wdt = await fetchDayTrader(sv, partyId).catch(() => null);
                if (wdt) state.dayTrader = { count: wdt.current, target: wdt.target };
                await refreshBalances(state, identityToken, proxy);
                render(global.__states);
                if (wdt && (wdt.completed || wdt.current >= wdt.target) && !SWAP.allowOvercap) {
                  logActivity(`[${tag}] DAY_TRADER ${wdt.current}/${wdt.target} kebaca pas nunggu settle`, COLOR.green);
                  done = need; break;
                }
                if (wdt && wdt.current > baseline) {
                  done = Math.max(done, wdt.current - startApi);
                  stuck = 0;
                  logActivity(`[${tag}] settle kebaca (DAY_TRADER ${wdt.current}/${wdt.target}) — lanjut swap`, COLOR.green);
                  break;
                }
                logActivity(`[${tag}] belum settle (DAY_TRADER ${(wdt && wdt.current) ?? '?'}/${(wdt && wdt.target) ?? '?'}) — tunggu ${Math.round(pollS / 60)} mnt lagi…`, COLOR.gray);
              }
            }
          }
        }
      } catch (e) {
        if (e && e.aborted) { logActivity(`[${tag}] dibatalkan: ${e.message}`, COLOR.yellow); break; }
        // DvpProposal nyangkut (ledger penuh / settlement stuck) → akun ini gak
        // bisa swap sekarang. SKIP, lanjut akun berikutnya (jangan numpukin).
        if (e && e.dvpStuck) { logActivity(`[${tag}] DvpProposal nyangkut → skip akun, lanjut berikutnya`, COLOR.yellow); break; }
        // FEE PROTECTION: fee > maxFeeCC. JANGAN swap (walau daily belum kelar).
        // Tunggu feeSpikeWaitSec lalu retry — done TIDAK naik, ulang sampai fee turun.
        if (e && e.feeSpike) {
          const waitS = Math.max(60, Number(SWAP.feeSpikeWaitSec) || 300);
          logActivity(`[${tag}] fee spike ${e.feeCC} CC > ${SWAP.maxFeeCC} CC — TUNDA swap, cek lagi ${Math.round(waitS / 60)} mnt`, COLOR.yellow);
          // Bersihin proposal sisa fee-spike (gated — cancelSettlement masih gagal).
          if (SWAP.autoCancelStale) {
            const c = await cleanupStaleProposals(sv, clients.canton, partyId, undefined, clients.privy).catch(() => 0);
            if (c) logActivity(`[${tag}] cleanup ${c} proposal sisa fee-spike`, COLOR.gray);
          }
          await refreshBalances(state, identityToken, proxy);
          render(global.__states);
          await sleep(waitS * 1000);
          continue;
        }
        // Likuiditas belum ada: bukan error, retry siklus berikutnya
        // (token akan auto-refresh di awal loop). Delay singkat biar gak spam.
        if (e && e.noLiquidity) {
          logActivity(`[${tag}] likuiditas ${direction} belum ada, retry…`, COLOR.gray);
          await sleep(SWAP.delayBetweenSwapsSec * 1000);
          continue;
        }
        // CC unlocked kurang utk fee (fee tiap swap pakai CC, besarnya dari server).
        // CC banyak kelock di settlement pending → tunggu unlock, JANGAN spam fail.
        if (e && e.insufficientFunds) {
          lowFeeStreak++;
          const miss = e.missingAmount ? ` (~${e.missingAmount} CC kurang)` : '';
          if (lowFeeStreak >= MAX_LOW_FEE) {
            logActivity(`[${tag}] Stop sesi: CC unlocked gak cukup utk fee${miss} setelah ${MAX_LOW_FEE}x. Tunggu settlement unlock CC / top-up.`, COLOR.red);
            break;
          }
          const waitS = Math.min(90, 30 * lowFeeStreak);
          logActivity(`[${tag}] CC unlocked kurang utk fee${miss} — CC kelock di settlement. Tunggu ${waitS}s biar unlock… (${lowFeeStreak}/${MAX_LOW_FEE})`, COLOR.yellow);
          await refreshBalances(state, identityToken, proxy);
          render(global.__states);
          await sleep(waitS * 1000);
          continue;
        }
        // Close (intent 'buy' = token→CC) gagal karena token kurang → auto-adjust
        // amount pakai actual LP rate, retry close. Fallback open kalau adjusted < min.
        // (intent 'buy' = kita serahkan token di KEDUA pair → gating bener.)
        if (e && e.insufficientBalance && direction === 'buy') {
          let retried = false;
          const closeLabel = `${SWAP.tokenLabel}→CC (adj)`;
          if (e.tokenNeeded && e.tokenHave && Number(amountCC) > 0) {
            const lpRatio = e.tokenNeeded / Number(amountCC); // token per CC (actual LP rate)
            const adjCC = floor4(e.tokenHave * 0.94 / lpRatio); // 6% safety margin
            if (adjCC >= minSwap) {
              const r = toRfq('buy', adjCC);
              logActivity(`[${tag}] ${SWAP.tokenLabel} kurang (LP rate ${lpRatio.toFixed(8)}/CC) → retry close ${adjCC} CC (auto-adjusted)`, COLOR.yellow);
              try {
                const res2 = await swapWithRetry(r.md, r.q, closeLabel);
                if (res2 && res2.ok) {
                  if (res2.feeCC) { recordBurn(res2.feeCC, tag); bumpDaily(state, res2.feeCC, 0); }
                  await handleSuccess(closeLabel);
                  done++; stuck = 0; lowFeeStreak = 0;
                  retried = true;
                }
              } catch (e2) {
                logActivity(`[${tag}] close adj gagal: ${shortSwapReason(e2)}`, COLOR.yellow);
              }
            }
          }
          if (!retried) {
            const openLabel = `CC→${SWAP.tokenLabel}`;
            logActivity(`[${tag}] ${e.message} → coba open (${openLabel}) sebagai gantinya`, COLOR.yellow);
            try {
              const r = toRfq('sell', amountCC);
              const res2 = await swapWithRetry(r.md, r.q, openLabel);
              if (res2 && res2.ok) { await handleSuccess(openLabel); continue; }
            } catch (e2) {
              if (e2 && e2.noLiquidity) { logActivity(`[${tag}] likuiditas open belum ada, retry…`, COLOR.gray); await sleep(SWAP.delayBetweenSwapsSec * 1000); continue; }
              logActivity(`[${tag}] swap open juga gagal: ${shortSwapReason(e2)}`, COLOR.red);
            }
          }
        } else {
          logActivity(`[${tag}] swap ${marketDir} gagal: ${shortSwapReason(e)}`, COLOR.red);
        }
        if (process.env.SWAP_DEBUG && e && e.stack) console.error('[swap-error-stack]', e.stack);
        await sleep(SWAP.delayBetweenSwapsSec * 1000);
      }
    }
    const fin = await fetchDayTrader(sv, partyId).catch(() => null);
    if (fin) { state.dayTrader = { count: fin.current, target: fin.target }; logActivity(`[${tag}] Selesai: DAY_TRADER ${fin.current}/${fin.target}${fin.current >= fin.target ? ' ✓' : ''}`, fin.current >= fin.target ? COLOR.green : COLOR.yellow); }
    render(global.__states);
  } catch (e) { throw e; }   // RETHROW → runAccountSwapSession (retry akun-level)
}
// Retry akun-level: setup transient/timeout (login/discovery actionID/balance/DAY_TRADER)
// dulu mati sekali → status Error, nunggu jadwal. Sekarang retry backoff dulu. AMAN krn
// sesi swap count-anchored ke DAY_TRADER API → re-run gak over-swap (sama kayak re-trigger
// startup/jadwal/dashboard). Cuma retry error TRANSIENT (timeout/reset/unauthorized/proxy);
// error lain → langsung Error. Config: swap.accountRetry (default 3).
async function runAccountSwapSession(i) {
  const a = ACCOUNTS[i], tag = a.label || a.email;
  const state = (global.__states && global.__states[i]) || makeStates()[i];
  const MAX = Math.max(1, Number((CONFIG.swap || {}).accountRetry) || 3);
  for (let attempt = 1; attempt <= MAX; attempt++) {
    try { await _accountSwapOnce(i); return; }
    catch (e) {
      const retryable = !!(e && (e.transient || e.unauthorized)) || isProxyErr(e);
      if (retryable && attempt < MAX) {
        const w = Math.min(30, 5 * attempt);
        logActivity(`[${tag}] setup gagal (${shortSwapReason(e)}) — retry akun ${attempt}/${MAX - 1}, tunggu ${w}s`, COLOR.yellow);
        state.status = 'idle'; state.message = `retry ${attempt}/${MAX - 1}`; render(global.__states);
        await sleep(w * 1000);
        continue;
      }
      state.status = 'error'; state.message = (e && e.message) || String(e);
      logActivity(`[${tag}] error: ${(e && e.message) || e}`, COLOR.red);
      return;
    }
  }
}

// Orkestrasi sesi swap semua akun. parallel (config swap.parallel, cuma opsi 0/1)
// vs sequential 1-per-1. OTP mutex global + token watcher bikin parallel aman.
async function runDayTraderSession(reason) {
  if (dtSessionRunning) { logActivity(`Sesi masih berjalan, lewati (${reason || ''})`, COLOR.gray); return; }
  dtSessionRunning = true;
  const conc = Math.max(1, Number(SWAP.concurrency) || 1);
  logActivity(`Mulai cek & auto-swap (${reason || 'manual'})${parallelSwapActive ? ` [parallel x${conc}]` : ''}`, COLOR.cyan);
  try {
    if (parallelSwapActive) {
      await mapLimit(ACCOUNTS.map((_, i) => i), conc, runAccountSwapSession);
    } else {
      for (let i = 0; i < ACCOUNTS.length; i++) await runAccountSwapSession(i);
    }
    logActivity('Sesi selesai — berhenti sampai jadwal berikutnya.', COLOR.cyan);
  } finally { dtSessionRunning = false; }
}

// ── Swap back ke CC (opsi 6) ──────────────────────────────────────────────────
// Dump SEMUA token aktif (SWAP.tokenId, di-set via setActivePair) → CC utk 1 akun.
// Reuse swapOnce (intent close/buy). UNLOCKED aja (ga reclaim lock). Loop sampai
// token dust (<minCC) ATAU CC unlocked < reserveCC (gak cukup fee reversal).
// Return {swaps, finalTok}. global.__states sengaja unset → render no-op (stdout bersih).
async function swapBackAccountToCC(state, log = () => { }) {
  const tag = state.label || state.email;
  const floor4 = (n) => Math.floor(Math.max(0, n) * 10000) / 10000;
  const reserve = Math.max(0, Number(SWAP_RESERVE) || 0);
  const minSwap = Number(SWAP_MIN);
  // Dust floor swap-back (CC equivalent). EDELx min-swap Silvana tinggi → sisa < 10 CC gak
  // bisa di-swap (bakal gagal/loop) → anggep dust, skip. Config swap.edelCethSwapBackDustCC.
  const dustFloorCC = SWAP.pairKey === 'edelx'
    ? Math.max(minSwap, Number((CONFIG.swap || {}).edelCethSwapBackDustCC) || 10)
    : minSwap;
  state.status = 'login';
  let clients;
  for (let pb = 0; pb <= Math.min(PROXIES.length - 1, 2); pb++) {
    try { clients = await buildSwapClients(state); break; }
    catch (e) {
      if ((isProxyErr(e) || isIpBlockErr(e)) && PROXIES.length > 1 && pb < Math.min(PROXIES.length - 1, 2)) { const np = rotateProxy(state.email); log(`[${tag}] proxy error login → rotate ${np ? np.host + ':' + np.port : '-'}`, COLOR.yellow); }
      else throw e;
    }
  }
  let { sv, partyId, identityToken, proxy } = clients;  // privy/canton dipakai swapOnce via ...clients
  state.status = 'ok';
  let userServiceCid = getUserServiceCid(state.email);
  if (!userServiceCid) {
    try { const party = await sv.recoverParty(partyId); if (party && party.userServiceCid) { userServiceCid = party.userServiceCid; patchAcctSession(state.email, { userServiceCid }); } }
    catch (e) { log(`[${tag}] recoverParty gagal: ${(e && e.message) || e}`, COLOR.yellow); }
  }
  await ensureActionIds(sv, partyId, tag);

  let swaps = 0;
  const t0 = Date.now(), BUDGET_MS = 1_800_000, MAX_ROUNDS = 40; // ~30 mnt/akun
  let round = 0;
  while (round < MAX_ROUNDS && Date.now() - t0 < BUDGET_MS) {
    round++;
    try { const fr = await ensureFreshClients(state, clients); if (fr !== clients) { clients = fr; ({ sv, partyId, identityToken, proxy } = clients); } } catch (_) { }
    await ensureActionIds(sv, partyId, tag);

    const tokUnlocked = await refreshBalances(state, identityToken, proxy).catch(() => 0);
    const ccUnlocked = ccUnlockedFrom(state);
    if (!(tokUnlocked > 0)) { log(`[${tag}] ${SWAP.tokenLabel} habis (0 unlocked) → selesai`, COLOR.green); break; }

    let ask = 0;
    // ask fallback ke last: EDELx-CC source "Calculated" gak punya bid/ask, cuma last.
    try { const pr = await sv.getPrice(SWAP.market).catch(() => null); ask = Number(pr && (pr.ask != null ? pr.ask : pr.last)) || 0; } catch (_) { ask = 0; }
    if (!(ask > 0)) { log(`[${tag}] harga ${SWAP.market} belum ada — tunggu`, COLOR.yellow); await sleep(Math.min(30000, SWAP.rfqRetryMs || 30000)); continue; }

    // Attempt awal = MAX. EDELx: 100% token (rata kanan; kalau insufficient di-reduce LP-rate
    // bertahap di catch, kek opsi 0/1). USDCx/cETH: buffer 0.95 (proven, cegah retry ekstra).
    const budgetFactor = SWAP.pairKey === 'edelx' ? 1.0 : 0.95;
    const tokenBudget = tokUnlocked * budgetFactor;
    const buyCapCC = floor4(SWAP.baseIsCC ? tokenBudget / ask : tokenBudget * ask);
    if (buyCapCC < dustFloorCC) { log(`[${tag}] sisa ${SWAP.tokenLabel} ~${buyCapCC} CC < min ${dustFloorCC} (dust) → selesai`, COLOR.green); break; }
    if (ccUnlocked < reserve) { log(`[${tag}] CC unlocked ${floor4(ccUnlocked)} < reserve ${reserve} (fee reversal) — butuh top-up CC, stop`, COLOR.red); break; }

    // close swap: intent buy (token→CC). md=dirClose, qty=base (CC kalau baseIsCC, else token).
    // REDUCTION: kalau insufficientBalance (token kurang gara2 LP rate ≠ quote walau saldo
    // > floor), kurangi amount pakai LP rate AKTUAL (mirror flow swap normal L3123) & retry
    // dikit demi dikit sampai muat / dust. Cegah stop padahal token masih ada.
    const md = SWAP.dirClose;
    let attemptCC = buyCapCC;
    let outcome = 'retry';   // 'ok' | 'stop' | 'dust' | 'retry'
    for (let adj = 0; adj <= 5; adj++) {
      if (attemptCC < dustFloorCC) { log(`[${tag}] sisa ${SWAP.tokenLabel} ~${attemptCC} CC < min ${dustFloorCC} (dust) → selesai`, COLOR.green); outcome = 'dust'; break; }
      const q = SWAP.baseIsCC ? String(attemptCC) : fmt10(String(ask > 0 ? attemptCC / ask : 0));
      if (!(Number(q) > 0)) { outcome = 'retry'; break; }
      log(`[${tag}] swap-back #${swaps + 1}: ${md} ${q} ${SWAP.baseIsCC ? 'CC' : SWAP.tokenLabel} [${SWAP.tokenLabel}→CC ~${attemptCC} CC${adj ? ` adj#${adj}` : ''}]`, COLOR.cyan);
      try {
        const res = await swapOnce({ ...clients, userServiceCid, log: (m) => log(`[${tag}] ${m}`, COLOR.gray), onWalletPicked: (id) => { try { patchAcctSession(state.email, { privyWalletId: id }); } catch (_) { } } }, md, q);
        if (res && res.ok) { swaps++; if (res.feeCC) { recordBurn(res.feeCC, tag); bumpDaily(state, res.feeCC, 0); } log(`[${tag}] ✓ swap-back #${swaps} sukses (fee ${res.feeCC != null ? res.feeCC + ' CC' : '?'})`, COLOR.green); outcome = 'ok'; }
        else { log(`[${tag}] swap-back gagal (no ok) — stop`, COLOR.yellow); outcome = 'stop'; }
        break;
      } catch (e) {
        // token kurang utk leg → kurangi pakai LP rate aktual (tokenHave) + margin 6%, retry.
        if (e && e.insufficientBalance) {
          const prev = attemptCC;
          if (e.tokenNeeded && e.tokenHave && attemptCC > 0) {
            const lpRatio = e.tokenNeeded / attemptCC;             // token per CC (rate aktual)
            attemptCC = floor4(lpRatio > 0 ? (e.tokenHave * 0.94 / lpRatio) : attemptCC * 0.9);
          } else attemptCC = floor4(attemptCC * 0.9);
          if (!(attemptCC > 0) || attemptCC >= prev) attemptCC = floor4(prev * 0.9);  // JAMIN turun
          log(`[${tag}] ${SWAP.tokenLabel} kurang (LP rate) → kurangi ${prev} → ${attemptCC} CC, retry`, COLOR.yellow);
          continue;
        }
        if (e && e.feeSpike) { const w = Math.max(60, Number(SWAP.feeSpikeWaitSec) || 300); log(`[${tag}] fee spike ${e.feeCC} > ${SWAP.maxFeeCC} CC — tunggu ${Math.round(w / 60)} mnt`, COLOR.yellow); await sleep(w * 1000); outcome = 'retry'; break; }
        if (e && e.insufficientFunds) { log(`[${tag}] CC kurang buat fee — stop (top-up CC)`, COLOR.red); outcome = 'stop'; break; }
        if (e && e.noLiquidity) { log(`[${tag}] likuiditas ${SWAP.tokenLabel}→CC belum ada — retry`, COLOR.gray); outcome = 'retry'; break; }
        if (e && (e.transient || e.unauthorized)) {
          log(`[${tag}] ${shortSwapReason(e)} — retry`, COLOR.yellow);
          if (e.unauthorized) { try { clients = await buildSwapClients(state); ({ sv, partyId, identityToken, proxy } = clients); } catch (_) { } }
          await sleep(4000); outcome = 'retry'; break;
        }
        log(`[${tag}] swap-back error: ${shortSwapReason(e)} — stop`, COLOR.red); outcome = 'stop'; break;
      }
    }
    if (outcome === 'stop' || outcome === 'dust') break;   // keluar while-ronde
    await sleep(SWAP.delayBetweenSwapsSec * 1000);          // 'ok'/'retry' → ronde berikut (refresh + recompute)
  }
  const finalTok = await refreshBalances(state, identityToken, proxy).catch(() => 0);
  log(`[${tag}] selesai: ${swaps} swap-back, sisa ${SWAP.tokenLabel} ${floor4(finalTok)} unlocked`, swaps ? COLOR.green : COLOR.yellow);
  return { swaps, finalTok };
}

// ── Ping-pong EDELx↔cETH (opsi 8) ─────────────────────────────────────────────
// Logic ikuti opsi 0/1 (target-driven dari earn-hub, semua akun, parallel/seq,
// reschedule harian) TAPI proses swap disesuaikan: token↔token (market EDELx-cETH,
// NO CC leg). Target dari task "EDELx-cETH Daily Trader". Tiap ronde: deteksi token
// dominan (CC-value) → dump FULL ke lawan (EDELx→cETH=sell, cETH→EDELx=buy). Fee CC
// terpisah (Amulet batch). Stop saat task X/X, dua token dust, atau CC habis (fee).
async function fetchEdelCethTrader(sv, partyId) {
  const tasks = await sv.earnTasks(partyId);
  return { dt: parseEdelCethTrader(tasks && tasks.items), all: dumpTaskCodes(tasks && tasks.items) };
}
// Refresh POIN (earnStats.totalPoints / fallback unclaimed) + opsional STREAK (task MONTHLY).
// Dipanggil pas sync swap selesai: POIN tiap swap, STREAK cuma swap pertama daily (withStreak).
async function refreshEarnStats(state, sv, partyId, opts = {}) {
  const withStreak = !!opts.withStreak;
  try {
    const stats = await sv.earnStats().catch(() => null);
    let pts = (stats && stats.totalPoints != null && Number.isFinite(Number(stats.totalPoints))) ? Number(stats.totalPoints) : null;
    if (withStreak || pts == null) {
      const tasks = await sv.earnTasks(partyId).catch(() => null);
      if (pts == null) pts = extractUnclaimedPoints(tasks);
      if (withStreak) { const stk = parseMonthlyStreak(tasks && tasks.items); if (stk != null) state.streak = stk; }
    }
    if (pts != null) { state.points = pts; updatePointsDiff(state); }
  } catch (_) { /* keep last */ }
}
async function runEdelCethAccount(i) {
  const a = ACCOUNTS[i], tag = a.label || a.email;
  const state = (global.__states && global.__states[i]) || makeStates()[i];
  const floor6 = (n) => Math.floor(Math.max(0, n) * 1e6) / 1e6;
  const reserve = Math.max(0, Number(SWAP_RESERVE) || 0);
  // Sizing mode 8 (config.mode8): usdAmount = ukuran leg EDELx→cETH (jual $12 tiap kali).
  // cETH→EDELx SELALU max (dump semua cETH), gagal → −1%/retry floor minUsd. minUsd =
  // gate dust (dua token < ini → stop) + floor reduce. Swap LANGSUNG, tanpa wait-recovery.
  const usdAmount = M8.usdAmount;
  const minUsd = M8.minUsd;
  try {
    state.status = 'login'; render(global.__states);
    let clients;
    for (let pb = 0; pb <= Math.min(PROXIES.length - 1, 2); pb++) {
      try { clients = await buildSwapClients(state); break; }
      catch (e) { if ((isProxyErr(e) || isIpBlockErr(e)) && PROXIES.length > 1 && pb < Math.min(PROXIES.length - 1, 2)) { const np = rotateProxy(state.email); logActivity(`[${tag}] proxy error login → rotate ${np ? np.host + ':' + np.port : '-'}`, COLOR.yellow); } else throw e; }
    }
    let { sv, partyId, identityToken, proxy } = clients;
    state.status = 'ok';
    let userServiceCid = getUserServiceCid(state.email);
    if (!userServiceCid) { try { const p = await sv.recoverParty(partyId); if (p && p.userServiceCid) { userServiceCid = p.userServiceCid; patchAcctSession(state.email, { userServiceCid }); } } catch (_) { } }
    await ensureActionIds(sv, partyId, tag);

    // Target dari earn-hub task EDELx-cETH (analog DAY_TRADER).
    let tinfo = await fetchEdelCethTrader(sv, partyId).catch(() => ({ dt: null, all: '' }));
    logActivity(`[${tag}] earn-hub tasks: ${tinfo.all || '(kosong)'}`, COLOR.gray);
    let dt = tinfo.dt;
    if (!dt) { logActivity(`[${tag}] task EDELx-cETH Daily Trader tak terbaca — set config swap.edelCethTaskCode (lihat list di atas). Skip.`, COLOR.yellow); return; }
    state.dayTrader = { count: dt.current, target: dt.target }; render(global.__states);
    // allowOvercap (kayak opsi 0/1): false → stop pas task penuh (10/10). true → lanjut
    // sampai dailyCap TOTAL swap sesi (task capped 10, jadi pakai counter `swaps` lokal).
    const overcap = M8.allowOvercap;
    const startCount = Number(dt.current) || 0;
    const dailyCap = M8.dailyCap;
    if (overcap ? (startCount >= dailyCap) : (dt.current >= dt.target)) { logActivity(`[${tag}] EDELx-cETH ${dt.current}/${dt.target}${overcap ? ` (overcap cap ${dailyCap})` : ''} sudah penuh ✓`, COLOR.green); return; }
    logActivity(`[${tag}] EDELx-cETH ${dt.current}/${dt.target} (task ${dt.code})${overcap ? ` — overcap → target ${dailyCap} swap` : ''} — mulai ping-pong`, COLOR.cyan);

    let swaps = 0;
    // Target tercapai: overcap → total swap sesi (startCount+swaps) ≥ dailyCap; else → task penuh.
    const targetReached = () => overcap ? (startCount + swaps >= dailyCap) : (dt && dt.current >= dt.target);
    let priceChecks = 0;  // counter cek-harga → tiap M8.cleanupEveryChecks: drain DvpProposal stale (kayak opsi 5)
    let proxyFails = 0;   // proxy error beruntun: retry 2x proxy sama, ke-3 rotate
    let hardErrs = 0;     // error tak-terklasifikasi beruntun → backoff naik (retry infinite, JANGAN stop)
    // RETRY INFINITE: gak ada cap ronde/waktu. Pas LP outage bot terus nyoba (proposal
    // timeout → retry ronde berikut) sampai target penuh / dust / CC habis. JANGAN berhenti
    // & nunggu jadwal besok. Target di-refresh tiap ronde (bisa reset 07:00 saat sesi jalan).
    while (true) {
      try { const fr = await ensureFreshClients(state, clients); if (fr !== clients) { clients = fr; ({ sv, partyId, identityToken, proxy } = clients); } } catch (_) { }
      await ensureActionIds(sv, partyId, tag);
      try { const ti = await fetchEdelCethTrader(sv, partyId); if (ti && ti.dt) { dt = ti.dt; state.dayTrader = { count: dt.current, target: dt.target }; } } catch (_) { }
      if (targetReached()) { logActivity(`[${tag}] EDELx-cETH ${dt.current}/${dt.target}${overcap ? ` (overcap ${startCount + swaps}/${dailyCap})` : ''} ✓ — berhenti`, COLOR.green); break; }

      // populate state.balances (SWAP.tokenId apapun; kita baca EDELx/cETH/CC manual).
      SWAP.tokenId = 'EDELX';
      await refreshBalances(state, identityToken, proxy).catch(() => 0);
      const edelx = unlockedOf(state, 'EDELX');
      const ceth = unlockedOf(state, 'CETH');
      const cc = ccUnlockedFrom(state);
      if (cc < reserve) { logActivity(`[${tag}] CC ${floor6(cc)} < reserve ${reserve} (fee reversal) — stop, top-up CC`, COLOR.red); break; }

      let deliver, edelxQty, minQty = 0, isMaxDump = false;   // minQty = EDELx senilai min swap (floor reduce); isMaxDump = dump penuh (kena haircut)
      let deliveredUsd = 0;   // USD-value niat yg dideliver (modal net gate; loss diukur delta real)
      // Di-hoist ke scope ronde biar net gate (bawah blok) bisa baca harga (spread) + deliveredUsd.
      let pe = null, pc = null, usdPerEdelx = 0, usdPerCeth = 0;
      let night = false;
      // Sizing baru: harga USD dari EDELx-USDCx & cETH-USDCx (USDCx≈USD, getPrice read-only,
      // 0 DvpProposal). Priority cETH: kalau ADA cETH (>minUsd) → dump SEMUA (auto ping-pong
      // balik ke EDELx), gagal −1%/retry floor minUsd. Kalau gak → jual EDELx sebesar usdAmount
      // ($12), atau max EDELx kalau worth < usdAmount. Dua-duanya < minUsd → dust, stop.
      {
        const usdPx = (pd) => { const b = Number(pd && pd.bid), a = Number(pd && pd.ask), l = Number(pd && pd.last); return (l > 0 ? l : (a > 0 && b > 0 ? (a + b) / 2 : (a > 0 ? a : (b > 0 ? b : 0)))) || 0; };
        pe = await sv.getPrice('EDELx-USDCx').catch(() => null);
        pc = await sv.getPrice('cETH-USDCx').catch(() => null);
        usdPerEdelx = usdPx(pe); usdPerCeth = usdPx(pc);
        if (!(usdPerEdelx > 0) || !(usdPerCeth > 0)) { logActivity(`[${tag}] harga USD belum ada — tunggu`, COLOR.yellow); await sleep(Math.min(30000, SWAP.rfqRetryMs || 30000)); continue; }
        // Cleanup rutin (req #3): tiap M8.cleanupEveryChecks cek-harga → drain DvpProposal stale (expired),
        // engine sama kayak opsi 5. AMAN mid-sesi (cuma reject yg lewat settleBefore, skip in-flight).
        priceChecks++;
        if (M8.cleanupEveryChecks > 0 && priceChecks % M8.cleanupEveryChecks === 0) {
          try {
            const ndr = await drainStaleDvpProposals(clients.sv, clients.canton, clients.privy, partyId, (m, c) => logActivity(`[${tag}] ${m}`, c));
            if (ndr) logActivity(`[${tag}] cleanup rutin (#${priceChecks} cek): ${ndr} DvpProposal stale di-drain`, COLOR.green);
          } catch (e) { logActivity(`[${tag}] cleanup rutin gagal: ${(e && e.message) || e}`, COLOR.yellow); }
        }
        night = mode8IsNight();   // di luar jam siang (dayEndHour..dayStartHour) → trabas: abaikan net + fee gate
        const valE = edelx * usdPerEdelx, valC = ceth * usdPerCeth;
        minQty = floor6(minUsd / usdPerEdelx);
        if (valC > minUsd) {
          // cETH → EDELx (buy), dump SEMUA cETH. Order dibayar cETH di ref×(1+orderCross)
          // (aggressive cross). Size di harga ORDER (bagi 1+orderCross) biar cost ≤ saldo cETH
          // → gak insufficient → gak retry −1% tiap swap. (Sebelumnya size di ref → 2% overshoot.)
          deliver = 'cETH';
          edelxQty = floor6((ceth * usdPerCeth) / usdPerEdelx / (1 + M8.orderCross));
          deliveredUsd = valC;
          isMaxDump = true;   // dump penuh cETH → pre-reduce haircut buffer
          logActivity(`[${tag}] deliver cETH MAX ${floor6(ceth)} (~$${valC.toFixed(2)}) → ${edelxQty} EDELx`, COLOR.gray);
        } else if (valE > minUsd) {
          // EDELx → cETH (sell), sebesar usdAmount (atau max EDELx kalau worth < usdAmount).
          deliver = 'EDELx';
          const swapUsd = Math.min(valE, usdAmount);
          edelxQty = floor6(swapUsd / usdPerEdelx);
          deliveredUsd = swapUsd;
          isMaxDump = swapUsd >= valE - 1e-9;   // haircut cuma kalau dump SEMUA EDELx (bukan leg fixed-$)
          logActivity(`[${tag}] deliver EDELx $${swapUsd.toFixed(2)} → ${edelxQty} EDELx @ $${usdPerEdelx.toFixed(6)}`, COLOR.gray);
        } else {
          logActivity(`[${tag}] EDELx $${valE.toFixed(2)} & cETH $${valC.toFixed(2)} dust (<$${minUsd}) → selesai`, COLOR.green);
          break;
        }
      }
      if (!(edelxQty > 0)) { await sleep(3000); continue; }

      // NET GATE round-trip (req #1: cari profit / allowed-loss) — anchor EDELx, SIANG aja.
      // BUKA posisi (EDELx→cETH) = bebas (catat modal pas sukses). TUTUP (cETH→EDELx, dump SEMUA cETH)
      // DI-GATE: EDELx yg diterima balik harus ≥ modal + minNetUsd. minNetUsd NEGATIF = allowed-loss,
      // POSITIF = cari profit, 0 = break-even, null = gate mati. MALAM (night) → dilewati (trabas).
      if (!night && M8.minNetUsd != null && deliver === 'cETH') {
        const hs = (pd) => { const b = Number(pd && pd.bid), a = Number(pd && pd.ask); return (a > 0 && b > 0) ? (a - b) / (a + b) : 0; };
        const spreadCost = deliveredUsd * (hs(pe) + hs(pc));   // deliveredUsd = valC (nilai cETH yg didump)
        // Haircut FIXED 0.1% (M8.haircut): terminal fee tetap (maker 0.1%), gak adaptif lagi.
        // rf = 1 − haircut. EDELx yg BALIK ≈ rf×value − spread.
        const rf = 1 - M8.haircut;
        const recvEdelxUsd = deliveredUsd * rf - spreadCost;   // ≈ USD-value EDELx yg beneran diterima balik
        const ref = getEdelCethRoundUsd(state.email);          // modal EDELx yg dikeluarin pas buka posisi
        if (ref != null) {
          const pnlEst = recvEdelxUsd - ref;
          if (pnlEst < M8.minNetUsd) {
            const w = Math.max(60, Number(M8.netWaitSec) || 300);
            logActivity(`[${tag}] tutup ditahan: EDELx balik ~$${recvEdelxUsd.toFixed(2)} (haircut ${(rf * 100).toFixed(1)}%) < modal $${ref.toFixed(2)} ${M8.minNetUsd >= 0 ? '+' : ''}${M8.minNetUsd} (pnl $${pnlEst.toFixed(3)}, ${M8.minNetUsd >= 0 ? 'cari profit' : 'allowed-loss'}) — tunda ${Math.round(w / 60)} mnt`, COLOR.yellow);
            await sleep(w * 1000); continue;
          }
        }
        // ref null (orphan cETH tanpa modal tercatat) → dump bootstrap, gak ditahan.
      }

      const { direction, leg } = edelCethLeg(deliver);   // ctx.leg (per-call, anti-race parallel)

      const countBefore = (dt && Number(dt.current)) || 0;   // task count sebelum swap (buat confirm on-chain)
      const recvId = deliver === 'EDELx' ? 'CETH' : 'EDELX'; // token yg bakal DITERIMA (settle → kredit ke unlocked)
      const recvBefore = unlockedOf(state, recvId);
      // Deliver side (buat ukur qty yg BENERAN keluar wallet — dust yg di-cancel gak kehitung).
      const deliverId = deliver === 'EDELx' ? 'EDELX' : 'CETH';
      const deliverBefore = unlockedOf(state, deliverId);
      const deliverPriceUsd = deliver === 'EDELx' ? usdPerEdelx : usdPerCeth;
      // Haircut FIXED (cuma MAX-DUMP): potong qty teoritis −haircut (0.1%) duluan biar
      // attempt-1 lolos (buffer deliver ≤ saldo), gak retry −1% dari nol. rf = 1 − haircut.
      if (isMaxDump) {
        const rf = 1 - M8.haircut;
        if (rf < 1) {
          let hq = floor6(edelxQty * rf);
          if (minQty > 0 && hq < minQty) hq = minQty;   // jangan di bawah min swap
          if (hq > 0 && hq < edelxQty) {
            logActivity(`[${tag}] haircut ${(M8.haircut * 100).toFixed(2)}%: ${edelxQty} → ${hq} EDELx`, COLOR.gray);
            edelxQty = hq;
          }
        }
      }
      let outcome = 'retry';
      let lastDustEdelx = 0;   // dust EDELx yg di-cancel di swap SUKSES (ketahan, bukan hilang) → koreksi loss
      for (let adj = 0; adj <= 60; adj++) {
        if (!(edelxQty > 0)) { outcome = 'dust'; break; }
        const q = fmt10(String(edelxQty));
        logActivity(`[${tag}] ping-pong #${swaps + 1}: ${direction} ${deliver}→${deliver === 'EDELx' ? 'cETH' : 'EDELx'} (${q} EDELx${adj ? ` adj#${adj}` : ''})`, COLOR.cyan);
        try {
          const res = await terminalSwapOnce({ ...clients, userServiceCid, leg, maxFeeCC: night ? Infinity : M8.maxFeeCC, minUsd, usdPerEdelx, cethPerEdelx: (usdPerCeth > 0 ? usdPerEdelx / usdPerCeth : 0), log: (m) => logActivity(`[${tag}] ${m}`, COLOR.gray), onWalletPicked: (id) => { try { patchAcctSession(state.email, { privyWalletId: id }); } catch (_) { } } }, direction, q);
          if (res && res.ok) { swaps++; proxyFails = 0; hardErrs = 0; lastDustEdelx = Number(res.dustEdelx) || 0; if (res.feeCC) { recordBurn(res.feeCC, tag); bumpDaily(state, res.feeCC, 0); } logActivity(`[${tag}] ✓ ping-pong #${swaps} sukses (fee ${res.feeCC != null ? res.feeCC + ' CC' : '?'})`, COLOR.green); outcome = 'ok'; }
          else { logActivity(`[${tag}] ping-pong gagal (no ok) — retry`, COLOR.yellow); await sleep(4000); outcome = 'retry'; }
          break;
        } catch (e) {
          // Server-side "Insufficient <tok> balance. Need X, available Y": local pre-check
          // (pakai estimate ourLeg.amount) lolos saat need≈available, tapi cost LP aktual >
          // estimate → settle nolak. Normalisasi → insufficientBalance biar reduce-retry jalan.
          if (e && !e.insufficientBalance) {
            const em = (e && e.message) || '';
            const nm = em.match(/Need\s*([0-9.]+)[\s,]+available\s*([0-9.]+)/i);
            if (nm || /Insufficient\s+\w+\s+balance/i.test(em)) {
              e.insufficientBalance = true;
              if (nm) { e.tokenNeeded = Number(nm[1]); e.tokenHave = Number(nm[2]); }
            }
          }
          if (e && e.insufficientBalance) {
            // Token kurang (cETH-max / EDELx) → turun 1%/retry, floor di qty senilai minUsd.
            // Kalau udah di min swap tapi tetap kurang → skip ronde, retry nanti (settle blm cair).
            const prev = edelxQty;
            if (minQty > 0 && prev <= minQty * 1.0001) {
              logActivity(`[${tag}] ${leg.tokenLabel} kurang bahkan di min swap — skip ronde`, COLOR.yellow);
              outcome = 'retry'; break;
            }
            let next = floor6(prev * 0.99);                  // −1%
            if (minQty > 0 && next < minQty) next = minQty;  // jangan di bawah min swap
            if (!(next > 0) || next >= prev) next = floor6(prev - 0.000001); // pasti turun
            edelxQty = next;
            logActivity(`[${tag}] ${leg.tokenLabel} kurang → ${prev} → ${edelxQty} EDELx (−1%), retry`, COLOR.yellow);
            continue;
          }
          if (e && e.feeSpike) { const w = Math.max(60, Number(M8.netWaitSec) || Number(SWAP.feeSpikeWaitSec) || 300); logActivity(`[${tag}] fee spike ${e.feeCC} > ${M8.maxFeeCC} CC (siang) — tunggu ${Math.round(w / 60)} mnt`, COLOR.yellow); await sleep(w * 1000); outcome = 'retry'; break; }
          // Action ID stale (404, Silvana redeploy): self-heal udah reset actionIdsVerified. Re-discover
          // paksa + retry ronde (JANGAN stop). ensureActionIds parse bundle by nama → id baru.
          if (e && (e.staleAction || /status=404|Server action not found/i.test((e && e.message) || ''))) {
            actionIdsVerified = false;
            logActivity(`[${tag}] action ID stale (404) → re-discover + retry`, COLOR.yellow);
            try { await ensureActionIds(sv, partyId, tag); } catch (_) { }
            await sleep(3000); outcome = 'retry'; break;
          }
          if (e && e.insufficientFunds) { logActivity(`[${tag}] CC kurang buat fee — stop (top-up CC)`, COLOR.red); outcome = 'stop'; break; }
          if (e && e.noLiquidity) { logActivity(`[${tag}] likuiditas ${leg.market} ${direction} belum ada — retry`, COLOR.gray); outcome = 'retry'; break; }
          // DvpProposal nyangkut (ledger cap-200 penuh) → drain stale dulu, lalu retry (bukan stop).
          if (e && e.dvpStuck) {
            logActivity(`[${tag}] ${shortSwapReason(e)} → cleanup DvpProposal + retry`, COLOR.yellow);
            try { const n = await drainStaleDvpProposals(clients.sv, clients.canton, clients.privy, partyId, (m, c) => logActivity(`[${tag}] ${m}`, c)); if (n) logActivity(`[${tag}] ${n} DvpProposal stale di-drain`, COLOR.green); } catch (_) { }
            await sleep(5000); outcome = 'retry'; break;
          }
          if (isProxyErr(e) || isIpBlockErr(e)) {
            // proxy error / IP ke-block WAF (403 HTML): retry 2x proxy SAMA, ke-3 rotate + rebuild.
            proxyFails++;
            if (proxyFails >= 3) {
              const np = rotateProxy(state.email);
              logActivity(`[${tag}] proxy error ${proxyFails}x → rotate ${np ? np.host + ':' + np.port : '-'}`, COLOR.yellow);
              try { clients = await buildSwapClients(state); ({ sv, partyId, identityToken, proxy } = clients); } catch (_) { }
              proxyFails = 0;
            } else {
              logActivity(`[${tag}] proxy error ${proxyFails}x — retry (proxy sama)`, COLOR.yellow);
            }
            await sleep(3000); outcome = 'retry'; break;
          }
          if (e && (e.transient || e.unauthorized)) { logActivity(`[${tag}] ${shortSwapReason(e)} — retry`, COLOR.yellow); if (e.unauthorized) { try { clients = await buildSwapClients(state); ({ sv, partyId, identityToken, proxy } = clients); } catch (_) { } } await sleep(4000); outcome = 'retry'; break; }
          // dvpProposalCid timeout = LP gak majuin proposal (stage 3→5, sering LP outage).
          // Retry INFINITE (while-loop tanpa cap). Cleanup proposal orphan diurus swapOnce cap-200.
          if (e && /dvpProposalCid timeout/i.test((e && e.message) || '')) { logActivity(`[${tag}] proposal gak maju (LP tak preconfirm) — retry [${String((e && e.message) || '').replace(/^.*?timeout\s*/i, '').slice(0, 120)}]`, COLOR.yellow); await sleep(4000); outcome = 'retry'; break; }
          // Error tak-terklasifikasi: JANGAN stop (goal = penuhi task). Retry dgn backoff naik
          // (cap 5 mnt) → infinite. Rebuild client tiap 5 error (jaga-jaga sesi korup). User Ctrl+C
          // kalau mau berhenti. actionIdsVerified di-reset biar ID ke-refresh kalau penyebabnya stale.
          hardErrs++;
          actionIdsVerified = false;
          const bw = Math.min(300, 10 * hardErrs);
          logActivity(`[${tag}] ping-pong error: ${shortSwapReason(e)} — retry #${hardErrs} (tunggu ${bw}s)`, COLOR.yellow);
          if (hardErrs % 5 === 0) { try { clients = await buildSwapClients(state); ({ sv, partyId, identityToken, proxy } = clients); logActivity(`[${tag}] rebuild client (error beruntun ${hardErrs}x)`, COLOR.gray); } catch (_) { } }
          await sleep(bw * 1000); outcome = 'retry'; break;
        }
      }
      if (outcome === 'stop' || outcome === 'dust') break;
      if (outcome === 'ok') {
        // Haircut FIXED 0.1% (M8.haircut) — gak ada learning adaptif lagi (terminal fee tetap).
        // CONFIRM ON-CHAIN + TUNGGU SALDO KEBAYAR: poll task CETH_EDELX_DAY_TRADER (count
        // naik = settle ke-register) DAN saldo token yg DITERIMA (recvId) beneran kredit
        // ke unlocked. WAJIB tunggu saldo: count bisa naik duluan sebelum UTXO recv muncul
        // → kalau lanjut, ronde berikut baca saldo lama (dust) → stop di 1/10 (BUG dulu).
        // Cek cepat [15s,20s,30s] lalu steady, refresh token+client tiap iterasi.
        // INFINITE sampai (count naik & recv kebayar) / saturated / cap settleWaitMaxMin.
        const SYNC_WAIT_MS = 5000;   // interval sync konstant 5s
        const MAX_WAIT_MS = Math.max(0, Number(SWAP.settleWaitMaxMin) || 0) * 60000;
        const tStart = Date.now();
        let countUp = false, recvOk = false;
        for (let r = 0; ; r++) {
          const w = SYNC_WAIT_MS;
          logActivity(`[${tag}] Sync EDELx-cETH… (cek ${r + 1}, tunggu ${Math.round(w / 1000)}s, sampai settle+saldo)`, COLOR.gray);
          await sleep(w);
          try { const fr = await ensureFreshClients(state, clients); if (fr !== clients) { clients = fr; ({ sv, partyId, identityToken, proxy } = clients); } } catch (_) { }
          const chk = await fetchEdelCethTrader(sv, partyId).catch(() => ({ dt: null }));
          if (chk.dt) { dt = chk.dt; state.dayTrader = { count: dt.current, target: dt.target }; }
          SWAP.tokenId = 'EDELX'; await refreshBalances(state, identityToken, proxy).catch(() => 0);
          render(global.__states);
          const recvNow = unlockedOf(state, recvId);
          if (chk.dt && chk.dt.current > countBefore) countUp = true;
          if (recvNow > recvBefore + Math.max(recvBefore * 0.25, 1e-7)) recvOk = true; // token recv udah kebayar
          if (countUp && recvOk) { logActivity(`[${tag}] ✓ confirmed (EDELx-cETH ${dt.current}/${dt.target}, ${recvId === 'CETH' ? 'cETH' : 'EDELx'} ${floor6(recvNow)} kebayar)`, COLOR.green); break; }
          if (chk.dt && chk.dt.current >= chk.dt.target && recvOk) break;        // target penuh & saldo masuk
          if (MAX_WAIT_MS && Date.now() - tStart > MAX_WAIT_MS) { logActivity(`[${tag}] settle/saldo belum kebaca ${Math.round(MAX_WAIT_MS / 60000)} mnt — lanjut (cap settleWaitMaxMin)`, COLOR.yellow); break; }
        }
        // Refresh POIN tiap sync selesai; STREAK cuma swap PERTAMA daily (date-gate streakSyncDate).
        {
          const today = todayStr();
          const firstDaily = acctSession(state.email).streakSyncDate !== today;
          await refreshEarnStats(state, sv, partyId, { withStreak: firstDaily });
          if (firstDaily) patchAcctSession(state.email, { streakSyncDate: today });
          render(global.__states);
        }
        // Net received (recvId) = unlocked skrg − sebelum swap. Deliver = yg BENERAN keluar wallet.
        const recvQty = Math.max(0, floor6(unlockedOf(state, recvId) - recvBefore));
        const deliveredQty = Math.max(0, floor6(deliverBefore - unlockedOf(state, deliverId)));
        // deliveredUsd ACTUAL: pakai qty yg beneran keluar (dust yg di-cancelSettlement gak dihitung).
        const deliveredUsdReal = deliveredQty > 0 ? deliveredQty * deliverPriceUsd : deliveredUsd;
        // LOSS = round-trip EDELx-anchored (bukan per-leg USD). Diukur SEKALI pas TUTUP posisi
        // (cETH→EDELx): loss = EDELx modal keluar − EDELx balik. Nangkep spread + terminal trading
        // fee (maker/taker, kebaked di harga) + haircut dalam 1 angka EDELx. CC FEE (kolom FEE/*)
        // TERPISAH — dibayar dari reserve CC, gak nyentuh delta EDELx → gak double-count di loss.
        // Dust yg di-cancel gak kehitung (deliveredQty/recvQty = delta unlocked real).
        if (deliver === 'EDELx') {
          // BUKA posisi: catat EDELx real keluar (anchor qty) + modal USD (buat net gate). Loss
          // BELUM realized — nunggu swap balik. Leg buka gak nambah loss.
          if (deliveredQty > 0) setEdelCethRoundEdelx(state.email, deliveredQty);
          if (deliveredUsdReal > 0) setEdelCethRoundUsd(state.email, deliveredUsdReal);
        } else {
          // TUTUP posisi (cETH→EDELx): recvQty = EDELx balik. loss = modal − balik.
          // Dust yg di-cancel di close (lastDustEdelx) = cETH yg KETAHAN (bakal ke-swap ronde
          // depan), BUKAN hilang → dihitung sebagai "balik" biar gak inflate loss.
          const roundEdelx = getEdelCethRoundEdelx(state.email);
          if (roundEdelx && recvQty > 0 && usdPerEdelx > 0) {
            const effReturn = recvQty + Math.max(0, Number(lastDustEdelx) || 0);
            const lossEdelx = Math.max(0, floor6(roundEdelx - effReturn));
            const lossUsd = lossEdelx * usdPerEdelx;
            if (lossUsd > 0) {
              bumpDaily(state, 0, lossUsd);
              logActivity(`[${tag}] round-trip loss: ${floor6(lossEdelx)} EDELx (~$${lossUsd.toFixed(3)}) [modal ${floor6(roundEdelx)} → balik ${floor6(recvQty)}${lastDustEdelx > 0 ? ` + dust ${floor6(lastDustEdelx)} ketahan` : ''}]`, COLOR.gray);
            }
            setEdelCethRoundEdelx(state.email, 0);   // clear anchor — round selesai
          }
        }
        if (targetReached()) { logActivity(`[${tag}] EDELx-cETH ${dt.current}/${dt.target}${overcap ? ` (overcap ${startCount + swaps}/${dailyCap})` : ''} ✓ — berhenti`, COLOR.green); break; }
        const delay = SWAP.postSwapDelayMinSec + Math.random() * Math.max(0, SWAP.postSwapDelayMaxSec - SWAP.postSwapDelayMinSec);
        await sleep(Math.max(3, delay) * 1000);
      } else {
        await sleep(SWAP.delayBetweenSwapsSec * 1000);
      }
    }
    SWAP.tokenId = 'EDELX';
    const fe = unlockedOf(state, 'EDELX'), fc = unlockedOf(state, 'CETH');
    logActivity(`[${tag}] ping-pong selesai: ${swaps} swap, sisa EDELx ${floor6(fe)} / cETH ${floor6(fc)}`, swaps ? COLOR.green : COLOR.yellow);
  } catch (e) {
    state.status = 'error'; state.message = shortSwapReason(e);
    logActivity(`[${tag}] ping-pong akun gagal: ${(e && e.message) || e}`, COLOR.red);
  }
}
async function runEdelCethSession(reason) {
  if (dtSessionRunning) { logActivity(`Sesi masih berjalan, lewati (${reason || ''})`, COLOR.gray); return; }
  dtSessionRunning = true;
  const conc = Math.max(1, Number(SWAP.concurrency) || 1);
  logActivity(`Mulai ping-pong EDELx↔cETH (${reason || 'manual'})${parallelSwapActive ? ` [parallel x${conc}]` : ''}`, COLOR.cyan);
  try {
    if (parallelSwapActive) await mapLimit(ACCOUNTS.map((_, i) => i), conc, runEdelCethAccount);
    else for (let i = 0; i < ACCOUNTS.length; i++) await runEdelCethAccount(i);
    logActivity('Sesi ping-pong selesai — berhenti sampai jadwal berikutnya.', COLOR.cyan);
  } finally { dtSessionRunning = false; }
}

// Engine sesi swap: 'daytrader' (opsi 0/1, CC↔token) | 'pingpong' (opsi 8, EDELx↔cETH).
// Di-set opsi 8 sebelum runMain. runMain + dashboard-trigger + scheduler lewat sini.
let SESSION_ENGINE = 'daytrader';
async function runSwapSession(reason) {
  return SESSION_ENGINE === 'pingpong' ? runEdelCethSession(reason) : runDayTraderSession(reason);
}

// ============================================================================
//  Scheduler harian (node-cron, fallback setTimeout)
// ============================================================================
function msUntilNext(hour, minute, tz) {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }).formatToParts(new Date()).reduce((a, p) => { a[p.type] = p.value; return a; }, {});
  let h = Number(parts.hour); if (h === 24) h = 0;
  const curSec = h * 3600 + Number(parts.minute) * 60 + Number(parts.second);
  let delta = (hour * 3600 + minute * 60) - curSec; if (delta <= 0) delta += 86400;
  return delta * 1000;
}
function scheduleDaily({ hour, minute, timezone, fn }) {
  try {
    const cron = require('node-cron');
    const expr = `${minute} ${hour} * * *`;
    cron.schedule(expr, () => { Promise.resolve(fn('cron')).catch(() => { }); }, { timezone });
    logActivity(`Penjadwal: node-cron "${expr}" TZ=${timezone}`, COLOR.gray);
    return;
  } catch (_) { logActivity('Penjadwal: fallback setTimeout', COLOR.gray); }
  const arm = () => { const ms = msUntilNext(hour, minute, timezone); setTimeout(async () => { try { await fn('timeout'); } catch (_) { } arm(); }, ms); };
  arm();
}

// ============================================================================
//  Web dashboard push (config-driven, no secrets in code) — lihat web.md §4d
//  config.json "dashboard": { enabled, url, api_key, source_id, push_interval_seconds }
//  Ship BLANK + disabled. Operator isi url + api_key sendiri lalu set enabled:true.
// ============================================================================
const DASH = Object.assign(
  { enabled: false, url: '', api_key: '', source_id: 'node-1', push_interval_seconds: 30 },
  CONFIG.dashboard || {}
);
const PROC_START = Date.now();

// Ekstrak saldo CC (amulet) & USDCx dari state.balances → { unlocked, locked }.
function balanceOf(state, tokenId) {
  const arr = Array.isArray(state.balances) ? state.balances : [];
  const b = arr.find(x => String((x.instrumentId && x.instrumentId.id) || '').toLowerCase() === tokenId);
  if (!b) return { unlocked: 0, locked: 0 };
  const unlocked = Number(b.totalUnlockedBalance ?? b.totalBalance ?? 0);
  const total = Number(b.totalBalance ?? 0);
  return { unlocked, locked: Math.max(0, total - unlocked) };
}
// ── Balance monitor (opsi 2): tabel + grand total, auto-refresh periodik ──────
// Cell balance: unlocked (hijau) + "+locked" (abu) kalau ada. visLen strip ANSI →
// pad align bener walau string udah diwarnai.
function _balCell(b, fmtFn) {
  if (!b) return paint('-', COLOR.gray);
  const u = paint(fmtFn(b.unlocked), COLOR.green);
  const l = b.locked > 1e-8 ? paint('+' + fmtFn(b.locked), COLOR.gray) : '';
  return u + l;
}
function renderBalanceTable(states, intervalMin, okCount, logBuf) {
  computeLayout(); clearScreen();
  const rows = states.map(s => {
    if (s._balErr) return { label: s.label || s.email, cc: paint('err', COLOR.red), usdcx: paint('err', COLOR.red), ceth: paint('err', COLOR.red), edelx: paint('err', COLOR.red) };
    return { label: s.label || s.email, cc: _balCell(balanceOf(s, 'amulet'), fmtCC), usdcx: _balCell(balanceOf(s, 'usdcx'), fmtUSDC), ceth: _balCell(balanceOf(s, 'ceth'), fmtCeth), edelx: _balCell(balanceOf(s, 'edelx'), fmtEdelx) };
  });
  const tot = { cc: { u: 0, l: 0 }, usdcx: { u: 0, l: 0 }, ceth: { u: 0, l: 0 }, edelx: { u: 0, l: 0 } };
  for (const s of states) {
    if (s._balErr) continue;
    const cc = balanceOf(s, 'amulet'), ux = balanceOf(s, 'usdcx'), ce = balanceOf(s, 'ceth'), ed = balanceOf(s, 'edelx');
    tot.cc.u += cc.unlocked; tot.cc.l += cc.locked; tot.usdcx.u += ux.unlocked; tot.usdcx.l += ux.locked; tot.ceth.u += ce.unlocked; tot.ceth.l += ce.locked; tot.edelx.u += ed.unlocked; tot.edelx.l += ed.locked;
  }
  const totalRow = { label: `TOTAL (${okCount}/${states.length})`, cc: _balCell({ unlocked: tot.cc.u, locked: tot.cc.l }, fmtCC), usdcx: _balCell({ unlocked: tot.usdcx.u, locked: tot.usdcx.l }, fmtUSDC), ceth: _balCell({ unlocked: tot.ceth.u, locked: tot.ceth.l }, fmtCeth), edelx: _balCell({ unlocked: tot.edelx.u, locked: tot.edelx.l }, fmtEdelx) };
  const head = { label: 'AKUN', cc: 'CC', usdcx: 'USDCx', ceth: 'cETH', edelx: 'EDELx' };
  const all = [head, ...rows, totalRow];
  const wl = Math.max(...all.map(r => visLen(r.label)));
  const wc = Math.max(...all.map(r => visLen(r.cc)));
  const wu = Math.max(...all.map(r => visLen(r.usdcx)));
  const we = Math.max(...all.map(r => visLen(r.ceth)));
  const wd = Math.max(...all.map(r => visLen(r.edelx)));
  const GAP = '  ';
  const mkRow = (r, style) => {
    const body = pad(r.label, wl, 'right') + GAP + pad(r.cc, wc, 'left') + GAP + pad(r.usdcx, wu, 'left') + GAP + pad(r.ceth, we, 'left') + GAP + pad(r.edelx, wd, 'left');
    return row(style ? paint(body, style) : body);
  };
  const out = [line()];
  out.push(row(paint(` Cek Balance — auto-refresh /${intervalMin} mnt `, COLOR.bold + COLOR.cyan)));
  out.push(row(paint(new Date().toLocaleString('id-ID') + '   ·   Ctrl+C berhenti', COLOR.gray)));
  out.push(sep());
  out.push(mkRow(head, COLOR.bold + COLOR.gray));
  out.push(sep());
  for (const r of rows) out.push(mkRow(r));
  out.push(sep());
  out.push(mkRow(totalRow, COLOR.bold));
  // ── log refresh (adaptive: isi sisa tinggi terminal), tetap dalam kotak ──
  out.push(sep());
  out.push(row(paint('▎ log refresh', COLOR.bold + COLOR.cyan)));
  const avail = Math.max(MIN_ACTIVITY_LINES, ROWS - out.length - 2);   // sisa baris utk log (+endl)
  const slice = (Array.isArray(logBuf) ? logBuf : []).slice(-avail);
  if (!slice.length) out.push(row(paint('(belum ada refresh)', COLOR.gray)));
  else slice.forEach(l => out.push(row(l)));
  out.push(endl());
  process.stdout.write(out.join('\n') + '\n');
}
async function runBalanceMonitor() {
  const states = makeStates();
  const intervalMin = Math.max(1, Number((CONFIG.dashboard || {}).balanceRefreshMin) || 1);
  const balLog = [];
  const pushLog = (msg, color) => {
    balLog.push(paint(new Date().toLocaleTimeString('id-ID') + ' ', COLOR.gray) + (color ? paint(msg, color) : msg));
    if (balLog.length > 200) balLog.splice(0, balLog.length - 200);
  };
  for (; ;) {
    await mapLimit(states, ACCT_CONCURRENCY, async (s) => {
      try {
        const proxy = pickProxy(s.privyEmail || s.email);
        const token = await ensurePrivyToken(s);
        const bal = await supaBalances(token, proxy);
        s.balances = (bal && bal.tokens) || [];
        s._balErr = null;
      } catch (e) { s._balErr = ((e && e.message) || String(e)).slice(0, 60); s.balances = s.balances || []; }
    });
    const okCount = states.filter(s => !s._balErr).length;
    const errs = states.filter(s => s._balErr);
    if (errs.length) pushLog(`refresh ${okCount}/${states.length} ok — ${errs.length} error: ${errs.map(s => s.label || s.email).join(', ').slice(0, 50)}`, COLOR.yellow);
    else pushLog(`refresh ${okCount}/${states.length} ok — next /${intervalMin} mnt`, COLOR.green);
    renderBalanceTable(states, intervalMin, okCount, balLog);
    await sleep(intervalMin * 60000);
  }
}
function buildDashboardItems(states) {
  return (states || []).map(s => ({
    label: s.label || s.email,
    email: s.email,
    status: s.status || 'idle',
    message: s.message || '',
    dayTrader: s.dayTrader ? { count: Number(s.dayTrader.count) || 0, target: Number(s.dayTrader.target) || 0 } : null,
    points: (s.points != null && Number.isFinite(Number(s.points))) ? Number(s.points) : null,
    cc: balanceOf(s, 'amulet'),
    usdcx: balanceOf(s, 'usdcx'),
    silvanaExpMs: s.silvanaExpMs || 0,
    tokenExpMs: s.tokenExpMs || 0,
  }));
}
function dashboardPayload(states) {
  const recent = DASH_ACTIVITY.slice(-50);
  return {
    sourceId: DASH.source_id || 'node-1',
    version: (typeof pkgVersion !== 'undefined' ? pkgVersion : undefined),
    uptimeSec: Math.round((Date.now() - PROC_START) / 1000),
    accounts: buildDashboardItems(states),
    schedule: { hour: Number(SCHED.hour) || 7, minute: Number(SCHED.minute) || 0, timezone: SCHED.timezone || 'Asia/Jakarta' },
    swapConfig: { mode: SWAP_MODE, minAmount: String(SWAP_MIN_AMOUNT), maxAmount: String(SWAP_MAX_AMOUNT), maxFeeCC: SWAP.maxFeeCC },
    sessionRunning: !!dtSessionRunning,
    prices: { ccUsdcx: CC_PRICE.ccUsdcx || 0 },
    recentActivity: recent,
    burnEvents: BURN_EVENTS.slice(-50),
    timestamp: Date.now(),
  };
}
async function pushToDashboard() {
  if (!DASH.enabled || !DASH.url || !DASH.api_key) return; // hard gate — silent no-op
  try {
    const base = String(DASH.url).replace(/\/+$/, '');
    await request('POST', base + '/api/push', {
      headers: { 'Content-Type': 'application/json', 'X-API-Key': DASH.api_key },
      body: JSON.stringify(dashboardPayload(global.__states || [])),
      timeoutMs: 15000,
    });
  } catch (_) { /* silent — jangan spam, jangan print key */ }
}
// Tarik perintah dari dashboard (swap_now / refresh / cleanup), eksekusi, ack.
async function pollDashboardCommands() {
  if (!DASH.enabled || !DASH.url || !DASH.api_key) return;
  const base = String(DASH.url).replace(/\/+$/, '');
  let cmds = [];
  try {
    const r = await request('GET', base + `/api/commands?sourceId=${encodeURIComponent(DASH.source_id || 'node-1')}`, {
      headers: { 'X-API-Key': DASH.api_key }, timeoutMs: 12000,
    });
    cmds = (r.json && Array.isArray(r.json.commands)) ? r.json.commands : [];
  } catch (_) { return; }
  for (const cmd of cmds) {
    let status = 'done', result = null;
    try {
      if (cmd.type === 'swap_now') {
        logActivity('Dashboard: jalankan sesi swap', COLOR.cyan);
        runSwapSession('dashboard').catch(() => { });
      } else if (cmd.type === 'refresh') {
        logActivity('Dashboard: refresh data', COLOR.cyan);
        if (!dtSessionRunning && global.__states) tickAll(global.__states).catch(() => { });
      } else if (cmd.type === 'cleanup') {
        logActivity('Dashboard: cleanup proposal nyangkut', COLOR.cyan);
        for (const st of (global.__states || [])) {
          try { const c = await buildSwapClients(st); await cleanupStaleProposals(c.sv, c.canton, c.partyId, undefined, c.privy); } catch (_) { }
        }
      } else if (cmd.type === 'set_modal') {
        const a = cmd.args || {};
        const newMin = Number(a.minAmount), newMax = Number(a.maxAmount);
        if (Number.isFinite(newMin) && newMin >= 0) SWAP_MIN_AMOUNT = newMin;
        if (Number.isFinite(newMax) && newMax >= 0) SWAP_MAX_AMOUNT = newMax;
        // persist ke config.json biar survive restart
        try {
          const cfg = loadJSON(CFG_PATH, {});
          cfg.swap = cfg.swap || {};
          cfg.swap.minAmount = String(SWAP_MIN_AMOUNT);
          cfg.swap.maxAmount = String(SWAP_MAX_AMOUNT);
          saveJSON(CFG_PATH, cfg);
        } catch (_) { }
        result = `modal → min ${SWAP_MIN_AMOUNT} max ${SWAP_MAX_AMOUNT || '∞'}`;
        logActivity(`Dashboard: set modal min ${SWAP_MIN_AMOUNT} max ${SWAP_MAX_AMOUNT || '∞'} CC`, COLOR.green);
      } else { status = 'failed'; result = 'unknown command'; }
    } catch (e) { status = 'failed'; result = (e && e.message) || String(e); }
    try {
      await request('POST', base + '/api/command-ack', {
        headers: { 'Content-Type': 'application/json', 'X-API-Key': DASH.api_key },
        body: JSON.stringify({ sourceId: DASH.source_id || 'node-1', id: cmd.id, status, result }),
        timeoutMs: 12000,
      });
    } catch (_) { }
  }
}
function startDashboardPush() {
  if (!DASH.enabled || !DASH.url || !DASH.api_key) return null; // disabled by default
  const ms = Math.max(5, Number(DASH.push_interval_seconds) || 30) * 1000;
  setTimeout(pushToDashboard, 10000);     // biar app init dulu
  setInterval(pushToDashboard, ms);
  setInterval(pollDashboardCommands, Math.max(10000, ms)); // poll perintah
  logActivity(`Dashboard push aktif → ${String(DASH.url).replace(/^https?:\/\//, '')} tiap ${Math.round(ms / 1000)}s`, COLOR.gray);
  return true;
}

// ============================================================================
//  Main + sub-command paste
// ============================================================================
function cleanGeoBlockedCookies() {
  try {
    const raw = fs.readFileSync(SESS_PATH, 'utf8');
    const data = JSON.parse(raw);
    let changed = 0;
    for (const k of Object.keys(data)) {
      if (data[k].silvanaCookies && data[k].silvanaCookies.geo_status) {
        delete data[k].silvanaCookies.geo_status;
        changed++;
      }
    }
    if (changed) {
      fs.writeFileSync(SESS_PATH, JSON.stringify(data, null, 2));
      logActivity(`Startup: hapus geo_status dari ${changed} akun di session.json`, COLOR.yellow);
    }
  } catch (_) { }
}

async function runMain() {
  cleanGeoBlockedCookies();
  logActivity(`Proxy: ${PROXIES.length} loaded (enabled=${PROXY_ENABLED}, file=${PROXY_FILE})`, PROXIES.length ? COLOR.green : COLOR.yellow);
  if (PROXIES.length) PROXIES.forEach((p, i) => logActivity(`  proxy[${i}]: ${p.host}:${p.port} auth=${!!p.auth}`, COLOR.gray));
  const states = makeStates();
  global.__states = states;
  const savedIds = loadActionIds();
  if (savedIds) logActivity(`Action IDs dimuat dari action_ids.json (${new Date(savedIds.savedAt).toLocaleString('id-ID')})`, COLOR.gray);
  process.stdout.on('resize', () => { try { render(global.__states); } catch (_) { } });
  setupKeyNav();  // panah ↑/↓ pindah view log per-akun (raw mode stdin)
  render(states);
  await tickAll(states);
  if (argv[0] === 'once') process.exit(0);

  scheduleDaily({ hour: Number(SCHED.hour) || 7, minute: Number(SCHED.minute) || 0, timezone: SCHED.timezone || 'Asia/Jakarta', fn: async (why) => { await runSwapSession(why); if (!dtSessionRunning) await tickAll(states).catch(() => { }); } });
  startDashboardPush();

  // Keep-alive token tiap KEEPALIVE_SEC (default 120s) — jaga Silvana+Supa gak
  // pernah expired walau quest udah selesai. Ringan, skip saat sesi swap jalan.
  const KA_MS = Math.max(60, Number((CONFIG.dashboard || {}).keepAliveSec) || 120) * 1000;
  setInterval(() => { if (!dtSessionRunning) keepAliveAll(states).catch(() => { }); }, KA_MS);

  // Token watcher — refresh token begitu mau/udah expired, KAPANPUN (termasuk saat
  // sesi swap aktif). Token-only (ringan), beda dari keepAlive yg ke-gate + fetch data.
  const TW_MS = Math.max(15, Number((CONFIG.dashboard || {}).tokenWatchSec) || 30) * 1000;
  setInterval(() => { refreshExpiringTokens(states).catch(() => { }); }, TW_MS);

  runSwapSession('startup').then(() => tickAll(states).catch(() => { })).catch(e => logActivity('sesi startup error: ' + e.message, COLOR.red));

  while (true) {
    await sleep(REFRESH_SEC * 1000);
    if (dtSessionRunning) render(states); else await tickAll(states);
  }
}

// passkey → session.json, akun → accounts.json. Dipakai paste & register.
function saveAccountPasskey(obj) {
  const patch = { passkey: obj.silvanaPasskey };
  if (obj.userServiceCid) patch.userServiceCid = obj.userServiceCid;
  patchAcctSession(obj.email, patch);
  const data = loadJSON(ACC_PATH, { accounts: [] });
  if (!Array.isArray(data.accounts)) data.accounts = [];
  const idx = data.accounts.findIndex(a => a && a.email === obj.email);
  const entry = { label: obj.label || obj.email.split('@')[0], email: obj.email };
  if (obj.privyEmail) entry.privyEmail = obj.privyEmail;
  if (idx >= 0) data.accounts[idx] = { ...data.accounts[idx], ...entry };
  else data.accounts.push(entry);
  saveJSON(ACC_PATH, data);
  return data.accounts.length;
}

// Tunggu user menempel 1 baris JSON {email,silvanaPasskey,...} di terminal → simpan.
function awaitPastedPasskey() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    let buf = '';
    rl.on('line', (l) => {
      buf += l.trim();
      let obj; try { obj = JSON.parse(buf); } catch (_) { return; }
      if (!obj || !obj.email || !obj.silvanaPasskey) { process.stdout.write(paint('JSON butuh email + silvanaPasskey\n', COLOR.red)); buf = ''; return; }
      const total = saveAccountPasskey(obj);
      process.stdout.write('\n' + paint(`✓ passkey → session.json, akun ${obj.email} → accounts.json (total ${total})`, COLOR.green) + '\n');
      process.stdout.write(paint('Set privyEmail di accounts.json bila Privy beda email, lalu: node index.js\n', COLOR.gray));
      rl.close(); resolve();
    });
  });
}

async function runPaste() {
  process.stdout.write(`\n${paint('SilvanaBot — Paste Passkey JSON', COLOR.bold + COLOR.cyan)}\nTempel ${paint('1 baris JSON', COLOR.cyan)} hasil register lalu Enter.\n\n`);
  await awaitPastedPasskey();
  process.exit(0);
}

// Snippet browser (versi terbukti dari old/snippet): generate passkey kustom,
// register ke Silvana via /api/passkeys/register/options (BODY KOSONG), lalu print
// 1 baris JSON utk dicopy. Dijalankan di Console app.silvana.one (sudah login).
const REGISTER_SNIPPET = `(async()=>{try{
const TE=new TextEncoder();
const log=(m,c)=>console.log('%c[SilvanaBot] '+m,'color:'+(c||'cyan')+';font-weight:bold');
const b64u=b=>btoa(String.fromCharCode.apply(null,new Uint8Array(b))).split('+').join('-').split('/').join('_').split('=').join('');
const b64uDec=s=>{s=s.split('-').join('+').split('_').join('/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0));};
const concat=(...a)=>{let n=0;for(const x of a)n+=x.length;const o=new Uint8Array(n);let k=0;for(const x of a){o.set(x,k);k+=x.length;}return o;};
const cint=n=>{if(n>=0&&n<=23)return new Uint8Array([n]);if(n<0&&n>=-24)return new Uint8Array([0x20|(-1-n)]);if(n>=24&&n<=255)return new Uint8Array([0x18,n]);throw new Error('cbor int');};
const cstr=b=>{const l=b.length;if(l<=23)return concat(new Uint8Array([0x40|l]),b);if(l<=255)return concat(new Uint8Array([0x58,l]),b);return concat(new Uint8Array([0x59,(l>>8)&0xff,l&0xff]),b);};
const cmap=p=>concat(new Uint8Array([0xa0|p.length]),...p.flat());
const ctstr=s=>{const b=TE.encode(s);return concat(new Uint8Array([0x60|b.length]),b);};
let me;try{const r=await fetch('/api/auth/me',{credentials:'include'});if(!r.ok)throw 0;me=(await r.json()).user;}catch(_){throw new Error('Belum login di app.silvana.one — login dulu lalu ulangi.');}
log('user: '+me.email);
const candidates=['/api/passkeys/register/options','/api/auth/passkey/registration/options','/api/auth/webauthn/register/options','/api/passkeys/options'];
let optsR=null,usedPath='';
for(const p of candidates){try{const r=await fetch(p,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'}});if(r.ok){optsR=r;usedPath=p;break;}}catch(_){}}
if(!optsR)throw new Error('Endpoint register/options tak ketemu — cek Network tab saat klik Add Passkey di UI.');
const opts=await optsR.json();
const verifyPath=usedPath.replace('/options','/verify');
const kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
const privJwk=await crypto.subtle.exportKey('jwk',kp.privateKey);
const pubJwk=await crypto.subtle.exportKey('jwk',kp.publicKey);
const credIdRaw=crypto.getRandomValues(new Uint8Array(32));
const credIdB64=b64u(credIdRaw);
const clientDataJSON=TE.encode(JSON.stringify({type:'webauthn.create',challenge:opts.challenge,origin:location.origin,crossOrigin:false}));
const rpId=(opts.rp&&opts.rp.id)||'silvana.one';
const rpIdHash=new Uint8Array(await crypto.subtle.digest('SHA-256',TE.encode(rpId)));
const x=b64uDec(pubJwk.x),y=b64uDec(pubJwk.y);
const coseKey=cmap([[cint(1),cint(2)],[cint(3),cint(-7)],[cint(-1),cint(1)],[cint(-2),cstr(x)],[cint(-3),cstr(y)]]);
const authData=concat(rpIdHash,new Uint8Array([0x45]),new Uint8Array([0,0,0,0]),new Uint8Array(16),new Uint8Array([0,credIdRaw.length]),credIdRaw,coseKey);
const attestationObject=concat(new Uint8Array([0xa3]),ctstr('fmt'),ctstr('none'),ctstr('attStmt'),new Uint8Array([0xa0]),ctstr('authData'),cstr(authData));
const credential={id:credIdB64,rawId:credIdB64,type:'public-key',authenticatorAttachment:'platform',transports:['internal'],response:{clientDataJSON:b64u(clientDataJSON),attestationObject:b64u(attestationObject)}};
const verR=await fetch(verifyPath,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:me.email,credential})});
const verT=await verR.text();
if(!verR.ok)throw new Error('register/verify gagal '+verR.status+': '+verT.slice(0,300));
log('register OK ('+verR.status+')','lime');
const userHandle=(opts.user&&opts.user.id)||'';
const payload={email:me.email,label:(me.email||'').split('@')[0],silvanaPasskey:{credentialId:credIdB64,userHandle,privateJwk:privJwk}};
const payloadStr=JSON.stringify(payload);
try{await navigator.clipboard.writeText(payloadStr);log('✓ JSON tersalin ke clipboard','lime');}catch(_){}
console.log('%c COPY 1 BARIS DI BAWAH INI ke terminal: ','background:#0a0;color:#fff;font-size:14px;padding:2px');
console.log(payloadStr);
}catch(e){console.error('REGISTER GAGAL:',(e&&e.message)||e);}})();`;

async function runRegister() {
  process.stdout.write('\n' + paint('SilvanaBot — Register Passkey', COLOR.bold + COLOR.cyan) + '\n\n');
  process.stdout.write(paint('1) Buka https://app.silvana.one dan pastikan SUDAH LOGIN.\n', COLOR.gray));
  process.stdout.write(paint('2) F12 → Console → (ketik "allow pasting" bila diminta) → paste script di bawah → Enter.\n', COLOR.gray));
  process.stdout.write(paint('3) Console mencetak 1 baris JSON. Copy baris itu, paste ke terminal ini, Enter.\n', COLOR.gray));
  process.stdout.write('\n' + paint('───────── COPY SCRIPT DI BAWAH INI ─────────', COLOR.yellow) + '\n');
  process.stdout.write(REGISTER_SNIPPET + '\n');
  process.stdout.write(paint('──────────────── sampai sini ───────────────', COLOR.yellow) + '\n\n');
  process.stdout.write(paint('Tempel JSON hasil di sini lalu Enter:', COLOR.cyan) + '\n');
  await awaitPastedPasskey();
  process.exit(0);
}

// ============================================================================
//  CLI
// ============================================================================
const argv = process.argv.slice(2);
module.exports = { render, makeStates, logActivity, computeLayout, runDayTraderSession, parseDayTrader, ensurePrivyToken, supaMe, getProxy, patchAcctSession, ACCOUNTS, M8, nowHourInTz, mode8IsNight, getEdelCethRoundUsd, setEdelCethRoundUsd };

if (require.main === module) {
  if (argv[0] === 'help' || argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(`
Usage:
  node index.js           dashboard + auto DAY_TRADER (swap sampai target, ulang tiap ${SCHED.hour}:00 WIB)
  node index.js once      render dashboard + fetch data sekali, lalu exit (tanpa swap)
  node index.js swap      jalankan SATU sesi DAY_TRADER lalu exit
  node index.js feecheck [ceth|usdcx|edelceth] [sell|buy] [amt]  cek fee live tanpa swap (dry-run, 0 CC, auto-cleanup)
  node index.js terminal [idx] [MARKET]        riset read-only page /terminal (server-action + /api + orderbook)
  node index.js terminal-order [idx] [go] [buy|sell]  probe submitOrder (dry tanpa go; go=live + auto-cancel)
  node index.js terminal-hist [idx]            dump settlement terminal (struktur split + consumedAmuletCids)
  node index.js terminal-swap [idx] [buy|sell] [go]   test 1 swap terminal penuh (submitOrder→settle), sizing usdAmount
  node index.js proposals  list settlement aktif (read-only) — cek proposal nyangkut
  node index.js cleanup    reject semua proposal nyangkut yg 0 dana kelock (sampah)
  node index.js register  cetak script utk daftarkan passkey baru via Console, lalu paste hasil
  node index.js paste     tempel JSON passkey hasil register → simpan ke session.json
  node index.js wallets   list Privy wallets per akun + tandai mana yg cached/match partyId
  node index.js pin <id>  pin privyWalletId ke session.json (utk akun pertama)
  node index.js help      tampilkan bantuan
`);
    process.exit(0);
  }
  if (argv[0] === 'wallets') {
    (async () => {
      for (const a of ACCOUNTS) {
        const state = { email: a.email, privyEmail: a.privyEmail || null, label: a.label, status: 'idle', message: '' };
        try {
          const proxy = pickProxy(state.privyEmail || state.email);
          const idTok = await ensurePrivyToken(state);
          const me = await supaMe(idTok, proxy);
          const partyId = me.data && me.data.partyId;
          const pat = (acctSession(a.email).privy || {}).privy_access_token;
          const cached = acctSession(a.email).privyWalletId || null;
          const privy = new PrivyWallet({ accessToken: pat, proxy, partyId, preferredWalletId: cached });
          await privy.authenticate();
          process.stdout.write('\n' + paint('▎ ' + (a.label || a.email), COLOR.bold + COLOR.cyan) + '\n');
          process.stdout.write(paint('  partyId: ', COLOR.gray) + (partyId || '?') + '\n');
          process.stdout.write(paint('  cached privyWalletId: ', COLOR.gray) + (cached || '(belum)') + '\n');
          process.stdout.write(paint('  Privy wallets:', COLOR.gray) + '\n');
          for (const w of privy.walletCandidates) {
            const mark = w.id === (privy.wallet && privy.wallet.id) ? paint(' ← AKTIF', COLOR.green) : '';
            const cachedMark = w.id === cached ? paint(' (cached)', COLOR.cyan) : '';
            process.stdout.write('    - ' + paint(w.id, COLOR.bold) + cachedMark + mark + '\n');
            process.stdout.write('      address: ' + (w.address || '-') + '\n');
            process.stdout.write('      pubkey:  ' + (w.public_key || '-') + '\n');
            process.stdout.write('      created: ' + new Date(w.created_at || 0).toISOString() + '\n');
          }
          if (privy.walletCandidates.length > 1) {
            process.stdout.write('\n' + paint('  ⚠ Multi-wallet. Kalau bot salah pilih → jalankan: ', COLOR.yellow));
            process.stdout.write(paint('node index.js pin <id>', COLOR.bold) + '\n');
          }
        } catch (e) {
          process.stdout.write(paint('  ERROR: ' + e.message + '\n', COLOR.red));
        }
      }
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + e.message, COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'pin') {
    const id = argv[1];
    if (!id) { console.error(paint('Usage: node index.js pin <walletId>', COLOR.red)); process.exit(1); }
    const a = ACCOUNTS[0];
    if (!a) { console.error(paint('accounts.json kosong', COLOR.red)); process.exit(1); }
    patchAcctSession(a.email, { privyWalletId: id });
    process.stdout.write(paint(`✓ privyWalletId pinned ke ${id} untuk ${a.email}\n`, COLOR.green));
    process.exit(0);
  } else if (argv[0] === 'register') {
    runRegister().catch(e => { console.error(paint('FATAL: ' + e.message, COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'paste') {
    runPaste().catch(e => { console.error(paint('FATAL: ' + e.message, COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'terminal') {
    // `node index.js terminal [idx] [MARKET]` — RESEARCH read-only: dump semua
    // server-action (name→id) + /api literal + probe endpoint orderbook di page
    // /terminal. Cari flow limit-order (spread kecil) pengganti swap RFQ. Nulis
    // terminal-research.json. GAK ngubah ledger.
    (async () => {
      const idx = Number(argv[1] || 0);
      const market = argv[2] || 'EDELx-cETH';
      const a = ACCOUNTS[idx];
      if (!a) { console.error(paint(`akun idx ${idx} gak ada (total ${ACCOUNTS.length})`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      process.stdout.write(paint(`TERMINAL research ${a.label || a.email} market=${market}…\n`, COLOR.cyan));
      const { sv, partyId, identityToken, proxy } = await buildSwapClients(state);
      const OUT = argv[3] || '/private/tmp/claude-501/-Users-ipall-SipalDrop-Waras-SilvanaBot-Sipal/c1ca07a4-bfb0-46e0-82aa-eeffc96a6078/scratchpad/terminal-research.json';
      const out = { account: a.label || a.email, partyId, market, ts: new Date().toISOString() };
      const opts = { jar: sv.jar, timeoutMs: 15000, proxy };
      const bearer = () => { try { return acctSession(a.email).privy.token || identityToken; } catch (_) { return identityToken; } };
      const hdr = (extra = {}) => ({ 'User-Agent': UA, 'Accept': '*/*', 'Accept-Language': 'en-US,en;q=0.9,id;q=0.8', 'Origin': APP_BASE, 'Referer': `${APP_BASE}/terminal?market=${market}`, ...extra });
      // ── 1. Fetch page /terminal + semua chunk JS
      const page = await request('GET', `${APP_BASE}/terminal?market=${encodeURIComponent(market)}`, { ...opts, headers: hdr({ 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8', 'Referer': APP_BASE + '/' }) });
      out.pageStatus = page.status;
      const html = page.text || '';
      const chunkUrls = new Set(); let m;
      const reChunk = /\/_next\/static\/chunks\/[^"'\s\\]+\.js/g;
      while ((m = reChunk.exec(html)) !== null) chunkUrls.add(m[0]);
      const bm = html.match(/"buildId"\s*:\s*"([^"]+)"/);
      if (bm) { out.buildId = bm[1]; try { const b = await request('GET', `${APP_BASE}/_next/static/${bm[1]}/_buildManifest.js`, { ...opts, timeoutMs: 8000 }); for (const cc of ((b.text || '').match(/static\/chunks\/[^"'\\]+\.js/g) || [])) chunkUrls.add('/_next/' + cc); } catch (_) { } }
      out.chunkCount = chunkUrls.size;
      const texts = await mapLimit([...chunkUrls], 8, url => request('GET', `${APP_BASE}${url}`, { ...opts, headers: hdr() }).then(r => r.status === 200 ? (r.text || '') : '').catch(() => ''));
      const blob = texts.join('\n');
      // ── 2. Server actions (name→id) di seluruh bundle terminal
      const name2id = {}; let mm;
      const reSA = /createServerReference\)\("([0-9a-f]{42})",\s*\w+\.callServer,\s*void\s*0,\s*\w+\.findSourceMapURL,\s*"([a-zA-Z0-9_$]+)"/g;
      while ((mm = reSA.exec(blob)) !== null) name2id[mm[2]] = mm[1];
      out.serverActions = name2id;
      out.serverActionNames = Object.keys(name2id).sort();
      // Dump raw bundle biar bisa di-grep offline (payload field names, call sites).
      try { require('fs').writeFileSync(OUT.replace(/\.json$/, '-bundle.js'), blob); } catch (_) { }
      // Snippet ±500 char di sekitar tiap terminal action name (buat baca payload shape).
      out.actionSnippets = {};
      for (const nm of ['submitOrder', 'cancelOrder', 'getTrafficFeeContextAction', 'prepareFeeTransferCommandAction', 'recordTransactionAction', 'submitPreconfirmation']) {
        const i = blob.indexOf('"' + nm + '"');
        if (i >= 0) out.actionSnippets[nm] = blob.slice(Math.max(0, i - 700), i + 200);
      }
      // action yg BUKAN bagian flow /swap (kandidat orderbook/limit-order)
      const swapNames = new Set(Object.values(ACTION_NAME));
      out.terminalOnlyActions = Object.keys(name2id).filter(n => !swapNames.has(n)).sort();
      // ── 3. Semua literal path /api di bundle (endpoint REST tanpa nebak)
      const apis = new Set();
      const reApi = /["'`](\/api\/[a-zA-Z0-9_\-\/{}.:$]+)["'`]/g;
      while ((mm = reApi.exec(blob)) !== null) apis.add(mm[1]);
      out.apiPaths = [...apis].sort();
      out.orderApiPaths = out.apiPaths.filter(p => /order|book|depth|trade|market|terminal|limit|open|cancel/i.test(p));
      // ── 4. Probe endpoint orderbook (read-only GET) — coba beberapa bentuk param
      const probes = [
        `/api/orderbook?market=${market}`, `/api/orderbook?marketId=${market}`, `/api/orderbook?symbol=${market}`,
        `/api/order-book?market=${market}`, `/api/orders?market=${market}`, `/api/orders?mine=true`,
        `/api/markets`, `/api/markets/${market}`, `/api/market?symbol=${market}`,
        `/api/depth?market=${market}`, `/api/trades?market=${market}`, `/api/terminal/orderbook?market=${market}`,
      ];
      out.probes = {};
      for (const p of probes) {
        try {
          const r = await request('GET', `${APP_BASE}${p}`, { ...opts, timeoutMs: 10000, headers: hdr({ 'Authorization': 'Bearer ' + bearer() }) });
          out.probes[p] = { status: r.status, body: (r.text || '').slice(0, 600) };
        } catch (e) { out.probes[p] = { status: 0, err: (e && e.message) || String(e) }; }
      }
      // ── 5. Probe tiap orderApiPath yang ketemu di bundle (GET, isi placeholder market)
      out.bundleProbes = {};
      for (const raw of out.orderApiPaths) {
        if (/[{$]/.test(raw)) continue; // skip yg butuh path-param
        const p = raw + (raw.includes('?') ? '&' : '?') + `market=${market}`;
        try {
          const r = await request('GET', `${APP_BASE}${p}`, { ...opts, timeoutMs: 10000, headers: hdr({ 'Authorization': 'Bearer ' + bearer() }) });
          out.bundleProbes[raw] = { status: r.status, body: (r.text || '').slice(0, 600) };
        } catch (e) { out.bundleProbes[raw] = { status: 0, err: (e && e.message) || String(e) }; }
      }
      // ── 6b. Full market spec + orderbook depth (no truncation)
      try {
        const r = await request('GET', `${APP_BASE}/api/markets`, { ...opts, headers: hdr({ 'Authorization': 'Bearer ' + bearer() }) });
        const j = r.json || JSON.parse(r.text || '{}');
        out.marketEntry = (j.markets || []).find(x => x.market_id === market) || null;
        out.allMarketIds = (j.markets || []).map(x => x.market_id);
      } catch (e) { out.marketEntry = { _err: (e && e.message) || String(e) }; }
      for (const st of ['all', 'ORDER_STATUS_ACTIVE']) {
        try {
          const r = await request('GET', `${APP_BASE}/api/orders?market=${encodeURIComponent(market)}&status=${st}`, { ...opts, headers: hdr({ 'Authorization': 'Bearer ' + bearer() }) });
          const j = r.json || JSON.parse(r.text || '{}');
          out['orders_' + st] = { count: (j.orders || []).length, sample: (j.orders || []).slice(0, 8) };
        } catch (e) { out['orders_' + st] = { _err: (e && e.message) || String(e) }; }
      }
      try {
        const r = await request('GET', `${APP_BASE}/api/market-data`, { ...opts, headers: hdr({ 'Authorization': 'Bearer ' + bearer() }) });
        const j = r.json || JSON.parse(r.text || '{}');
        out.marketDataFull = j.market_data || j;
      } catch (_) { }
      // ── 6. Konteks: harga + settlement-proposals aktif (buat bandingin spread)
      out.price = await sv.getPrice(market).catch(() => null);
      try { const sp = await sv.listSettlementProposals(); out.settlementProposalsCount = sp.length; out.settlementProposalsSample = sp.slice(0, 3); } catch (_) { }
      saveJSON(OUT, out);
      process.stdout.write(paint(`\n✓ page ${out.pageStatus}, ${out.chunkCount} chunks, ${out.serverActionNames.length} server-actions\n`, COLOR.green));
      process.stdout.write(paint(`terminal-only actions: `, COLOR.cyan) + (out.terminalOnlyActions.join(', ') || '(none)') + '\n');
      process.stdout.write(paint(`order-ish /api paths: `, COLOR.cyan) + (out.orderApiPaths.join(', ') || '(none)') + '\n');
      process.stdout.write(paint(`REST probe hits (status<400): `, COLOR.cyan) + (Object.entries({ ...out.probes, ...out.bundleProbes }).filter(([, v]) => v.status && v.status < 400).map(([k]) => k).join(', ') || '(none)') + '\n');
      process.stdout.write(paint(`→ full dump: ${OUT}\n`, COLOR.gray));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.stack) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'terminal-order') {
    // `node index.js terminal-order [idx] [go] [buy|sell]` — LIVE PROBE 1 market order
    // di /terminal (CLOB) buat pastiin 2 unknown: (1) linkage order→proposalId, (2) FOK
    // lpOnly match + task. Sizing = M8.usdAmount (leg mode 8). TANPA `go` = DRY (gak submit).
    // Dgn `go` = submitOrder beneran → tangkap linkage → AUTO-CANCEL (order+settlement) biar
    // GAK nyangkut. Probe TIDAK allocate/preconfirm → dana kita TIDAK ke-lock (lock cuma pas
    // allocate Canton). Dump ke terminal-order-probe.json.
    (async () => {
      const idx = Number(argv[1] || 9);
      const GO = argv.includes('go');
      const sideArg = argv.find(x => x === 'buy' || x === 'sell') || null;
      const market = 'EDELx-cETH';
      const a = ACCOUNTS[idx];
      if (!a) { console.error(paint(`akun idx ${idx} gak ada (total ${ACCOUNTS.length})`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      process.stdout.write(paint(`TERMINAL-ORDER probe ${a.label || a.email} ${market} ${GO ? paint('[LIVE]', COLOR.red) : '[DRY]'}…\n`, COLOR.cyan));
      const { sv, partyId, identityToken, proxy } = await buildSwapClients(state);
      const OUTP = '/private/tmp/claude-501/-Users-ipall-SipalDrop-Waras-SilvanaBot-Sipal/c1ca07a4-bfb0-46e0-82aa-eeffc96a6078/scratchpad/terminal-order-probe.json';
      const rec = { account: a.label || a.email, partyId, market, live: GO, ts: new Date().toISOString() };
      const opts = { jar: sv.jar, timeoutMs: 15000, proxy };
      const bearer = () => { try { return acctSession(a.email).privy.token || identityToken; } catch (_) { return identityToken; } };
      const hdr = (extra = {}) => ({ 'User-Agent': UA, 'Accept': '*/*', 'Origin': APP_BASE, 'Referer': `${APP_BASE}/terminal?market=${market}`, ...extra });
      const restJSON = async (path) => { try { const r = await request('GET', `${APP_BASE}${path}`, { ...opts, headers: hdr({ 'Authorization': 'Bearer ' + bearer() }) }); return { status: r.status, json: r.json || (() => { try { return JSON.parse(r.text || ''); } catch (_) { return null; } })() }; } catch (e) { return { status: 0, err: (e && e.message) || String(e) }; } };
      // ── resolve id action terminal dari bundle /terminal (fresh, tahan redeploy)
      const scanTermIds = async () => {
        const page = await request('GET', `${APP_BASE}/terminal?market=${encodeURIComponent(market)}`, { ...opts, headers: hdr({ 'Accept': 'text/html' }) });
        const html = page.text || ''; const urls = new Set(); let m;
        const re = /\/_next\/static\/chunks\/[^"'\s\\]+\.js/g; while ((m = re.exec(html)) !== null) urls.add(m[0]);
        const bm = html.match(/"buildId"\s*:\s*"([^"]+)"/);
        if (bm) { try { const b = await request('GET', `${APP_BASE}/_next/static/${bm[1]}/_buildManifest.js`, { ...opts, timeoutMs: 8000 }); for (const cc of ((b.text || '').match(/static\/chunks\/[^"'\\]+\.js/g) || [])) urls.add('/_next/' + cc); } catch (_) { } }
        const texts = await mapLimit([...urls], 8, u => request('GET', `${APP_BASE}${u}`, { ...opts, headers: hdr() }).then(r => r.status === 200 ? (r.text || '') : '').catch(() => ''));
        const n2i = {}; const reSA = /createServerReference\)\("([0-9a-f]{42})",\s*\w+\.callServer,\s*void\s*0,\s*\w+\.findSourceMapURL,\s*"([a-zA-Z0-9_$]+)"/g;
        let mm; for (const t of texts) while ((mm = reSA.exec(t)) !== null) n2i[mm[2]] = mm[1];
        return n2i;
      };
      const ids = await scanTermIds();
      rec.actionIds = { submitOrder: ids.submitOrder, cancelOrder: ids.cancelOrder, submitPreconfirmation: ids.submitPreconfirmation, getSettlementStatus: ids.getSettlementStatus };
      if (!ids.submitOrder) { console.error(paint('submitOrder id gak ketemu di bundle terminal — abort', COLOR.red)); saveJSON(OUTP, rec); process.exit(1); }
      // ── saldo + harga → sizing usdAmount
      SWAP.tokenId = 'EDELX';
      await refreshBalances(state, identityToken, proxy).catch(() => 0);
      const edelx = unlockedOf(state, 'EDELX'), ceth = unlockedOf(state, 'CETH'), cc = ccUnlockedFrom(state);
      const usdPx = (pd) => { const b = Number(pd && pd.bid), a2 = Number(pd && pd.ask), l = Number(pd && pd.last); return (l > 0 ? l : (a2 > 0 && b > 0 ? (a2 + b) / 2 : (a2 > 0 ? a2 : (b > 0 ? b : 0)))) || 0; };
      const pe = await sv.getPrice('EDELx-USDCx').catch(() => null);
      const pc = await sv.getPrice('cETH-USDCx').catch(() => null);
      const pec = await sv.getPrice('EDELx-cETH').catch(() => null);
      const usdPerEdelx = usdPx(pe), usdPerCeth = usdPx(pc), cethPerEdelx = Number(pec && pec.last) || (usdPerCeth > 0 ? usdPerEdelx / usdPerCeth : 0);
      rec.balances = { edelx, ceth, cc }; rec.prices = { usdPerEdelx, usdPerCeth, cethPerEdelx };
      const valE = edelx * usdPerEdelx, valC = ceth * usdPerCeth;
      // pilih side: arg override → else fundable (usdAmount leg = EDELx→cETH=sell)
      let side = sideArg;
      if (!side) side = (valE >= M8.usdAmount) ? 'sell' : (valC >= M8.usdAmount ? 'buy' : (valE >= valC ? 'sell' : 'buy'));
      const edelxQty = Math.floor((M8.usdAmount / (usdPerEdelx || 1)) * 1e6) / 1e6;   // base EDELx qty senilai usdAmount
      const ref = cethPerEdelx;                                                        // cETH per 1 EDELx (harga book)
      const factor = side === 'buy' ? 1.02 : 0.98;                                     // market cross agresif (sama frontend)
      const price = fmt10(String(ref * factor));
      const payload = { partyId, marketId: market, orderType: side, price, quantity: fmt10(String(edelxQty)), timeInForce: 'FOK', requirements: { lpOnly: true } };
      rec.sizing = { usdAmount: M8.usdAmount, side, edelxQty, ref, price, fundable: side === 'sell' ? valE : valC };
      process.stdout.write(paint(`\nsaldo: EDELx ${edelx.toFixed(2)} ($${valE.toFixed(2)}) | cETH ${ceth.toFixed(6)} ($${valC.toFixed(2)}) | CC ${cc.toFixed(2)}\n`, COLOR.gray));
      process.stdout.write(paint(`sizing usdAmount $${M8.usdAmount} → ${side.toUpperCase()} ${edelxQty} EDELx @ ${price} cETH (ref ${ref.toExponential(3)}, ${side === 'buy' ? '×1.02' : '×0.98'} FOK lpOnly)\n`, COLOR.cyan));
      process.stdout.write(paint(`payload submitOrder:\n`, COLOR.gray) + JSON.stringify(payload) + '\n');
      if (!GO) { rec.mode = 'dry'; saveJSON(OUTP, rec); process.stdout.write(paint(`\n[DRY] gak submit. Tambah 'go' buat live. dump: ${OUTP}\n`, COLOR.yellow)); process.exit(0); }
      // ── LIVE: snapshot proposal sebelum, submit, tangkap linkage, auto-cancel
      const propsBefore = await sv.listSettlementProposals().catch(() => []);
      rec.proposalsBefore = propsBefore.map(p => p.proposalId);
      process.stdout.write(paint(`\n[LIVE] submitOrder…\n`, COLOR.red));
      let orderRes;
      try { orderRes = await sv.swapAction(ids.submitOrder, [payload]); }
      catch (e) { orderRes = { _err: (e && e.message) || String(e) }; }
      rec.submitOrderResult = orderRes;
      process.stdout.write(paint(`submitOrder → `, COLOR.cyan) + JSON.stringify(orderRes).slice(0, 400) + '\n');
      const orderId = orderRes && orderRes.order && (orderRes.order.orderId || orderRes.order.id);
      rec.orderId = orderId || null;
      // ── poll linkage: orders?mine + settlement-proposals baru + getSettlementStatus
      rec.linkPolls = [];
      let foundProposalId = null;
      for (let r = 0; r < 8 && GO; r++) {
        await sleep(4000);
        const mine = await restJSON(`/api/orders?mine=true`);
        const myOrder = (mine.json && (mine.json.orders || []).find(o => (o.orderId || o.id) === orderId)) || null;
        const propsNow = await sv.listSettlementProposals().catch(() => []);
        const fresh = propsNow.filter(p => !rec.proposalsBefore.includes(p.proposalId) && (p.buyer === partyId || p.seller === partyId));
        if (!foundProposalId && fresh[0]) foundProposalId = fresh[0].proposalId;
        // linkage kandidat dari field order
        const linkFromOrder = myOrder && (myOrder.settlementId || myOrder.proposalId || (myOrder.settlement && myOrder.settlement.id));
        if (!foundProposalId && linkFromOrder) foundProposalId = linkFromOrder;
        rec.linkPolls.push({ i: r, orderStatus: myOrder && myOrder.status, orderKeys: myOrder ? Object.keys(myOrder) : null, freshProposals: fresh.map(p => ({ id: p.proposalId, status: p.status, buyer: p.buyer === partyId ? 'me' : 'lp', base: p.baseQuantity })), linkFromOrder: linkFromOrder || null });
        process.stdout.write(paint(`  poll#${r}: order ${myOrder ? myOrder.status : '(gak ada di mine)'} | proposal baru ${fresh.length}${foundProposalId ? ' → ' + foundProposalId.slice(0, 14) : ''}\n`, COLOR.gray));
        if (foundProposalId) { try { const st = await sv.swapAction(ids.getSettlementStatus, [{ settlementId: foundProposalId, partyId }]); rec.settlementStatus = st; process.stdout.write(paint(`  getSettlementStatus stage=${st && st.stage} dvpCid=${(st && st.dvpProposalCid || '').slice(0, 12)}\n`, COLOR.gray)); } catch (e) { rec.settlementStatusErr = (e && e.message) || String(e); } break; }
      }
      rec.foundProposalId = foundProposalId;
      // ── AUTO-CANCEL: order (kalau masih open) + settlement proposal (kalau kebuat, belum alloc)
      rec.cleanup = {};
      if (orderId && ids.cancelOrder) { try { rec.cleanup.cancelOrder = await sv.swapAction(ids.cancelOrder, [{ orderId, partyId }]); } catch (e) { rec.cleanup.cancelOrder = { _err: (e && e.message) || String(e) }; } process.stdout.write(paint(`  cancelOrder → ${JSON.stringify(rec.cleanup.cancelOrder).slice(0, 160)}\n`, COLOR.yellow)); }
      if (foundProposalId) { try { rec.cleanup.cancelSettlement = await sv.cancelSettlement(foundProposalId, partyId, 'probe cleanup'); } catch (e) { rec.cleanup.cancelSettlement = { _err: (e && e.message) || String(e) }; } process.stdout.write(paint(`  cancelSettlement → ${JSON.stringify(rec.cleanup.cancelSettlement).slice(0, 160)}\n`, COLOR.yellow)); }
      // verifikasi saldo gak ke-lock
      await sleep(3000); SWAP.tokenId = 'EDELX'; await refreshBalances(state, identityToken, proxy).catch(() => 0);
      rec.balancesAfter = { edelx: unlockedOf(state, 'EDELX'), ceth: unlockedOf(state, 'CETH'), cc: ccUnlockedFrom(state) };
      saveJSON(OUTP, rec);
      process.stdout.write(paint(`\n✓ probe selesai. saldo after: EDELx ${rec.balancesAfter.edelx.toFixed(2)} cETH ${rec.balancesAfter.ceth.toFixed(6)} CC ${rec.balancesAfter.cc.toFixed(2)}\n`, COLOR.green));
      process.stdout.write(paint(`linkage proposalId: ${foundProposalId || '(gak ketemu)'}\n`, foundProposalId ? COLOR.green : COLOR.yellow));
      process.stdout.write(paint(`→ dump: ${OUTP}\n`, COLOR.gray));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.stack) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'terminal-hist') {
    // `node index.js terminal-hist [idx]` — read-only: tarik settlement RECENT (incl closed)
    // buat liat struktur split terminal (orderMatch:true) + consumedAmuletCids. GAK ngubah apa2.
    (async () => {
      const idx = Number(argv[1] || 9);
      const a = ACCOUNTS[idx]; if (!a) { console.error(paint(`akun idx ${idx} gak ada`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      const { sv, canton, partyId, identityToken, proxy } = await buildSwapClients(state);
      const OUTP = '/private/tmp/claude-501/-Users-ipall-SipalDrop-Waras-SilvanaBot-Sipal/c1ca07a4-bfb0-46e0-82aa-eeffc96a6078/scratchpad/terminal-hist.json';
      const opts = { jar: sv.jar, timeoutMs: 15000, proxy };
      const bearer = () => { try { return acctSession(a.email).privy.token || identityToken; } catch (_) { return identityToken; } };
      const hdr = (extra = {}) => ({ 'User-Agent': UA, 'Accept': '*/*', 'Origin': APP_BASE, 'Referer': `${APP_BASE}/terminal?market=EDELx-cETH`, 'Authorization': 'Bearer ' + bearer(), ...extra });
      const rec = { partyId, ts: new Date().toISOString() };
      // settlement-proposals incl closed (terminal + swap history)
      const r = await request('GET', `${APP_BASE}/api/settlement-proposals?partyId=${encodeURIComponent(partyId)}&includeClosed=1`, { ...opts, headers: hdr() });
      const j = r.json || (() => { try { return JSON.parse(r.text || ''); } catch (_) { return {}; } })();
      const props = (j && j.proposals) || [];
      rec.total = props.length;
      rec.terminal = props.filter(p => p.orderMatch).length;
      rec.rfq = props.filter(p => p.rfqId).length;
      rec.sample = props.slice(0, 12).map(p => ({ proposalId: p.proposalId, orderMatch: !!p.orderMatch, rfqId: p.rfqId || null, orderId: p.orderId || null, market: p.marketId, base: p.baseQuantity, quote: p.quoteQuantity, price: p.settlementPrice, status: p.status, buyer: p.buyer === partyId ? 'me' : 'lp', createdAt: p.createdAt }));
      // getSettlementHistory (consumedAmuletCids) buat 3 proposal terminal terbaru
      const ids = await (async () => { try { const pg = await request('GET', `${APP_BASE}/terminal?market=EDELx-cETH`, { ...opts, headers: hdr({ 'Accept': 'text/html' }) }); const html = pg.text || ''; const urls = new Set(); let m; const re = /\/_next\/static\/chunks\/[^"'\s\\]+\.js/g; while ((m = re.exec(html)) !== null) urls.add(m[0]); const bm = html.match(/"buildId"\s*:\s*"([^"]+)"/); if (bm) { try { const b = await request('GET', `${APP_BASE}/_next/static/${bm[1]}/_buildManifest.js`, { ...opts, timeoutMs: 8000 }); for (const cc of ((b.text || '').match(/static\/chunks\/[^"'\\]+\.js/g) || [])) urls.add('/_next/' + cc); } catch (_) { } } const texts = await mapLimit([...urls], 8, u => request('GET', `${APP_BASE}${u}`, { ...opts, headers: hdr() }).then(x => x.status === 200 ? (x.text || '') : '').catch(() => '')); const n2i = {}; const reSA = /createServerReference\)\("([0-9a-f]{42})",\s*\w+\.callServer,\s*void\s*0,\s*\w+\.findSourceMapURL,\s*"([a-zA-Z0-9_$]+)"/g; let mm; for (const t of texts) while ((mm = reSA.exec(t)) !== null) n2i[mm[2]] = mm[1]; return n2i; } catch (_) { return {}; } })();
      rec.histIds = { getSettlementHistory: ids.getSettlementHistory, getSettlementStatus: ids.getSettlementStatus };
      rec.hist = [];
      for (const p of props.filter(x => x.orderMatch).slice(0, 4)) {
        try { const h = ids.getSettlementHistory ? await sv.swapAction(ids.getSettlementHistory, [{ proposalId: p.proposalId, partyId }]) : null; const st = ids.getSettlementStatus ? await sv.swapAction(ids.getSettlementStatus, [{ settlementId: p.proposalId, partyId }]).catch(() => null) : null; rec.hist.push({ proposalId: p.proposalId, orderId: p.orderId, base: p.baseQuantity, consumedAmuletCids: h && h.consumedAmuletCids, stage: st && st.stage, dvpCid: st && st.dvpProposalCid }); } catch (e) { rec.hist.push({ proposalId: p.proposalId, _err: (e && e.message) || String(e) }); }
      }
      saveJSON(OUTP, rec);
      process.stdout.write(paint(`\n✓ ${rec.total} proposals (terminal ${rec.terminal}, rfq ${rec.rfq}) → ${OUTP}\n`, COLOR.green));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.stack) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'terminal-swap') {
    // `node index.js terminal-swap [idx] [buy|sell] [go]` — LIVE test terminalSwapOnce
    // (full: submitOrder → settle N proposal / dust-cancel) 1 akun, sizing usdAmount.
    // TANPA `go` = DRY (print sizing, gak submit). Dgn `go` = REAL (sign + bayar fee).
    (async () => {
      const idx = Number(argv[1] || 9);
      const GO = argv.includes('go');
      const sideArg = argv.find(x => x === 'buy' || x === 'sell') || null;
      const a = ACCOUNTS[idx]; if (!a) { console.error(paint(`akun idx ${idx} gak ada`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      process.stdout.write(paint(`TERMINAL-SWAP ${a.label || a.email} ${GO ? paint('[LIVE]', COLOR.red) : '[DRY]'}…\n`, COLOR.cyan));
      const clients = await buildSwapClients(state);
      const { sv, partyId, identityToken, proxy } = clients;
      let userServiceCid = getUserServiceCid(a.email);
      if (!userServiceCid) { try { const p = await sv.recoverParty(partyId); if (p && p.userServiceCid) { userServiceCid = p.userServiceCid; patchAcctSession(a.email, { userServiceCid }); } } catch (_) { } }
      await ensureActionIds(sv, partyId, a.label || a.email);
      SWAP.tokenId = 'EDELX'; await refreshBalances(state, identityToken, proxy).catch(() => 0);
      const edelx = unlockedOf(state, 'EDELX'), ceth = unlockedOf(state, 'CETH'), cc = ccUnlockedFrom(state);
      const usdPx = (pd) => { const b = Number(pd && pd.bid), a2 = Number(pd && pd.ask), l = Number(pd && pd.last); return (l > 0 ? l : (a2 > 0 && b > 0 ? (a2 + b) / 2 : (a2 > 0 ? a2 : (b > 0 ? b : 0)))) || 0; };
      const usdPerEdelx = usdPx(await sv.getPrice('EDELx-USDCx').catch(() => null));
      const usdPerCeth = usdPx(await sv.getPrice('cETH-USDCx').catch(() => null));
      const valE = edelx * usdPerEdelx, valC = ceth * usdPerCeth;
      let side = sideArg || ((valE >= M8.usdAmount) ? 'sell' : (valC >= M8.usdAmount ? 'buy' : (valE >= valC ? 'sell' : 'buy')));
      const deliver = side === 'buy' ? 'cETH' : 'EDELx';
      const { leg } = edelCethLeg(deliver);
      // Sizing SAMA kayak mode 8: BUY = dump SEMUA cETH di harga ORDER (÷1+orderCross);
      // SELL = min(valE, usdAmount). Biar test faithful (reproduksi dump-all).
      const edelxQty = side === 'buy'
        ? Math.floor(((ceth * usdPerCeth) / (usdPerEdelx || 1) / (1 + M8.orderCross)) * 1e6) / 1e6
        : Math.floor((Math.min(valE, M8.usdAmount) / (usdPerEdelx || 1)) * 1e6) / 1e6;
      process.stdout.write(paint(`saldo EDELx ${edelx.toFixed(2)} ($${valE.toFixed(2)}) cETH ${ceth.toFixed(6)} ($${valC.toFixed(2)}) CC ${cc.toFixed(2)}\n`, COLOR.gray));
      process.stdout.write(paint(`→ ${side.toUpperCase()} ${edelxQty} EDELx (deliver ${deliver}, sizing $${M8.usdAmount}, minUsd $${M8.minUsd})\n`, COLOR.cyan));
      if (!GO) { process.stdout.write(paint(`[DRY] gak submit. Tambah 'go' buat live.\n`, COLOR.yellow)); process.exit(0); }
      const res = await terminalSwapOnce({ ...clients, userServiceCid, leg, maxFeeCC: M8.maxFeeCC, minUsd: M8.minUsd, usdPerEdelx, cethPerEdelx: (usdPerCeth > 0 ? usdPerEdelx / usdPerCeth : 0), log: (m) => process.stdout.write(paint('  ' + m + '\n', COLOR.gray)), onWalletPicked: (id) => { try { patchAcctSession(a.email, { privyWalletId: id }); } catch (_) { } } }, side, edelxQty);
      process.stdout.write(paint(`\n✓ hasil: ${JSON.stringify(res)}\n`, COLOR.green));
      await sleep(4000); SWAP.tokenId = 'EDELX'; await refreshBalances(state, identityToken, proxy).catch(() => 0);
      process.stdout.write(paint(`saldo after: EDELx ${unlockedOf(state, 'EDELX').toFixed(2)} cETH ${unlockedOf(state, 'CETH').toFixed(6)} CC ${ccUnlockedFrom(state).toFixed(2)}\n`, COLOR.gray));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.stack) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'swap') {
    // `node index.js swap [ceth|usdcx] [sell|buy]` — pilih pair (default usdcx) +
    // paksa arah INTENT (sell=open CC→token, buy=close token→CC).
    let ai = 1;
    if (PAIRS[argv[ai]]) { setActivePair(argv[ai]); ai++; }
    if (argv[ai] === 'sell' || argv[ai] === 'buy') global.__forceDir = argv[ai];
    process.stdout.write(paint(`pair: ${SWAP.market} (CC↔${SWAP.tokenLabel})\n`, COLOR.cyan));
    (async () => { global.__states = makeStates(); render(global.__states); await runDayTraderSession('manual'); process.exit(0); })().catch(e => { console.error(paint('FATAL: ' + e.message, COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'proposals') {
    // `node index.js proposals` — list settlement/DvpProposal aktif (read-only).
    // Buat ngecek apakah feecheck/skip-spike ninggalin proposal nyangkut.
    (async () => {
      const a = ACCOUNTS[0];
      if (!a) { console.error(paint('accounts.json kosong', COLOR.red)); process.exit(1); }
      const state = makeStates()[0];
      const { sv, partyId } = await buildSwapClients(state);
      const allRaw = await sv.listSettlementProposals().catch(() => []);
      const all = allRaw.filter(p => p.buyer === partyId || p.seller === partyId);
      process.stdout.write(paint(`\nparty ${partyId.slice(0, 24)}… — total proposals: ${all.length}\n`, COLOR.cyan));
      for (const p of all) {
        const st = await sv.swapAction(SWAP.actionIds.pollProposal, [{ settlementId: p.proposalId, partyId }]).catch(() => null);
        const stage = (st && st.stage) || 0;
        const isBuyer = p.buyer === partyId;
        const ourAlloc = st ? (isBuyer ? st.allocationBuyerCid : st.allocationSellerCid) : null;
        const locked = ourAlloc && ourAlloc !== '$undefined';
        const rej = st && (st.buyerRejected || st.sellerRejected);
        const tag = stage >= 9 ? 'SETTLED' : rej ? 'REJECTED' : locked ? 'LOCKED(dana kita kekunci)' : 'pending(0 dana kita)';
        process.stdout.write(`  - ${p.proposalId.slice(0, 16)}… stage ${stage} ${isBuyer ? 'BUY' : 'SELL'} ${p.baseQuantity} CC → ${paint(tag, locked ? COLOR.red : stage >= 9 ? COLOR.green : COLOR.gray)}\n`);
      }
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'diag') {
    // `node index.js diag [idx]` — DUMP struktur ledger asli (read-only) ke diag-out.json
    // buat cari tau kenapa proposal nyangkut: status DvpProposal, jumlah Allocation,
    // shape getDsoInfo/getOpenRound. GAK ngubah apa-apa.
    (async () => {
      const idx = Number(argv[1] || 0);
      const a = ACCOUNTS[idx];
      if (!a) { console.error(paint(`akun idx ${idx} gak ada (total ${ACCOUNTS.length})`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      process.stdout.write(paint(`DIAG ${a.label || a.email}…\n`, COLOR.cyan));
      const { sv, canton, partyId } = await buildSwapClients(state);
      const out = { account: a.label || a.email, partyId, ts: new Date().toISOString() };
      // DvpProposal active_contracts
      const dvps = await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(e => ({ _err: (e && e.message) || String(e) }));
      if (Array.isArray(dvps)) {
        out.dvpCount = dvps.length;
        out.dvpRowKeys = dvps[0] ? Object.keys(dvps[0]) : [];
        out.dvpCreateArgKeys = (dvps[0] && dvps[0].createArgument) ? Object.keys(dvps[0].createArgument) : [];
        const statusCount = {};
        let mineProposer = 0, mineCounter = 0;
        for (const c of dvps) {
          const ca = c.createArgument || {};
          const status = ca.status || (ca.terms && ca.terms.status) || ca.state || '(no-status-field)';
          statusCount[String(status)] = (statusCount[String(status)] || 0) + 1;
          if (ca.proposer === partyId) mineProposer++;
          if (ca.counterparty === partyId) mineCounter++;
        }
        out.dvpStatusCount = statusCount;
        out.dvpMineProposer = mineProposer;
        out.dvpMineCounter = mineCounter;
        out.dvpSampleFull = dvps.slice(0, 2).map(c => c.createArgument);
      } else out.dvpErr = dvps;
      // RAW probe helper (pakai identity token canton)
      const idTok = (acctSession(a.email).privy || {}).token;
      const px = getProxy(a.email);
      const tryGet = async (qs) => { try { const r = await request('GET', `${SUPA}/active_contracts?${qs}`, { headers: supaHeaders(idTok), timeoutMs: 20000, proxy: px }); return { status: r.status, n: Array.isArray(r.json) ? r.json.length : (r.json ? 'obj' : (r.text || '').slice(0, 100)) }; } catch (e) { return { err: (e && e.message) || String(e) }; } };
      // Allocation interface — coba beberapa format query (yg lama 400)
      const HOLD = '#splice-api-token-holding-v1:Splice.Api.Token.HoldingV1:Holding';
      out.allocVariants = {
        'templateIds=alloc': await tryGet('templateIds=' + encodeURIComponent(ALLOCATION_IFACE)),
        'interfaceIds=alloc': await tryGet('interfaceIds=' + encodeURIComponent(ALLOCATION_IFACE)),
        'interfaceIds=holding': await tryGet('interfaceIds=' + encodeURIComponent(HOLD)),
        'templateIds=holding': await tryGet('templateIds=' + encodeURIComponent(HOLD)),
      };
      // DUMP row interface alloc ASLI (cari field cid yg bener) + test 1 withdraw.
      try {
        const ra = await request('GET', `${SUPA}/active_contracts?interfaceIds=${encodeURIComponent(ALLOCATION_IFACE)}`, { headers: supaHeaders(idTok), timeoutMs: 20000, proxy: px });
        const arr = Array.isArray(ra.json) ? ra.json : [];
        out.allocIfaceCount = arr.length;
        out.allocIfaceSample = arr.slice(0, 1); // FULL 1 row → liat struktur
      } catch (e) { out.allocIfaceErr = (e && e.message) || String(e); }
      // TEST 1 withdraw prepare (capture error FULL) — pakai getDsoInfo context.
      try { await sv.discoverActionIds(); } catch (_) { }
      const dsoT = await sv.swapAction(SWAP.actionIds.getDsoInfo, []).catch(e => ({ _err: (e && e.message) }));
      const arc = _normContract(dsoT && dsoT.amulet_rules && dsoT.amulet_rules.contract);
      const omc = _normContract(dsoT && dsoT.latest_mining_round && dsoT.latest_mining_round.contract);
      const testCid = (out.allocIfaceSample && out.allocIfaceSample[0] && _acContractId(out.allocIfaceSample[0]));
      out.withdrawTest = { testCid, arc: !!(arc && arc.contractId), omc: !!(omc && omc.contractId) };
      if (testCid && arc && omc) {
        const body = { commands: [{ ExerciseCommand: { templateId: ALLOCATION_IFACE, contractId: testCid, choice: 'Allocation_Withdraw', choiceArgument: { extraArgs: { context: { values: { 'expire-lock': { tag: 'AV_Bool', value: true }, 'amulet-rules': { tag: 'AV_ContractId', value: arc.contractId }, 'open-round': { tag: 'AV_ContractId', value: omc.contractId } } }, meta: { values: {} } } } } }], disclosedContracts: [{ templateId: omc.templateId, contractId: omc.contractId, createdEventBlob: omc.createdEventBlob, synchronizerId: SWAP.synchronizerId }, { templateId: arc.templateId, contractId: arc.contractId, createdEventBlob: arc.createdEventBlob, synchronizerId: SWAP.synchronizerId }] };
        try { const pr = await request('POST', `${SUPA}/prepare_transaction`, { headers: supaHeaders(idTok), body: JSON.stringify(body), timeoutMs: 30000, proxy: px }); out.withdrawTest.prepStatus = pr.status; out.withdrawTest.prepBody = (pr.text || '').slice(0, 600); } catch (e) { out.withdrawTest.prepErr = (e && e.message) || String(e); }
      }
      // open round dari getDsoInfo (getOpenRound action 404) → pakai latest_mining_round
      // getDsoInfo / getOpenRound raw (force discover dulu)
      try { await sv.discoverActionIds(); } catch (_) { }
      out.idDso = SWAP.actionIds.getDsoInfo; out.idOmr = SWAP.actionIds.getOpenRound;
      out.getDsoInfo = await sv.swapAction(SWAP.actionIds.getDsoInfo, []).catch(e => ({ _err: (e && e.message) || String(e) }));
      out.getOpenRound = await sv.swapAction(SWAP.actionIds.getOpenRound, []).catch(e => ({ _err: (e && e.message) || String(e) }));
      const fp = path.join(ROOT, 'diag-out.json');
      fs.writeFileSync(fp, JSON.stringify(out, null, 2));
      process.stdout.write(paint(`\n✓ ditulis ${fp}\n`, COLOR.green));
      process.stdout.write(`  DvpProposal=${out.dvpCount} (proposer=${out.dvpMineProposer} counter=${out.dvpMineCounter})\n`);
      process.stdout.write(`  allocVariants=${JSON.stringify(out.allocVariants)}\n`);
      process.stdout.write(`  byCid=${JSON.stringify(out.byCid || null)}\n`);
      process.stdout.write(`  miningRound.contract=${out.getDsoInfo && out.getDsoInfo.latest_mining_round && out.getDsoInfo.latest_mining_round.contract ? 'OK' : 'MISSING'}\n`);
      process.exit(0);
    })().catch(e => { console.error(paint('DIAG FATAL: ' + (e && e.stack || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'cleanup') {
    // `node index.js cleanup` — cancel proposal nyangkut yg 0 dana kita kekunci
    // (stage<9, belum settle, alloc kita kosong, umur >90s). Aman: gak ada dana
    // ke-lock. Cancel via cancelSettlement (V2). NEVER sentuh LOCKED/SETTLED.
    (async () => {
      const a = ACCOUNTS[0];
      if (!a) { console.error(paint('accounts.json kosong', COLOR.red)); process.exit(1); }
      const state = makeStates()[0];
      const { sv, canton, partyId, privy } = await buildSwapClients(state);
      const n = await cleanupStaleProposals(sv, canton, partyId, (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n'), privy);
      process.stdout.write(paint(`\ncleanup selesai — ${n} proposal dibersihin (cancel + withdraw)\n`, COLOR.green));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'feecheck') {
    // `node index.js feecheck [ceth|usdcx|edelceth] [sell|buy] [amount]` — dry-run: flow
    // swap ASLI sampai feeCtx lalu STOP sebelum submit. Log 3 angka fee. 0 CC kebayar.
    // dir = arah MARKET-NATIVE (langsung ke swapOnce); amt = base quantity (CC utk
    // usdcx, cETH utk ceth, EDELx utk edelceth). Pakai buat validasi sebelum live!
    // edelceth (opsi 8 token↔token): sell=deliver EDELx, buy=deliver cETH; amt = EDELx base.
    let ai = 1;
    if (argv[ai] === 'edelceth' || argv[ai] === 'edel') { ai++; const dv = (argv[ai] === 'buy') ? 'cETH' : 'EDELx'; setEdelCethLeg(dv); }
    else if (PAIRS[argv[ai]]) { setActivePair(argv[ai]); ai++; }
    const dir = (argv[ai] === 'buy') ? 'buy' : 'sell';
    const amt = String(argv[ai + 1] || SWAP_MIN_AMOUNT || '11');
    const unit = SWAP.tokenToToken ? 'EDELx(base)' : (SWAP.baseIsCC ? 'CC' : SWAP.tokenLabel);
    (async () => {
      const a = ACCOUNTS[0];
      if (!a) { console.error(paint('accounts.json kosong', COLOR.red)); process.exit(1); }
      const state = makeStates()[0];
      process.stdout.write(paint(`feecheck (dry-run): ${SWAP.market} ${dir} ${amt} ${unit} — ${a.label || a.email}\n`, COLOR.cyan));
      const clients = await buildSwapClients(state);
      let userServiceCid = getUserServiceCid(a.email);
      if (!userServiceCid) {
        const party = await clients.sv.recoverParty(clients.partyId).catch(() => null);
        if (party && party.userServiceCid) { userServiceCid = party.userServiceCid; patchAcctSession(a.email, { userServiceCid }); }
      }
      try {
        await swapOnce({ ...clients, userServiceCid, dryRun: true, log: (m) => process.stdout.write('  ' + m + '\n') }, dir, amt);
        console.error(paint('swap selesai TANPA abort — cek dryRun guard', COLOR.red));
      } catch (e) {
        if (e && e.dryRun) {
          const f = e.fees || {};
          process.stdout.write('\n' + paint('=== FEE CHECK (dry-run, 0 CC kebayar) ===', COLOR.bold + COLOR.green) + '\n');
          process.stdout.write(`  estimateFee   : ${f.estFeeCC} CC\n`);
          process.stdout.write(`  quote (${f.lp}) : ${f.quoteFeeCC} CC\n`);
          process.stdout.write(`  feeCtx REAL   : ${paint(String(f.realFeeCC) + ' CC', COLOR.bold)}\n`);
          process.stdout.write(`  batas maxFeeCC: ${SWAP.maxFeeCC} CC\n`);
        } else {
          console.error(paint('feecheck error: ' + ((e && e.message) || e), COLOR.red));
        }
      }
      // Auto-cleanup: reject proposal yg dibuat dry-run (0 dana kelock) biar 0 sisa.
      const n = await cleanupStaleProposals(clients.sv, clients.canton, clients.partyId, undefined, clients.privy).catch(() => 0);
      if (n) process.stdout.write(paint(`  ${n} proposal nyangkut dibersihin\n`, COLOR.green));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv.length === 0) {
    if (!ACCOUNTS.length) { console.error(paint('accounts.json kosong. Jalankan: node index.js register', COLOR.red)); process.exit(1); }
    (async () => {
      process.stdout.write('\n' + paint('SilvanaBot-Sipal', COLOR.bold + COLOR.cyan) + '\n');
      process.stdout.write(paint('  0) swap CC→cETH   — dashboard + auto DAY_TRADER (pair cETH)', COLOR.gray) + '\n');
      process.stdout.write(paint('  1) swap CC→USDCx  — dashboard + auto DAY_TRADER (pair USDCx)', COLOR.gray) + '\n');
      process.stdout.write(paint('  2) check balance  — tabel CC/USDCx/cETH/EDELx + total, auto-refresh /1mnt', COLOR.gray) + '\n');
      process.stdout.write(paint('  3) run (OTP urut) — login akun 1-per-1 (OTP gak tabrakan) lalu run USDCx', COLOR.gray) + '\n');
      process.stdout.write(paint('  4) change wallet  — ganti wallet supa 1 akun (hapus lama → login email supa baru)', COLOR.gray) + '\n');
      process.stdout.write(paint('  5) maintenance    — a) cleanup DvpProposal stale  b) reset season (fee + loss → 0)', COLOR.gray) + '\n');
      process.stdout.write(paint('  6) swap back      — dump token (USDCx/cETH/EDELx) → CC, SEMUA akun', COLOR.gray) + '\n');
      process.stdout.write(paint('  7) EDELx manual   — a) CC→EDELx (input CC, multi-akun parallel)  b) dump EDELx→CC (1 akun)', COLOR.gray) + '\n');
      process.stdout.write(paint('  8) EDELx↔cETH     — ping-pong bolak-balik, SEMUA akun (target earn-hub)', COLOR.gray) + '\n');
      process.stdout.write(paint('  9) bulk back      — dump ke CC, SEMUA akun (pilih pair: USDCx/cETH/EDELx/semua)', COLOR.gray) + '\n');
      const ans = (await prompt(paint('pilih [0/1/2/3/4/5/6/7/8/9]: ', COLOR.bold))).trim();
      if (ans === '2') {
        // Cek balance: tabel + grand total, AUTO-REFRESH tiap N menit (default 15,
        // config.dashboard.balanceRefreshMin). Loop terus — Ctrl+C buat berhenti.
        await runBalanceMonitor(); // infinite loop; ga balik
        return;
      }
      if (ans === '3') {
        // OTP sequential: login tiap akun SATU PER SATU (concurrency 1) biar prompt
        // OTP gak tabrakan di stdin. Token nyimpan ke session.json → tickAll paralel
        // sesudahnya pakai cache, gak prompt lagi.
        const states = makeStates();
        global.__states = states;
        process.stdout.write('\n' + paint('Login berurutan (OTP satu per satu)…', COLOR.cyan) + '\n');
        let ok = 0, fail = 0;
        for (let i = 0; i < states.length; i++) {
          const s = states[i];
          process.stdout.write('\n' + paint(`[${i + 1}/${states.length}] ${s.label || s.email}`, COLOR.bold) + '\n');
          try {
            await ensurePrivyToken(s);
            await ensureSilvanaSession(s).catch(() => null);
            process.stdout.write(paint('  ✓ login OK', COLOR.green) + '\n');
            ok++;
          } catch (e) {
            process.stdout.write(paint('  ✗ ' + ((e && e.message) || e), COLOR.red) + '\n');
            fail++;
          }
        }
        process.stdout.write('\n' + paint(`Login selesai: ${ok} OK, ${fail} gagal. Lanjut run…`, fail ? COLOR.yellow : COLOR.green) + '\n');
      }
      if (ans === '4') {
        // Ganti wallet supa 1 akun: hapus wallet lama (privy login + walletId + party +
        // userServiceCid), login email supa BARU (OTP), re-derive party/wallet via
        // buildSwapClients. passkey + cookie Silvana TETAP (identitas akun gak berubah).
        process.stdout.write('\n' + paint('Ganti wallet supa — pilih akun:', COLOR.bold + COLOR.cyan) + '\n');
        ACCOUNTS.forEach((a, i) => process.stdout.write(paint(`  ${i}) ${a.label || a.email}  (supa: ${a.privyEmail || a.email})`, COLOR.gray) + '\n'));
        const idx = Number((await prompt(paint(`pilih akun [0-${ACCOUNTS.length - 1}]: `, COLOR.bold))).trim());
        if (!Number.isInteger(idx) || idx < 0 || idx >= ACCOUNTS.length) { console.error(paint('pilihan gak valid', COLOR.red)); process.exit(1); }
        const acct = ACCOUNTS[idx];
        const newEmail = (await prompt(paint(`email supa baru utk ${acct.label || acct.email}: `, COLOR.bold))).trim().toLowerCase();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(newEmail)) { console.error(paint('format email gak valid', COLOR.red)); process.exit(1); }
        // backup session.json
        const bak = `session.json.bak-${new Date().toISOString().replace(/[:.]/g, '-')}`;
        try { fs.copyFileSync(SESS_PATH, bak); process.stdout.write(paint(`backup: ${bak}\n`, COLOR.gray)); } catch (_) { }
        // hapus wallet supa lama (keep passkey + silvanaCookies)
        const store = loadStore();
        if (store[acct.email]) { for (const f of ['privy', 'privyWalletId', 'partyId', 'userServiceCid']) delete store[acct.email][f]; saveStore(store); }
        process.stdout.write(paint(`  wallet supa lama dihapus utk ${acct.email}\n`, COLOR.green));
        // update privyEmail di accounts.json (persist) + in-memory
        const data = loadJSON(ACC_PATH, { accounts: [] });
        const entry = (data.accounts || []).find(x => x.email === acct.email);
        if (entry) { entry.privyEmail = newEmail; saveJSON(ACC_PATH, data); }
        acct.privyEmail = newEmail;
        // login OTP email baru + re-derive party/wallet
        const state = { email: acct.email, privyEmail: newEmail, label: acct.label, status: 'idle', message: '' };
        global.__states = [state];
        process.stdout.write('\n' + paint(`Login supa baru ${newEmail} (tunggu OTP)…`, COLOR.cyan) + '\n');
        try {
          const clients = await buildSwapClients(state);
          let usc = null;
          try { const party = await clients.sv.recoverParty(clients.partyId); if (party && party.userServiceCid) { usc = party.userServiceCid; patchAcctSession(acct.email, { userServiceCid: usc }); } } catch (_) { }
          process.stdout.write('\n' + paint('✓ wallet supa baru aktif', COLOR.bold + COLOR.green) + '\n');
          process.stdout.write(paint(`  supa email     : ${newEmail}\n`, COLOR.gray));
          process.stdout.write(paint(`  partyId        : ${clients.partyId}\n`, COLOR.gray));
          process.stdout.write(paint(`  walletId       : ${(clients.privy && clients.privy.wallet && clients.privy.wallet.id) || '-'}\n`, COLOR.gray));
          process.stdout.write(paint(`  userServiceCid : ${usc || '(auto-recover saat swap)'}\n`, COLOR.gray));
        } catch (e) {
          console.error(paint('ganti wallet gagal: ' + ((e && e.message) || e), COLOR.red));
          console.error(paint(`restore session lama: cp ${bak} session.json`, COLOR.yellow));
          process.exit(1);
        }
        process.exit(0);
      }
      if (ans === '5') {
        // Sub-menu maintenance:
        //   a) cleanup      — archive DvpProposal stale nyangkut (cap-200)
        //   b) reset season — nol-in akumulator SEASON di dashboard (tanggal season gak
        //                     menentu → user yg nentuin kapan season baru mulai)
        process.stdout.write('\n' + paint('Maintenance:', COLOR.bold + COLOR.cyan) + '\n');
        process.stdout.write(paint('  a) cleanup      — bersihin DvpProposal stale nyangkut', COLOR.gray) + '\n');
        process.stdout.write(paint('  b) reset season — nol-in kolom SEASON + LOSS/SN (fee kebakar + spread loss) di dashboard', COLOR.gray) + '\n');
        const sub5 = (await prompt(paint('pilih [a/b]: ', COLOR.bold))).trim().toLowerCase();
        if (sub5 !== 'a' && sub5 !== 'b') { console.error(paint('pilihan gak valid', COLOR.red)); process.exit(1); }

        // Picker akun dipakai dua-duanya (index tunggal atau 'a' = semua akun).
        const pickAccounts = async (judul) => {
          process.stdout.write('\n' + paint(judul, COLOR.bold + COLOR.cyan) + '\n');
          ACCOUNTS.forEach((a, i) => process.stdout.write(paint(`  ${i}) ${a.label || a.email}`, COLOR.gray) + '\n'));
          process.stdout.write(paint('  a) SEMUA akun', COLOR.gray) + '\n');
          const sel = (await prompt(paint(`pilih akun [0-${ACCOUNTS.length - 1} / a]: `, COLOR.bold))).trim().toLowerCase();
          if (sel === 'a' || sel === 'all' || sel === '*') return ACCOUNTS.slice();
          const idx = Number(sel);
          if (!Number.isInteger(idx) || idx < 0 || idx >= ACCOUNTS.length) { console.error(paint('pilihan gak valid', COLOR.red)); process.exit(1); }
          return [ACCOUNTS[idx]];
        };

        if (sub5 === 'b') {
          // Reset season: hapus akumulator feeSeason + spreadSeason di session.json. Cuma
          // angka dashboard — gak nyentuh saldo/ledger, gak bisa di-undo (angka lama ilang).
          const targets = await pickAccounts('Reset season (fee + loss) — pilih akun:');
          const before = targets.map(a => { const s = acctSession(a.email) || {}; return { acct: a, fee: Number(s.feeSeason) || 0, spread: Number(s.spreadSeason) || 0 }; });
          const feeBefore = before.reduce((x, b) => x + b.fee, 0);
          const lossBefore = before.reduce((x, b) => x + b.spread, 0);
          process.stdout.write('\n' + paint('Yang bakal di-reset:', COLOR.bold) + '\n');
          before.forEach(b => process.stdout.write(paint(`  ${b.acct.label || b.acct.email}: fee ${fmtSeason(b.fee)} CC · loss $${fmtSeason(b.spread)} → 0`, COLOR.gray) + '\n'));
          process.stdout.write(paint(`  total: fee ${fmtSeason(feeBefore)} CC`, COLOR.mag) + paint(` · loss $${fmtSeason(lossBefore)}`, COLOR.red) + '\n');
          const ok = (await prompt(paint('Yakin reset? angka lama ilang permanen [y/N]: ', COLOR.bold + COLOR.yellow))).trim().toLowerCase();
          if (ok !== 'y' && ok !== 'ya' && ok !== 'yes') { process.stdout.write(paint('dibatalin — season gak berubah\n', COLOR.gray)); process.exit(0); }
          for (const b of before) resetSeason(b.acct.email);
          process.stdout.write('\n' + paint(`✓ season di-reset — ${targets.length} akun, fee ${fmtSeason(feeBefore)} CC + loss $${fmtSeason(lossBefore)} dinolin`, COLOR.bold + COLOR.green) + '\n');
          process.exit(0);
        }

        // sub5 === 'a' → cleanup DvpProposal stale nyangkut (archive yg 0-dana, tua>120s).
        // Gantiin "ganti wallet" buat akun kena cap-200 "Menunggu DvpProposal".
        const targets = await pickAccounts('Cleanup DvpProposal stale — pilih akun:');
        // global.__states sengaja TIDAK di-set → render no-op, output bersih lewat stdout.
        const olog = (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n');
        const cleanupOne = async (acct) => {
          const tag = acct.label || acct.email;
          const st = { email: acct.email, privyEmail: acct.privyEmail || null, label: acct.label, status: 'idle', message: '' };
          try {
            const { sv, canton, partyId, privy } = await buildSwapClients(st);
            const before = (await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(() => [])).length;
            const n = await drainStaleDvpProposals(sv, canton, privy, partyId, (m, c) => olog(`  [${tag}] ${m}`, c));
            const after = (await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(() => [])).length;
            olog(`[${tag}] ✓ cleanup — ${n} dibersihin (DvpProposal ${before} → ${after})`, COLOR.bold + COLOR.green);
            return n;
          } catch (e) {
            olog(`[${tag}] cleanup gagal: ${(e && e.message) || e}`, COLOR.red);
            return 0;
          }
        };
        process.stdout.write('\n' + paint(`Cleanup ${targets.length} akun…`, COLOR.cyan) + '\n');
        let total = 0;
        const runOne = async (acct) => { total += await cleanupOne(acct); };
        if (targets.length > 1 && SWAP.parallel) { olog(`(parallel x${SWAP.concurrency})`, COLOR.gray); await mapLimit(targets, Math.max(1, Number(SWAP.concurrency) || 1), runOne); }
        else { for (const acct of targets) await runOne(acct); }
        process.stdout.write('\n' + paint(`✓ cleanup selesai — total ${total} dibersihin (${targets.length} akun)`, COLOR.bold + COLOR.green) + '\n');
        process.exit(0);
      }
      if (ans === '6') {
        // Swap back: dump SEMUA token (USDCx / cETH / EDELx) → CC buat SEMUA akun.
        // swapBackAccountToCC = loop dump SWAP.tokenId→CC + reduce-on-fail (insufficientBalance
        // → kurangi amount bertahap, mirip opsi 0/1). Unlocked aja. One-shot lalu exit.
        process.stdout.write('\n' + paint('Swap back ke CC — pilih pair:', COLOR.bold + COLOR.cyan) + '\n');
        process.stdout.write(paint('  1) USDCx → CC', COLOR.gray) + '\n');
        process.stdout.write(paint('  2) cETH  → CC', COLOR.gray) + '\n');
        process.stdout.write(paint('  3) EDELx → CC', COLOR.gray) + '\n');
        const sub = (await prompt(paint('pilih [1/2/3]: ', COLOR.bold))).trim();
        const pk = sub === '3' ? 'edelx' : sub === '2' ? 'ceth' : sub === '1' ? 'usdcx' : null;
        if (!pk) { console.error(paint('pilihan gak valid', COLOR.red)); process.exit(1); }
        setActivePair(pk);
        const states = makeStates();
        // NB: sengaja TIDAK set global.__states → logActivity/render jadi no-op
        // (render butuh array), output bersih lewat olog stdout (kayak opsi 5).
        process.stdout.write('\n' + paint(`Swap back ${SWAP.tokenLabel} → CC — ${states.length} akun…`, COLOR.bold + COLOR.cyan) + '\n');
        const olog = (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n');
        let totalSwaps = 0;
        const runOne = async (s) => {
          try { const r = await swapBackAccountToCC(s, olog); totalSwaps += (r && r.swaps) || 0; }
          catch (e) { olog(`[${s.label || s.email}] swap back gagal: ${(e && e.message) || e}`, COLOR.red); }
        };
        if (SWAP.parallel) { olog(`(parallel x${SWAP.concurrency})`, COLOR.gray); await mapLimit(states, Math.max(1, Number(SWAP.concurrency) || 1), runOne); }
        else { for (const s of states) await runOne(s); }
        process.stdout.write('\n' + paint(`✓ swap back selesai — ${totalSwaps} swap-back total (${states.length} akun)`, COLOR.bold + COLOR.green) + '\n');
        process.exit(0);
      }
      if (ans === '7') {
        // Fee gate DIMATIKAN (maxFeeCC=∞) di kedua mode.
        //   a) CC→EDELx : input amount CC, swap sekali. 1 / beberapa / SEMUA akun (PARALLEL).
        //   b) EDELx→CC : dump SEMUA EDELx jadi CC, 1 akun (reuse swapBackAccountToCC).
        // Aman parallel (7a): semua akun sama-sama buy CC→EDELx (SWAP stabil, gak flip
        // per-akun kayak mode 8). weProvideCC → gak sentuh SWAP.tokenId per-swap.
        process.stdout.write('\n' + paint('Opsi 7 — pilih mode:', COLOR.bold + COLOR.cyan) + '\n');
        process.stdout.write(paint('  a) CC → EDELx   — input CC, swap sekali (1/beberapa/SEMUA akun, parallel)', COLOR.gray) + '\n');
        process.stdout.write(paint('  b) EDELx → CC   — dump SEMUA EDELx jadi CC, 1 akun', COLOR.gray) + '\n');
        const sub = (await prompt(paint('pilih [a/b]: ', COLOR.bold))).trim().toLowerCase();
        if (sub !== 'a' && sub !== 'b') { console.error(paint('pilihan gak valid', COLOR.red)); process.exit(1); }
        setActivePair('edelx');     // market EDELx-CC, tokenId EDELX, dirOpen buy / dirClose sell
        SWAP.maxFeeCC = Infinity;   // force: abaikan fee (kedua mode, proses exit setelahnya)

        if (sub === 'b') {
          // Dump TOTAL EDELx → CC, 1 akun (picker). swapBackAccountToCC loop sampai dust.
          process.stdout.write('\n' + paint('Dump EDELx→CC — pilih akun:', COLOR.bold + COLOR.cyan) + '\n');
          ACCOUNTS.forEach((a, i) => process.stdout.write(paint(`  ${i}) ${a.label || a.email}`, COLOR.gray) + '\n'));
          const idx = Number((await prompt(paint(`pilih akun [0-${ACCOUNTS.length - 1}]: `, COLOR.bold))).trim());
          if (!Number.isInteger(idx) || idx < 0 || idx >= ACCOUNTS.length) { console.error(paint('pilihan gak valid', COLOR.red)); process.exit(1); }
          const acct = ACCOUNTS[idx];
          process.stdout.write('\n' + paint(`[${acct.label || acct.email}] dump SEMUA EDELx → CC (abaikan fee)…`, COLOR.cyan) + '\n');
          try {
            const r = await swapBackAccountToCC(makeStates()[idx], (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n'));
            process.stdout.write('\n' + paint(`✓ dump selesai — ${r.swaps} swap EDELx→CC, sisa EDELx ${Number(r.finalTok).toFixed(6)} unlocked`, COLOR.bold + COLOR.green) + '\n');
          } catch (e) { console.error(paint('dump EDELx→CC gagal: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); }
          process.exit(0);
        }

        // sub === 'a' : CC→EDELx. Pilih akun (nomor / 0,2,5 / a=semua) → input CC (sama tiap
        // akun) → swap PARALLEL. Fee terpisah (Amulet batch). RFQ unit EDELx (base).
        process.stdout.write('\n' + paint('Swap CC→EDELx — pilih akun:', COLOR.bold + COLOR.cyan) + '\n');
        ACCOUNTS.forEach((a, i) => process.stdout.write(paint(`  ${i}) ${a.label || a.email}`, COLOR.gray) + '\n'));
        const sel = (await prompt(paint(`pilih akun [nomor / 0,2,5 / a=semua]: `, COLOR.bold))).trim().toLowerCase();
        let idxs;
        if (sel === 'a' || sel === 'all' || sel === '*') idxs = ACCOUNTS.map((_, i) => i);
        else idxs = [...new Set(sel.split(/[,\s]+/).map(x => Number(x)).filter(n => Number.isInteger(n) && n >= 0 && n < ACCOUNTS.length))];
        if (!idxs.length) { console.error(paint('pilihan akun gak valid', COLOR.red)); process.exit(1); }
        const ccStr = (await prompt(paint('amount CC yg mau di-swap ke EDELx per akun (fee terpisah): ', COLOR.bold))).trim();
        const ccAmount = Number(ccStr);
        if (!Number.isFinite(ccAmount) || ccAmount <= 0) { console.error(paint('amount CC gak valid', COLOR.red)); process.exit(1); }
        const olog = (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n');
        const doBuyEdelx = async (idx) => {
          const acct = ACCOUNTS[idx], tag = acct.label || acct.email;
          const MAX = Math.max(1, Number((CONFIG.swap || {}).accountRetry) || 4);
          for (let attempt = 1; attempt <= MAX; attempt++) {
            try {
              const clients = await buildSwapClients(makeStates()[idx]);
              let userServiceCid = getUserServiceCid(acct.email);
              if (!userServiceCid) { const party = await clients.sv.recoverParty(clients.partyId).catch(() => null); if (party && party.userServiceCid) { userServiceCid = party.userServiceCid; patchAcctSession(acct.email, { userServiceCid }); } }
              // Harga EDELx-CC bisa telat/null (transient) → retry 3x sebelum dianggap gagal.
              let ccPerEdelx = 0;
              for (let p = 0; p < 3 && !(ccPerEdelx > 0); p++) {
                const pd = await clients.sv.getPrice('EDELx-CC').catch(() => null);
                ccPerEdelx = Number(pd && (pd.ask != null ? pd.ask : pd.last)) || 0;
                if (!(ccPerEdelx > 0)) await sleep(3000);
              }
              if (!(ccPerEdelx > 0)) throw Object.assign(new Error('harga EDELx-CC gak kebaca'), { transient: true });
              const edelxQty = (ccAmount / ccPerEdelx).toFixed(6);
              olog(`[${tag}] CC→EDELx ${ccAmount} CC ≈ ${edelxQty} EDELx${attempt > 1 ? ` (retry ${attempt - 1})` : ''}…`, COLOR.cyan);
              const r = await swapOnce({ ...clients, userServiceCid, log: (m) => olog(`[${tag}] ${m}`, COLOR.gray), onWalletPicked: (id) => { try { patchAcctSession(acct.email, { privyWalletId: id }); } catch (_) { } } }, 'buy', edelxQty);
              if (r && r.feeCC) recordBurn(r.feeCC, tag);
              olog(`[${tag}] ✓ CC→EDELx submitted — ${edelxQty} EDELx (fee ${r.feeCC != null ? r.feeCC + ' CC' : '?'})${r.completed ? ' · confirmed' : ' · menunggu settle'}`, COLOR.green);
              return;   // sukses
            } catch (e) {
              const retryable = !!(e && (e.transient || e.unauthorized)) || isProxyErr(e) || isIpBlockErr(e);
              if (retryable && attempt < MAX) {
                if (isProxyErr(e) || isIpBlockErr(e)) { const np = rotateProxy(acct.email); olog(`[${tag}] proxy/IP-block → rotate ${np ? np.host + ':' + np.port : '-'} (retry ${attempt}/${MAX - 1})`, COLOR.yellow); }
                else olog(`[${tag}] ${shortSwapReason(e)} — retry ${attempt}/${MAX - 1}`, COLOR.yellow);
                await sleep(Math.min(20000, 4000 * attempt));
                continue;
              }
              olog(`[${tag}] CC→EDELx gagal: ${(e && e.message) || e}`, COLOR.red);
              return;
            }
          }
        };
        // Discover action IDs SEKALI (global, shared) sebelum parallel — cegah 404
        // acceptQuote (Silvana redeploy → fallback ID stale) + discovery storm.
        try {
          const c0 = await buildSwapClients(makeStates()[idxs[0]]);
          await ensureActionIds(c0.sv, c0.partyId, ACCOUNTS[idxs[0]].label || ACCOUNTS[idxs[0]].email);
        } catch (e) { olog(`discover action IDs gagal: ${(e && e.message) || e} (self-heal 404 tetap jalan per-swap)`, COLOR.yellow); }
        const conc = Math.max(1, Number(SWAP.concurrency) || 1);
        process.stdout.write('\n' + paint(`Swap CC→EDELx ${ccAmount} CC × ${idxs.length} akun${idxs.length > 1 ? ` · PARALLEL x${conc}` : ''}…`, COLOR.bold + COLOR.cyan) + '\n');
        if (idxs.length > 1) await mapLimit(idxs, conc, doBuyEdelx);
        else await doBuyEdelx(idxs[0]);
        process.stdout.write('\n' + paint(`✓ CC→EDELx selesai — ${idxs.length} akun`, COLOR.bold + COLOR.green) + '\n');
        process.exit(0);
      }
      if (ans === '8') {
        // Ping-pong EDELx↔cETH, SEMUA akun, target-driven dari earn-hub (analog opsi 0/1:
        // dashboard + reschedule harian) via SESSION_ENGINE='pingpong'. Proses swap
        // token↔token (NO CC leg); fee CC terpisah. Parallel per config swap.parallel.
        SESSION_ENGINE = 'pingpong';
        parallelSwapActive = SWAP.parallel;
        process.stdout.write('\n' + paint(`Engine: PING-PONG EDELx↔cETH — SEMUA akun${parallelSwapActive ? ` · PARALLEL x${SWAP.concurrency}` : ''}`, COLOR.bold + COLOR.cyan) + '\n');
        runMain().catch(e => { console.error(paint('FATAL: ' + (e && e.stack || e), COLOR.red)); process.exit(1); });
        return;
      }
      if (ans === '9') {
        // Bulk back ke CC — SEMUA akun. Sub-menu pilih pair (USDCx/cETH/EDELx/SEMUA).
        // Reuse swapBackAccountToCC (loop dump token→CC + reduce-on-fail: kalau LP rate
        // bikin insufficientBalance, amount dikurangi bertahap sampai muat/dust). Fee gate
        // NORMAL (kayak opsi 6; feeSpike → tunggu). Unlocked aja. One-shot lalu exit.
        process.stdout.write('\n' + paint('Bulk back ke CC — pilih pair:', COLOR.bold + COLOR.cyan) + '\n');
        process.stdout.write(paint('  1) USDCx → CC', COLOR.gray) + '\n');
        process.stdout.write(paint('  2) cETH  → CC', COLOR.gray) + '\n');
        process.stdout.write(paint('  3) EDELx → CC', COLOR.gray) + '\n');
        process.stdout.write(paint('  4) SEMUA pair (USDCx + cETH + EDELx)', COLOR.gray) + '\n');
        const sub = (await prompt(paint('pilih [1/2/3/4]: ', COLOR.bold))).trim();
        const pairs = sub === '1' ? ['usdcx'] : sub === '2' ? ['ceth'] : sub === '3' ? ['edelx'] : sub === '4' ? ['usdcx', 'ceth', 'edelx'] : null;
        if (!pairs) { console.error(paint('pilihan gak valid', COLOR.red)); process.exit(1); }
        const states = makeStates();
        // global.__states sengaja TIDAK di-set → render no-op, output bersih lewat olog.
        const olog = (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n');
        let totalSwaps = 0;
        for (const pk of pairs) {
          setActivePair(pk);
          const lbl = SWAP.tokenLabel;
          process.stdout.write('\n' + paint(`Bulk back ${lbl} → CC — ${states.length} akun…`, COLOR.bold + COLOR.cyan) + '\n');
          const runOne = async (s) => {
            try { const r = await swapBackAccountToCC(s, olog); totalSwaps += (r && r.swaps) || 0; }
            catch (e) { olog(`[${s.label || s.email}] bulk back ${lbl} gagal: ${(e && e.message) || e}`, COLOR.red); }
          };
          if (SWAP.parallel) { olog(`(parallel x${SWAP.concurrency})`, COLOR.gray); await mapLimit(states, Math.max(1, Number(SWAP.concurrency) || 1), runOne); }
          else { for (const s of states) await runOne(s); }
        }
        process.stdout.write('\n' + paint(`✓ bulk back selesai — ${totalSwaps} swap-back total (${states.length} akun, ${pairs.length} pair)`, COLOR.bold + COLOR.green) + '\n');
        process.exit(0);
      }
      const pair = setActivePair(ans === '0' ? 'ceth' : 'usdcx');
      // Parallel cuma utk opsi 0 & 1 (config swap.parallel). Opsi 3 (OTP urut) → sequential.
      parallelSwapActive = SWAP.parallel && (ans === '0' || ans === '1');
      process.stdout.write('\n' + paint(`Pair aktif: ${pair.market} (CC↔${pair.tokenLabel})${parallelSwapActive ? ` · PARALLEL x${SWAP.concurrency}` : ''}`, COLOR.bold + COLOR.cyan) + '\n');
      runMain().catch(e => { console.error(paint('FATAL: ' + (e && e.stack || e), COLOR.red)); process.exit(1); });
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else {
    console.error(paint('cmd tidak dikenal: ' + argv[0] + '. Lihat: node index.js help', COLOR.red));
    process.exit(1);
  }
  process.on('SIGINT', () => { process.stdout.write('\n' + paint('bye 👋', COLOR.gray) + '\n'); process.exit(0); });
}
