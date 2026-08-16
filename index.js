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
// Akun "wallet kunci-mentah": partyId-nya terikat ke ed25519 key yg KITA pegang
// (bukan Privy TEE) — mis. wallet hasil register di luar onboarding web. UI & Privy
// TEE gak bisa nandatanganin (BAD SIGNATURE); bot sign pakai crypto.sign. Dipisah dari
// session.json biar jelas & gak kecampur. Format: { "email": "<b64 pkcs8>" } atau
// { "email": { "privateKey": "<b64 pkcs8>", "publicKey": "<b64 32B>", "note": "…" } }.
// TIDAK di-commit (.gitignore) — berisi private key.
const RAWKEYS_PATH = path.join(ROOT, 'raw_keys.json');
// Wallet Walley (walley.cc) — alternatif Supanova. Filenya SENGAJA di luar repo
// (defaultnya folder bot Walley) karena isinya mnemonic; jangan pernah disalin ke sini.
// Urutan cari file wallet Walley:
//   1. env WALLEY_WALLETS            (paling menang, buat path khusus)
//   2. walley_wallets.jsonl di repo  (gitignored — tempat lokal kalau folder bot
//                                     Walley gak ada / mau dipisah per deploy)
//   3. ../../walley/wallets.jsonl    (default: output bot Walley)
const WALLEY_WALLETS_PATH = process.env.WALLEY_WALLETS
  || (fs.existsSync(path.join(ROOT, 'walley_wallets.jsonl')) ? path.join(ROOT, 'walley_wallets.jsonl') : null)
  || path.join(path.dirname(path.dirname(ROOT)), 'walley', 'wallets.jsonl');
const WALLEY_API = 'https://api.walley.cc';
// Interface Holding standar token Canton — dipakai buat baca saldo dari ledger API.
const HOLDING_IFACE = '#splice-api-token-holding-v1:Splice.Api.Token.HoldingV1:Holding';

function loadJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) {
    if (fallback !== undefined) return fallback;
    throw new Error(`Gagal baca ${p}: ${e.message}`);
  }
}
function saveJSON(p, obj) { fs.writeFileSync(p, JSON.stringify(obj, null, 2)); }

// Kunci ed25519 mentah utk akun wallet kunci-mentah (raw_keys.json). Balikin
// { key: KeyObject, pub: '<b64 32B pubkey turunan>' } atau null kalau akun ini bukan
// mode kunci-mentah. Dipakai buildSwapClients → PrivyWallet(rawCantonKey).
function loadRawKey(email) {
  let map; try { map = JSON.parse(fs.readFileSync(RAWKEYS_PATH, 'utf8')); } catch (_) { return null; }
  const v = map[email] || map[(email || '').toLowerCase()];
  if (!v) return null;
  const b64 = typeof v === 'string' ? v : v.privateKey;
  if (!b64) return null;
  try {
    const key = crypto.createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error(`bukan ed25519 (${key.asymmetricKeyType})`);
    const spki = crypto.createPublicKey(key).export({ format: 'der', type: 'spki' });
    const pub = spki.slice(spki.length - 32).toString('base64');
    // Verifikasi opsional: kalau publicKey dicantumin, harus cocok.
    const want = typeof v === 'object' && v.publicKey;
    if (want && want !== pub) throw new Error(`pubkey gak cocok (file ${want} vs turunan ${pub})`);
    return { key, pub };
  } catch (e) { try { logActivity(`raw key ${email} gagal: ${(e && e.message) || e}`, COLOR.red); } catch (_) { } return null; }
}

// ── Wallet Walley (walley.cc) ────────────────────────────────────────────────
// Alternatif Supanova. Bedanya mendasar: kunci ada DI SINI (seed 32 byte dari
// mnemonic → Ed25519), jadi tanda tangan lokal — gak ada TEE, gak ada Privy.
// Silvana emang dukung Walley (bundle-nya punya WALLET.WALLEY / connectWalley),
// tapi jalur webnya lewat popup + localStorage. Yang dipakai bot ini API server
// Walley langsung, sama kayak yang dipakai bot Python di folder walley/.
//
// Auth: POST /v1/auth/challenge → tanda tangani challenge → POST /v1/auth/verify
//       → {access_token, expires_at}. Token di-cache per party sampai mepet expiry.
const _walleyTok = new Map();   // partyId → {token, expMs}

// seed 32 byte → private key Ed25519. PKCS8 buat Ed25519 = prefix tetap + seed.
// Walley meng-encode seed 32 byte LANGSUNG di recovery phrase (bukan BIP39
// PBKDF2) — lihat README bot Walley: "recovery phrase meng-encode seed itu secara
// langsung". Jadi mnemonic -> entropy 32 byte = seed, bukan lewat seed derivation.
function mnemonicToSeedHex(mnemonic) {
  const words = String(mnemonic).trim().split(/\s+/);
  const wl = fs.readFileSync(path.join(path.dirname(path.dirname(ROOT)), 'walley', 'bip39_english.txt'), 'utf8').trim().split('\n').map(x => x.trim());
  let bits = '';
  for (const w of words) {
    const i = wl.indexOf(w);
    if (i < 0) throw new Error(`kata '${w}' gak ada di wordlist BIP39`);
    bits += i.toString(2).padStart(11, '0');
  }
  const entBits = Math.floor(bits.length / 33) * 32;
  const buf = Buffer.alloc(entBits / 8);
  for (let i = 0; i < buf.length; i++) buf[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return buf.toString('hex');
}
function walleyKeyFromSeed(seedHex) {
  const seed = Buffer.from(String(seedHex).replace(/^0x/, ''), 'hex');
  if (seed.length !== 32) throw new Error(`seed harus 32 byte, dapat ${seed.length}`);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const key = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = crypto.createPublicKey(key).export({ format: 'der', type: 'spki' });
  return { key, pubRaw: spki.slice(spki.length - 32), pubDerB64: spki.toString('base64') };
}

// wallets.jsonl dari bot Walley: satu JSON per baris.
function loadWalleyWallets() {
  let raw; try { raw = fs.readFileSync(WALLEY_WALLETS_PATH, 'utf8'); } catch (_) { return []; }
  const out = [];
  const push = (w) => {
    if (!w || !w.party_id) return;
    // seed_hex ATAU mnemonic — kalau cuma mnemonic, seed diturunkan sekali di sini
    // supaya sisa kode cukup pegang seed_hex.
    if (!w.seed_hex && w.mnemonic) { try { w.seed_hex = mnemonicToSeedHex(w.mnemonic); } catch (_) { return; } }
    if (w.seed_hex) out.push(w);
  };
  // Dukung DUA bentuk: JSONL (satu objek per baris, output bot Walley) dan JSON
  // array biasa — biar gampang kalau kamu nyusun filenya manual.
  const t = raw.trim();
  if (t.startsWith('[')) { try { (JSON.parse(t) || []).forEach(push); return out; } catch (_) { } }
  for (const line of raw.split('\n')) {
    const ln = line.trim(); if (!ln) continue;
    try { push(JSON.parse(ln)); } catch (_) { }
  }
  return out;
}

async function walleyReq(method, path_, { body = null, token = null, proxy = null } = {}) {
  const headers = { 'User-Agent': 'Mozilla/5.0', Accept: 'application/json', Origin: 'https://walley.cc', Referer: 'https://walley.cc/' };
  if (token) headers.Authorization = 'Bearer ' + token;
  if (body) headers['Content-Type'] = 'application/json';
  const r = await request(method, `${WALLEY_API}${path_}`, { headers, body: body ? JSON.stringify(body) : null, timeoutMs: REQ.timeoutMs, proxy });
  if (r.status === 401 || r.status === 403) { const e = new Error(`walley ${path_} ${r.status}`); e.unauthorized = true; throw e; }
  // Pesan DAML_FAILURE-nya panjang dan justru ekornya yg nerangin kontrak/choice mana
  // yg nolak — jangan dipotong pendek.
  if (r.status < 200 || r.status >= 300) throw new Error(`walley ${path_} status=${r.status} body=${(r.text || '').replace(/\s+/g, ' ').slice(0, 900)}`);
  return r.json != null ? r.json : (() => { try { return JSON.parse(r.text); } catch (_) { return null; } })();
}

async function walleyToken(w, proxy = null) {
  const hit = _walleyTok.get(w.party_id);
  if (hit && hit.expMs - 30000 > Date.now()) return hit.token;
  const { key, pubDerB64 } = walleyKeyFromSeed(w.seed_hex);
  const ch = await walleyReq('POST', '/v1/auth/challenge', { body: {}, proxy });
  const challenge = ch && ch.challenge;
  if (!challenge) throw new Error('walley challenge kosong');
  const signature = crypto.sign(null, Buffer.from(challenge, 'utf8'), key).toString('base64');
  const res = await walleyReq('POST', '/v1/auth/verify', {
    body: { party_id: w.party_id, public_key: pubDerB64, challenge, signature }, proxy,
  });
  if (!res || !res.access_token) throw new Error(`walley verify gagal: ${JSON.stringify(res).slice(0, 150)}`);
  const expMs = Number(res.expires_at) ? Number(res.expires_at) * 1000 : Date.now() + 10 * 60000;
  _walleyTok.set(w.party_id, { token: res.access_token, expMs });
  return res.access_token;
}

// Holding party (semua instrument) lewat ledger API proxy Walley.
async function walleyHoldings(w, proxy = null) {
  const token = await walleyToken(w, proxy);
  const end = await walleyReq('GET', '/v1/proxy/v2/state/ledger-end', { token, proxy });
  const body = {
    filter: { filtersByParty: { [w.party_id]: { cumulative: [{ identifierFilter: { InterfaceFilter: { value: { interfaceId: HOLDING_IFACE, includeInterfaceView: true } } } }] } } },
    verbose: false, activeAtOffset: (end && end.offset) || 0,
  };
  const rows = await walleyReq('POST', '/v1/proxy/v2/state/active-contracts', { body, token, proxy });
  const bal = {};
  for (const row of (Array.isArray(rows) ? rows : [])) {
    // Bentuk asli row (terpantau live):
    //   {workflowId, contractEntry:{ JsActiveContract:{ createdEvent:{…, interfaceViews:[…] } } }}
    // Nama pembungkusnya JsActiveContract — bukan activeContract. Jangan ditebak:
    // ambil kunci apa pun di dalam contractEntry yang punya createdEvent.
    const entry = (row && row.contractEntry) || row || {};
    let created = entry.createdEvent || null;
    if (!created) for (const k of Object.keys(entry)) { const v = entry[k]; if (v && v.createdEvent) { created = v.createdEvent; break; } }
    if (!created) continue;
    const views = (created && created.interfaceViews) || [];
    for (const v of views) {
      const val = (v && (v.viewValue || v.value)) || null;
      if (!val) continue;
      const id = (val.instrumentId && (val.instrumentId.id || val.instrumentId)) || val.instrument || '?';
      const amt = Number(val.amount || 0);
      const locked = val.lock != null && val.lock !== '$undefined' && val.lock !== null;
      if (!bal[id]) bal[id] = { unlocked: 0, locked: 0, utxo: 0 };
      bal[id][locked ? 'locked' : 'unlocked'] += amt;
      bal[id].utxo++;
    }
  }
  return bal;
}

// Party operator Silvana — tujuan Op_CreateUserServiceRequest. Diambil dari bundle
// web Silvana (onboardingStore), bukan tebakan.
// getMultiCall makan ~10 detik tiap panggil (diukur), padahal config-nya nyaris
// gak berubah. Di-cache per proses dengan TTL; kalau contract-nya diganti server,
// prepare bakal nolak dan cache di-invalidate lewat clearMultiCallCache().
let _mcCache = null;
const MC_TTL_MS = 10 * 60000;
async function getMultiCallCached(sv) {
  if (_mcCache && Date.now() - _mcCache.t < MC_TTL_MS) return _mcCache.v;
  const v = await getMultiCallCached(sv);
  if (v && v.contractId) _mcCache = { t: Date.now(), v };
  return v;
}
function clearMultiCallCache() { _mcCache = null; }

const SILVANA_OPERATOR = 'silvana-orderbook::1220997446016f1e96be9215bab224eace372752853ef99175c332307489bccbb07b';

// Cid UTXO Amulet unlocked milik party Walley — dipakai jadi inputHoldings MultiCall
// (fee onboarding dibayar dari situ).
async function walleyAmuletCids(w, proxy = null) {
  const token = await walleyToken(w, proxy);
  const end = await walleyReq('GET', '/v1/proxy/v2/state/ledger-end', { token, proxy });
  const body = {
    filter: { filtersByParty: { [w.party_id]: { cumulative: [{ identifierFilter: { InterfaceFilter: { value: { interfaceId: HOLDING_IFACE, includeInterfaceView: true } } } }] } } },
    verbose: false, activeAtOffset: (end && end.offset) || 0,
  };
  const rows = await walleyReq('POST', '/v1/proxy/v2/state/active-contracts', { body, token, proxy });
  const cids = []; let total = 0;
  for (const row of (Array.isArray(rows) ? rows : [])) {
    const entry = (row && row.contractEntry) || row || {};
    let created = entry.createdEvent || null;
    if (!created) for (const k of Object.keys(entry)) { const v = entry[k]; if (v && v.createdEvent) { created = v.createdEvent; break; } }
    if (!created || !created.contractId) continue;
    for (const v of (created.interfaceViews || [])) {
      const val = (v && (v.viewValue || v.value)) || null;
      if (!val) continue;
      const id = (val.instrumentId && val.instrumentId.id) || '';
      const locked = val.lock != null;
      if (String(id).toUpperCase() !== 'AMULET' || locked) continue;
      cids.push(created.contractId); total += Number(val.amount || 0);
    }
  }
  return { cids, total: Number(total.toFixed(10)) };
}

// Bungkus prepared transaction Walley dengan tanda tangan Ed25519 lokal.
// Bentuknya persis yg dipakai bot Python (_sign_prepared).
function walleySignPrepared(w, prepared) {
  const { key } = walleyKeyFromSeed(w.seed_hex);
  const hash = prepared.prepared_transaction_hash;
  const sig = crypto.sign(null, Buffer.from(hash, 'base64'), key).toString('base64');
  return {
    prepared_transaction: prepared.prepared_transaction,
    hashing_scheme_version: prepared.hashing_scheme_version,
    signature: { format: 'RAW', signature: sig, signed_by: walleyFingerprint(w), signing_algorithm_spec: 'ED25519' },
  };
}
// Fingerprint = yg dipakai Canton buat nunjuk kunci. Disimpan di wallets.jsonl.
function walleyFingerprint(w) { return w.fingerprint; }

// Cari cid UserService party Walley di ledger, lalu daftarin ke Silvana.
// Operator Silvana ngubah UserServiceRequest jadi UserService sendiri (terpantau
// live: request 0, UserService 1 beberapa detik setelah submit). Silvana BARU
// ngakuin party-nya setelah dipanggil autoRecoverParty — /api/parties/{id} balik
// null sampai itu dilakukan, dan itu yg bikin polling doang gak pernah kelar.
async function walleyUserServiceCid(w) {
  const token = await walleyToken(w);
  const end = await walleyReq('GET', '/v1/proxy/v2/state/ledger-end', { token });
  const T = '#utility-settlement-app-v1:Utility.Settlement.App.V1.Service.User:UserService';
  const body = {
    filter: { filtersByParty: { [w.party_id]: { cumulative: [{ identifierFilter: { TemplateFilter: { value: { templateId: T, includeCreatedEventBlob: false } } } }] } } },
    verbose: false, activeAtOffset: (end && end.offset) || 0,
  };
  const rows = await walleyReq('POST', '/v1/proxy/v2/state/active-contracts', { body, token });
  for (const row of (Array.isArray(rows) ? rows : [])) {
    const entry = (row && row.contractEntry) || row || {};
    let created = entry.createdEvent || null;
    if (!created) for (const k of Object.keys(entry)) { const v = entry[k]; if (v && v.createdEvent) { created = v.createdEvent; break; } }
    if (created && created.contractId) return created.contractId;
  }
  return null;
}

async function finishOnboard(sv, w, acct) {
  const P = (m, c) => process.stdout.write(paint(m + '\n', c || COLOR.gray));
  P('\nnunggu UserService muncul di ledger…');
  let cid = null;
  for (let i = 0; i < 12 && !cid; i++) {
    cid = await walleyUserServiceCid(w).catch(() => null);
    if (!cid) { process.stdout.write(paint(`  cek ${i + 1}/12…\n`, COLOR.gray)); await sleep(5000); }
  }
  if (!cid) { P('⚠ UserService belum muncul — coba lagi beberapa menit.', COLOR.yellow); return false; }
  P(`✓ UserService on-chain: ${String(cid).slice(0, 26)}…`, COLOR.green);
  const { pubRaw } = walleyKeyFromSeed(w.seed_hex);
  const res = await sv.swapAction(SWAP.actionIds.autoRecoverParty, [{
    partyId: w.party_id, userServiceCid: cid,
    publicKey: pubRaw.toString('base64'), email: acct.email,
  }]).catch(e => ({ _err: (e && e.message) || String(e) }));
  P(`autoRecoverParty → ${JSON.stringify(res).slice(0, 200)}`, res && res.success ? COLOR.green : COLOR.yellow);
  const pr = await sv.recoverParty(w.party_id).catch(() => null);
  if (pr && pr.userServiceCid) { P(`✓ Silvana ngakuin party ini — userServiceCid ${String(pr.userServiceCid).slice(0, 24)}…`, COLOR.green); return true; }
  P('⚠ /api/parties masih null — cek pesan autoRecoverParty di atas.', COLOR.yellow);
  return false;
}


// ── Canton lewat Walley — antarmuka SAMA PERSIS dengan CantonClient ──────────
// Supaya seluruh jalur swap gak perlu diubah, kelas ini niru metode yg dipakai
// pemanggil: activeContracts / activeContractsByInterface / prepareTransaction /
// submitPrepared / queryCompletion, plus balances().
//
// Bedanya di bawah kap:
//   Supanova  POST /canton/api/prepare_transaction {commands:[{ExerciseCommand:…}],
//             disclosedContracts:[…]}                       -> {hash}
//             POST /canton/api/submit_prepared {hash,signature} -> {submissionId}
//   Walley    POST /v1/transactions/prepare {commands:{act_as,command_id,
//             commands:[{type:'Exercise',template_id:{package_id,module_name,
//             entity_name},…}],disclosed_contracts:[…]}, fee_payer}
//                                                          -> {transaction,token,fee_transaction?}
//             POST /v1/transactions/submit-and-wait {party_id,transaction,token,…}
//
// Pemetaan bentuk command-nya BUKAN tebakan: dipakai apa adanya oleh walley-onboard
// yang sudah terbukti bikin UserService on-chain.
class WalleyCantonClient {
  constructor({ wallet, timeoutMs = REQ.timeoutMs, proxy = null, tag = null } = {}) {
    this.w = wallet; this.timeoutMs = timeoutMs; this.proxy = proxy; this.tag = tag;
    this._prep = new Map();   // hash -> {transaction, fee_transaction, token}
    this._done = new Map();   // submissionId -> hasil submit-and-wait
  }
  get partyId() { return this.w.party_id; }
  get token() { return null; }   // pemanggil kadang baca ini; Walley pakai token sendiri

  // "pkg:Module:Entity" -> {package_id, module_name, entity_name}
  static splitTemplate(t) {
    const [package_id, module_name, entity_name] = String(t).split(':');
    return { package_id, module_name, entity_name };
  }

  _toWalley(body) {
    const cmds = (body.commands || []).map((c) => {
      if (c.ExerciseCommand) {
        const e = c.ExerciseCommand;
        return { type: 'Exercise', template_id: WalleyCantonClient.splitTemplate(e.templateId), contract_id: e.contractId, choice: e.choice, choice_argument: e.choiceArgument };
      }
      if (c.CreateCommand) {
        const e = c.CreateCommand;
        return { type: 'Create', template_id: WalleyCantonClient.splitTemplate(e.templateId), create_arguments: e.createArguments || e.createArgument };
      }
      throw new Error(`command Walley gak dikenal: ${Object.keys(c).join(',')}`);
    });
    return {
      act_as: [this.w.party_id],
      command_id: body.commandId || `bot-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
      commands: cmds,
      disclosed_contracts: (body.disclosedContracts || []).filter(d => d && d.contractId).map(d => ({
        contract_id: d.contractId,
        created_event_blob: d.createdEventBlob,
        template_id: WalleyCantonClient.splitTemplate(d.templateId),
        synchronizer_id: d.synchronizerId || SWAP.synchronizerId,
      })),
    };
  }

  async prepareTransaction(body) {
    await waitTrafficGate(this.tag);
    const token = await walleyToken(this.w, this.proxy);
    let prep;
    try {
      prep = await walleyReq('POST', '/v1/transactions/prepare', { body: { commands: this._toWalley(body), fee_payer: this.w.party_id }, token, proxy: this.proxy });
    } catch (e) {
      logDebug('walley prepare REQUEST', this._toWalley(body));
      logDebug('walley prepare ERROR', (e && e.message) || String(e));
      // Kontrak MultiCall di cache bisa udah gak aktif (server ganti) — buang cache
      // biar percobaan berikutnya ngambil yg baru.
      if (/CONTRACT_NOT_FOUND|not found|disclosed/i.test((e && e.message) || '')) clearMultiCallCache();
      throw e;
    }
    const tx = prep && prep.transaction;
    if (!tx || !tx.prepared_transaction_hash) throw new Error(`walley prepare gak balikin transaksi: ${JSON.stringify(prep).slice(0, 220)}`);
    this._prep.set(tx.prepared_transaction_hash, prep);
    // Bentuk balasannya disamakan sama Supanova ({hash}) biar pemanggil gak berubah.
    return { hash: tx.prepared_transaction_hash, costEstimation: prep.fee_amount != null ? { totalTrafficCostEstimation: prep.fee_amount } : undefined };
  }

  async submitPrepared({ hash /* signature diabaikan: Walley minta amplop utuh */ }) {
    const prep = this._prep.get(hash);
    if (!prep) throw new Error('walley submit: hasil prepare gak ketemu buat hash ini');
    const token = await walleyToken(this.w, this.proxy);
    const body = { party_id: this.w.party_id, transaction: walleySignPrepared(this.w, prep.transaction), token: prep.token };
    if (prep.fee_transaction) body.fee_transaction = walleySignPrepared(this.w, prep.fee_transaction);
    const res = await walleyReq('POST', '/v1/transactions/submit-and-wait', { body, token, proxy: this.proxy });
    // submit-and-wait udah NUNGGU selesai, jadi submissionId cuma penanda lokal.
    const id = (res && (res.submission_id || res.submissionId)) || `walley-${hash.slice(0, 16)}`;
    this._done.set(id, res);
    this._prep.delete(hash);
    return { submissionId: id };
  }

  async queryCompletion(submissionId) {
    // Gak ada polling: submit-and-wait udah blocking. Kalau balasannya nyimpen status
    // gagal, teruskan apa adanya biar completionErr() bisa nandain.
    const r = this._done.get(submissionId);
    if (!r) return { status: 'completed' };
    const st = String((r.status || r.state || '')).toLowerCase();
    if (st.includes('fail') || st.includes('reject')) return { status: 'failed', message: r.message || JSON.stringify(r).slice(0, 200) };
    return { status: 'completed', ...r };
  }

  async _acs(filter) {
    const token = await walleyToken(this.w, this.proxy);
    const end = await walleyReq('GET', '/v1/proxy/v2/state/ledger-end', { token, proxy: this.proxy });
    const body = { filter: { filtersByParty: { [this.w.party_id]: { cumulative: [{ identifierFilter: filter }] } } }, verbose: false, activeAtOffset: (end && end.offset) || 0 };
    const rows = await walleyReq('POST', '/v1/proxy/v2/state/active-contracts', { body, token, proxy: this.proxy });
    const out = [];
    for (const row of (Array.isArray(rows) ? rows : [])) {
      const entry = (row && row.contractEntry) || row || {};
      let created = entry.createdEvent || null;
      if (!created) for (const k of Object.keys(entry)) { const v = entry[k]; if (v && v.createdEvent) { created = v.createdEvent; break; } }
      if (!created || !created.contractId) continue;
      out.push({
        contractId: created.contractId, templateId: created.templateId,
        createArgument: created.createArgument, createdEventBlob: created.createdEventBlob,
        interfaceViews: created.interfaceViews,
      });
    }
    return out;
  }
  async activeContracts(templateId) { return this._acs({ TemplateFilter: { value: { templateId, includeCreatedEventBlob: true } } }); }
  async activeContractsByInterface(interfaceId) { return this._acs({ InterfaceFilter: { value: { interfaceId, includeInterfaceView: true } } }); }

  /** Saldo dalam BENTUK YANG SAMA dengan /canton/api/balances Supanova. */
  async balances() {
    const rows = await this._acs({ InterfaceFilter: { value: { interfaceId: HOLDING_IFACE, includeInterfaceView: true } } });
    const byId = new Map();
    for (const c of rows) {
      for (const v of (c.interfaceViews || [])) {
        const val = (v && (v.viewValue || v.value)) || null;
        if (!val || !val.instrumentId) continue;
        const key = val.instrumentId.id;
        if (!byId.has(key)) byId.set(key, { instrumentId: { admin: val.instrumentId.admin, id: key }, unlockedUtxos: [], lockedUtxos: [] });
        const slot = val.lock != null ? 'lockedUtxos' : 'unlockedUtxos';
        byId.get(key)[slot].push({ contractId: c.contractId, amount: String(val.amount) });
      }
    }
    // Field AGREGAT wajib ikut: unlockedOf()/balOf() baca totalUnlockedBalance dan
    // totalBalance, BUKAN panjang array UTXO. Tanpa ini saldo kebaca 0 dan sizing
    // swap jadi nol padahal ledgernya berisi.
    const tokens = [...byId.values()].map(t => {
      const sum = (arr) => arr.reduce((n, u) => n + (Number(u.amount) || 0), 0);
      const un = sum(t.unlockedUtxos), lo = sum(t.lockedUtxos);
      return { ...t, totalUnlockedBalance: String(un), totalBalance: String(un + lo) };
    });
    return { tokens };
  }
}

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
// Root API Supanova. Endpoint transfer wallet ADA DI LUAR /canton/api (dia di
// /canton/transfers/*), makanya SUPA gak kepake buat itu.
const SUPA_ROOT = 'https://api.supanova.app';
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
  // Token pembayar settlement fee RFQ. [] = CC (Amulet). ["USDCx"] = bayar USDCx.
  feeTokens: Array.isArray((CONFIG.swap || {}).feeTokens) ? (CONFIG.swap || {}).feeTokens : [],
  // Ambang minimum saldo TOKEN FEE (kalau feeTokens dipakai). 0 = cukup > 0.
  minFeeTokenReserve: Number((CONFIG.swap || {}).minFeeTokenReserve) || 0,

  // PLAFON MUTLAK — beda sama maxFeeCC. maxFeeCC itu gate "tunggu sampai fee turun"
  // yang SENGAJA di-bypass di dua tempat: mode 8 malam (trabas biar task kelar sebelum
  // reset 07:00) dan opsi 7 (force dump). Di situ batasnya jadi Infinity = gak ada
  // batas sama sekali, satu spike bisa ngebakar CC sebanyak apa pun. hardMaxFeeCC
  // berlaku di SEMUA jalur, gak bisa di-bypass ctx.maxFeeCC. Fee normal 1.23 CC (RFQ)
  // / 4.3 CC (terminal), jadi 15 itu ~3x skenario terburuk. 0 = matikan (gak disaranin).
  hardMaxFeeCC: Number((CONFIG.swap || {}).hardMaxFeeCC) || 15,
  feeSpikeWaitSec: Number((CONFIG.swap || {}).feeSpikeWaitSec) || 300,
  // === ANTI-DEADLOCK ===
  // Loop sync (tunggu counter earn-hub naik) dulu default 0 = TANPA batas. Fatal pas
  // reset harian lewat: count balik ke 0 sedangkan pembanding masih 10, jadi syarat
  // "count naik" gak akan pernah kepenuhi lagi → loop abadi, sesi gak pernah kelar.
  settleWaitMaxMin: Number((CONFIG.swap || {}).settleWaitMaxMin) || 15,
  // Batas satu akun boleh jalan dalam satu sesi. Tanpa ini, satu akun yg nyangkut di
  // await yg gak pernah balik nyandera mapLimit → seluruh sesi gak pernah selesai.
  accountMaxMin: Number((CONFIG.swap || {}).accountMaxMin) || 180,
  // Umur maksimum flag dtSessionRunning. Lewat ini flag dianggap basi dan dipaksa
  // lepas — kalau nggak, cron harian dilewati terus ("Sesi masih berjalan").
  sessionMaxHours: Number((CONFIG.swap || {}).sessionMaxHours) || 8,
  // Selagi sesi jalan, tetap segarin angka task tiap sekian menit. Dulu tickAll
  // di-gate total sama dtSessionRunning → dashboard beku nampilin angka kemarin.
  tickWhileSessionMin: Number((CONFIG.swap || {}).tickWhileSessionMin) || 10,
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
    // RFQ atomic (atomic-dvp-v2) — fallback dari capture live 26/07; di-refresh discovery.
    // WAJIB ada di sini walau cuma fallback: loadActionIds() cuma nyalin key yang SUDAH
    // kedaftar di blok ini, jadi kalau absen → id undefined → request kirim
    // header "next-action: undefined" dan gagal.
    requestQuotesV2: '40e78d795076258197adc5a17f1f85f08f66fadd57',
    acceptQuoteAtomic: '407aa32e2cafb0913a28a50790e93f7067e0a76995',
    estimateAtomicFee: '40ff80578b40a2c5566773980bc129e555e8608708',
    utilityTransferFactory: '403012b2ecabece63b143fb85b33121dc20aff6efd',
    utilityAcceptContext: '40085ee36335ef548b28082bcc171a91c65793cf74',
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
    autoRecoverParty: '400e5f853d',
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
// Siang (dayStartHour..dayEndHour WIB): net gate (minNetUsd) + fee gate (maxFeeCC). Malam: trabas
// — TAPI cuma maxFeeCC yg ditrabas; swap.hardMaxFeeCC tetap nempel (lihat effFeeCap).
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
  // PENETRASI harga lewat best price ORDERBOOK (bukan deviasi dari feed cross-rate).
  // BUY  = bestAsk×(1+cross)  → nyeberang ask, langsung jadi taker.
  // SELL = bestBid×(1−cross)  → nyeberang bid, langsung jadi taker.
  // Cukup kecil (default 0.001 = 0.1%) karena base-nya UDAH harga book yg bisa match —
  // dulu 0.02 dipakai buat nutup gap feed cross-rate yg meleset ~3.6% (dan tetap gagal).
  // PENTING sizing BUY: cost cETH = qty × harga ORDER → size dibagi (1+cross) di harga book.
  orderCross: _m8num(_m8.orderCross, 0.001),
  // timeInForce order terminal. GTD = kayak GTC (nempel di book, boleh partial fill)
  // TAPI mati sendiri di expiresAt → order gak jadi zombie kalau bot mati (Ctrl+C /
  // crash / reboot) di antara submitOrder dan cancelOrder. Server dukung GTC/IOC/FOK/GTD
  // (dari bundle: GTD = "Good Till Date - expires at specified time").
  orderTif: String(_m8.orderTif || 'GTD').toUpperCase(),
  // Umur order buat GTD (detik). Cuma jaring pengaman — jalur normal tetap cancelOrder
  // dalam ~30s. Jangan kependekan: order kudu masih hidup selama poll proposal
  // (orderWaitSec) + grace.
  orderTtlSec: _m8num(_m8.orderTtlSec, 120),
  // Lama nunggu order ke-match (detik) sebelum dianggap gak ada likuiditas → cancelOrder.
  orderWaitSec: _m8num(_m8.orderWaitSec, 30),
  // Lama nunggu COUNTERPARTY nyelesaiin bagiannya (detik) waktu sisi kita udah selesai
  // (nextAction=WAIT). Jangan kepanjangan: likuiditas sering sepi & cepat habis, mending
  // cancel lalu coba lagi/pindah jalur daripada nyangkut lama. Default 90.
  waitCounterpartySec: _m8num(_m8.waitCounterpartySec, 90),
  // FALLBACK RFQ: kalau sisa waktu sampai reset harian (dayStartHour) tinggal <= jam ini
  // DAN task belum penuh → pakai jalur /swap (RFQ) yg TERBUKTI jalan waktu CLOB mandek,
  // dan fee-nya lebih murah (terukur 1.23 CC vs 4.3 CC di terminal). 0 = matiin fallback.
  rfqFallbackHour: _m8num(_m8.rfqFallbackHour, 3),
  // Grace setelah proposal PERTAMA muncul: kasih waktu chunk lain (split multi-maker)
  // nyusul sebelum kita cancel sisa order.
  orderGraceMs: _m8num(_m8.orderGraceMs, 3000),
  // SUMBER HARGA: book LP = harga yg beneran bisa keisi (fallback ke full book kalau
  // sisi yg dibutuhin kosong). Beda dari orderLpOnly di bawah — jangan disatuin.
  bookLpOnly: _m8.bookLpOnly !== false,
  // BATAS LAWAN MATCH (requirements.lpOnly). true = cuma LP (settle andal). false =
  // siapa aja (bisa dapat harga lebih bagus, tapi counterparty non-LP sering gak
  // preconfirm → settlement mandek stage 2).
  orderLpOnly: _m8.orderLpOnly === true,
  taskCode: String(_m8.taskCode || _m8sw.edelCethTaskCode || '').toUpperCase(),
  // allowOvercap (kayak opsi 0/1): false = stop pas task 'EDELx-cETH Daily Trader'
  // penuh (10/10). true = boleh swap LEBIH dari task target sampai dailySwapCount
  // total swap sesi (task tetap capped 10, dihitung pakai counter swap lokal).
  allowOvercap: (_m8.allowOvercap != null ? _m8.allowOvercap === true : (_m8sw.allowOvercap === true)),
  dailyCap: Math.max(1, _m8num(_m8.dailySwapCount, _m8num(_m8sw.dailySwapCount, 10))),
  // Pasangan token ping-pong. base/quote HARUS cocok sama market_id Silvana
  // ("<base>-<quote>"), lihat `node index.js markets`.
  // Ambang nilai USD tempat settlement fee turun ke tier murah (diukur ~$10).
  // 0 = matikan penyesuaian.
  feeTierMinUsd: _m8num(_m8.feeTierMinUsd, 10),
  // Minimum order value yg DIPAKSA server RFQ ($10 saat diukur). Ini lantai keras,
  // beda dari minUsd yg cuma ukuran yg diinginkan.
  rfqMinUsd: _m8num(_m8.rfqMinUsd, 10),
  pair: (_m8.pair && _m8.pair.base && _m8.pair.quote) ? { base: String(_m8.pair.base), quote: String(_m8.pair.quote) } : { base: 'EDELx', quote: 'cETH' },
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
// Sisa jam sampai task harian reset (dayStartHour, default 07:00 WIB). Dipakai buat
// mutusin kapan nyerah dari CLOB dan pindah ke jalur RFQ biar target harian kekejar.
function hoursUntilDailyReset() {
  const h = nowHourInTz(M8.timezone);
  const reset = M8.dayStartHour;
  return h < reset ? reset - h : 24 - h + reset;
}
// true = waktunya pakai jalur RFQ (/swap) gantiin CLOB. Alasan: likuiditas orderbook
// sering sepi/cepat habis dan counterparty CLOB kadang gak nyelesaiin settlement,
// sedangkan RFQ di-quote LANGSUNG sama LP (terbukti tetap jalan pas CLOB mandek total,
// fee malah lebih murah). Dipakai cuma pas mepet reset & target belum kekejar.
// Set target swap harian SAAT RUN (nimpa config mode8.allowOvercap/dailySwapCount).
// Kenapa perlu: allowOvercap=true DOANG gak cukup — kalau dailySwapCount tetap 10
// sedangkan task udah 10/10, startCount >= dailyCap langsung berhenti. Jadi overcap
// SELALU butuh target > 10. Balikin deskripsi buat di-log, atau null kalau gak dipakai.
//   'overcap'  → target = dailySwapCount config (kalau > 10) atau 2x task target
//   'target=N' / 'overcap N' → target = N
function applyOvercapArg(argv) {
  let n = null;
  for (let i = 0; i < argv.length; i++) {
    const a = String(argv[i]);
    const m = a.match(/^(?:target|overcap)=(\d+)$/i);
    if (m) { n = Number(m[1]); break; }
    if (/^overcap$/i.test(a)) { const nx = Number(argv[i + 1]); n = Number.isFinite(nx) && nx > 0 ? nx : (M8.dailyCap > 10 ? M8.dailyCap : 20); break; }
  }
  if (!n || n <= 0) return null;
  M8.allowOvercap = true;
  M8.dailyCap = n;
  return `overcap ON — target ${n} swap/akun (abaikan task penuh 10/10)`;
}

// Jalur ping-pong yg dipilih SAAT RUN (bukan config): 'clob' = orderbook /terminal
// (default, perilaku lama), 'rfq' = jalur /swap AtomicDVP. Di-set menu 8 / 8r atau
// subcommand pingpong / pingpong-rfq. Dipisah biar dua mode gak campur.
let PINGPONG_ROUTE = 'clob';
function mode8ShouldUseRfq() {
  if (PINGPONG_ROUTE === 'rfq') return true;
  // Mode CLOB tetap punya jaring pengaman: pindah RFQ kalau mepet reset & belum kelar.
  const lim = Number(M8.rfqFallbackHour) || 0;
  return lim > 0 && hoursUntilDailyReset() <= lim;
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
// Pasangan token ping-pong (mode 8). Dulu dipatok EDELx/cETH; sekarang bebas —
// market_id Silvana = "<base>-<quote>", dan arah swap ditentukan mana yang DIKIRIM:
// kirim base = sell, kirim quote = buy. Daftar market aktif bisa dilihat lewat
// menu 8 (picker) atau `node index.js markets`.
const P8 = {
  get base() { return (M8.pair && M8.pair.base) || 'EDELx'; },
  get quote() { return (M8.pair && M8.pair.quote) || 'cETH'; },
  get baseId() { return String(P8.base).toUpperCase(); },
  get quoteId() { return String(P8.quote).toUpperCase(); },
  get market() { return `${P8.base}-${P8.quote}`; },
};
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
  // Kirim BASE = sell, kirim QUOTE = buy. tokenAdmin cuma fallback — admin asli
  // diambil dari terms DVP waktu swap, jadi pasangan baru gak perlu daftar admin.
  const isBase = String(deliver).toUpperCase() === P8.baseId;
  const adminOf = (id) => (id === 'EDELX' ? EDEL_CETH.edelxAdmin : id === 'CETH' ? EDEL_CETH.cethAdmin : null);
  return {
    direction: isBase ? 'sell' : 'buy',
    leg: {
      market: P8.market, baseIsCC: P8.baseId === 'CC', tokenToToken: true,
      tokenId: isBase ? P8.baseId : P8.quoteId,
      tokenLabel: isBase ? P8.base : P8.quote,
      tokenAdmin: adminOf(isBase ? P8.baseId : P8.quoteId),
    },
  };
}

// ---- UI constants ----
const MIN_ACTIVITY_LINES = 4;
// View panel log: 0 = SYSTEM (semua log), 1..N = akun ke-(selView-1). Navigasi ↑/↓.
let selView = 0;
// Flag parallel swap aktif (di-set di menu, cuma opsi 0/1 + config swap.parallel).
let parallelSwapActive = false;
// Batasi sesi ke sebagian akun (buat uji coba). null = semua akun.
// Diisi lewat argumen `only=3` atau `only=0,2,5` di subcommand pingpong.
let ONLY_ACCOUNTS = null;
function applyOnlyArg(argv) {
  for (const a of argv) {
    const m = String(a).match(/^only=([\d,\-]+)$/i);
    if (!m) continue;
    const out = [];
    for (const part of m[1].split(',').filter(Boolean)) {
      const rg = part.match(/^(\d+)-(\d+)$/);
      if (rg) { const lo = Number(rg[1]), hi = Number(rg[2]); for (let i = Math.min(lo, hi); i <= Math.max(lo, hi); i++) out.push(i); }
      else if (/^\d+$/.test(part)) out.push(Number(part));
    }
    const uniq = [...new Set(out)].filter(i => ACCOUNTS[i]);
    if (uniq.length) { ONLY_ACCOUNTS = uniq; return `only → ${uniq.length} akun: ${uniq.map(i => ACCOUNTS[i].label || ACCOUNTS[i].email).join(', ')}`; }
  }
  return null;
}
// Indeks akun yg ikut sesi (hormatin ONLY_ACCOUNTS).
function sessionAccountIdxs() { return ONLY_ACCOUNTS ? ONLY_ACCOUNTS.slice() : ACCOUNTS.map((_, i) => i); }

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
// Index percobaan login TERAKHIR saat rotate proxy (0..2 tergantung jumlah proxy).
// Math.max(0, …) WAJIB: tanpa proxy (PROXIES kosong) Math.min(-1, 2) = -1, jadi loop
// `pb <= -1` GAK PERNAH jalan sekalipun → `clients` tetap undefined → langsung crash
// "Cannot destructure property 'sv' of 'clients' as it is undefined". Bug ini gak
// pernah kelihatan di VPS karena di sana proxy.txt selalu keisi.
function proxyTryMax() { return Math.max(0, Math.min(PROXIES.length - 1, 2)); }
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
  constructor({ accessToken, timeoutMs = REQ.timeoutMs, proxy = null, preferredWalletId = null, partyId = null, rawCantonKey = null } = {}) {
    this.accessToken = accessToken; this.timeoutMs = timeoutMs; this.proxy = proxy;
    this.preferredWalletId = preferredWalletId; this.partyId = partyId;
    this.caId = crypto.randomUUID(); this.wallet = null; this.authzKey = null; this.authzExpiresAt = 0;
    this.walletCandidates = [];
    // Mode kunci-mentah: sign lokal pakai ed25519 KeyObject, BUKAN Privy TEE. Party
    // yg diregister di luar onboarding web terikat ke key ini; Privy TEE punya key beda
    // → kalau dipaksa TEE selalu BAD SIGNATURE. rawCantonKey = { key, pub } dari loadRawKey.
    this.rawKey = (rawCantonKey && rawCantonKey.key) || null;
    this.rawPub = (rawCantonKey && rawCantonKey.pub) || null;
    if (this.rawKey) this.wallet = { id: 'raw-ed25519', chain_type: 'stellar', raw: true };
  }
  async authenticate() {
    if (this.rawKey) return this.wallet;   // kunci-mentah: gak perlu handshake TEE
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
    // Mode kunci-mentah: tanda tangan ed25519 lokal atas byte hash. Balikin HEX —
    // sigToB64 yg nanti normalisasi ke base64 (konsisten dgn jalur Privy TEE).
    // Terbukti live: Canton nerima signature ini utk onboarding party ce95.
    if (this.rawKey) {
      const h = Buffer.from(String(hashHex).replace(/^0x/, ''), 'hex');
      return crypto.sign(null, h, this.rawKey).toString('hex');
    }
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
    if (this.rawKey) return null;   // kunci-mentah tunggal & definitif — gak ada rotasi
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
// Saldo untuk SATU akun, sadar pilihan wallet-nya. Akun Walley saldonya di ledger
// Walley, bukan di /canton/api/balances Supanova — tanpa ini dashboard nampilin
// angka party Supanova padahal bot-nya nge-swap di party Walley.
async function balancesFor(email, token, proxy) {
  const wsel = (acctSession(email) || {}).wallet;
  if (wsel && wsel.kind === 'walley') {
    const w = loadWalleyWallets().find(x => x.party_id === wsel.partyId || x.party_hint === wsel.partyHint);
    if (w) return new WalleyCantonClient({ wallet: w, proxy }).balances();
  }
  return supaBalances(token, proxy);
}
async function supaBalances(token, proxy) {
  const r = await request('GET', `${SUPA}/balances`, { headers: supaHeaders(token), timeoutMs: REQ.timeoutMs, proxy });
  if (r.status === 401) { const e = new Error('balances 401'); e.unauthorized = true; throw e; }
  if (r.status >= 400) throw new Error(`balances status=${r.status}`);
  return r.json;
}
// Plafon fee efektif buat SATU swap = min(batas per-call, plafon mutlak).
// ctx.maxFeeCC dipakai mode 8 buat override per-call (malam = Infinity). Plafon
// mutlak SWAP.hardMaxFeeCC tetap nempel biar override itu gak jadi "tanpa batas".
function effFeeCap(ctxCap) {
  const soft = ctxCap != null ? Number(ctxCap) : Number(SWAP.maxFeeCC);
  const hard = Number(SWAP.hardMaxFeeCC);
  return hard > 0 ? Math.min(soft, hard) : soft;
}

// ── Gate traffic-credit sequencer Canton ────────────────────────────────────
// `SEQUENCER_NOT_ENOUGH_TRAFFIC_CREDIT: Member has insufficient traffic credit`
// itu rate-limit sequencer yg dihitung PER MEMBER (participant node), BUKAN per
// party — semua akun kita nempel di node Supanova yg sama (partyId hint `supa1`),
// jadi jatah traffic-nya SATU EMBER buat semua. Kelihatan di log: beberapa akun
// kena barengan di detik yg persis sama. Jatahnya ngisi ulang sendiri seiring waktu
// (base rate), gak perlu top-up manual.
//
// Konsekuensi: backoff PER-AKUN percuma. Sementara akun A nunggu 10s, akun B–E
// masih nembak dan embernya gak pernah sempat keisi. Makanya gate-nya GLOBAL:
// sekali ada yg kena, SEMUA akun ikut nahan sampai waktunya lewat.
const TRAFFIC = { until: 0, hits: 0 };
// Backoff naik 30s per kejadian beruntun, cap 5 mnt. Turun lagi tiap swap sukses.
function trafficPenalize() {
  TRAFFIC.hits++;
  const s = Math.min(300, 30 * TRAFFIC.hits);
  TRAFFIC.until = Math.max(TRAFFIC.until, Date.now() + s * 1000);
  return s;
}
function trafficRelax() { if (TRAFFIC.hits > 0) TRAFFIC.hits--; }
// Tahan sampai gate kebuka. Jitter di ujung biar akun-akun gak lepas serempak
// (kalau barengan lagi, embernya langsung kuras lagi = herd).
async function waitTrafficGate(tag) {
  let held = false;
  while (Date.now() < TRAFFIC.until) {
    if (!held) { held = true; logActivity(`[${tag || '-'}] tahan ${Math.ceil((TRAFFIC.until - Date.now()) / 1000)}s — traffic node abis (gate global)`, COLOR.yellow); }
    await sleep(Math.min(5000, Math.max(250, TRAFFIC.until - Date.now())));
  }
  if (held) await sleep(Math.floor(Math.random() * 5000));
}
// Bikin error dari queryCompletion status failed/rejected, sekalian ditandai kalau
// penyebabnya rate-limit sequencer — bukan salah transaksi kita, jadi rebuild client
// / rescan action-id (perlakuan default error tak-terklasifikasi) cuma buang waktu.
function completionErr(status, message) {
  const msg = String(message || '');
  const e = new Error(`transaksi ${status}: ${msg}`);
  // REQUEST_FAILED muncul barengan TRAFFIC_CREDIT tiap kali sequencer kedorong —
  // diperlakukan sama: tahan, jangan retry cepat.
  if (/NOT_ENOUGH_TRAFFIC_CREDIT|SEQUENCER_REQUEST_FAILED|ABORTED_DUE_TO_SHUTDOWN/i.test(msg)) e.trafficLimit = true;
  return e;
}

class CantonClient {
  // token bisa berupa string statis ATAU fungsi () => token (live dari session).
  // tag = label akun, cuma dipakai buat log gate traffic (opsional).
  constructor({ token, timeoutMs = REQ.timeoutMs, proxy = null, tag = null } = {}) { this._token = token; this.timeoutMs = timeoutMs; this.proxy = proxy; this.tag = tag; }
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
    // Gate di sini (bukan di submit) biar prepare+sign gak dikerjain percuma pas
    // jatah traffic lagi kosong — submit-nya pasti ditolak.
    await waitTrafficGate(this.tag);
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
  /** Saldo — disamakan antarmukanya dengan WalleyCantonClient.balances(). */
  async balances() { return supaBalances(this.token, this.proxy); }
}
function toScaled(s) { const [i, f = ''] = String(s).split('.'); const frac = (f + '0'.repeat(10)).slice(0, 10); const neg = i.startsWith('-'); const ii = neg ? i.slice(1) : i; const v = BigInt((ii || '0') + frac); return neg ? -v : v; }
function fromScaled(v) { const neg = v < 0n; let a = neg ? -v : v; const s = a.toString().padStart(11, '0'); return (neg ? '-' : '') + s.slice(0, -10) + '.' + s.slice(-10); }
function addDp(a, b) { return fromScaled(toScaled(a) + toScaled(b)); }
function fmt10(s) { return fromScaled(toScaled(s)); }
// Daml Time (createdAt/allocateBefore/settleBefore dari terms DVP) → string ISO µs.
// Ledger biasanya balik STRING (dibiarin apa adanya). Tapi kadang balik NUMBER (µs
// since epoch) atau protobuf {seconds,nanos} → prepare_transaction nolak dgn
// "Expected ujson.Str (data: 1784994988000000)". Konversi ke canonical ISO 6-digit µs
// (format Daml Time) supaya cocok sama nilai on-chain. Terbukti live pada opsi 7.
function damlTime(v) {
  if (v == null || typeof v === 'string') return v;
  let us;
  if (typeof v === 'number') us = Math.round(v);
  else if (typeof v === 'object' && v.seconds != null) us = Number(v.seconds) * 1e6 + Math.floor(Number(v.nanos || 0) / 1000);
  else return v;
  const sec = Math.floor(us / 1e6), frac = String(us - sec * 1e6).padStart(6, '0');
  return new Date(sec * 1000).toISOString().replace(/\.\d+Z$/, '') + '.' + frac + 'Z';
}
// Normalisasi 3 field waktu di terms DVP (sisanya — deliveries/payments/amount — VERBATIM).
function normDvpTerms(terms) {
  if (!terms) return terms;
  return { ...terms, createdAt: damlTime(terms.createdAt), allocateBefore: damlTime(terms.allocateBefore), settleBefore: damlTime(terms.settleBefore) };
}
// Bulatkan harga ke tick_size ledger (1e-10, dari /api/markets EDELx-cETH).
//   up=true  → ke ATAS (BUY: jangan sampai jatuh di bawah ask → gak match)
//   up=false → ke BAWAH (SELL: jangan sampai naik di atas bid → gak match)
// toFixed(10) WAJIB: harga EDELx-cETH ~5e-6, kalau nilainya turun di bawah 1e-6
// Number.toString() keluar notasi eksponensial ("5.3e-7") dan toScaled/fmt10 pecah.
function tickPrice(n, up) {
  const t = Number(n) / 1e-10;
  return ((up ? Math.ceil(t) : Math.floor(t)) * 1e-10).toFixed(10);
}
// Harga level terjauh yg kudu disapu buat ngisi `qty` di sisi book ini (levels udah
// terurut best→worst). Balikin {price, full}: full=false berarti book gak cukup dalam
// (qty > total depth) → harga = level terakhir yg ada.
function bookPriceForQty(levels, qty) {
  let rem = Number(qty) || 0, price = 0, full = false;
  for (const l of (levels || [])) {
    price = l.price; rem -= l.quantity;
    if (rem <= 1e-12) { full = true; break; }
  }
  return { price, full };
}
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
  // Daftarin party ke Silvana setelah UserService-nya ada on-chain (dipakai walley-onboard).
  autoRecoverParty: 'autoRecoverParty',
  // ── RFQ ATOMIC (atomic-dvp-v2) ── Silvana udah pindah dari alur DvpProposal ke
  // settle SEKALI TEMBAK: ExerciseCommand #atomic-dvp-v2:AtomicDVP → AtomicDVP_Settle.
  // Di jalur ini dvpProposalCid GAK PERNAH ADA (makanya swapOnce lama nyangkut di
  // "poll: dvpProposalCid timeout" stage 3 — server malah nunggu KITA lanjut).
  // Ditangkap live 26/07 dari UI /swap. Fee jauh lebih murah: 1.24 CC vs 4.3 CC CLOB.
  requestQuotesV2: 'requestQuotesV2Action',
  acceptQuoteAtomic: 'acceptQuoteAtomicAction',
  estimateAtomicFee: 'estimateAtomicFeeAction',
  // Konteks transfer/accept per instrument → sumber base/quoteTransferFactoryCid,
  // instrument-configuration cid, dan sisa disclosedContracts buat AtomicDVP_Settle.
  utilityTransferFactory: 'getUtilityTransferFactoryContextAction',
  utilityAcceptContext: 'getUtilityAcceptContextAction',
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
      // Cetak NAMA action, bukan hash mentahnya. Hash-nya build-specific dan berubah tiap
      // redeploy, jadi kalau muncul di dashboard sama sekali gak kebaca — mesti di-scrape
      // dari bundle dulu buat tau action mana yg jebol.
      const nm = Object.keys(SWAP.actionIds).find(n => SWAP.actionIds[n] === actionId);
      logDebug(`swapAction ${nm || '?'} (${actionId}) ${r.status}`, r.text || '');
      // Next.js NYEMBUNYIIN pesan asli error server action di produksi — yg kekirim cuma
      // amplop flight ("0:{...}") plus digest. Digest itu satu-satunya pegangan yg nyambung
      // ke log server mereka, jadi diangkat ke pesan error kalau ada.
      const dg = (String(r.text || '').match(/"digest"\s*:\s*"([^"]+)"/) || [])[1];
      const e = new Error(`swapAction ${nm || actionId.slice(0, 12)} status=${r.status}${dg ? ` digest=${dg}` : ''} body=${(r.text || '').replace(/\s+/g, ' ').slice(0, 130)}`);
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
    // Nama chunk gak selalu hex murni (bisa ada huruf/angka/dash/underscore/slash,
    // mis. app/swap/page-xxxx.js) — pola ketat bikin sebagian chunk kelewat di-scan.
    const reChunk = /\/_next\/static\/chunks\/[^"'\s\\]+?\.js/g;
    for (const path of ['/swap', '/terminal']) {
      const page = await request('GET', `${APP_BASE}${path}`, this._opts({ headers: this._hdr({ 'Accept': 'text/html,*/*;q=0.8', 'Referer': APP_BASE + '/' }) })).catch(() => ({ text: '' }));
      const html = page.text || '';
      while ((m = reChunk.exec(html)) !== null) chunkUrls.add(m[0]);
      const bm = html.match(/"buildId"\s*:\s*"([^"]+)"/);
      if (bm) { try { const b = await request('GET', `${APP_BASE}/_next/static/${bm[1]}/_buildManifest.js`, this._opts({ timeoutMs: 8000 })); for (const cc of ((b.text || '').match(/static\/chunks\/[a-f0-9]+\.js/g) || [])) chunkUrls.add('/_next/' + cc); } catch (_) { } }
    }
    const texts = await mapLimit([...chunkUrls], 8, url => request('GET', `${APP_BASE}${url}`, this._opts({ headers: this._hdr({ 'Referer': APP_BASE + '/swap' }), timeoutMs: 12000 })).then(r => r.status === 200 ? (r.text || '') : '').catch(() => ''));
    const name2id = {};
    // Nama fungsi BOLEH mengandung ANGKA/underscore/$ — `[a-zA-Z]+` bikin action
    // seperti `requestQuotesV2Action` (ada "2") GAK PERNAH ke-discover, jadi bot
    // nempel di fallback id lama → 404 "Server action not found". Panjang id juga
    // gak selalu 42 (kepantau 40-44).
    const reSA = /createServerReference\)\("([0-9a-f]{40,44})",\s*\w+\.callServer,\s*void\s*0,\s*\w+\.findSourceMapURL,\s*"([a-zA-Z0-9_$]+)"/g;
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
  /** Wallet yg ke-link di sisi Silvana (kartu "Connected Wallets" di /settings). */
  async listWallets() {
    const r = await request('GET', `${APP_BASE}/api/wallets`, this._opts({
      headers: this._hdr({ 'Accept': '*/*', 'Referer': APP_BASE + '/settings', ...this._bearerHdr }),
    }));
    if (r.status !== 200) throw new Error(`wallets status=${r.status} body=${(r.text || '').slice(0, 160)}`);
    let j = r.json; if (!j) { try { j = JSON.parse(r.text); } catch (_) { } }
    return Array.isArray(j) ? j : [];
  }

  /**
   * Tautkan party ke akun Silvana — jalur yg dipakai UI: POST /api/wallets {partyId}.
   * UI NELAN hasilnya (`.catch(()=>{})`), jadi kalau server nolak halaman diam aja.
   * Di sini errornya DIANGKAT supaya kelihatan (mis. 409 "already linked to another
   * account"). Balikin {ok, status, body}.
   */
  async linkWallet(partyId) {
    const r = await request('POST', `${APP_BASE}/api/wallets`, this._opts({
      headers: this._hdr({ 'Accept': '*/*', 'Content-Type': 'application/json', 'Referer': APP_BASE + '/settings', ...this._bearerHdr }),
      body: JSON.stringify({ partyId }),
    }));
    let j = r.json; if (!j) { try { j = JSON.parse(r.text); } catch (_) { } }
    return { ok: r.status >= 200 && r.status < 300, status: r.status, body: j || (r.text || '').slice(0, 200) };
  }

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
  // partyId WAJIB dikirim: tanpa param itu endpoint balikin `proposals:[]` MELULU
  // (verified live — bukan error, cuma kosong senyap), jadi proposal tahap-awal
  // (PENDING, belum jadi DvpProposal di ledger) gak pernah kelihatan.
  async listSettlementProposals(partyId, { includeClosed = false } = {}) {
    const pid = partyId || this.partyId;
    const qs = [pid ? `partyId=${encodeURIComponent(pid)}` : '', includeClosed ? 'includeClosed=1' : ''].filter(Boolean).join('&');
    const r = await request('GET', `${APP_BASE}/api/settlement-proposals${qs ? '?' + qs : ''}`, this._opts({
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
  /**
   * ORDERBOOK asli (REST, endpoint yg sama dipakai UI /terminal — verified live).
   *   GET /api/orderbook-depth/{market}?depth=20[&lpOnly=1]  -> {bids:[], asks:[]}
   * WAJIB dipakai buat harga order, JANGAN getPrice(): EDELx-cETH itu market
   * `cross_rate` (price_feeds: EDELx-USDCx ÷ cETH-USDCx) — getPrice balikin
   * source:"Calculated" yg terukur meleset +3.6% di atas bestBid → limit SELL
   * nyangkut di atas bid (gak pernah match) & BUY overpay.
   * lpOnly=1 = book yg beneran bisa match order kita (kita kirim requirements.lpOnly),
   * sama kayak toggle "LP-only matching" di UI.
   * Balikin {bids,asks,bestBid,bestAsk} — bids desc, asks asc — atau null kalau gagal.
   */
  async orderbookDepth(market, { lpOnly = true, depth = 20 } = {}) {
    const mk = market || 'EDELx-cETH';
    const u = `${APP_BASE}/api/orderbook-depth/${encodeURIComponent(mk)}?depth=${depth}${lpOnly ? '&lpOnly=1' : ''}`;
    const r = await request('GET', u, this._opts({ headers: this._hdr({ 'Accept': '*/*', 'Referer': `${APP_BASE}/terminal?market=${encodeURIComponent(mk)}`, ...this._bearerHdr }) }));
    if (r.status !== 200) return null;
    let j = r.json; if (!j) { try { j = JSON.parse(r.text); } catch (_) { } }
    if (!j) return null;
    const norm = (a) => (Array.isArray(a) ? a : [])
      .map(x => ({ price: Number(x.price), quantity: Number(x.quantity) }))
      .filter(x => x.price > 0 && x.quantity > 0);
    const bids = norm(j.bids).sort((a, b) => b.price - a.price);
    const asks = norm(j.asks).sort((a, b) => a.price - b.price);
    return { bids, asks, bestBid: bids.length ? bids[0].price : 0, bestAsk: asks.length ? asks[0].price : 0 };
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

// Pilih pasangan token DUA TAHAP: token asal dulu, baru token tujuan yg beneran
// punya market sama dia. Lebih enak daripada nyodorin belasan "EDELx-cETH" mentah
// yg maksa user mikir sendiri mana base mana quote.
// Balikin {market, base, quote, from, to} — base/quote ngikut orientasi market
// asli (yg nentuin sell/buy), from/to ngikut yg dipilih user.
// getPrice balikin {marketId, last, source, timestamp} — field harganya `last`,
// BUKAN price/value. Salah nebak field bikin rate 0 dan swap ditolak dengan
// "harga <market> gak kebaca" padahal harganya ada.
function priceOf(px) {
  if (!px) return 0;
  return Number(px.last ?? px.price ?? px.value ?? px.lastPrice ?? 0) || 0;
}

async function pickTokenPair(sv, { title = 'Pilih token', fromLabel = 'Token ASAL (yg dikirim)', toLabel = 'Token TUJUAN (yg diterima)' } = {}) {
  const mk = await fetchMarkets(sv);
  if (!mk.length) throw new Error('daftar market kosong');
  const tokens = [...new Set(mk.flatMap(m => [m.base, m.quote]))].sort((a, b) => a.localeCompare(b));
  const pasangan = (t) => mk.filter(m => m.base === t || m.quote === t);
  const fromItems = tokens.map(t => ({
    label: String(t).padEnd(8),
    detail: paint(`${pasangan(t).length} pasangan`, COLOR.gray),
  }));
  const f = await pickList({ title: `${title} — ${fromLabel}:`, items: fromItems });
  if (!f.length) return null;
  const from = tokens[f[0]];
  const lawan = pasangan(from).map(m => ({ tok: m.base === from ? m.quote : m.base, m }));
  const t = await pickList({
    title: `${title} — ${toLabel} (dari ${from}):`,
    items: lawan.map(x => ({ label: String(x.tok).padEnd(8), detail: paint(`market ${x.m.id}`, COLOR.gray) })),
  });
  if (!t.length) return null;
  const { tok: to, m } = lawan[t[0]];
  return { market: m.id, base: m.base, quote: m.quote, from, to };
}

// Daftar market aktif dari Silvana. Dipakai picker pasangan token mode 8 supaya
// user milih dari yg BENERAN ada, bukan ngetik bebas lalu gagal pas swap.
async function fetchMarkets(sv) {
  const r = await request('GET', `${APP_BASE}/api/markets`, sv._opts({ headers: sv._hdr({ 'Accept': 'application/json', 'Referer': APP_BASE + '/swap', ...sv._bearerHdr }) }));
  if (r.status !== 200) throw new Error(`markets status=${r.status}`);
  let j = r.json; if (!j) { try { j = JSON.parse(r.text); } catch (_) { } }
  const arr = Array.isArray(j) ? j : (j && j.markets) || [];
  return arr.filter(m => m && m.market_id && m.is_active !== false)
    .map(m => ({ id: m.market_id, base: m.base_instrument, quote: m.quote_instrument, type: (m.price_feeds && m.price_feeds.type) || 'langsung' }));
}

// ── Picker interaktif (panah ↑/↓, spasi centang, Enter konfirmasi) ───────────
// Dipakai menu transfer buat milih akun & token tanpa ngetik indeks. Item bisa
// di-`disabled` (mis. saldo dust) — tetep KELIHATAN biar user tau kenapa akun itu
// gak ikut, tapi gak bisa dicentang.
// Kalau stdin bukan TTY (dipipe/CI) otomatis balik ke mode ketik, biar skrip tetep jalan.
//
// items: [{ label, detail?, disabled?, note? }]
// balik: array index terpilih (multi) atau [index] (single). [] = dibatalin.
async function pickList({ title, items, multi = false, hint = '' }) {
  const N = items.length;
  if (!N) return [];
  const enabled = items.map((it, i) => (it && !it.disabled) ? i : -1).filter(i => i >= 0);
  // Semua item terkunci → jangan balik diam-diam, itu kebaca sebagai "batal" padahal
  // sebenarnya gak ada yg bisa dipilih. Tampilin daftarnya biar alasannya kelihatan.
  if (!enabled.length) {
    process.stdout.write('\n' + paint(title, COLOR.bold + COLOR.cyan) + '\n');
    items.forEach(it => process.stdout.write(paint(`  ${it.label}${it.detail ? '  ' + it.detail : ''}  ${it.note || '[gak bisa dipilih]'}`, COLOR.gray) + '\n'));
    process.stdout.write(paint('gak ada yg bisa dipilih.\n', COLOR.red));
    return [];
  }

  if (!process.stdin.isTTY) {
    // Fallback ketik: "all" | "0,2,5" | "0-4" | campuran.
    process.stdout.write('\n' + paint(title, COLOR.bold + COLOR.cyan) + '\n');
    items.forEach((it, i) => process.stdout.write(paint(`  ${i}) ${it.label}${it.detail ? '  ' + it.detail : ''}${it.disabled ? '  [' + (it.note || 'dilewati') + ']' : ''}`, it.disabled ? COLOR.gray : COLOR.white) + '\n'));
    const raw = (await prompt(paint(multi ? `pilih [0-${N - 1} / all]: ` : `pilih [0-${N - 1}]: `, COLOR.bold))).trim();
    const out = [];
    if (/^(all|semua|\*)$/i.test(raw)) enabled.forEach(i => out.push(i));
    else for (const part of raw.split(',').map(x => x.trim()).filter(Boolean)) {
      const m = part.match(/^(\d+)\s*-\s*(\d+)$/);
      if (m) { const lo = Number(m[1]), hi = Number(m[2]); for (let i = Math.min(lo, hi); i <= Math.max(lo, hi); i++) out.push(i); }
      else if (/^\d+$/.test(part)) out.push(Number(part));
    }
    return [...new Set(out)].filter(i => enabled.includes(i)).slice(0, multi ? undefined : 1);
  }

  // Readline bareng ditutup dulu — kalau nggak dia ikut nyedot stdin dan panahnya
  // ketelen. getRL() bikin ulang sendiri pas prompt() berikutnya dipanggil.
  try { if (_rl) { _rl.close(); _rl = null; } } catch (_) { }
  const sel = new Set();
  let cur = enabled[0];
  const head = paint(title, COLOR.bold + COLOR.cyan)
    + '\n' + paint(hint || (multi ? '↑/↓ pindah · SPASI centang · a semua · Enter lanjut · q batal'
      : '↑/↓ pindah · Enter pilih · q batal'), COLOR.gray);
  process.stdout.write('\n' + head + '\n');
  const draw = (first) => {
    if (!first) process.stdout.write(`\x1b[${N}A`);
    for (let i = 0; i < N; i++) {
      const it = items[i];
      const mark = multi ? (sel.has(i) ? '[x] ' : '[ ] ') : '';
      const arrow = i === cur ? '❯ ' : '  ';
      const body = `${arrow}${mark}${it.label}${it.detail ? '  ' + it.detail : ''}${it.disabled ? '  ' + (it.note || 'dilewati') : ''}`;
      const col = it.disabled ? COLOR.gray : (i === cur ? COLOR.bold + COLOR.cyan : COLOR.white);
      process.stdout.write('\x1b[2K' + paint(body, col) + '\n');
    }
  };
  draw(true);

  return await new Promise((resolve) => {
    const done = (val) => {
      try { process.stdin.setRawMode(false); } catch (_) { }
      process.stdin.removeListener('keypress', onKey);
      process.stdin.pause();
      if (useColor) process.stdout.write('\x1b[?25h');
      resolve(val);
    };
    const onKey = (str, key) => {
      if (!key) return;
      if (key.ctrl && key.name === 'c') { done([]); process.stdout.write('\n' + paint('bye 👋', COLOR.gray) + '\n'); process.exit(0); }
      const step = (d) => {
        const at = enabled.indexOf(cur);
        cur = enabled[(at + d + enabled.length) % enabled.length];
      };
      if (key.name === 'up' || key.name === 'k') step(-1);
      else if (key.name === 'down' || key.name === 'j') step(1);
      else if (multi && (key.name === 'space')) { sel.has(cur) ? sel.delete(cur) : sel.add(cur); }
      else if (multi && (str === 'a' || str === 'A')) { if (sel.size === enabled.length) sel.clear(); else enabled.forEach(i => sel.add(i)); }
      else if (key.name === 'return' || key.name === 'enter') {
        const out = multi ? (sel.size ? [...sel].sort((x, y) => x - y) : [cur]) : [cur];
        draw(false); process.stdout.write('\n');
        return done(out);
      } else if (str === 'q' || key.name === 'escape') { draw(false); process.stdout.write('\n'); return done([]); }
      else return;
      draw(false);
    };
    readline.emitKeypressEvents(process.stdin);
    try { process.stdin.setRawMode(true); } catch (_) { }
    process.stdin.resume();
    if (useColor) process.stdout.write('\x1b[?25l');
    process.stdin.on('keypress', onKey);
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
  const feeCap = effFeeCap(ctx.maxFeeCC);
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
      const bal = await canton.balances();
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
      const bal = await canton.balances();
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

  const multiCall = await getMultiCallCached(sv);
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
        terms: normDvpTerms(ca.terms),   // deliveries/payments ASLI; waktu dinormalisasi ke string ISO µs
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
    const bal = await canton.balances();
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
    if (q && (q.status === 'failed' || q.status === 'rejected')) throw completionErr(q.status, q.message);
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
  //    cancelPendingForFresh cuma baca DvpProposal di LEDGER — settlement tahap AWAL
  //    (PENDING, belum naik jadi DvpProposal) gak kejaring. Sapu lewat REST juga:
  //    order GTC yg settle-nya batal bisa ke-match ULANG sama LP → PENDING nyantol.
  try {
    const pend = await sv.listSettlementProposals(ctx.partyId).catch(() => []);
    const graceMs = (Number(M8.waitCounterpartySec) || 300) * 1000;
    for (const p of pend) {
      if (String(p.marketId || '') !== market) continue;
      if (!/PENDING/i.test(String(p.status || ''))) continue;
      if (p.buyer !== ctx.partyId && p.seller !== ctx.partyId) continue;
      // JANGAN bunuh proposal yg masih SEHAT: sisi kita udah confirm & tinggal nunggu
      // counterparty. Kalau di-cancel di sini, trade yg hampir jadi kebuang lalu diulang
      // dari nol (bikin makin lama). Dana kita belum ke-lock, jadi aman dibiarin.
      const createdMs = Number((p.createdAt && p.createdAt.seconds) || 0) * 1000;
      const ageMs = createdMs > 0 ? Date.now() - createdMs : Infinity;
      if (ageMs < graceMs) {
        const st = await sv.swapAction(SWAP.actionIds.pollProposal, [{ settlementId: p.proposalId, partyId: ctx.partyId }]).catch(() => null);
        const mine = st ? (p.buyer === ctx.partyId ? st.buyerNextAction : st.sellerNextAction) : undefined;
        if (mine === 7) {   // 7 = WAIT → giliran counterparty, kasih waktu
          log(`settlement ${String(p.proposalId).slice(0, 12)}… masih jalan (${Math.round(ageMs / 1000)}s, giliran counterparty) → dibiarin`);
          continue;
        }
      }
      log(`settlement PENDING nyantol ${String(p.proposalId).slice(0, 12)}… → cancel (fresh start)`);
      await sv.cancelSettlement(p.proposalId, ctx.partyId, 'stale pending before new order').catch(() => { });
    }
  } catch (_) { }

  // 1. HARGA dari ORDERBOOK (bukan getPrice). getPrice(EDELx-cETH) itu feed synthetic
  //    `cross_rate` (EDELx-USDCx ÷ cETH-USDCx) — terukur live +3.6% di atas bestBid,
  //    jadi limit SELL kita nangkring DI ATAS bid (gak pernah match, FOK kill →
  //    "likuiditas belum ada") dan BUY overpay ~5%. Book lpOnly = book yg beneran
  //    bisa match order kita (requirements.lpOnly). Book kosong → noLiquidity (retry),
  //    JANGAN submit ngawur.
  // DUA HAL BEDA, jangan disatuin:
  //   bookLpOnly  = SUMBER HARGA. Book LP = harga yg beneran bisa keisi.
  //   orderLpOnly = BATAS LAWAN MATCH (requirements.lpOnly). Default false = boleh
  //                 match siapa aja, jadi kalau ada bid non-LP lebih bagus kita dapat
  //                 price improvement — tapi harga tetap dipatok dari book LP.
  // Kenapa penting (terpantau live 26/07): full book sering CROSSED (bid > ask) karena
  // order2 di situ sama-sama mensyaratkan lpOnly → saling kunci, gak bisa kita match.
  // Kalau harga diambil dari full book, limit kita nangkring di level yg mustahil keisi
  // (SELL @0.00000545 padahal LP bid cuma 0.00000516) → "order gak match" terus.
  const priceLpOnly = M8.bookLpOnly !== false;
  const useLpOnly = M8.orderLpOnly === true;
  let book = await sv.orderbookDepth(market, { lpOnly: priceLpOnly, depth: 20 }).catch(() => null);
  let best = book ? (side === 'buy' ? book.bestAsk : book.bestBid) : 0;
  // LP kosong di SISI ini → mau gak mau pricing dari full book (mending nyoba daripada diam).
  if (!(best > 0) && priceLpOnly) {
    const alt = await sv.orderbookDepth(market, { lpOnly: false, depth: 20 }).catch(() => null);
    const altBest = alt ? (side === 'buy' ? alt.bestAsk : alt.bestBid) : 0;
    if (altBest > 0) { book = alt; best = altBest; log(`book LP ${side} kosong → pricing dari FULL book (best ${altBest.toFixed(10)})`); }
  }
  if (!(best > 0)) {
    // Kalau book yg dipakai kosong, intip varian satunya biar pesan errornya BERGUNA:
    // "LP mundur tapi full book ada isi" itu saran aksi (matiin bookLpOnly), beda dari
    // "market beneran kering". Cuma buat diagnosa — gak ngubah perilaku order.
    const e = new Error(`book ${market} ${side} kosong di LP maupun full book (bestBid=${(book && book.bestBid) || 0}, bestAsk=${(book && book.bestAsk) || 0})`);
    e.noLiquidity = true; throw e;
  }
  // Sapu N level kalau qty > size level teratas → limit dipasang di level TERJAUH yg
  // kudu disapu, biar sisa qty gak nyangkut di harga best doang.
  const sweep = bookPriceForQty(side === 'buy' ? book.asks : book.bids, edelxQty);
  const base = sweep.price > 0 ? sweep.price : best;
  const cross = Number(M8.orderCross) || 0.001;
  // Nyeberang (crossing) + bulatkan ke tick ke arah yg AMAN: BUY ke atas, SELL ke bawah.
  const price = tickPrice(base * (side === 'buy' ? 1 + cross : 1 - cross), side === 'buy');
  let qty = Number(edelxQty);
  // Safety net BUY: cost cETH = qty × price. Kalau harga book gerak naik antara sizing
  // (call-site) dan submit, potong qty biar gak "Insufficient cETH balance".
  const maxCeth = Number(ctx.maxDeliverCeth) || 0;
  if (side === 'buy' && maxCeth > 0) {
    const cost = qty * Number(price);
    if (cost > maxCeth) {
      const trimmed = Math.floor((maxCeth / Number(price)) * 1e6) / 1e6;
      log(`cost ${cost.toFixed(8)} > saldo cETH ${maxCeth.toFixed(8)} → qty ${qty} → ${trimmed}`);
      qty = trimmed;
    }
  }
  if (!(qty > 0)) { const e = new Error('qty jadi 0 setelah cap saldo cETH'); e.insufficientBalance = true; throw e; }

  // CAP KE DEPTH YG BENERAN KEJANGKAU HARGA LIMIT KITA. Tanpa ini bot minta qty penuh,
  // cuma ke-fill sebagian (book tipis / kegerus akun lain yg jalan paralel), sisanya jadi
  // chunk < minUsd → di-cancel sebagai dust → settledCount 0 → "tidak ada chunk yg settle".
  // Terpantau live 26/07: BUY 1252 EDELx cuma fill 456 (~$4.59) lalu dibuang semua.
  // Mending minta sebanyak yg muat: fill penuh, gak ada dust, gak ada order+cancel sia-sia.
  {
    const levels = side === 'buy' ? book.asks : book.bids;
    const P = Number(price);
    const reachable = (levels || []).filter(l => side === 'buy' ? l.price <= P : l.price >= P);
    const reachableQty = reachable.reduce((s, l) => s + l.quantity, 0);
    if (reachableQty > 0 && reachableQty < qty) {
      const trimmed = Math.floor(reachableQty * 1e6) / 1e6;
      log(`depth kejangkau ${trimmed} EDELx < minta ${qty} → potong qty (hindari partial-fill jadi dust)`);
      qty = trimmed;
    }
    // Kalau yg muat aja udah di bawah minUsd, chunk hasilnya PASTI dibuang sebagai dust.
    // Jangan submit sama sekali: hemat order+cancel, dan retry-nya kena backoff noLiquidity.
    const valUsd = qty * (Number(ctx.usdPerEdelx) || 0);
    if (minUsd > 0 && valUsd > 0 && valUsd < minUsd) {
      const e = new Error(`depth ${side} cuma ~$${valUsd.toFixed(2)} (${qty.toFixed(0)} EDELx) < minUsd $${minUsd} — tunggu book keisi`);
      e.noLiquidity = true; throw e;
    }
  }

  const qtyStr = fmt10(String(qty));
  const tif = M8.orderTif || 'GTD';
  // GTD → expiresAt WAJIB (frontend: `expiresAt: "GTD"===tif ? new Date(x).toISOString() : undefined`).
  // Ini jaring pengaman kalau proses mati di antara submitOrder dan cancelOrder: order
  // GTC yg ditinggalkan bakal hidup selamanya dan ke-match ulang tiap settlement dibatalin,
  // sedangkan GTD mati sendiri. TTL dibikin > orderWaitSec + grace biar jalur normal aman.
  const ttlSec = Math.max(Number(M8.orderWaitSec || 30) + 30, Number(M8.orderTtlSec) || 120);
  const expiresAt = tif === 'GTD' ? new Date(Date.now() + ttlSec * 1000).toISOString() : undefined;
  log(`terminal ${side.toUpperCase()} ${qtyStr} EDELx @ ${price} cETH (${tif}${expiresAt ? ` ttl ${ttlSec}s` : ''} ${useLpOnly ? 'lpOnly' : 'ALL-book'}; book bid ${book.bestBid.toFixed(10)} / ask ${book.bestAsk.toFixed(10)}${sweep.full ? '' : ' — depth kurang'})`);
  // requirements.lpOnly HARUS seiring sama book yg dibaca (M8.bookLpOnly) — kalau beda,
  // bot mempersempit lawan-match tanpa sadar. Terpantau live 26/07: LP mundur TOTAL
  // (book lpOnly bid 0 / ask 0) sementara FULL book punya 5.589 EDELx bid — semua order
  // SELL ditolak sendiri sampai lpOnly dimatikan. Set mode8.bookLpOnly=false biar bot
  // boleh match order non-LP juga.
  const ord = await sv.submitOrder({ partyId: ctx.partyId, marketId: market, orderType: side, price, quantity: qtyStr, timeInForce: tif, expiresAt, ...(useLpOnly ? { requirements: { lpOnly: true } } : {}) });
  if (!ord || ord.success === false || !ord.order) {
    const e = new Error(`submitOrder: ${(ord && (ord.error || ord.message)) || 'gagal'}`); e.noLiquidity = true; throw e;
  }
  const orderId = ord.order.orderId || ord.order.id;
  inflightAdd(ctx, 'orders', orderId);   // biar ke-cancel kalau bot dihentikan di tengah jalan

  // 2. Proposal(s) hasil order (poll; split → >1). Beda dari FOK: GTC yg gak match
  //    TETAP NEMPEL di book (ngunci dana) → wajib cancelOrder di semua jalur keluar.
  const pollProps = () => sv.proposalsByOrderId(ctx.partyId, orderId)
    .catch(() => [])
    .then(list => list.filter(p => p.buyer === ctx.partyId || p.seller === ctx.partyId));
  let props = [];
  const deadline = Date.now() + Math.max(5000, (Number(M8.orderWaitSec) || 30) * 1000);
  while (Date.now() < deadline) {
    props = await pollProps();
    if (props.length) break;
    await sleep(2500);
  }
  if (!props.length) {
    await sv.cancelOrder(orderId, ctx.partyId).catch(() => { });
    inflightDone(ctx, 'orders', orderId);
    const e = new Error('order gak match (book kosong / LP absen)'); e.noLiquidity = true; throw e;
  }
  // Grace: kasih chunk lain (split multi-maker) waktu nyusul, baru putuskan sisa.
  if (M8.orderGraceMs > 0) {
    await sleep(M8.orderGraceMs);
    const again = await pollProps();
    if (again.length > props.length) props = again;
  }
  // WAJIB cancelOrder di sini — SELALU, bukan cuma pas partial fill. Beda kritis dari
  // FOK: order GTC TETAP HIDUP di book sesudah match. Kalau settle-nya gagal/di-cancel
  // (mis. fee gate), order yg masih hidup itu KE-MATCH LAGI sama LP → lahir proposal
  // PENDING liar yg gak ada yg urus (terpantau live: order 107718813 → 1 CANCELLED +
  // 1 PENDING). Chunk yg UDAH jadi proposal gak kena cancel ini — proposal berdiri
  // sendiri, lepas dari order. Full fill → cancelOrder no-op (error diabaikan).
  const filled = props.reduce((s, p) => s + (Number(p.baseQuantity) || 0), 0);
  if (filled + 1e-9 < qty) log(`partial fill ${filled.toFixed(6)}/${qtyStr} EDELx → sisa di-cancel`);
  await sv.cancelOrder(orderId, ctx.partyId).catch(() => { });
  inflightDone(ctx, 'orders', orderId);
  // Daftar SEMUA proposal SEKARANG (bukan pas masuk loop settle) — kalau bot dihentikan
  // di sela-sela, proposal yang belum sempat kedaftar bakal ngegantung.
  for (const _p of props) inflightAdd(ctx, 'proposals', _p.proposalId);
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
  // PROMOSI CHUNK TERBESAR. minUsd itu maksudnya buang SERPIHAN dust, bukan buang order
  // yg ke-fill penuh. Tapi kalau engine nge-SPLIT rata ke banyak maker, TIAP chunk bisa
  // di bawah ambang padahal TOTALnya jauh di atas → dulu semua kebuang & swap gagal
  // ("tidak ada chunk yg settle"). Terpantau live 26/07: fill $12.65 kepecah $10.29 +
  // $2.35, dua-duanya dibuang cuma karena kurang $0.21 dari ambang.
  // Aturan: kalau GAK ADA chunk yg lolos TAPI total fill ≥ minUsd, settle chunk TERBESAR
  // (1 settlement = 1 task, fee CC tetap sekali), sisanya tetap dibuang sbg dust.
  if (!toSettle.length && toCancel.length) {
    const totalUsd = toCancel.reduce((s, x) => s + x.valUsd, 0);
    if (totalUsd >= minUsd) {
      toCancel.sort((a, b) => b.valUsd - a.valUsd);
      const top = toCancel.shift();
      toSettle.push(top.p);
      log(`split rata: semua chunk < minUsd tapi total ~$${totalUsd.toFixed(2)} ≥ $${minUsd} → settle chunk terbesar ${Number(top.p.baseQuantity).toFixed(2)} EDELx (~$${top.valUsd.toFixed(2)})`);
    }
  }
  // PASS 1 — CANCEL SEMUA DUST DULU, SEBELUM sign apapun. Dust gak pernah masuk
  //   prepareDvpFee/prepareTransfer/sign → 0 fee CC buat chunk dust (permintaan user).
  //   dustEdelxTotal = jumlah EDELx chunk yg di-cancel (base EDELx utk buy/sell) → dipakai
  //   loss round-trip biar dust yg KETAHAN (bukan hilang) gak kehitung loss.
  for (const { p, valUsd } of toCancel) {
    log(`dust ${Number(p.baseQuantity).toFixed(2)} EDELx (~$${valUsd.toFixed(2)} < minUsd $${minUsd}) → cancelSettlement (sebelum sign, 0 fee)`);
    await sv.cancelSettlement(p.proposalId, ctx.partyId, 'dust chunk below minUsd').catch(() => { });
    inflightDone(ctx, 'proposals', p.proposalId);
    dustCount++;
    dustEdelxTotal += Number(p.baseQuantity) || 0;
  }
  // PASS 2 — SETTLE chunk ≥ minUsd (besar dulu), sekuensial + excludeHoldingCids.
  //   Cuma chunk yg value USD ≥ minUsd (config) yg di-sign & bayar fee.
  toSettle.sort((a, b) => Number(b.baseQuantity) - Number(a.baseQuantity));
  for (const p of toSettle) {
    inflightAdd(ctx, 'proposals', p.proposalId);
    try {
      const r = await settleTerminalProposal(ctx, p, consumed);
      if (r && r.ok) { settledCount++; if (r.feeCC) feeTotal += r.feeCC; (r.consumed || []).forEach(c => consumed.add(c)); }
      inflightDone(ctx, 'proposals', p.proposalId);
    } catch (e) {
      lastErr = e; log(`settle ${p.proposalId.slice(0, 12)}… gagal: ${(e && e.message) || e}`);
      if (e && e.feeSpike) throw e; // fee gate → bubble up (mode 8 tunggu)
    }
  }
  if (!settledCount) {
    // Semua chunk kebuang jadi dust = kondisi PASAR (book tipis / kegerus akun paralel),
    // bukan error tak-dikenal. Tandai noLiquidity biar kena backoff yg bener & gak
    // ngitung hardErrs (yg tiap 5x micu rebuild client percuma).
    if (!lastErr && dustCount) {
      const e = new Error(`semua ${dustCount} chunk < minUsd $${minUsd} (total ${dustEdelxTotal.toFixed(2)} EDELx ~$${(dustEdelxTotal * usdPerEdelx).toFixed(2)}) — book cuma sanggup segitu`);
      e.noLiquidity = true; throw e;
    }
    throw (lastErr || new Error('tidak ada chunk yg settle'));
  }
  return { ok: true, direction: side, orderId, settled: settledCount, dust: dustCount, dustEdelx: dustEdelxTotal, feeCC: feeTotal || null };
}

// ============================================================================
//  RFQ ATOMIC (atomic-dvp-v2) — settle SEKALI TEMBAK, tanpa DvpProposal
// ============================================================================
// Silvana pindah dari alur DvpProposal ke AtomicDVP_Settle. swapOnce lama nunggu
// dvpProposalCid yg GAK PERNAH muncul di jalur ini → "poll: dvpProposalCid timeout"
// stage 3 (server malah nunggu KITA lanjut). Dipetakan live 26/07 dari UI /swap.
// Untung ganda: fee ~1.24 CC (vs 4.3 CC CLOB) & harga lebih bagus dari orderbook.
//
// Alur: requestQuotesV2 → acceptQuoteAtomic (dapat envelope + tanda tangan LP)
//       → utilityTransferFactory per instrument → getTransferFactoryContext(Amulet)
//       → rakit AtomicDVP_Settle → prepare → sign → submit.
// ── Registry in-flight: order & settlement yang BELUM kelar ─────────────────
// Dipakai graceful shutdown (Ctrl+C): order GTD/GTC yang keburu ditinggal bakal
// nempel di orderbook dan bisa ke-match ulang, settlement PENDING ngegantung di
// akun. Dua-duanya di-cancel dulu sebelum proses mati.
const INFLIGHT = new Map();   // email -> {sv, partyId, label, orders:Set, proposals:Set}
function inflightOf(ctx) {
  const key = ctx.email || (ctx.state && ctx.state.email) || String(ctx.partyId || 'x');
  let e = INFLIGHT.get(key);
  if (!e) { e = { sv: ctx.sv, partyId: ctx.partyId, label: ctx.label || key, orders: new Set(), proposals: new Set() }; INFLIGHT.set(key, e); }
  e.sv = ctx.sv; e.partyId = ctx.partyId;   // refresh (client bisa di-rebuild)
  return e;
}
const inflightAdd = (ctx, kind, id) => { if (id) inflightOf(ctx)[kind].add(id); };
const inflightDone = (ctx, kind, id) => { const e = INFLIGHT.get(ctx.email || (ctx.state && ctx.state.email) || String(ctx.partyId || 'x')); if (e && id) e[kind].delete(id); };
// Bersihin semua yang masih nyantol. Dipakai SIGINT — dibatasi waktu biar Ctrl+C
// gak ngegantung; Ctrl+C kedua langsung maksa keluar.
async function cancelInflight(log = () => { }) {
  let n = 0;
  for (const [, e] of INFLIGHT) {
    for (const oid of [...e.orders]) {
      try { await e.sv.cancelOrder(oid, e.partyId); log(`  [${e.label}] order ${oid} di-cancel`); n++; } catch (_) { }
      e.orders.delete(oid);
    }
    for (const pid of [...e.proposals]) {
      try { await e.sv.cancelSettlement(pid, e.partyId, 'bot dihentikan'); log(`  [${e.label}] settlement ${String(pid).slice(0, 12)}… di-cancel`); n++; } catch (_) { }
      e.proposals.delete(pid);
    }
  }
  return n;
}

const UTIL_NS = 'utility.digitalasset.com/';
// Konteks transfer utk 1 instrument. inputHoldingCids WAJIB punya SISI PENGIRIM —
// kosong / salah sisi = 500 (terverifikasi: digest 4118613165 / 1034054957).
// Respons "context" dari server pernah DATAR ({factoryId, disclosedContracts, …}) dan
// sejak salah satu redeploy DIBUNGKUS ({ok:true, context:{factoryId, …}}). Semua cek di
// bawah (facOf / pickInstrumentConfigCid / disclosedContracts / choiceContextData) baca
// dari level atas, jadi begitu servernya membungkus, respons SUKSES kebaca sebagai GAGAL
// — persis kejadian "utilityTransferFactory(EDELx) gagal — holding kita(2) → {"ok":true,
// "context":{"factoryId":…}}". Buka bungkusnya di satu tempat, terima dua-duanya biar
// gak pecah lagi kalau servernya balik ke bentuk lama.
function unwrapCtx(r) {
  if (!r || typeof r !== 'object') return r;
  const c = r.context;
  if (c && typeof c === 'object' && (c.factoryId || c.factory || c.choiceContextData || c.choiceContext || c.disclosedContracts || c.disclosed)) return c;
  return r;
}
async function utilityTransferCtx(sv, { admin, id, amount, sender, receiver, holdingCids, altHoldingCids }) {
  const now = new Date();
  const mk = (hold) => [{
    receiver, amount, instrumentId: { admin, id },
    requestedAt: now.toISOString(),
    executeBefore: new Date(now.getTime() + 130_000).toISOString(),
    sender, inputHoldingCids: hold || [],
  }];
  // Server nolak (500, pesan disembunyiin Next.js) kalau inputHoldingCids bukan milik
  // sisi pengirim. Aturan pastinya beda-beda per arah, jadi coba beberapa bentuk.
  const tries = [['holding kita', holdingCids || []]];
  if (altHoldingCids && altHoldingCids.length) tries.push(['holding LP', altHoldingCids]);
  tries.push(['tanpa holding', []]);
  // Kumpulin SEMUA kegagalan, jangan cuma yg terakhir. Dulu yg dilempar cuma percobaan
  // pamungkas (inputHoldingCids: []) yg SELALU balik "No holdings provided" — pesan yg
  // gak bisa ditindaklanjuti, sementara alasan asli percobaan pertama ("Given holdings
  // are invalid" dst) kebuang. Bikin kejadian nyata di lapangan gak bisa didiagnosa.
  const errs = [];
  for (const [what, hold] of tries) {
    const raw = await sv.swapAction(SWAP.actionIds.utilityTransferFactory, mk(hold)).catch(e => ({ _err: (e && e.message) || String(e) }));
    const r = raw && raw._err ? raw : unwrapCtx(raw);
    if (r && !r._err && (r.factoryId || (r.factory && r.factory.factoryId))) return r;
    const why = (r && (r._err || r.error || r.message)) || JSON.stringify(raw || null);
    errs.push(`${what}(${(hold || []).length}) → ${String(why).replace(/\s+/g, ' ').slice(0, 140)}`);
  }
  throw new Error(`utilityTransferFactory(${id}) gagal — ${errs.join(' | ')}`);
}
// Ambil cid InstrumentConfiguration dari disclosedContracts hasil context.
function pickInstrumentConfigCid(ctx) {
  const dc = (ctx && (ctx.disclosedContracts || ctx.disclosed)) || [];
  const hit = dc.find(d => /Configuration\.Instrument:InstrumentConfiguration/.test(String(d.templateId || '')));
  return hit && hit.contractId;
}
// transferArgs == acceptArgs (terverifikasi identik di capture UI).
function utilArgs({ transferRuleCid, instrumentConfigCid }) {
  return {
    context: {
      values: {
        [UTIL_NS + 'receiver-credentials']: { tag: 'AV_List', value: [] },
        [UTIL_NS + 'transfer-rule']: { tag: 'AV_ContractId', value: transferRuleCid },
        [UTIL_NS + 'sender-credentials']: { tag: 'AV_List', value: [] },
        [UTIL_NS + 'enable-result-contracts']: { tag: 'AV_Bool', value: true },
        [UTIL_NS + 'instrument-configuration']: { tag: 'AV_ContractId', value: instrumentConfigCid },
      },
    },
    // WAJIB ada walau kosong — tanpa ini Canton nolak:
    // "Missing non-optional fields: HashSet(extraArgs)".
    meta: { values: {} },
  };
}

// Swap 1x lewat jalur RFQ ATOMIC. `side`: 'sell' = kirim EDELx terima cETH.
// `baseQty` = jumlah base (EDELx). Balikin {ok, feeCC, quoteId}.
async function swapOnceAtomic(ctx, side, baseQty) {
  const { sv, privy, canton, partyId, identityToken, proxy, log = () => { } } = ctx;
  const L = ctx.leg || {};
  const market = L.market || 'EDELx-cETH';
  const [baseId, quoteId2] = String(market).split('-');     // EDELx, cETH
  const feeCap = effFeeCap(ctx.maxFeeCC);

  // 1. Quote v2 (rfqId dari /api/rfq/stream v1 DITOLAK acceptQuoteAtomic).
  // feeTokens = token buat bayar settlement fee. [] / dihilangkan = CC (Amulet).
  // ["USDCx"] bikin LP ngasih quote dgn fee dalam USDCx. Namanya JAMAK dan berupa
  // array — ini yg bikin tebakan feeInstrumentId/feeInstrument/feeToken semuanya
  // meleset; ketahuan dari capture request UI (tools/inspect.js).
  const feeTokens = (ctx.feeTokens != null ? ctx.feeTokens : SWAP.feeTokens) || [];
  const rq = await sv.swapAction(SWAP.actionIds.requestQuotesV2, [{
    partyId, marketId: market, direction: side, quantity: String(baseQty),
    ...(feeTokens.length ? { feeTokens } : {}),
  }]);
  const quotes = (rq && rq.quotes) || [];
  if (!rq || rq.success === false || !quotes.length) {
    const e = new Error(`requestQuotesV2: ${(rq && (rq.error || rq.message)) || 'gak ada quote'}`); e.noLiquidity = true; throw e;
  }
  // quoteQuantity terbaik: sell → paling BANYAK diterima; buy → paling SEDIKIT dibayar.
  quotes.sort((a, b) => side === 'sell' ? Number(b.quoteQuantity) - Number(a.quoteQuantity) : Number(a.quoteQuantity) - Number(b.quoteQuantity));

  // 2. Accept → envelope bertanda tangan LP. LP kadang OVER-QUOTE (nawarin lebih dari
  //    yg dia pegang) lalu nolak pas confirm ("InsufficientHoldings") — jangan langsung
  //    nyerah, coba LP berikutnya yg harganya nomor 2.
  let acc = null, env = null, pick = null, lastErr = '';
  for (const cand of quotes) {
    log(`RFQ ${side} ${baseQty} ${baseId} → ${cand.quoteQuantity} ${quoteId2} @ ${cand.price} (${cand.lpName}, ${quotes.length} quote)`);
    const r = await sv.swapAction(SWAP.actionIds.acceptQuoteAtomic, [{ partyId, rfqId: rq.rfqId, quoteId: cand.quoteId }]).catch(e => ({ success: false, error: (e && e.message) || String(e) }));
    if (r && r.success !== false && r.envelope) { acc = r; env = r.envelope; pick = cand; break; }
    lastErr = (r && (r.error || r.message)) || 'no envelope';
    log(`   ${cand.lpName} nolak: ${String(lastErr).slice(0, 100)} — coba LP lain`);
  }
  if (!env) {
    const e = new Error(`acceptQuoteAtomic: semua ${quotes.length} LP nolak (${String(lastErr).slice(0, 120)})`);
    if (/InsufficientHoldings/i.test(lastErr)) e.noLiquidity = true; else e.transient = true;
    throw e;
  }
  const q = env.quote || {};
  const weSendBase = String(q.side || side).toLowerCase() === 'sell';

  // fee gate SEBELUM bikin transaksi apa pun
  const feeCC = Number((q.lpFees && q.lpFees[0] && q.lpFees[0].amount) || 0);
  if (Number.isFinite(feeCC) && feeCC > 0) {
    // Instrumennya dibaca dari q.lpFees — fee0 baru dideklarasi jauh di bawah, jadi
    // nyentuh dia di sini kena TDZ ("Cannot access 'fee0' before initialization").
    const _fi = (q.lpFees && q.lpFees[0] && q.lpFees[0].instrumentId) || 'Amulet';
    const feeUnit = String(_fi).toUpperCase() === 'AMULET' ? 'CC' : _fi;
    log(`Fee RFQ: ${feeCC} ${feeUnit} (batas ${feeCap})`);
    if (feeCC > feeCap) { const e = new Error(`fee ${feeCC} CC > batas ${feeCap} CC`); e.feeSpike = true; e.feeCC = feeCC; throw e; }
  }

  // 3. Holding kita + CC utk fee.
  const bal = await canton.balances();
  const toks = (bal && bal.tokens) || [];
  const holdOf = (id) => { const t = toks.find(x => String((x.instrumentId && x.instrumentId.id) || '').toUpperCase() === String(id).toUpperCase()); return ((t && t.unlockedUtxos) || []).map(u => u.contractId).filter(Boolean); };
  const sendId = weSendBase ? baseId : quoteId2;
  const userHoldings = holdOf(sendId);
  if (!userHoldings.length) { const e = new Error(`gak ada holding ${sendId}`); e.insufficientBalance = true; throw e; }
  // CEK SANGGUP KIRIM. LP boleh ngutip lebih gede dari yg kita sizing — harga gerak
  // antara sizing dan quote. Kalau gak dicek, prepare-nya baru nolak jauh di belakang
  // dengan "input holdings do not cover leg amount", dan itu gak kebaca sebagai
  // kekurangan saldo jadi engine gak ngecilin qty. Jalur CLOB udah punya cap serupa
  // (maxDeliverCeth); jalur RFQ dulu sama sekali gak punya.
  {
    const sumOf = (id) => {
      const t = toks.find(x => String((x.instrumentId && x.instrumentId.id) || '').toUpperCase() === String(id).toUpperCase());
      return t ? Number(t.totalUnlockedBalance || 0) : 0;
    };
    const kirim = Number(weSendBase ? q.baseAmount : q.quoteAmount) || 0;
    const punya = sumOf(sendId);
    if (kirim > 0 && punya > 0 && kirim > punya + 1e-12) {
      const e = new Error(`${sendId} kurang buat leg: butuh ${kirim} punya ${punya} (LP ngutip lebih gede dari sizing)`);
      e.insufficientBalance = true; e.tokenNeeded = kirim; e.tokenHave = punya;
      throw e;
    }
  }
  const ccHoldings = holdOf('Amulet');
  // CC cuma WAJIB kalau fee-nya emang dibayar CC. Waktu feeTokens dipasang (mis.
  // USDCx), akun tanpa CC sama sekali tetap sah — dulu cek ini gak bersyarat jadi
  // semua akun ber-fee-USDCx mental di sini dengan pesan "top-up CC" yg menyesatkan.
  const _feeTok = (ctx.feeTokens != null ? ctx.feeTokens : SWAP.feeTokens) || [];
  if (_feeTok.length) {
    // Coba id terpetakan DULU, lalu simbol mentah — id registry bisa berupa UUID
    // (USD8) dan pemetaannya bisa basi kalau server ganti. Jangan gagalin swap cuma
    // gara-gara nama; kalau dua-duanya kosong barulah memang gak punya.
    const cari = [feeInstrumentOf(_feeTok[0]), String(_feeTok[0])];
    if (!cari.some(x => holdOf(x).length)) {
      const e = new Error(`gak ada holding ${_feeTok[0]} buat bayar fee`);
      e.insufficientFunds = true; throw e;
    }
  } else if (!holdOf('Amulet').length) {
    const e = new Error('gak ada CC buat bayar fee'); e.insufficientFunds = true; throw e;
  }

  // 4. Konteks transfer per instrument. Sisi PENGIRIM yang nyetor holding.
  const refs = env.utilityAcceptRefs || [];
  // instrumentId di utilityAcceptRefs GAK SELALU simbol. Terpantau live di market
  // cETH-USD8: ref-nya ["cETH", "8694894e-f159-42e1-80c9-ed14b94365b7"] — USD8
  // terdaftar pakai UUID. Nyocokin lewat simbol doang bikin "utilityAcceptRefs gak
  // punya USD8" padahal ref-nya ada.
  // Strategi: cocokin simbol dulu; sisa ref yg gak keklaim otomatis jadi leg satunya
  // (RFQ selalu 2 leg, jadi eliminasi ini aman).
  const bySym = (id) => refs.find(r => String(r.instrumentId).toUpperCase() === String(id).toUpperCase());
  const refBase = bySym(baseId);
  const refQuote = bySym(quoteId2);
  const sisa = refs.filter(r => r !== refBase && r !== refQuote);
  const refFor = (id) => {
    const direct = bySym(id);
    if (direct) return direct;
    if (sisa.length === 1) return sisa[0];   // satu-satunya yg belum keklaim
    return null;
  };
  const lp = env.lpPartyId;
  const mkCtx = async (id, amount, weSend) => {
    const ref = refFor(id);
    if (!ref) throw new Error(`utilityAcceptRefs gak punya ${id} (isi: ${refs.map(r => r.instrumentId).join(', ')})`);
    const c = await utilityTransferCtx(sv, {
      // Pakai instrumentId dari REF, bukan simbol — registry ngenalnya lewat id itu.
      admin: ref.instrumentAdmin, id: ref.instrumentId, amount,
      sender: weSend ? partyId : lp, receiver: weSend ? lp : partyId,
      holdingCids: weSend ? userHoldings.slice(0, 8) : (env.lpInputHoldingCids || []),
      altHoldingCids: weSend ? (env.lpInputHoldingCids || []) : userHoldings.slice(0, 8),
    });
    return { ctx: c, ref };
  };
  const baseCtx = await mkCtx(baseId, String(q.baseAmount), weSendBase);
  const quoteCtx = await mkCtx(quoteId2, String(q.quoteAmount), !weSendBase);

  // 5. Konteks fee — factoryCid utk `fees`. Instrumennya ikut quote (lihat feeTokens).
  const fee0 = (q.lpFees && q.lpFees[0]) || null;
  let feeFactoryCid = null, feeDisclosed = [], feeExtraArgs = null, feeHoldCids = [];
  if (fee0) {
    // Factory mana yg dipakai TERGANTUNG instrument fee-nya:
    //   Amulet (CC)  → getTransferFactoryContextAction (SWAP.actionIds.prepareTransfer)
    //   USDCx dst    → getUtilityTransferFactoryContextAction (Utility registry)
    // Terlihat di capture UI: waktu fee dibayar USDCx, panggilan fee-nya ke
    // utility factory dgn instrumentId {admin:"decentralized-usdc-interchain-rep::…",
    // id:"USDCx"} — bukan ke factory Amulet.
    const feeIsAmulet = String(fee0.instrumentId).toUpperCase() === 'AMULET';
    const feeAction = feeIsAmulet ? SWAP.actionIds.prepareTransfer : SWAP.actionIds.utilityTransferFactory;
    // Holding buat bayar fee: CC kalau Amulet, holding instrument fee-nya kalau bukan.
    const feeHold = feeIsAmulet ? ccHoldings.slice(0, 8) : holdOf(fee0.instrumentId).slice(0, 8);
    feeHoldCids = feeHold;
    if (!feeHold.length) { const e = new Error(`gak ada holding ${fee0.instrumentId} buat bayar fee`); e.insufficientFunds = true; throw e; }
    const now = new Date();
    const fcRaw = await sv.swapAction(feeAction, [{
      receiver: fee0.receiver, amount: String(fee0.amount),
      instrumentId: { admin: fee0.instrumentAdmin, id: fee0.instrumentId },
      requestedAt: now.toISOString(),
      executeBefore: new Date(now.getTime() + 130_000).toISOString(),
      sender: partyId, inputHoldingCids: feeHold,
    }]);
    // Jalur Amulet kena bungkus `context` yg sama. Di sini lebih berbahaya: hasilnya
    // `|| null`, jadi kalau kelewat dia gagal DIAM-DIAM, bukan melempar.
    const fc = unwrapCtx(fcRaw);
    feeFactoryCid = (fc && (fc.factoryId || (fc.factory && fc.factory.factoryId))) || null;
    feeDisclosed = (fc && (fc.disclosedContracts || fc.disclosed)) || [];
    // fees[].extraArgs WAJIB = choiceContextData dari factory Amulet (transfer-preapproval,
    // open-round, external-party-config-state, amulet-rules). Tanpa ini Canton nolak
    // "Missing non-optional fields: HashSet(extraArgs)".
    const fcv = (fc && fc.choiceContextData && fc.choiceContextData.values)
      || (fc && fc.choiceContext && fc.choiceContext.choiceContextData && fc.choiceContext.choiceContextData.values)
      || null;
    if (!fcv) throw new Error(`fee choiceContext (${fee0.instrumentId}) kosong: ${JSON.stringify(fc).slice(0, 200)}`);
    feeExtraArgs = { context: { values: fcv }, meta: { values: {} } };
    if (!feeFactoryCid) throw new Error(`fee factory (${fee0.instrumentId}) gagal: ${JSON.stringify(fc).slice(0, 160)}`);
  }

  // 6. Rakit AtomicDVP_Settle.
  const facOf = (c) => c.factoryId || (c.factory && c.factory.factoryId);
  const argsFor = (c) => utilArgs({ transferRuleCid: c.ref.transferRule.contractId, instrumentConfigCid: pickInstrumentConfigCid(c.ctx) });
  const baseArgs = argsFor(baseCtx), quoteArgs = argsFor(quoteCtx);
  const disclosed = [];
  const seen = new Set();
  // utilityAcceptRefs[].transferRule juga HARUS ikut di-disclose — cid-nya dipakai di
  // *TransferArgs, dan tanpa blob-nya Canton nolak "Contract could not be found".
  const refDisclosed = refs.map(r => r && r.transferRule).filter(x => x && x.contractId && x.createdEventBlob);
  for (const d of [...(env.disclosed || []), ...refDisclosed, ...(baseCtx.ctx.disclosedContracts || baseCtx.ctx.disclosed || []), ...(quoteCtx.ctx.disclosedContracts || quoteCtx.ctx.disclosed || []), ...feeDisclosed]) {
    if (!d || !d.contractId || seen.has(d.contractId)) continue;
    seen.add(d.contractId);
    disclosed.push({ contractId: d.contractId, createdEventBlob: d.createdEventBlob, templateId: d.templateId, synchronizerId: d.synchronizerId || env.synchronizerId });
  }
  const body = {
    commands: [{
      ExerciseCommand: {
        templateId: env.dvp.templateId, contractId: env.dvp.contractId, choice: 'AtomicDVP_Settle',
        choiceArgument: {
          // lpFees dari envelope pakai bentuk {instrumentAdmin, instrumentId:"Amulet"},
          // sedangkan Canton mau {instrumentId:{admin,id}} — kalau diteruskan apa adanya
          // ditolak "Unexpected fields: instrumentAdmin".
          quote: {
            ...q,
            lpFees: (q.lpFees || []).map(f => (f && f.instrumentAdmin)
              ? { receiver: f.receiver, instrumentId: { admin: f.instrumentAdmin, id: f.instrumentId }, amount: String(f.amount) }
              : f),
          },
          quoteSignature: env.quoteSignature,
          ticketCid: q.ticketId ? q.ticketId : null,
          lpInputHoldingCids: env.lpInputHoldingCids || [],
          // GABUNGAN holding token yg kita kirim + UTXO CC buat fee. Daml-nya ngambil
          // fee dari "pool" yg sama; kalau CC gak ikut → "no pool holdings for fee
          // instrument". Di capture UI userInputHoldingCids memang campuran keduanya.
          // Holding INSTRUMENT FEE wajib ikut, bukan cuma CC. Waktu fee dibayar USDCx
          // dan yg dikirim tetap CC, ledger nolak: "no pool holdings for fee instrument".
          userInputHoldingCids: [...userHoldings.slice(0, 8), ...(feeHoldCids.length ? feeHoldCids.slice(0, 4) : ccHoldings.slice(0, 4))],
          baseTransferFactoryCid: facOf(baseCtx.ctx), quoteTransferFactoryCid: facOf(quoteCtx.ctx),
          baseTransferArgs: baseArgs, baseAcceptArgs: baseArgs,      // identik (verified)
          quoteTransferArgs: quoteArgs, quoteAcceptArgs: quoteArgs,
          fees: fee0 ? [{ receiver: fee0.receiver, amount: String(fee0.amount), instrumentId: { admin: fee0.instrumentAdmin, id: fee0.instrumentId }, factoryCid: feeFactoryCid, extraArgs: feeExtraArgs, description: null }] : [],
        },
      },
    }],
    disclosedContracts: disclosed,
  };
  log(`AtomicDVP_Settle: ${disclosed.length} disclosed · fee ${feeCC} ${(fee0 && fee0.instrumentId && String(fee0.instrumentId).toUpperCase() !== 'AMULET') ? fee0.instrumentId : 'CC'}`);

  // 7. prepare → sign → submit.
  const prep = await canton.prepareTransaction(body);
  if (!prep || !prep.hash) throw new Error('prepare_transaction gagal (no hash)');
  const hashHex = b64HashToHex(prep.hash);
  const sigMaxTries = Math.max(1, (privy.walletCandidates && privy.walletCandidates.length) || 1) + 1;
  let sub = null;
  for (let i = 1; i <= sigMaxTries; i++) {
    const sig = await privy.rawSign(hashHex);
    try { sub = await canton.submitPrepared({ hash: prep.hash, signature: sigToB64(sig) }); if (ctx.onWalletPicked && privy.wallet) { try { ctx.onWalletPicked(privy.wallet.id); } catch (_) { } } break; }
    catch (e) {
      if (/bad signature/i.test((e && e.message) || '')) { const nx = privy.nextWallet(); if (nx) { log(`BAD SIGNATURE → rotasi wallet ${String(nx.id).slice(0, 8)}…`); continue; } }
      throw e;
    }
  }
  if (!sub || !sub.submissionId) throw new Error('submit_prepared gagal');
  for (let i = 0; i < SWAP.completionMaxTries; i++) {
    const c = await canton.queryCompletion(sub.submissionId).catch(() => null);
    if (c && c.status === 'completed') break;
    if (c && (c.status === 'failed' || c.status === 'rejected')) throw completionErr(c.status, c.message);
    await sleep(SWAP.completionPollMs);
  }
  return { ok: true, direction: side, quoteId: pick.quoteId, feeCC: Number.isFinite(feeCC) ? feeCC : null, settled: 1, dust: 0, dustEdelx: 0 };
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
  const feeCap = effFeeCap(ctx.maxFeeCC);

  // 1. Preconfirm terminal: submitPreconfirmation + recordEvent(preconfirmation_role,
  //    holdingsByToken {CC,token}) → LP/orderbook majuin proposal → dvpProposalCid.
  const meta = { accept: true, source: 'order_match' };
  try {
    const bal = await canton.balances();
    const toks = (bal && bal.tokens) || [];
    const holdings = {}, totals = {};
    const add = (tk, key) => { const utxos = (tk && tk.unlockedUtxos || []).map(u => ({ cid: u.contractId, amount: fmt10(String(u.amount)) })).filter(x => x.cid); if (utxos.length) { holdings[key] = utxos; totals[key] = utxos.reduce((s, u) => s + Number(u.amount), 0); } };
    add(toks.find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === 'AMULET'), 'CC');
    const myTok = toks.find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === String(legTokenId).toUpperCase());
    if (myTok) add(myTok, (myTok.instrumentId && myTok.instrumentId.id) || legTokenLabel);
    if (Object.keys(holdings).length) { meta.holdingsByToken = holdings; meta.totalByToken = totals; }
  } catch (_) { }
  // Hasil preconfirm DIPERIKSA. Dulu di-await tanpa cek: kalau ditolak (action ID stale /
  // proposal udah beda state), bot tetap lanjut polling dvpProposalCid sampai timeout dan
  // errornya nyasar jadi "LP tak preconfirm" — padahal KITA yg gagal preconfirm.
  const pre = await sv.submitPreconfirmation(proposalId, partyId, true).catch(e => ({ _err: (e && e.message) || String(e) }));
  if (pre && (pre._err || pre.success === false)) {
    log(`preconfirm ${role} DITOLAK: ${pre._err || pre.error || pre.message || JSON.stringify(pre).slice(0, 160)}`);
  }
  await sv.swapAction(A.recordEvent, [{ partyId, recordedByRole: role, eventType: `preconfirmation_${role}`, result: 'success', proposalId, metadata: meta }]).catch(() => { });

  // 2. Poll dvpProposalCid.
  //    NextAction (dari bundle): 1=preconfirm 2/5=pay_fee 3/4/8=sign_contract 6=allocate 7=WAIT.
  //    Kalau aksi KITA = WAIT, artinya sisi kita udah kelar dan tinggal nunggu counterparty
  //    ("Your side is done" di UI) — dana kita BELUM ke-lock, jadi nunggu itu GRATIS.
  //    Default 80s (40×2s) kependekan: terpantau live LP baru gerak >97s. Kalau kita
  //    nyerah duluan, ronde berikut malah nge-cancel proposal yg hampir jadi lalu ulang
  //    dari nol. Jadi: perpanjang tunggu HANYA saat giliran counterparty; kalau ternyata
  //    giliran KITA yg nyangkut, keluar cepat (itu bug sisi kita, bukan nunggu orang).
  const WAIT_ACTION = 7;
  const baseMs = SWAP.pollMaxTries * SWAP.pollIntervalMs;
  const maxMs = Math.max(baseMs, (Number(M8.waitCounterpartySec) || 300) * 1000);
  const tPoll = Date.now();
  let dvpCid = null, lastPoll = null, waitLogged = false;
  while (Date.now() - tPoll < maxMs) {
    const st = await sv.swapAction(A.pollProposal, [{ settlementId: proposalId, partyId }]).catch(e => ({ _err: e && e.message }));
    lastPoll = st;
    if (st && typeof st.dvpProposalCid === 'string' && st.dvpProposalCid.startsWith('00')) { dvpCid = st.dvpProposalCid; break; }
    // stage >= 9 tanpa dvpProposalCid = settlement-nya UDAH DITUTUP (terpantau live:
    // stage 13 + status SETTLEMENT_STATUS_CANCELLED). Gak akan ada DvpProposal lagi,
    // jadi nunggu sisa waktunya percuma — dulu tetap dijagain sampai 82s tiap percobaan.
    if (st && Number(st.stage) >= 9) break;
    if (Date.now() - tPoll > baseMs) {
      const mine = st ? (weAreBuyer ? st.buyerNextAction : st.sellerNextAction) : undefined;
      if (mine != null && mine !== WAIT_ACTION) break;   // giliran kita → jangan tunggu lama
      if (!waitLogged) { log(`sisi kita selesai — nunggu counterparty (maks ${Math.round(maxMs / 1000)}s)`); waitLogged = true; }
    }
    await sleep(SWAP.pollIntervalMs);
  }
  if (!dvpCid) {
    const mine = lastPoll ? (weAreBuyer ? lastPoll.buyerNextAction : lastPoll.sellerNextAction) : undefined;
    // Payload poll UTUH ke swap-debug.log — pesan error-nya kepotong 160 char, padahal
    // justru field di ekornya (status/stage/alasan) yg nerangin kenapa settlement mati.
    logDebug(`pollProposal timeout proposalId=${proposalId} stage=${lastPoll && lastPoll.stage} weAreBuyer=${weAreBuyer}`, lastPoll);
    // Sinyal "sisi kita udah kelar" TIDAK cukup diambil dari nextAction. Begitu settlement
    // ditutup, API balikin nextAction 0 buat KEDUA sisi (bukan 7=WAIT), jadi patokan lama
    // salah baca kasus ini sebagai "giliran kita" alias bug sisi kita. Yang bener dibaca
    // dari flag preconfirm: kita true & lawan false = lawan yg gak pernah gerak.
    const ourPre = lastPoll ? (weAreBuyer ? lastPoll.buyerPreconfirmed : lastPoll.sellerPreconfirmed) : undefined;
    const theirPre = lastPoll ? (weAreBuyer ? lastPoll.sellerPreconfirmed : lastPoll.buyerPreconfirmed) : undefined;
    const theirRej = lastPoll ? (weAreBuyer ? lastPoll.sellerRejected : lastPoll.buyerRejected) : undefined;
    const stalled = mine === WAIT_ACTION || (ourPre === true && theirPre === false);
    const why = theirRej ? ' — counterparty NOLAK'
      : stalled ? ` — sisi kita SELESAI (preconfirmed), counterparty gak pernah preconfirm${Number(lastPoll && lastPoll.stage) >= 9 ? `, settlement ditutup di stage ${lastPoll.stage}` : ''}`
        : '';
    const e = new Error(`dvpProposalCid timeout setelah ${Math.round((Date.now() - tPoll) / 1000)}s${why} (last=${JSON.stringify(lastPoll).slice(0, 200)})`);
    if (stalled) e.counterpartyStalled = true;   // bukan salah kita → jangan hitung hardErr
    throw e;
  }

  // 3. getMultiCall + DvpProposal ASLI dari ledger (terms verbatim).
  const multiCall = await getMultiCallCached(sv);
  if (!multiCall || !multiCall.contractId) throw new Error('getMultiCall gagal');
  let dvp = null, unburied = false, lastCount = 0;
  for (let i = 0; i < SWAP.pollMaxTries; i++) {
    const list = await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(() => []);
    lastCount = (list || []).length;
    const hit = (list || []).find(c => c.contractId === dvpCid);
    if (hit && hit.createArgument && hit.createArgument.terms) { const ca = hit.createArgument; dvp = { cid: dvpCid, terms: normDvpTerms(ca.terms), executor: ca.operator, proposer: ca.proposer, counterparty: ca.counterparty, proposerIsBuyer: ca.proposerIsBuyer }; break; }
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
    const bal = await canton.balances();
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
    if (q && (q.status === 'failed' || q.status === 'rejected')) throw completionErr(q.status, q.message);
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
  // Headless (pm2/nohup/`> log`) gak punya TTY → stdout.columns undefined → W jatuh ke
  // 44 dan SEMUA baris aktivitas kepotong "…", pesan error jadi gak kebaca di file log.
  // Hormati env COLUMNS/LINES dulu (COLUMNS=200 node index.js pingpong > log).
  const cols = process.stdout.columns || Number(process.env.COLUMNS) || 0, rows = process.stdout.rows || Number(process.env.LINES) || 0;
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
  const o = state.overcap;
  if (state.status === 'error') return ['● Error', COLOR.red];
  // Pas overcap, task penuh 10/10 BUKAN berarti kelar — patokannya target overcap.
  // Tanpa ini semua baris nampilin "Selesai" padahal masih nge-swap.
  if (o && Number(o.target) > 0 && Number(o.done) < Number(o.target)) return ['● Swap', COLOR.yellow];
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
  // Kolom OVERCAP cuma muncul kalau overcap emang lagi jalan — kolom SWAP mentok di
  // task earn-hub (10/10) jadi pas overcap progres sebenernya (mis. 22/50) gak keliatan
  // sama sekali. prio 0 = jangan didrop pas terminal sempit; percuma nyalain overcap
  // kalau angkanya justru ilang duluan.
  const overcapCols = (Array.isArray(states) && states.some(s => s && s.overcap && Number(s.overcap.target) > 0))
    ? [{
      title: 'OVERCAP', prio: 0, cap: 9, cell: s => {
        const o = s && s.overcap;
        if (!o || !(Number(o.target) > 0)) return ['-', COLOR.gray];
        return [`${o.done}/${o.target}`, Number(o.done) >= Number(o.target) ? COLOR.green : COLOR.cyan];
      }
    }]
    : [];
  const COLS = [
    { title: 'AKUN', prio: 0, cap: 16, align: 'l', cell: s => [truncVis(s.label || '-', 16), COLOR.bold] },
    { title: 'STATUS', prio: 1, cap: 10, cell: s => statusInfo(s) },
    { title: 'SWAP', prio: 0, cap: 7, cell: s => [s.dayTrader ? `${s.dayTrader.count}/${s.dayTrader.target}` : '-', s.dayTrader && s.dayTrader.count >= s.dayTrader.target ? COLOR.green : COLOR.white] },
    ...overcapCols,
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
    // Kolom fee token NON-CC cuma nongol kalau emang ada — biar layout lama gak
    // berubah buat akun yg fee-nya masih CC.
    ...((Array.isArray(states) && states.some(x => Number(x && x.feeTokSeason) > 0))
      ? [{ title: 'FEE-TOK', prio: 2, cap: 12, cell: s => [Number(s.feeTokSeason) > 0 ? `${fmtSeason(s.feeTokSeason)} ${s.feeTokUnit || ''}`.trim() : '-', Number(s.feeTokSeason) > 0 ? COLOR.cyan : COLOR.gray] }]
      : []),
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
  const seasonFeeTok = (states || []).reduce((n, x) => n + (Number(x && x.feeTokSeason) || 0), 0);
  const seasonFeeTokUnit = ((states || []).find(x => x && x.feeTokUnit) || {}).feeTokUnit || '';
  const seasonLoss = st.reduce((a, s) => a + (Number(s.spreadSeason) || 0), 0);
  return [
    sep(),
    row(paint('Season fee total ', COLOR.gray) + paint(fmtSeason(seasonFee) + ' CC', COLOR.bold + COLOR.mag)
      + (seasonFeeTok > 0 ? paint(' + ' + fmtSeason(seasonFeeTok) + ' ' + (seasonFeeTokUnit || ''), COLOR.bold + COLOR.cyan) : '')
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
// Satuan fee IKUT instrumentnya. Sejak fee bisa dibayar USDCx, menjumlahkan
// semuanya sebagai "CC" bikin angka season campur aduk dan gak ada artinya.
function feeUnitNow() { return (SWAP.feeTokens && SWAP.feeTokens[0]) || 'CC'; }
// Nama token fee di REQUEST beda sama instrumentId di HOLDINGS. Diukur live lewat
// requestQuotesV2: feeTokens ["TUSDT"] balik settlementFee dgn instrumentId
// "tf-usdt". Kalau dicari pakai "TUSDT" holdingnya gak ketemu dan swap ditolak
// dgn alasan yg salah. CC -> Amulet juga beda nama.
// Yg didukung server (diuji): CC, USDCx, TUSDT. USD8 & EDELx ditolak (gak ada quote).
const FEE_TOKEN_IDS = ['CC', 'USDCx', 'TUSDT', 'USD8'];
// USD8 kedaftar pakai UUID di registry, bukan simbolnya (kebaca dari settlementFee
// waktu feeTokens ["USD8"] dan dari utilityAcceptRefs market cETH-USD8). Kalau UUID
// ini berubah, cocokinnya jatuh ke simbol lewat fallback di holdFeeOf().
const FEE_TOKEN_INSTRUMENT = { CC: 'Amulet', AMULET: 'Amulet', USDCX: 'USDCx', TUSDT: 'tf-usdt', USD8: '8694894e-f159-42e1-80c9-ed14b94365b7' };
// Alias umum: nama token di market/menu -> instrumentId di holdings.
// Bukan cuma urusan fee — menu swap juga perlu, karena CC itu instrument "Amulet"
// dan TUSDT itu "tf-usdt". Nyari pakai nama menu bikin saldo kebaca 0 padahal ada.
function instrumentIdOf(tok) { return feeInstrumentOf(tok); }
function feeInstrumentOf(tok) {
  const k = String(tok || 'CC').toUpperCase();
  return FEE_TOKEN_INSTRUMENT[k] || String(tok);
}
function recordBurn(feeAmt, label, unit) {
  const f = Number(feeAmt);
  if (!Number.isFinite(f) || f <= 0) return;
  const u = unit || feeUnitNow();
  BURN_EVENTS.push({ ts: Date.now(), feeCC: f, unit: u, label: String(label || '') });
  if (BURN_EVENTS.length > BURN_EVENTS_MAX) BURN_EVENTS.splice(0, BURN_EVENTS.length - BURN_EVENTS_MAX);
  logActivity(`[${label || 'swap'}] fee ${f.toFixed(4)} ${u} kebakar`, COLOR.yellow);
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
  const spreadToday = (same ? Number(s.spreadToday) || 0 : 0) + (Number(spreadUsd) || 0);
  const spreadSeason = (Number(s.spreadSeason) || 0) + (Number(spreadUsd) || 0);
  // Fee CC tetap di feeToday/feeSeason (kompatibel sama data lama). Fee token lain
  // masuk ember terpisah feeTokToday/feeTokSeason + feeTokUnit, jadi angkanya gak
  // ketimbun jadi satu dengan CC.
  const unit = (arguments.length > 3 && arguments[3]) ? String(arguments[3]) : 'CC';
  const amt = Number(feeCC) || 0;
  const isCC = String(unit).toUpperCase() === 'CC' || String(unit).toUpperCase() === 'AMULET';
  const feeToday = (same ? Number(s.feeToday) || 0 : 0) + (isCC ? amt : 0);
  const feeSeason = (Number(s.feeSeason) || 0) + (isCC ? amt : 0);
  const sameUnit = String(s.feeTokUnit || unit) === String(unit);
  const feeTokToday = (same && sameUnit ? Number(s.feeTokToday) || 0 : 0) + (isCC ? 0 : amt);
  const feeTokSeason = (sameUnit ? Number(s.feeTokSeason) || 0 : 0) + (isCC ? 0 : amt);
  const patch = { statDate: today, feeToday, spreadToday, feeSeason, spreadSeason, feeTokToday, feeTokSeason };
  if (!isCC) patch.feeTokUnit = unit;
  patchAcctSession(email, patch);
  return { feeToday, spreadToday, feeSeason, spreadSeason, feeTokToday, feeTokSeason, feeTokUnit: isCC ? (s.feeTokUnit || null) : unit };
}
// Wrapper: persist + update state buat dashboard live.
function bumpDaily(state, feeCC, spreadUsd, unit) {
  if (!state || !state.email) return;
  const r = persistDaily(state.email, feeCC, spreadUsd, unit || feeUnitNow());
  state.feeToday = r.feeToday; state.spreadToday = r.spreadToday;
  state.feeSeason = r.feeSeason; state.spreadSeason = r.spreadSeason; state.statDate = todayStr();
  state.feeTokToday = r.feeTokToday; state.feeTokSeason = r.feeTokSeason; state.feeTokUnit = r.feeTokUnit;
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
    try { const bal = await balancesFor(state.email, token, proxy); state.balances = (bal && bal.tokens) || []; } catch (_) { }
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
async function tickAll(states) {
  // Hormatin only= juga di sini. Tanpa ini, `only=5` tetap nge-login SEMUA akun pas
  // startup — dan satu akun yg tokennya expired bikin seluruh proses nunggu prompt OTP,
  // jadi kelihatan nge-hang padahal cuma satu akun yg bermasalah.
  const pilih = ONLY_ACCOUNTS ? states.filter((_, i) => ONLY_ACCOUNTS.includes(i)) : states;
  await mapLimit(pilih, ACCT_CONCURRENCY, s => tickAccount(s));
}

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
let dtSessionStartMs = 0;

// Gerbang masuk sesi — balik false berarti "lewati". Dulu cek-nya cuma
// `if (dtSessionRunning) return`, dan itu bikin satu kegagalan jadi permanen:
// kalau ada akun nyangkut, mapLimit gak pernah resolve → `finally` gak jalan →
// flag true SELAMANYA. Akibatnya cron harian dilewati terus DAN tickAll ikut
// ke-gate, jadi dashboard beku nampilin angka kemarin (kejadian 27/07: sesi
// mulai, senyap 5 jam, cron 07:00 WIB cuma nulis "Sesi masih berjalan").
// Sekarang flag yg lebih tua dari sessionMaxHours dianggap basi dan dipaksa lepas.
function claimSession(reason) {
  if (dtSessionRunning) {
    const ageMs = dtSessionStartMs ? Date.now() - dtSessionStartMs : 0;
    const capMs = Math.max(1, Number(SWAP.sessionMaxHours) || 8) * 3600000;
    if (!(dtSessionStartMs && ageMs > capMs)) {
      logActivity(`Sesi masih berjalan ${Math.round(ageMs / 60000)} mnt, lewati (${reason || ''})`, COLOR.gray);
      return false;
    }
    logActivity(`Sesi sebelumnya nyangkut ${Math.round(ageMs / 60000)} mnt (> ${Math.round(capMs / 3600000)} jam) — flag dipaksa lepas, lanjut (${reason || ''})`, COLOR.yellow);
  }
  dtSessionRunning = true;
  dtSessionStartMs = Date.now();
  return true;
}

// Jalanin kerjaan satu akun dengan batas waktu. Promise-nya gak bisa dibatalin —
// yg nyangkut tetap nyangkut di background — tapi mapLimit lanjut, jadi sesi tetap
// kelar dan flag sesi kelepas. Itu bedanya antara "satu akun gagal" dan "bot mati".
function withAccountDeadline(fn, label) {
  const capMs = Math.max(0, Number(SWAP.accountMaxMin) || 0) * 60000;
  if (!capMs) return fn();
  // JANGAN unref timer ini. Kalau di-unref dan kebetulan gak ada handle lain yg
  // idup, Node keluar sebelum timernya nyala — deadline-nya jadi gak pernah kejadian.
  // Timernya di-clearTimeout begitu fn beres, jadi gak nahan proses lebih lama.
  let t = null;
  const guard = new Promise((res) => {
    t = setTimeout(() => { logActivity(`[${label}] nyangkut > ${Math.round(capMs / 60000)} mnt — dilepas, sesi lanjut tanpa akun ini`, COLOR.red); res(null); }, capMs);
  });
  return Promise.race([Promise.resolve().then(fn).finally(() => { if (t) clearTimeout(t); }), guard]);
}

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
    return { label: a.label || `akun-${i + 1}`, email: a.email, privyEmail: a.privyEmail || null, status: 'idle', message: '', balances: null, dayTrader: null, overcap: null, points: null, pointsDiff: d.pointsDiff, volume: null, activity: null, streak: null, log: [], feeToday: d.feeToday, spreadToday: d.spreadToday, feeSeason: d.feeSeason, spreadSeason: d.spreadSeason, statDate: d.statDate };
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
  // Akun kunci-mentah: token Privy (Bearer) TETAP dibutuhin buat auth API canton
  // (prepare/submit), tapi `pat` (buat TEE raw_sign) TIDAK — sign-nya lokal.
  const rawCantonKey = loadRawKey(email);
  if (!pat && !rawCantonKey) throw new Error('privy_access_token tidak ada di session');
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
  // Akun kunci-mentah: lewati pemilihan wallet TEE, pakai key lokal.
  const preferredWalletId = acctSession(email).privyWalletId || null;
  const privy = new PrivyWallet({ accessToken: pat, timeoutMs: REQ.timeoutMs, proxy, preferredWalletId, partyId, rawCantonKey });
  await privy.authenticate();
  if (rawCantonKey) logActivity(`[${state.label || email}] mode kunci-mentah (pub ${rawCantonKey.pub.slice(0, 12)}…) — sign lokal, bukan Privy TEE`, COLOR.cyan);

  // Auto-cache walletId yg terpilih biar konsisten across runs. (Skip mode kunci-mentah:
  // 'raw-ed25519' bukan Privy walletId asli, jangan dicache.)
  if (!rawCantonKey && privy.wallet && privy.wallet.id && privy.wallet.id !== preferredWalletId) {
    patchAcctSession(email, { privyWalletId: privy.wallet.id });
    if (privy.walletCandidates.length > 1) {
      logActivity(`[${state.label || email}] Privy multi-wallet (${privy.walletCandidates.length}) → pakai ${privy.wallet.id.slice(0, 8)}…`, COLOR.gray);
    }
  }

  // Token LIVE (fungsi baca session terbaru) — JANGAN string statis. Kalau token
  // refresh/expired mid-sesi, string statis bikin canton 401 → active_contracts
  // []→ "DvpProposal lookup failed activeCount:0" walau /swap (pakai sv.bearer
  // live) masih jalan. Samain sumber token dgn sv.bearer.
  const cantonSupa = new CantonClient({ token: () => { try { return acctSession(email).privy.token || identityToken; } catch (_) { return identityToken; } }, timeoutMs: REQ.timeoutMs, proxy, tag: state.label || email });

  // Pilihan wallet per akun (session.json[email].wallet). Default Supanova supaya
  // akun lama gak berubah perilaku sama sekali. Kalau 'walley', SEMUA operasi Canton
  // (prepare/submit/ACS/saldo) pindah ke API Walley dan tanda tangan jadi LOKAL
  // pakai seed — Privy TEE gak dipakai sama sekali.
  const wsel = acctSession(email).wallet || null;
  if (wsel && wsel.kind === 'walley') {
    const w = loadWalleyWallets().find(x => x.party_id === wsel.partyId || x.party_hint === wsel.partyHint);
    if (!w) throw new Error(`wallet Walley '${wsel.partyHint || wsel.partyId}' gak ketemu di ${WALLEY_WALLETS_PATH}`);
    const canton = new WalleyCantonClient({ wallet: w, timeoutMs: REQ.timeoutMs, proxy, tag: state.label || email });
    // Shim penanda tangan: bentuknya niru PrivyWallet supaya jalur swap gak berubah.
    // rawSign gak kepake buat Walley (amplopnya ditandatangani di submitPrepared),
    // tapi tetap disediain karena beberapa jalur manggilnya.
    const signer = {
      wallet: null, walletCandidates: [],
      async authenticate() { return true; },
      async rawSign(hashHex) { const { key } = walleyKeyFromSeed(w.seed_hex); return crypto.sign(null, Buffer.from(String(hashHex).replace(/^0x/, ''), 'hex'), key).toString('hex'); },
      nextWallet() { return null; },
    };
    return { sv, privy: signer, canton, partyId: w.party_id, identityToken, proxy, walletKind: 'walley', walley: w };
  }
  return { sv, privy, canton: cantonSupa, partyId, identityToken, proxy, walletKind: 'supanova' };
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
  const proposals = await sv.listSettlementProposals(partyId).catch(() => []);
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

// Kirim CC (Amulet) ke party lain. Dipakai subcommand `transfer` DAN menu interaktif
// opsi t — sengaja satu fungsi biar validasinya gak kembar lalu beda diam-diam.
//
// CUMA CC. Konteks factory Amulet berdiri sendiri (getTransferFactoryContextAction
// balikin factoryId + choiceContextData + disclosed sekaligus). EDELx/cETH lewat
// Utility registry yg butuh cid `transfer-rule`, dan satu-satunya sumber cid itu di
// kode ini adalah env.utilityAcceptRefs — isi envelope RFQ, cuma ada DI TENGAH swap.
// Transfer berdiri sendiri buat token itu gak bisa diturunkan tanpa capture UI
// transfer beneran. Jangan dikarang.
//
// go=false (default) = DRY-RUN: nampilin rencana, gak ngirim apa-apa.
// Kirim token ke party lain lewat endpoint transfer WALLET Supanova.
//
// Ini jalur yg dipakai app.supanova.app sendiri (bukan Silvana — Silvana itu platform
// trading, gak punya wallet sama sekali). Endpointnya di luar /canton/api/, makanya
// probe awal 404 terus:
//   POST /canton/transfers/prepare_transfer  {receiverPartyId, amount, instrumentId,
//                                             instrumentAdmin?, memo?}  -> {hash,...}
//   GET  /canton/transfers/calculate_transfer_fee?partyId=&instrumentId=&instrumentAdmin=
// Server yg ngerakit command + bayar fee-nya, kita tinggal tanda tangan hash-nya lalu
// submit_prepared. Jauh lebih simpel dari rakit MultiCall sendiri — dan karena
// instrumentId bebas, token selain CC ikut kelayan.
//
// go=false (default) = DRY-RUN: nampilin rencana + fee, gak ngirim apa-apa.
async function transferToken({ idx, tokenArg, amountArg, toArg, go = false, out = null }) {
  const P = out || ((m, c) => process.stdout.write(paint(m + '\n', c || COLOR.gray)));
  const bad = (m) => { throw new Error(m); };
  const a = ACCOUNTS[idx];
  if (!a) bad(`akun idx ${idx} gak ada. Lihat: node index.js balance all`);
  if (!toArg) bad('tujuan kosong. Isi partyId (hint::sidikjari) atau #N / label akun sendiri');

  // Resolusi tujuan. `#N` atau label/email akun sendiri -> partyId dari session.json
  // (transfer internal). Selain itu dianggap partyId mentah, bentuknya divalidasi.
  let receiver = String(toArg), receiverNote = 'EKSTERNAL';
  const byIdx = receiver.startsWith('#') ? Number(receiver.slice(1)) : NaN;
  const byLabel = ACCOUNTS.findIndex(x => (x.label || '') === receiver || x.email === receiver);
  const internalIdx = Number.isFinite(byIdx) ? byIdx : (byLabel >= 0 ? byLabel : -1);
  if (internalIdx >= 0) {
    const tgt = ACCOUNTS[internalIdx];
    if (!tgt) bad(`akun tujuan idx ${internalIdx} gak ada`);
    const pid = (acctSession(tgt.email) || {}).partyId;
    if (!pid) bad(`akun ${tgt.label || tgt.email} belum punya partyId di session.json — login dulu`);
    receiver = pid; receiverNote = `INTERNAL (${tgt.label || tgt.email})`;
  }
  if (!/^[^:]+::[0-9a-f]{16,}$/i.test(receiver)) bad(`partyId tujuan bentuknya gak wajar: ${receiver}\nHarusnya 'hint::sidikjari-hex'.`);

  const state = makeStates()[idx];
  const { privy, canton, partyId } = await buildSwapClients(state);
  if (receiver === partyId) bad('tujuan sama dengan pengirim — dibatalkan');
  const tokenRaw = String(tokenArg || 'CC');
  const wantId = /^(cc|amulet)$/i.test(tokenRaw) ? 'Amulet' : tokenRaw;
  const idTok = state.identityToken || canton.token;
  const proxy = getProxy(a.email);

  const bal = await balancesFor(state.email, idTok, proxy);
  const tok = ((bal && bal.tokens) || []).find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === wantId.toUpperCase());
  if (!tok) bad(`instrument '${tokenRaw}' gak ada di balances. Lihat: node index.js balance ${idx}`);
  const instrumentId = tok.instrumentId.id, instrumentAdmin = tok.instrumentId.admin;
  const utxos = (tok.unlockedUtxos || []).filter(u => u.contractId);
  const unlocked = utxos.reduce((s, u) => s + (Number(u.amount) || 0), 0);

  // Fee transfer ditanya duluan supaya `max` bisa dihitung dan rencananya jujur.
  let feeCC = null;
  {
    const qs = `partyId=${encodeURIComponent(partyId)}&instrumentId=${encodeURIComponent(instrumentId)}&instrumentAdmin=${encodeURIComponent(instrumentAdmin)}`;
    const r = await request('GET', `${SUPA_ROOT}/canton/transfers/calculate_transfer_fee?${qs}`, { headers: supaHeaders(idTok), timeoutMs: REQ.timeoutMs, proxy });
    // Field-nya `supaFee` / `amuletTransferFee` (dua-duanya 16 waktu diukur live), BUKAN
    // feeCC/fee/amount. Fee-nya FLAT 16 CC — sama buat CC, EDELx, maupun cETH.
    if (r.status === 200 && r.json) feeCC = Number(r.json.supaFee ?? r.json.amuletTransferFee ?? r.json.feeCC ?? r.json.fee);
  }

  // `max` / `all` = kirim seluruh saldo unlocked instrument ini. Buat CC, fee kepotong
  // dari saldo yg sama jadi disisain; token lain fee-nya tetap dibayar pakai CC.
  let amt;
  if (/^(max|all|full|semua)$/i.test(String(amountArg))) {
    // Fee dibayar pakai CC. Kalau yg dikirim CC juga, fee HARUS disisain dari saldo yg
    // sama — kalau nggak, "max" bikin saldo kurang buat bayar fee-nya sendiri.
    const reserve = (instrumentId === 'Amulet' && Number.isFinite(feeCC)) ? feeCC : 0;
    const floorTo = (n, dp) => Math.floor(Math.max(0, n) * 10 ** dp) / 10 ** dp;
    amt = floorTo(unlocked - reserve, instrumentId === 'cETH' ? 8 : 6);
    if (!(amt > 0)) bad(`saldo ${instrumentId} gak cukup buat dikirim (unlocked ${unlocked}, sisain fee ${reserve})`);
  } else {
    amt = Number(amountArg);
    if (!Number.isFinite(amt) || amt <= 0) bad(`jumlah '${amountArg}' gak valid`);
  }
  if (amt > unlocked) bad(`jumlah ${amt} ${instrumentId} > saldo unlocked ${unlocked.toFixed(10)}`);

  P(`\n▎ TRANSFER ${go ? '[LIVE]' : '[DRY-RUN]'}`, COLOR.bold + (go ? COLOR.red : COLOR.cyan));
  P(`  dari    : ${a.label || a.email}`);
  P(`  party   : ${partyId}`);
  P(`  ke      : ${receiver}`);
  P(`  sifat   : ${receiverNote}`, receiverNote === 'EKSTERNAL' ? COLOR.yellow : COLOR.gray);
  P(`  token   : ${instrumentId}`);
  P(`  jumlah  : ${fmt10(String(amt))}  (unlocked ${unlocked.toFixed(6)} dari ${utxos.length} UTXO)`);
  P(`  fee     : ${Number.isFinite(feeCC) ? feeCC + ' CC' : '(server gak kasih angka)'}`);
  if (!go) { P('  dry-run — belum ada yg dikirim (CLI: tambah `go` di akhir · menu: lanjut ke konfirmasi)', COLOR.cyan); return { dryRun: true, receiver, amount: amt, instrumentId, feeCC, unlocked }; }

  const body = { receiverPartyId: receiver, amount: fmt10(String(amt)), instrumentId, instrumentAdmin };
  const r = await request('POST', `${SUPA_ROOT}/canton/transfers/prepare_transfer`, { headers: { ...supaHeaders(idTok), 'Content-Type': 'application/json' }, body: JSON.stringify(body), timeoutMs: REQ.timeoutMs, proxy });
  if (r.status !== 200 && r.status !== 201) {
    logDebug('prepare_transfer REQUEST', body);
    logDebug(`prepare_transfer RESPONSE status=${r.status}`, r.text);
    bad(`prepare_transfer status=${r.status} body=${(r.text || '').slice(0, 300)}`);
  }
  const prep = r.json || {};
  if (!prep.hash) bad(`prepare_transfer gak balikin hash: ${JSON.stringify(prep).slice(0, 250)}`);

  const hashHex = b64HashToHex(prep.hash);
  let sub = null;
  const tries = Math.max(1, (privy.walletCandidates && privy.walletCandidates.length) || 1) + 1;
  for (let st = 1; st <= tries; st++) {
    const sigRaw = await privy.rawSign(hashHex);
    try { sub = await canton.submitPrepared({ hash: prep.hash, signature: sigToB64(sigRaw) }); break; }
    catch (e) { if (/bad signature/i.test((e && e.message) || '')) { const nxt = privy.nextWallet(); if (nxt) continue; } throw e; }
  }
  if (!sub || !sub.submissionId) bad('submit_prepared gagal');
  for (let i = 0; i < SWAP.completionMaxTries; i++) {
    const c = await canton.queryCompletion(sub.submissionId).catch(() => null);
    if (c && c.status === 'completed') { P(`\n✓ terkirim — ${fmt10(String(amt))} ${instrumentId} → ${receiver.slice(0, 28)}…`, COLOR.green); return { ok: true, receiver, amount: amt, instrumentId, submissionId: sub.submissionId }; }
    if (c && (c.status === 'failed' || c.status === 'rejected')) throw completionErr(c.status, c.message);
    await sleep(SWAP.completionPollMs);
  }
  P('\n⚠ submit OK tapi completion belum kebaca — cek saldo manual.', COLOR.yellow);
  return { ok: null, receiver, amount: amt, instrumentId, submissionId: sub.submissionId };
}
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
    const b = await balancesFor(state.email, token, proxy);
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
    for (let _pb = 0; _pb <= proxyTryMax(); _pb++) {
      try { clients = await buildSwapClients(state); break; }
      catch (e) {
        if ((isProxyErr(e) || isIpBlockErr(e)) && PROXIES.length > 1 && _pb < proxyTryMax()) {
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
    // Progres overcap buat kolom OVERCAP (engine daytrader). Alasannya sama kayak mode 8:
    // kolom SWAP mentok di target task, jadi swap ke-11 dst gak keliatan progresnya.
    state.overcap = (SWAP.allowOvercap && dailyCap > apiCap) ? { done: startApi, target: effective } : null;
    const bumpOvercap = () => { if (state.overcap) state.overcap.done = startApi + done; };
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
          // Reset harian (07:00 WIB) lewat di tengah nunggu: count balik ke 0 sedangkan
          // baseCount masih angka kemarin → syarat "count > baseCount" mustahil kepenuhi
          // selamanya. Tanpa ini loop-nya abadi walau settle-nya sendiri sukses.
          if (realDt && realDt.current < baseCount) {
            logActivity(`[${tag}] task ke-reset harian (${baseCount}→${realDt.current}) — sync distop, lanjut`, COLOR.yellow);
            break;
          }
          if (MAX_WAIT_MS && Date.now() - tStart > MAX_WAIT_MS) {                    // cap waktu (settleWaitMaxMin)
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
          trafficRelax();
          if (res.feeCC) { recordBurn(res.feeCC, tag); bumpDaily(state, res.feeCC, 0); }
          const realDt = await handleSuccess(label);
          if (realDt && realDt.current > beforeApi) {
            done = Math.max(done + 1, realDt.current - startApi);
            bumpOvercap();
            stuck = 0;
            lowFeeStreak = 0;
            logActivity(`[${tag}] ✓ confirmed on-chain (DAY_TRADER ${realDt.current}/${realDt.target})`, COLOR.green);
          } else if (SWAP.allowOvercap && realDt && realDt.current >= realDt.target) {
            // Sudah lewat batas API DAY_TRADER. Counter pakai settle on-chain
            // (res.ok = settlement settled by waitForSettlement). Verifikasi
            // DAY_TRADER tetap di-log walau gak naik.
            done++;
            bumpOvercap();
            trafficRelax();
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
        // Rate-limit sequencer: jatah traffic member (node Supanova) abis, dan embernya
        // dipakai BARENGAN semua akun → gate global, bukan backoff per akun.
        if (e && e.trafficLimit) {
          const s = trafficPenalize();
          logActivity(`[${tag}] traffic credit node abis — tahan ${s}s (gate global, semua akun)`, COLOR.yellow);
          await waitTrafficGate(tag);
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
                  done++; bumpOvercap(); stuck = 0; lowFeeStreak = 0;
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
  if (!claimSession(reason)) return;
  const conc = Math.max(1, Number(SWAP.concurrency) || 1);
  const lbl = (i) => (ACCOUNTS[i] && (ACCOUNTS[i].label || ACCOUNTS[i].email)) || `akun ${i}`;
  logActivity(`Mulai cek & auto-swap (${reason || 'manual'})${parallelSwapActive ? ` [parallel x${conc}]` : ''}`, COLOR.cyan);
  try {
    if (parallelSwapActive) {
      await mapLimit(sessionAccountIdxs(), conc, (i) => withAccountDeadline(() => runAccountSwapSession(i), lbl(i)));
    } else {
      for (const i of sessionAccountIdxs()) await withAccountDeadline(() => runAccountSwapSession(i), lbl(i));
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
  for (let pb = 0; pb <= proxyTryMax(); pb++) {
    try { clients = await buildSwapClients(state); break; }
    catch (e) {
      if ((isProxyErr(e) || isIpBlockErr(e)) && PROXIES.length > 1 && pb < proxyTryMax()) { const np = rotateProxy(state.email); log(`[${tag}] proxy error login → rotate ${np ? np.host + ':' + np.port : '-'}`, COLOR.yellow); }
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
        // Rate-limit sequencer (ember traffic dipake bareng semua akun) → gate global.
        if (e && e.trafficLimit) { const s = trafficPenalize(); log(`[${tag}] traffic credit node abis — tahan ${s}s (gate global)`, COLOR.yellow); await waitTrafficGate(tag); outcome = 'retry'; break; }
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
    for (let pb = 0; pb <= proxyTryMax(); pb++) {
      try { clients = await buildSwapClients(state); break; }
      catch (e) { if ((isProxyErr(e) || isIpBlockErr(e)) && PROXIES.length > 1 && pb < proxyTryMax()) { const np = rotateProxy(state.email); logActivity(`[${tag}] proxy error login → rotate ${np ? np.host + ':' + np.port : '-'}`, COLOR.yellow); } else throw e; }
    }
    let { sv, partyId, identityToken, proxy } = clients;
    state.status = 'ok';
    let userServiceCid = getUserServiceCid(state.email);
    if (!userServiceCid) { try { const p = await sv.recoverParty(partyId); if (p && p.userServiceCid) { userServiceCid = p.userServiceCid; patchAcctSession(state.email, { userServiceCid }); } } catch (_) { } }
    await ensureActionIds(sv, partyId, tag);

    // Target dari earn-hub task ${P8.market} (analog DAY_TRADER).
    let tinfo = await fetchEdelCethTrader(sv, partyId).catch(() => ({ dt: null, all: '' }));
    logActivity(`[${tag}] earn-hub tasks: ${tinfo.all || '(kosong)'}`, COLOR.gray);
    let dt = tinfo.dt;
    if (!dt) { logActivity(`[${tag}] task ${P8.market} Daily Trader tak terbaca — set config swap.edelCethTaskCode (lihat list di atas). Skip.`, COLOR.yellow); return; }
    state.dayTrader = { count: dt.current, target: dt.target }; render(global.__states);
    // allowOvercap (kayak opsi 0/1): false → stop pas task penuh (10/10). true → lanjut
    // sampai dailyCap TOTAL swap sesi (task capped 10, jadi pakai counter `swaps` lokal).
    const overcap = M8.allowOvercap;
    const startCount = Number(dt.current) || 0;
    const dailyCap = M8.dailyCap;
    if (overcap ? (startCount >= dailyCap) : (dt.current >= dt.target)) { logActivity(`[${tag}] ${P8.market} ${dt.current}/${dt.target}${overcap ? ` (overcap cap ${dailyCap})` : ''} sudah penuh ✓`, COLOR.green); return; }
    logActivity(`[${tag}] ${P8.market} ${dt.current}/${dt.target} (task ${dt.code})${overcap ? ` — overcap → target ${dailyCap} swap` : ''} — mulai ping-pong`, COLOR.cyan);

    let swaps = 0;
    // Progres overcap buat kolom OVERCAP di dashboard. Kolom SWAP mentok di task
    // earn-hub (10/10), jadi tanpa ini progres sebenernya gak keliatan sama sekali.
    state.overcap = overcap ? { done: startCount, target: dailyCap } : null;
    const bumpOvercap = () => { if (state.overcap) { state.overcap.done = startCount + swaps; } };
    // Target tercapai: overcap → total swap sesi (startCount+swaps) ≥ dailyCap; else → task penuh.
    const targetReached = () => overcap ? (startCount + swaps >= dailyCap) : (dt && dt.current >= dt.target);
    let priceChecks = 0;  // counter cek-harga → tiap M8.cleanupEveryChecks: drain DvpProposal stale (kayak opsi 5)
    let proxyFails = 0;   // proxy error beruntun: retry 2x proxy sama, ke-3 rotate
    let hardErrs = 0;     // error tak-terklasifikasi beruntun → backoff naik (retry infinite, JANGAN stop)
    let noLiqStreak = 0;  // noLiquidity beruntun → backoff naik. TANPA ini bot nembak submitOrder
                          // tiap ~4s non-stop: spam log, banjirin server, dan bisa MICU rate-limit
                          // yg justru bikin submitOrder ditolak (spiral makin gagal).
    // RETRY INFINITE: gak ada cap ronde/waktu. Pas LP outage bot terus nyoba (proposal
    // timeout → retry ronde berikut) sampai target penuh / dust / CC habis. JANGAN berhenti
    // & nunggu jadwal besok. Target di-refresh tiap ronde (bisa reset 07:00 saat sesi jalan).
    while (true) {
      try { const fr = await ensureFreshClients(state, clients); if (fr !== clients) { clients = fr; ({ sv, partyId, identityToken, proxy } = clients); } } catch (_) { }
      await ensureActionIds(sv, partyId, tag);
      try { const ti = await fetchEdelCethTrader(sv, partyId); if (ti && ti.dt) { dt = ti.dt; state.dayTrader = { count: dt.current, target: dt.target }; } } catch (_) { }
      if (targetReached()) { logActivity(`[${tag}] ${P8.market} ${dt.current}/${dt.target}${overcap ? ` (overcap ${startCount + swaps}/${dailyCap})` : ''} ✓ — berhenti`, COLOR.green); break; }

      // populate state.balances (SWAP.tokenId apapun; kita baca EDELx/cETH/CC manual).
      SWAP.tokenId = P8.baseId;
      await refreshBalances(state, identityToken, proxy).catch(() => 0);
      const edelx = unlockedOf(state, P8.baseId);
      const ceth = unlockedOf(state, P8.quoteId);
      const cc = ccUnlockedFrom(state);
      // Reserve dijaga pada instrument yg BENERAN dipakai bayar fee. Kalau feeTokens
      // di-set (mis. USDCx), CC nol itu WAJAR dan gak boleh bikin berhenti — dulu
      // guard ini selalu nuntut CC jadi akun ber-fee-USDCx mati sebelum swap pertama.
      const feeTok = (SWAP.feeTokens && SWAP.feeTokens[0]) || null;
      if (feeTok) {
        const feeBal = unlockedOf(state, feeInstrumentOf(feeTok).toUpperCase());
        // Ambang buat token fee: pakai minFeeTokenReserve kalau ada, kalau nggak
        // cukup "lebih dari nol" — fee USDCx per swap cuma ~0.15.
        const feeMin = Number(SWAP.minFeeTokenReserve) || 0;
        if (!(feeBal > feeMin)) { logActivity(`[${tag}] ${feeTok} ${floor6(feeBal)} habis (buat fee) — stop, top-up ${feeTok}`, COLOR.red); break; }
      } else if (cc < reserve) {
        logActivity(`[${tag}] CC ${floor6(cc)} < reserve ${reserve} (fee reversal) — stop, top-up CC`, COLOR.red); break;
      }

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
        pe = await sv.getPrice(`${P8.base}-USDCx`).catch(() => null);
        pc = await sv.getPrice(`${P8.quote}-USDCx`).catch(() => null);
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
        // LANTAI DUST != minUsd. Minimum order RFQ itu $10 (ditolak server di bawah
        // itu), sedangkan minUsd cuma ukuran yg DIINGINKAN. Dulu gerbangnya pakai
        // minUsd 10.5, jadi akun bersaldo $10.1-$10.4 dinyatakan dust dan sesi
        // berhenti 0 swap padahal swap segitu sah. Karena saldo menyusut tiap ronde
        // (loss + fee), akun makin lama pasti mendarat di celah itu dan mandek.
        // Margin: haircut max-dump (0.5%) + 0.2% buat gerak harga.
        const rfqMin = Math.max(0, Number(M8.rfqMinUsd) || 10);
        const dustFloor = rfqMin * (1 + (Number(M8.haircut) || 0) + 0.002);
        if (valC > dustFloor) {
          // cETH → EDELx (buy), dump SEMUA cETH. Order dibayar cETH di bestAsk×(1+orderCross).
          // Size di harga ORDER dari ORDERBOOK (bukan cross-rate USD: feed itu meleset ~3.6%,
          // bikin qty overshoot → "Insufficient cETH" → retry −1% tiap swap). Book gagal →
          // fallback cross-rate USD (terminalSwapOnce tetap nge-cap pakai maxDeliverCeth).
          deliver = P8.quote;
          const bkA = await sv.orderbookDepth(P8.market, { lpOnly: M8.bookLpOnly !== false, depth: 20 }).catch(() => null);
          const askPx = (bkA && bkA.bestAsk) || 0;   // cETH per EDELx
          edelxQty = askPx > 0
            ? floor6(ceth / (askPx * (1 + M8.orderCross)))
            : floor6((ceth * usdPerCeth) / usdPerEdelx / (1 + M8.orderCross));
          deliveredUsd = valC;
          isMaxDump = true;   // dump penuh cETH → pre-reduce haircut buffer
          logActivity(`[${tag}] deliver cETH MAX ${floor6(ceth)} (~$${valC.toFixed(2)}) → ${edelxQty} EDELx`, COLOR.gray);
        } else if (valE > dustFloor) {
          // EDELx → cETH (sell), sebesar usdAmount (atau max EDELx kalau worth < usdAmount).
          deliver = P8.base;
          // TIER FEE: di bawah ~$10 settlement fee 3x lebih mahal. Diukur live pada
          // EDELx-cETH: $9.5 kena 19.97 CC / 1.8 USDCx / 0.9 TUSDT, sedangkan $10.5
          // cuma 6.66 / 0.6 / 0.3. Jadi swap kecil itu mahal BUKAN karena persentase,
          // tapi karena jatuh ke tier mahal. Naikkan ke ambang kalau saldo cukup.
          const tierMin = Math.max(0, Number(M8.feeTierMinUsd) || 0);
          let swapUsd = Math.min(valE, usdAmount);
          if (tierMin > 0 && swapUsd < tierMin) {
            if (valE >= tierMin) { logActivity(`[${tag}] $${swapUsd.toFixed(2)} di bawah tier fee murah ($${tierMin}) → dinaikin ke $${tierMin.toFixed(2)}`, COLOR.yellow); swapUsd = tierMin; }
            else logActivity(`[${tag}] cuma punya $${valE.toFixed(2)} — di bawah tier $${tierMin}, fee bakal ~3x lebih mahal`, COLOR.yellow);
          }
          edelxQty = floor6(swapUsd / usdPerEdelx);
          deliveredUsd = swapUsd;
          isMaxDump = swapUsd >= valE - 1e-9;   // haircut cuma kalau dump SEMUA EDELx (bukan leg fixed-$)
          logActivity(`[${tag}] deliver EDELx $${swapUsd.toFixed(2)} → ${edelxQty} EDELx @ $${usdPerEdelx.toFixed(6)}`, COLOR.gray);
        } else {
          logActivity(`[${tag}] modal kurang — EDELx $${valE.toFixed(2)} & cETH $${valC.toFixed(2)}, dua-duanya di bawah minimum order $${dustFloor.toFixed(2)} → stop, top-up`, COLOR.yellow);
          break;
        }
      }
      if (!(edelxQty > 0)) { await sleep(3000); continue; }

      // NET GATE round-trip (req #1: cari profit / allowed-loss) — anchor EDELx, SIANG aja.
      // BUKA posisi (EDELx→cETH) = bebas (catat modal pas sukses). TUTUP (cETH→EDELx, dump SEMUA cETH)
      // DI-GATE: EDELx yg diterima balik harus ≥ modal + minNetUsd. minNetUsd NEGATIF = allowed-loss,
      // POSITIF = cari profit, 0 = break-even, null = gate mati. MALAM (night) → dilewati (trabas).
      if (!night && M8.minNetUsd != null && String(deliver).toUpperCase() === P8.quoteId) {
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
      const recvId = String(deliver).toUpperCase() === P8.baseId ? P8.quoteId : P8.baseId; // token yg bakal DITERIMA (settle → kredit ke unlocked)
      const recvBefore = unlockedOf(state, recvId);
      // Deliver side (buat ukur qty yg BENERAN keluar wallet — dust yg di-cancel gak kehitung).
      const deliverId = String(deliver).toUpperCase() === P8.baseId ? P8.baseId : P8.quoteId;
      const deliverBefore = unlockedOf(state, deliverId);
      const deliverPriceUsd = String(deliver).toUpperCase() === P8.baseId ? usdPerEdelx : usdPerCeth;
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
        // Mepet reset & target belum penuh → pindah ke jalur RFQ (/swap). CLOB kadang
        // match tapi counterparty gak nyelesaiin settlement; RFQ di-quote langsung sama
        // LP, terbukti tetap jalan pas CLOB mandek total, fee juga lebih murah.
        const useRfq = mode8ShouldUseRfq();
        logActivity(`[${tag}] ping-pong #${swaps + 1}: ${direction} ${deliver}→${String(deliver).toUpperCase() === P8.baseId ? P8.quote : P8.base} (${q} ${P8.base}${adj ? ` adj#${adj}` : ''})${useRfq ? ` [RFQ — sisa ${hoursUntilDailyReset()}j ke reset]` : ''}`, COLOR.cyan);
        try {
          const swapCtx = { ...clients, email: state.email, label: tag, userServiceCid, leg, maxFeeCC: night ? Infinity : M8.maxFeeCC, minUsd, usdPerEdelx, maxDeliverCeth: (String(deliver).toUpperCase() === P8.quoteId ? ceth : 0), log: (m) => logActivity(`[${tag}] ${m}`, COLOR.gray), onWalletPicked: (id) => { try { patchAcctSession(state.email, { privyWalletId: id }); } catch (_) { } } };
          // RFQ pakai qty BASE yg sama (EDELx) + ctx.leg yg sama → aman buat token↔token.
          const res = useRfq
            ? await swapOnceAtomic(swapCtx, direction, q)
            : await terminalSwapOnce(swapCtx, direction, q);
          if (res && res.ok) { swaps++; bumpOvercap(); proxyFails = 0; hardErrs = 0; noLiqStreak = 0; trafficRelax(); lastDustEdelx = Number(res.dustEdelx) || 0; if (res.feeCC) { recordBurn(res.feeCC, tag); bumpDaily(state, res.feeCC, 0); } logActivity(`[${tag}] ✓ ping-pong #${swaps} sukses (fee ${res.feeCC != null ? res.feeCC + ' ' + ((SWAP.feeTokens && SWAP.feeTokens[0]) || 'CC') : '?'})`, COLOR.green); outcome = 'ok'; }
          else { logActivity(`[${tag}] ping-pong gagal (no ok) — retry`, COLOR.yellow); await sleep(4000); outcome = 'retry'; }
          break;
        } catch (e) {
          // Server-side "Insufficient <tok> balance. Need X, available Y": local pre-check
          // (pakai estimate ourLeg.amount) lolos saat need≈available, tapi cost LP aktual >
          // estimate → settle nolak. Normalisasi → insufficientBalance biar reduce-retry jalan.
          if (e && !e.insufficientBalance) {
            const em = (e && e.message) || '';
            const nm = em.match(/Need\s*([0-9.]+)[\s,]+available\s*([0-9.]+)/i);
            // "input holdings do not cover leg amount" itu bentuk Daml dari kekurangan
            // saldo — tanpa pola ini dia jatuh ke hardErrs dan qty gak pernah dikecilin.
            if (nm || /Insufficient\s+\w+\s+balance/i.test(em) || /input holdings do not cover leg amount/i.test(em)) {
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
          if (e && e.noLiquidity) {
            // Tampilkan ALASAN ASLI — noLiquidity punya 3 sumber yg dulu kelihatan sama
            // persis di log: (a) "submitOrder: <alasan server>" = order DITOLAK (cepat, <5s),
            // (b) "book … kosong" = bestBid/bestAsk 0, (c) "order gak match" = udah nunggu
            // orderWaitSec penuh. Tanpa detail ini gak ketahuan mana yg kejadian.
            noLiqStreak++;
            const w = Math.min(180, 10 * noLiqStreak);
            logActivity(`[${tag}] likuiditas ${leg.market} ${direction} belum ada: ${shortSwapReason(e)} — retry #${noLiqStreak} (tunggu ${w}s)`, COLOR.gray);
            await sleep(w * 1000);
            outcome = 'retry'; break;
          }
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
          // Jatah traffic node abis — ember dipake BARENGAN semua akun. Tahan lewat gate
          // global (semua akun ikut berhenti nembak), JANGAN rebuild client / rescan
          // action-id: sesi & action-id-nya sehat, cuma sequencer yg lagi nolak.
          if (e && e.trafficLimit) {
            const s = trafficPenalize();
            logActivity(`[${tag}] traffic credit node abis — tahan ${s}s (gate global, semua akun)`, COLOR.yellow);
            await waitTrafficGate(tag); outcome = 'retry'; break;
          }
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
          logActivity(`[${tag}] Sync ${P8.market}… (cek ${r + 1}, tunggu ${Math.round(w / 1000)}s, sampai settle+saldo)`, COLOR.gray);
          await sleep(w);
          try { const fr = await ensureFreshClients(state, clients); if (fr !== clients) { clients = fr; ({ sv, partyId, identityToken, proxy } = clients); } } catch (_) { }
          const chk = await fetchEdelCethTrader(sv, partyId).catch(() => ({ dt: null }));
          if (chk.dt) { dt = chk.dt; state.dayTrader = { count: dt.current, target: dt.target }; }
          SWAP.tokenId = P8.baseId; await refreshBalances(state, identityToken, proxy).catch(() => 0);
          render(global.__states);
          const recvNow = unlockedOf(state, recvId);
          if (chk.dt && chk.dt.current > countBefore) countUp = true;
          if (recvNow > recvBefore + Math.max(recvBefore * 0.25, 1e-7)) recvOk = true; // token recv udah kebayar
          if (countUp && recvOk) { logActivity(`[${tag}] ✓ confirmed (${P8.market} ${dt.current}/${dt.target}, ${recvId === P8.quoteId ? P8.quote : P8.base} ${floor6(recvNow)} kebayar)`, COLOR.green); break; }
          if (chk.dt && chk.dt.current >= chk.dt.target && recvOk) break;        // target penuh & saldo masuk
          // Reset harian lewat pas nunggu → count jatuh ke 0, countBefore masih angka
          // kemarin, jadi countUp gak akan pernah true lagi. Ini persis yg bikin sesi
          // 27/07 nyangkut. Keluar, biarin ronde berikutnya baca angka yg udah reset.
          if (chk.dt && chk.dt.current < countBefore) {
            logActivity(`[${tag}] task ke-reset harian (${countBefore}→${chk.dt.current}) — sync distop, lanjut`, COLOR.yellow);
            break;
          }
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
        if (String(deliver).toUpperCase() === P8.baseId) {
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
        if (targetReached()) { logActivity(`[${tag}] ${P8.market} ${dt.current}/${dt.target}${overcap ? ` (overcap ${startCount + swaps}/${dailyCap})` : ''} ✓ — berhenti`, COLOR.green); break; }
        const delay = SWAP.postSwapDelayMinSec + Math.random() * Math.max(0, SWAP.postSwapDelayMaxSec - SWAP.postSwapDelayMinSec);
        await sleep(Math.max(3, delay) * 1000);
      } else {
        await sleep(SWAP.delayBetweenSwapsSec * 1000);
      }
    }
    SWAP.tokenId = P8.baseId;
    const fe = unlockedOf(state, P8.baseId), fc = unlockedOf(state, P8.quoteId);
    logActivity(`[${tag}] ping-pong selesai: ${swaps} swap, sisa EDELx ${floor6(fe)} / cETH ${floor6(fc)}`, swaps ? COLOR.green : COLOR.yellow);
  } catch (e) {
    state.status = 'error'; state.message = shortSwapReason(e);
    logActivity(`[${tag}] ping-pong akun gagal: ${(e && e.message) || e}`, COLOR.red);
  }
}
async function runEdelCethSession(reason) {
  if (!claimSession(reason)) return;
  const conc = Math.max(1, Number(SWAP.concurrency) || 1);
  const lbl = (i) => (ACCOUNTS[i] && (ACCOUNTS[i].label || ACCOUNTS[i].email)) || `akun ${i}`;
  logActivity(`Mulai ping-pong EDELx↔cETH (${reason || 'manual'})${parallelSwapActive ? ` [parallel x${conc}]` : ''}`, COLOR.cyan);
  try {
    const idxs = sessionAccountIdxs();
    if (parallelSwapActive) await mapLimit(idxs, conc, (i) => withAccountDeadline(() => runEdelCethAccount(i), lbl(i)));
    else for (const i of idxs) await withAccountDeadline(() => runEdelCethAccount(i), lbl(i));
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
// Warna per token biar kolom gampang dibedain, dan angka NOL diredupkan supaya
// yang berisi langsung kelihatan. Sebelumnya semua hijau — layar penuh angka
// hijau yang sama bikin susah nyari mana yang beneran ada isinya.
function _balCell(b, fmtFn, color) {
  if (!b) return paint('-', COLOR.gray);
  const zero = !(Number(b.unlocked) > 1e-8);
  const u = paint(fmtFn(b.unlocked), zero ? COLOR.gray : (color || COLOR.green));
  const l = b.locked > 1e-8 ? paint('+' + fmtFn(b.locked), COLOR.yellow) : '';
  return u + l;
}
function renderBalanceTable(states, intervalMin, okCount, logBuf) {
  computeLayout(); clearScreen();
  // Satu baris per WALLET (supa + walley), bukan per akun — biar dana di kedua
  // party kelihatan sekaligus. Potongan partyId ikut biar gampang dicocokin waktu
  // nyiapin kiriman bulk.
  // Potongan lama ngambil 10 char PERTAMA fingerprint — semua party mulai "1220…"
  // jadi kelihatan mirip semua dan gak ada gunanya. Sekarang: hint (yg emang beda
  // tiap wallet, mis. walley-bebek) + ekor fingerprint biar tetap unik.
  const shortPid = (pid) => {
    if (!pid) return '';
    const [hint, fp] = String(pid).split('::');
    return `${String(hint || '?').slice(0, 16)}…${String(fp || '').slice(-6)}`;
  };
  const cellsOf = (toks) => {
    const fake = { balances: toks || [] };
    return {
      cc: _balCell(balanceOf(fake, 'amulet'), fmtCC, COLOR.mag), usdcx: _balCell(balanceOf(fake, 'usdcx'), fmtUSDC, COLOR.cyan),
      ceth: _balCell(balanceOf(fake, 'ceth'), fmtCeth, COLOR.yellow), edelx: _balCell(balanceOf(fake, 'edelx'), fmtEdelx, COLOR.green),
    };
  };
  const rows = [];
  for (const s of states) {
    const nm = s.label || s.email;
    const aktif = ((acctSession(s.email) || {}).wallet || {}).kind || 'supanova';
    if (s._balErr) { rows.push({ label: nm, wallet: paint('err', COLOR.red), pid: '', cc: paint('err', COLOR.red), usdcx: '', ceth: '', edelx: '' }); continue; }
    if (s._balSupa) rows.push({ label: nm, wallet: paint('supa' + (aktif === 'supanova' ? '*' : ' '), aktif === 'supanova' ? COLOR.cyan : COLOR.gray), pid: paint(shortPid(s._pidSupa), COLOR.gray), ...cellsOf(s._balSupa) });
    if (s._balWalley) rows.push({ label: s._balSupa ? '' : nm, wallet: paint('walley' + (aktif === 'walley' ? '*' : ' '), aktif === 'walley' ? COLOR.cyan : COLOR.gray), pid: paint(shortPid(s._pidWalley), COLOR.gray), ...cellsOf(s._balWalley) });
  }
  const tot = { cc: { u: 0, l: 0 }, usdcx: { u: 0, l: 0 }, ceth: { u: 0, l: 0 }, edelx: { u: 0, l: 0 } };
  for (const s of states) {
    if (s._balErr) continue;
    for (const toks of [s._balSupa, s._balWalley]) {
      if (!toks) continue;
      const fake = { balances: toks };
      const cc = balanceOf(fake, 'amulet'), ux = balanceOf(fake, 'usdcx'), ce = balanceOf(fake, 'ceth'), ed = balanceOf(fake, 'edelx');
      tot.cc.u += cc.unlocked; tot.cc.l += cc.locked; tot.usdcx.u += ux.unlocked; tot.usdcx.l += ux.locked; tot.ceth.u += ce.unlocked; tot.ceth.l += ce.locked; tot.edelx.u += ed.unlocked; tot.edelx.l += ed.locked;
    }
  }
  const totalRow = { label: `TOTAL (${okCount}/${states.length})`, wallet: '', pid: '', cc: _balCell({ unlocked: tot.cc.u, locked: tot.cc.l }, fmtCC, COLOR.mag), usdcx: _balCell({ unlocked: tot.usdcx.u, locked: tot.usdcx.l }, fmtUSDC, COLOR.cyan), ceth: _balCell({ unlocked: tot.ceth.u, locked: tot.ceth.l }, fmtCeth, COLOR.yellow), edelx: _balCell({ unlocked: tot.edelx.u, locked: tot.edelx.l }, fmtEdelx, COLOR.green) };
  const head = { label: 'AKUN', wallet: 'WALLET', pid: 'PARTY', cc: 'CC', usdcx: 'USDCx', ceth: 'cETH', edelx: 'EDELx' };
  const all = [head, ...rows, totalRow];
  const wl = Math.max(...all.map(r => visLen(r.label)));
  const ww = Math.max(...all.map(r => visLen(r.wallet || '')));
  const wp = Math.max(...all.map(r => visLen(r.pid || '')));
  const wc = Math.max(...all.map(r => visLen(r.cc)));
  const wu = Math.max(...all.map(r => visLen(r.usdcx)));
  const we = Math.max(...all.map(r => visLen(r.ceth)));
  const wd = Math.max(...all.map(r => visLen(r.edelx)));
  const GAP = '  ';
  const mkRow = (r, style) => {
    const body = pad(r.label, wl, 'right') + GAP + pad(r.wallet || '', ww, 'right') + GAP + pad(r.pid || '', wp, 'right') + GAP + pad(r.cc, wc, 'left') + GAP + pad(r.usdcx, wu, 'left') + GAP + pad(r.ceth, we, 'left') + GAP + pad(r.edelx, wd, 'left');
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
        // Ambil KEDUA wallet, jangan cuma yg aktif — kalau nggak, akun yg udah pindah
        // ke Walley kelihatan nol padahal dananya masih di party Supanova.
        const bs = await supaBalances(token, proxy).catch(() => null);
        s._balSupa = (bs && bs.tokens) || null;
        s._pidSupa = (acctSession(s.email) || {}).partyId || null;
        s._balWalley = null; s._pidWalley = null;
        const wsel = (acctSession(s.email) || {}).wallet;
        if (wsel && wsel.partyId) {
          const w = loadWalleyWallets().find(x => x.party_id === wsel.partyId || x.party_hint === wsel.partyHint);
          if (w) {
            s._pidWalley = w.party_id;
            const bw = await new WalleyCantonClient({ wallet: w, proxy }).balances().catch(() => null);
            s._balWalley = (bw && bw.tokens) || null;
          }
        }
        s.balances = s._balSupa || [];
        s._balErr = (!s._balSupa && !s._balWalley) ? 'gagal baca saldo' : null;
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
    // Progres overcap ikut dikirim — kolom SWAP mentok di target task, jadi tanpa ini
    // dashboard web sama butanya kayak dashboard terminal sebelum ada kolom OVERCAP.
    overcap: s.overcap ? { done: Number(s.overcap.done) || 0, target: Number(s.overcap.target) || 0 } : null,
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

  // Dulu tickAll ke-gate TOTAL sama dtSessionRunning, jadi selagi sesi jalan angka
  // task gak pernah dibaca ulang. Pas sesi nyangkut, dashboard beku nampilin angka
  // kemarin — kelihatan "10/10 selesai" padahal task-nya udah reset berjam-jam lalu.
  // Sekarang tetap disegarkan tiap tickWhileSessionMin walau sesi aktif.
  let lastTickMs = Date.now();
  while (true) {
    await sleep(REFRESH_SEC * 1000);
    if (!dtSessionRunning) { await tickAll(states); lastTickMs = Date.now(); continue; }
    render(states);
    const gap = Math.max(0, Number(SWAP.tickWhileSessionMin) || 0) * 60000;
    if (gap && Date.now() - lastTickMs > gap) { lastTickMs = Date.now(); await tickAll(states).catch(() => { }); }
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

async function runPaste(file) {
  // `node index.js paste <file.json>` — buat hasil tombol "Download .json" di ekstensi
  // (tinggal scp ke VPS), gak usah nempel manual. Tanpa argumen = tempel seperti biasa.
  if (file) {
    let obj;
    try { obj = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (e) { console.error(paint(`gagal baca ${file}: ${(e && e.message) || e}`, COLOR.red)); process.exit(1); }
    if (!obj || !obj.email || !obj.silvanaPasskey) { console.error(paint('JSON butuh email + silvanaPasskey', COLOR.red)); process.exit(1); }
    const total = saveAccountPasskey(obj);
    process.stdout.write(paint(`✓ passkey → session.json, akun ${obj.email} → accounts.json (total ${total})`, COLOR.green) + '\n');
    process.exit(0);
  }
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
  process.stdout.write(paint('CARA GAMPANG (disarankan): pakai ekstensi di folder extension/\n', COLOR.green));
  process.stdout.write(paint('  chrome://extensions → Developer mode → Load unpacked → pilih folder extension/\n', COLOR.gray));
  process.stdout.write(paint('  Buka app.silvana.one (sudah login) → klik ikon ekstensi → "Daftarkan Passkey" → "Copy JSON"\n', COLOR.gray));
  process.stdout.write(paint('  Lalu di sini: node index.js paste   (atau: node index.js paste hasil.json)\n', COLOR.gray));
  process.stdout.write('\n' + paint('CARA MANUAL (fallback, tanpa ekstensi):', COLOR.yellow) + '\n');
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
// buildSwapClients/SWAP/transferCC ikut diekspor biar bisa diprobe dari skrip luar
// tanpa nyalain bot (require aman: runMain kegate `require.main === module`).
module.exports = { balancesFor, instrumentIdOf, render, makeStates, logActivity, computeLayout, runDayTraderSession, parseDayTrader, ensurePrivyToken, supaMe, supaBalances, getProxy, patchAcctSession, ACCOUNTS, M8, SWAP, buildSwapClients, transferToken, pickList, nowHourInTz, mode8IsNight, getEdelCethRoundUsd, setEdelCethRoundUsd };

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
  node index.js cleanup [idx|all]  reject proposal nyangkut yg 0 dana kelock (default akun 0)
  node index.js cancel-order <orderId> [idx]   batalin order terminal yg masih nyantol di orderbook (TiF GTC)
  node index.js pingpong [overcap N]      mode 8 via CLOB /terminal, SEMUA akun (headless/pm2)
  node index.js pingpong-rfq [overcap N]  mode 8 via RFQ /swap AtomicDVP (fee ~1.24 CC, anti-CLOB-macet)
                              overcap N = lanjut swap walau task 10/10 penuh, sampai N swap/akun
  node index.js tif-probe [idx] [GTD|GTC] [ttlSec]  cek server hormatin expiresAt (order jauh dari book, 0 CC)
  node index.js acct-diag [idx]   diagnosa 1 akun (read-only, tanpa OTP): auth/me, KYC, earn-hub task
  node index.js register  cara daftar passkey baru (pakai ekstensi di extension/, atau script Console)
  node index.js paste [file.json]  simpan JSON passkey → session.json (tanpa arg = tempel manual)
  node index.js balance [idx|all]  saldo unlocked+locked semua instrument per akun (read-only)
  node index.js transfer <idx> <token> <jumlah|max> <tujuan> [go]   kirim token ke party lain
                              token  = CC / EDELx / cETH / dll (lihat: balance <idx>)
                              jumlah = angka, atau 'max' buat kirim semua (CC disisain buat fee)
                              tujuan = partyId (hint::sidikjari) ATAU #N / label akun sendiri
                              TANPA go = dry-run (cuma nampilin rencana + fee, gak ngirim)
  node index.js walley [n]   cek wallet Walley (auth + holding) — read-only
  node index.js wallets   list Privy wallets per akun + tandai mana yg cached/match partyId
  node index.js pin <id>  pin privyWalletId ke session.json (utk akun pertama)
  node index.js help      tampilkan bantuan
`);
    process.exit(0);
  }
  if (argv[0] === 'balance') {
    // `node index.js balance [idx|all]` — READ-ONLY. Dashboard cuma nampilin CC/cETH/EDELx;
    // ini nampilin SEMUA instrument apa adanya dari /canton/api/balances, plus jumlah UTXO
    // (fragmentasi holding itu yg bikin transfer/fee kadang nolak) dan porsi yg ke-lock.
    (async () => {
      const arg = String(argv[1] || 'all');
      const idxs = arg === 'all' ? ACCOUNTS.map((_, i) => i) : [Number(arg) || 0];
      for (const i of idxs) {
        const a = ACCOUNTS[i];
        if (!a) { console.error(paint(`akun idx ${i} gak ada`, COLOR.red)); continue; }
        const state = makeStates()[i];
        let bal = null, partyId = '?';
        try {
          const idTok = await ensurePrivyToken(state);
          // supaMe balik {status, data} — partyId-nya di .data, bukan di level atas.
          partyId = ((await supaMe(idTok, getProxy(a.email))).data || {}).partyId || '?';
          bal = await balancesFor(a.email, idTok, getProxy(a.email));
        } catch (e) {
          process.stdout.write(paint(`▎ ${a.label || a.email} — GAGAL: ${(e && e.message) || e}\n`, COLOR.red));
          continue;
        }
        process.stdout.write('\n' + paint(`▎ ${a.label || a.email}`, COLOR.bold + COLOR.cyan)
          + paint(`  party ${String(partyId).slice(0, 28)}…\n`, COLOR.gray));
        const toks = (bal && bal.tokens) || [];
        if (!toks.length) { process.stdout.write(paint('  (tidak ada instrument)\n', COLOR.gray)); continue; }
        process.stdout.write(paint('  INSTRUMENT   UNLOCKED            LOCKED           UTXO  ADMIN\n', COLOR.gray));
        for (const t of toks) {
          const id = (t.instrumentId && t.instrumentId.id) || '?';
          const admin = (t.instrumentId && t.instrumentId.admin) || '?';
          const un = (t.unlockedUtxos || []).reduce((s, u) => s + (Number(u.amount) || 0), 0);
          const lo = (t.lockedUtxos || []).reduce((s, u) => s + (Number(u.amount) || 0), 0);
          const nUn = (t.unlockedUtxos || []).length, nLo = (t.lockedUtxos || []).length;
          process.stdout.write('  ' + String(id).padEnd(12)
            + paint(un.toFixed(10).padEnd(20), COLOR.green)
            + paint((lo > 0 ? lo.toFixed(10) : '-').padEnd(17), lo > 0 ? COLOR.yellow : COLOR.gray)
            + paint(String(nUn + (nLo ? '+' + nLo : '')).padEnd(6), COLOR.gray)
            + paint(String(admin).slice(0, 26) + '…', COLOR.gray) + '\n');
        }
      }
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'transfer') {
    // `node index.js transfer <idx> CC <jumlah> <tujuan> [go]`
    // Inti kerjanya ada di transferToken() — dipakai bareng sama menu interaktif (opsi t).
    // Token bebas (CC/EDELx/cETH/…), jumlah boleh `max` buat kirim semua.
    (async () => {
      const die = (m) => { console.error(paint(m, COLOR.red)); process.exit(1); };
      try {
        await transferToken({ idx: Number(argv[1]), tokenArg: String(argv[2] || 'CC'), amountArg: String(argv[3] || ''), toArg: String(argv[4] || ''), go: argv.includes('go') });
        process.exit(0);
      } catch (e) { die(((e && e.message) || String(e))); }
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'walley') {
    // `node index.js walley [n]` — READ-ONLY. Cek klien Walley: auth challenge/verify
    // pakai kunci lokal, lalu baca holding tiap party. Dipakai buat mastiin lapisan
    // Walley jalan sebelum apa pun disambungin ke Silvana.
    (async () => {
      const ws = loadWalleyWallets();
      if (!ws.length) { console.error(paint(`wallets.jsonl gak kebaca di ${WALLEY_WALLETS_PATH}\n(atur lewat env WALLEY_WALLETS)`, COLOR.red)); process.exit(1); }
      const n = Math.max(1, Math.min(ws.length, Number(argv[1]) || 5));
      process.stdout.write(paint(`\n${ws.length} wallet Walley di ${WALLEY_WALLETS_PATH}\ncek ${n} pertama:\n`, COLOR.cyan));
      let ok = 0, kosong = 0;
      for (const w of ws.slice(0, n)) {
        try {
          const bal = await walleyHoldings(w);
          const ids = Object.keys(bal);
          const ringkas = ids.length
            ? ids.map(k => `${k}=${bal[k].unlocked}${bal[k].locked ? '+' + bal[k].locked + ' lock' : ''}`).join(' · ')
            : paint('(kosong — belum ada holding)', COLOR.yellow);
          if (!ids.length) kosong++;
          ok++;
          process.stdout.write('  ' + paint(String(w.party_hint || '-').padEnd(24), COLOR.bold)
            + paint(String(w.party_id).slice(0, 26) + '…  ', COLOR.gray) + ringkas + '\n');
        } catch (e) {
          process.stdout.write('  ' + paint(String(w.party_hint || '-').padEnd(24), COLOR.bold)
            + paint('GAGAL: ' + ((e && e.message) || e), COLOR.red) + '\n');
        }
      }
      process.stdout.write(paint(`\n${ok}/${n} party kebaca · ${kosong} masih kosong (butuh CC sebelum bisa dipakai)\n`, COLOR.cyan));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'walley-onboard') {
    // `node index.js walley-onboard <akunIdx> <hint|partyId> [go]`
    // Bikin UserServiceRequest on-chain buat party Walley, biar Silvana ngenalin dia
    // sebagai party yg udah onboard. Perintahnya PERSIS yg dipakai web Silvana:
    //   {tag:'Op_CreateUserServiceRequest', value:{operator: SILVANA_OPERATOR}}
    // dibungkus Execute_MultiCall (satu command — Canton cuma nerima satu).
    // Transaksinya lewat API Walley: /v1/transactions/prepare → tanda tangan lokal
    // → /v1/transactions/submit-and-wait. Tanpa `go` cuma nampilin rencana.
    (async () => {
      const die = (m) => { console.error(paint(m, COLOR.red)); process.exit(1); };
      const idx = Number(argv[1]);
      const who = String(argv[2] || '');
      const go = argv.includes('go');
      const a = ACCOUNTS[idx];
      if (!a) die(`akun idx ${argv[1]} gak ada`);
      const ws = loadWalleyWallets();
      const w = ws.find(x => x.party_id === who || x.party_hint === who || String(x.party_id).startsWith(who));
      if (!w) die(`wallet Walley '${who}' gak ketemu di ${WALLEY_WALLETS_PATH}`);
      const P = (m, c) => process.stdout.write(paint(m + '\n', c || COLOR.gray));

      const token = await walleyToken(w);
      const holds = await walleyAmuletCids(w);
      P(`\n▎ WALLEY ONBOARD ${go ? '[LIVE]' : '[DRY-RUN]'}`, COLOR.bold + (go ? COLOR.red : COLOR.cyan));
      P(`  akun    : ${a.label || a.email}`);
      P(`  party   : ${w.party_id}`);
      P(`  CC      : ${holds.total} dari ${holds.cids.length} UTXO unlocked`);

      // MultiCall config diambil dari Silvana (butuh sesi akun ini).
      const state = makeStates()[idx];
      const { sv } = await buildSwapClients(state);

      // Tautkan party ke akun Silvana kalau belum. Jalur UI: POST /api/wallets {partyId}.
      // Idempotent: kalau udah ada di daftar, dilewati.
      const linked = await sv.listWallets().catch(() => []);
      if (linked.some(x => x.partyId === w.party_id)) {
        P(`  wallet  : udah ke-link di Silvana (${(linked.find(x => x.partyId === w.party_id) || {}).name || '-'})`, COLOR.green);
      } else if (!go) {
        P(`  wallet  : BELUM ke-link — bakal di-POST /api/wallets pas dijalanin pakai go`, COLOR.yellow);
      } else {
        const lr = await sv.linkWallet(w.party_id);
        P(`  wallet  : link → ${lr.status} ${JSON.stringify(lr.body).slice(0, 140)}`, lr.ok ? COLOR.green : COLOR.red);
        if (!lr.ok) die('penautan wallet gagal — lihat pesan di atas (409 = party udah nempel di akun lain)');
      }
      const mc = await getMultiCallCached(sv);
      if (!mc || !mc.contractId) die('getMulticallConfigAction gagal');
      // Guard CC ditaruh SETELAH link: penautan wallet sama sekali gak butuh CC,
      // jadi jangan diblokir cuma karena party-nya masih kosong.
      if (!holds.cids.length) die('party Walley gak punya UTXO CC unlocked — isi CC dulu, inputHoldings MultiCall butuh minimal 1 UTXO');
      P(`  multicall: ${String(mc.templateId).slice(0, 46)}…`);

      // templateId Silvana "pkg:Module:Entity" → bentuk terpisah yg diminta Walley.
      const [pkgId, moduleName, entityName] = String(mc.templateId).split(':');
      const command = {
        act_as: [w.party_id],
        command_id: `walley-onboard-${Date.now()}`,
        commands: [{
          type: 'Exercise',
          template_id: { package_id: pkgId, module_name: moduleName, entity_name: entityName },
          contract_id: mc.contractId,
          choice: 'Execute_MultiCall',
          choice_argument: {
            sender: w.party_id,
            inputHoldings: holds.cids,
            operations: [{ tag: 'Op_CreateUserServiceRequest', value: { operator: SILVANA_OPERATOR } }],
          },
        }],
        // template_id di disclosed_contracts juga bentuk TERPISAH, bukan string
        // "pkg:Module:Entity" — kirim string bikin body ditolak sebelum sempat
        // divalidasi isinya ("Failed to deserialize the JSON body").
        disclosed_contracts: mc.blob ? [{
          contract_id: mc.contractId,
          created_event_blob: mc.blob,
          template_id: { package_id: pkgId, module_name: moduleName, entity_name: entityName },
          synchronizer_id: mc.synchronizerId,
        }] : [],
      };
      // Idempotent: kalau UserService-nya udah ada, langsung ke tahap daftarin aja.
      const sudah = await walleyUserServiceCid(w).catch(() => null);
      if (sudah) {
        P(`  UserService udah ada on-chain (${String(sudah).slice(0, 20)}…) — lewati pembuatan`, COLOR.green);
        if (!go) { P('\n  dry-run — tambah `go` buat daftarin ke Silvana.', COLOR.cyan); process.exit(0); }
        await finishOnboard(sv, w, a);
        process.exit(0);
      }
      if (!go) { P('\n  dry-run — belum ada yg dikirim. Tambah `go` buat eksekusi.', COLOR.cyan); process.exit(0); }

      const prep = await walleyReq('POST', '/v1/transactions/prepare', { body: { commands: command, fee_payer: w.party_id }, token });
      if (!prep || !prep.transaction) die(`prepare gagal: ${JSON.stringify(prep).slice(0, 250)}`);
      P(`  fee     : ${prep.fee_amount != null ? prep.fee_amount : '?'}`);
      const signed = walleySignPrepared(w, prep.transaction);
      const signedFee = prep.fee_transaction ? walleySignPrepared(w, prep.fee_transaction) : null;
      const body = { party_id: w.party_id, transaction: signed, token: prep.token };
      if (signedFee) body.fee_transaction = signedFee;
      const res = await walleyReq('POST', '/v1/transactions/submit-and-wait', { body, token });
      P(`\n✓ submit OK — ${JSON.stringify(res).slice(0, 180)}`, COLOR.green);

      await finishOnboard(sv, w, a);
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'wallets') {
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
    runPaste(argv[1] || null).catch(e => { console.error(paint('FATAL: ' + e.message, COLOR.red)); process.exit(1); });
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
      // Sizing SAMA kayak mode 8: BUY = dump SEMUA cETH di harga ORDER dari ORDERBOOK
      // (÷1+orderCross); SELL = min(valE, usdAmount). Biar test faithful (reproduksi dump-all).
      const bk = await sv.orderbookDepth(leg.market, { lpOnly: M8.bookLpOnly !== false, depth: 20 }).catch(() => null);
      const askPx = (bk && bk.bestAsk) || 0;
      const edelxQty = side === 'buy'
        ? (askPx > 0
          ? Math.floor((ceth / (askPx * (1 + M8.orderCross))) * 1e6) / 1e6
          : Math.floor(((ceth * usdPerCeth) / (usdPerEdelx || 1) / (1 + M8.orderCross)) * 1e6) / 1e6)
        : Math.floor((Math.min(valE, M8.usdAmount) / (usdPerEdelx || 1)) * 1e6) / 1e6;
      process.stdout.write(paint(`saldo EDELx ${edelx.toFixed(2)} ($${valE.toFixed(2)}) cETH ${ceth.toFixed(6)} ($${valC.toFixed(2)}) CC ${cc.toFixed(2)}\n`, COLOR.gray));
      // Bandingin book (yg bisa match) vs feed cross-rate (yg dulu dipakai & bikin gagal).
      if (bk) {
        const refFeed = usdPerCeth > 0 ? usdPerEdelx / usdPerCeth : 0;
        const basePx = side === 'buy' ? bk.bestAsk : bk.bestBid;
        const px = tickPrice(basePx * (side === 'buy' ? 1 + M8.orderCross : 1 - M8.orderCross), side === 'buy');
        process.stdout.write(paint(`book ${M8.bookLpOnly !== false ? 'lpOnly' : 'ALL'}: bid ${bk.bestBid.toFixed(10)} (${bk.bids.length} lvl) | ask ${bk.bestAsk.toFixed(10)} (${bk.asks.length} lvl)\n`, COLOR.gray));
        process.stdout.write(paint(`feed cross-rate (LAMA, salah): ${refFeed.toFixed(10)} → selisih vs bestBid ${(refFeed && bk.bestBid ? ((refFeed / bk.bestBid - 1) * 100).toFixed(2) : '?')}%\n`, COLOR.yellow));
        process.stdout.write(paint(`harga order ${side.toUpperCase()} (BARU, dari book): ${px} cETH — TiF ${M8.orderTif}\n`, COLOR.green));
      } else {
        process.stdout.write(paint(`book gak kebaca — terminalSwapOnce bakal noLiquidity\n`, COLOR.red));
      }
      // `rfq` = paksa jalur /swap (RFQ) alih-alih CLOB — buat nguji fallback rfqFallbackHour
      // tanpa harus nunggu jam mepet reset.
      const VIA_RFQ = argv.includes('rfq');
      process.stdout.write(paint(`→ ${side.toUpperCase()} ${edelxQty} EDELx (deliver ${deliver}, sizing $${M8.usdAmount}, minUsd $${M8.minUsd})${VIA_RFQ ? '  [jalur RFQ /swap]' : '  [jalur CLOB /terminal]'}\n`, COLOR.cyan));
      if (!GO) { process.stdout.write(paint(`[DRY] gak submit. Tambah 'go' buat live${VIA_RFQ ? '' : ', atau `rfq` buat lewat jalur /swap'}.\n`, COLOR.yellow)); process.exit(0); }
      const swapCtx = { ...clients, email: a.email, label: a.label || a.email, userServiceCid, leg, maxFeeCC: M8.maxFeeCC, minUsd: M8.minUsd, usdPerEdelx, maxDeliverCeth: (side === 'buy' ? ceth : 0), log: (m) => process.stdout.write(paint('  ' + m + '\n', COLOR.gray)), onWalletPicked: (id) => { try { patchAcctSession(a.email, { privyWalletId: id }); } catch (_) { } } };
      const res = VIA_RFQ
        ? await swapOnceAtomic(swapCtx, side, edelxQty)
        : await terminalSwapOnce(swapCtx, side, edelxQty);
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
    // `node index.js proposals [idx|all]` — list settlement/DvpProposal aktif (read-only).
    // Buat ngecek apakah feecheck/skip-spike ninggalin proposal nyangkut. Dulu hardcode
    // akun 0 doang — proposal nyangkut di akun lain gak kelihatan (sama kayak `cleanup`).
    // nextAction dicetak juga: itu yg ngebedain "kita yg belum gerak" vs "LP yg diem".
    (async () => {
      const arg = String(argv[1] || '0');
      const idxs = arg === 'all' ? ACCOUNTS.map((_, i) => i) : [Number(arg) || 0];
      for (const _i of idxs) {
        const a = ACCOUNTS[_i];
        if (!a) { console.error(paint(`akun idx ${_i} gak ada`, COLOR.red)); continue; }
        const state = makeStates()[_i];
        const { sv, partyId } = await buildSwapClients(state);
        const allRaw = await sv.listSettlementProposals(partyId, { includeClosed: true }).catch(() => []);
        const all = allRaw.filter(p => p.buyer === partyId || p.seller === partyId);
        process.stdout.write(paint(`\n▎ ${a.label || a.email} — party ${partyId.slice(0, 20)}… — ${all.length} proposal\n`, COLOR.bold + COLOR.cyan));
        for (const p of all) {
          const st = await sv.swapAction(SWAP.actionIds.pollProposal, [{ settlementId: p.proposalId, partyId }]).catch(() => null);
          const stage = (st && st.stage) || 0;
          const isBuyer = p.buyer === partyId;
          const ourAlloc = st ? (isBuyer ? st.allocationBuyerCid : st.allocationSellerCid) : null;
          const locked = ourAlloc && ourAlloc !== '$undefined';
          const rej = st && (st.buyerRejected || st.sellerRejected);
          const tag = stage >= 9 ? 'SETTLED' : rej ? 'REJECTED' : locked ? 'LOCKED(dana kita kekunci)' : 'pending(0 dana kita)';
          // nextAction: 1=preconfirm 2/5=pay_fee 3/4/8=sign_contract 6=allocate 7=WAIT.
          // 7 di sisi kita = giliran lawan; lawan bukan 7 = lawan yg belum gerak.
          const na = st ? `buyerNext=${st.buyerNextAction} sellerNext=${st.sellerNextAction}` : 'nextAction=?';
          process.stdout.write(`  - ${p.proposalId.slice(0, 16)}… stage ${stage} ${isBuyer ? 'BUY' : 'SELL'} ${p.baseQuantity} · ${na} · status ${p.status || '-'} → ${paint(tag, locked ? COLOR.red : stage >= 9 ? COLOR.green : COLOR.gray)}\n`);
        }
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
  } else if (argv[0] === 'pingpong' || argv[0] === 'pingpong-rfq') {
    // `node index.js pingpong` — mode 8 (ping-pong EDELx↔cETH) SEMUA akun, PERSIS
    // menu 8 tapi tanpa prompt interaktif → bisa jalan headless (pm2/nohup/tee log).
    PINGPONG_ROUTE = (argv[0] === 'pingpong-rfq' || argv.includes('rfq')) ? 'rfq' : 'clob';
    const _oc = applyOvercapArg(argv);
    if (_oc) process.stdout.write(paint(_oc + '\n', COLOR.yellow));
    const _on = applyOnlyArg(argv);
    if (_on) process.stdout.write(paint(_on + '\n', COLOR.yellow));
    SESSION_ENGINE = 'pingpong';
    parallelSwapActive = SWAP.parallel;
    process.stdout.write('\n' + paint(`Engine: PING-PONG EDELx↔cETH [${PINGPONG_ROUTE === 'rfq' ? 'RFQ /swap' : 'CLOB /terminal'}] — SEMUA akun${parallelSwapActive ? ` · PARALLEL x${SWAP.concurrency}` : ''}`, COLOR.bold + COLOR.cyan) + '\n');
    runMain().catch(e => { console.error(paint('FATAL: ' + (e && e.stack || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'tif-probe') {
    // `node index.js tif-probe [idx] [GTD|GTC|IOC] [ttlSec]` — buktiin server beneran
    // hormatin expiresAt. Order dipasang JAUH dari book (SELL 5x bestAsk) supaya GAK
    // MUNGKIN match → 0 settlement, 0 CC, 0 dana ke-lock. Lalu tunggu lewat TTL dan
    // pakai cancelOrder sebagai PROBE: masih `success:true` = order MASIH HIDUP (TiF
    // gak dihormati); error/`false` = order udah mati sendiri (persis yg kita mau).
    // `/api/orders?mine=true` gak bisa dipakai — dia balik 0 walau order masih aktif.
    (async () => {
      const idx = Number(argv[1] || 0);
      const tif = String(argv[2] || 'GTD').toUpperCase();
      const ttlSec = Math.max(30, Number(argv[3]) || 60);
      const a = ACCOUNTS[idx]; if (!a) { console.error(paint(`akun idx ${idx} gak ada`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      const { sv, partyId } = await buildSwapClients(state);
      await ensureActionIds(sv, partyId, a.label || a.email);
      const market = EDEL_CETH.market;
      const book = await sv.orderbookDepth(market, { lpOnly: M8.bookLpOnly !== false, depth: 20 });
      if (!book || !(book.bestAsk > 0)) { console.error(paint('book kosong — probe dibatalin', COLOR.red)); process.exit(1); }
      const price = tickPrice(book.bestAsk * 5, true);   // 5x ask → mustahil match
      // Server nolak order di bawah nilai minimum ($10): "Order value $X is below the
      // minimum order value $10.00". Nilai dihitung qty × price × USD/cETH, jadi qty
      // dihitung mundur dari target $12 (bukan angka mati) — di harga 5x ask tetap
      // mustahil match.
      const pc = await sv.getPrice('cETH-USDCx').catch(() => null);
      const usdPerCeth = Number(pc && (pc.last || pc.ask || pc.bid)) || 0;
      if (!(usdPerCeth > 0)) { console.error(paint('harga cETH-USDCx gak kebaca — probe dibatalin', COLOR.red)); process.exit(1); }
      const qty = Math.ceil(12 / (Number(price) * usdPerCeth));
      const expiresAt = tif === 'GTD' ? new Date(Date.now() + ttlSec * 1000).toISOString() : undefined;
      const olog = (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n');
      olog(`book: bid ${book.bestBid.toFixed(10)} / ask ${book.bestAsk.toFixed(10)} | cETH $${usdPerCeth}`);
      olog(`submitOrder SELL ${qty} EDELx @ ${price} (5x ask — mustahil match, ~$${(qty * Number(price) * usdPerCeth).toFixed(2)}), TiF ${tif}${expiresAt ? ` expiresAt ${expiresAt}` : ''}`, COLOR.cyan);
      const ord = await sv.submitOrder({ partyId, marketId: market, orderType: 'sell', price, quantity: fmt10(String(qty)), timeInForce: tif, expiresAt, requirements: { lpOnly: true } });
      if (!ord || ord.success === false || !ord.order) { console.error(paint(`submitOrder DITOLAK: ${JSON.stringify(ord).slice(0, 300)}`, COLOR.red)); process.exit(1); }
      const orderId = ord.order.orderId || ord.order.id;
      olog(`✓ diterima — orderId ${orderId} status ${ord.order.status || '?'}`, COLOR.green);
      olog(`tunggu ${ttlSec + 20}s (TTL + 20s margin)…`);
      await sleep((ttlSec + 20) * 1000);
      const c = await sv.cancelOrder(orderId, partyId);
      const alive = !!(c && c.success === true);
      olog(`cancelOrder (probe) → ${JSON.stringify(c).slice(0, 220)}`);
      olog(alive
        ? `✗ order MASIH HIDUP setelah ${ttlSec}s — ${tif} gak bikin order expired (udah saya cancel barusan)`
        : `✓ order UDAH MATI sendiri — ${tif} dihormati server`, alive ? COLOR.red : COLOR.green);
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'atomic-probe') {
    // `node index.js atomic-probe [idx] [sell|buy] [qtyEDELx]` — READ-ONLY (0 CC).
    // rfqStream → pilih quote → acceptQuoteAtomicAction → DUMP responsnya.
    // Tujuan: mastiin acceptQuoteAtomic nyediain SEMUA argumen AtomicDVP_Settle
    // (quoteSignature, ticketCid, *TransferArgs, *AcceptArgs, factoryCid, fees,
    // disclosedContracts). Gak prepare/submit apa pun.
    (async () => {
      const idx = Number(argv[1] || 0);
      const side = (argv[2] === 'buy') ? 'buy' : 'sell';
      const qty = String(argv[3] || '1200');
      const a = ACCOUNTS[idx]; if (!a) { console.error(paint(`akun idx ${idx} gak ada`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      const olog = (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n');
      const clients = await buildSwapClients(state);
      const { sv, partyId } = clients;
      await ensureActionIds(sv, partyId, a.label || a.email);
      // PAKSA discover penuh: ensureActionIds cuma probe 2 ID kritis, jadi action yg BARU
      // ditambahin ke ACTION_NAME (requestQuotesV2/acceptQuoteAtomic) gak ke-refresh dan
      // masih pakai fallback hardcoded yg udah stale → 404 "Server action not found".
      const disc = await sv.discoverActionIds().catch(e => ({ _err: (e && e.message) || String(e) }));
      if (disc && disc.changed && disc.changed.length) { saveActionIds(); olog(`discover: ${disc.changed.length} ID di-refresh`, COLOR.green); }
      const market = EDEL_CETH.market;
      olog(`\n▎ ${a.label || a.email} — ${side.toUpperCase()} ${qty} EDELx di ${market}`, COLOR.bold + COLOR.cyan);
      olog(`actionId requestQuotesV2  : ${SWAP.actionIds.requestQuotesV2}`);
      olog(`actionId acceptQuoteAtomic: ${SWAP.actionIds.acceptQuoteAtomic}`);

      // RFQ v1 (/api/rfq/stream) DITOLAK acceptQuoteAtomic ("RFQ not found or expired")
      // → jalur atomic butuh RFQ yg dibikin requestQuotesV2Action. Coba v2 dulu.
      olog('\n1) requestQuotesV2Action…');
      const v2args = [{ partyId, marketId: market, direction: side, quantity: qty }];
      let v2 = await sv.swapAction(SWAP.actionIds.requestQuotesV2, v2args).catch(e => ({ _err: (e && e.message) || String(e) }));
      olog(`   → ${JSON.stringify(v2).slice(0, 400)}`, (v2 && !v2._err) ? COLOR.green : COLOR.yellow);
      let rfq = null, quote = null;
      if (v2 && !v2._err && (v2.rfqId || v2.quotes)) {
        rfq = { rfqId: v2.rfqId, quotes: v2.quotes || [], rejections: [] };
        quote = (rfq.quotes || [])[0];
        olog(`   v2: rfqId ${rfq.rfqId} · ${rfq.quotes.length} quote`, COLOR.green);
      }
      if (!quote) {
        olog('\n1b) fallback rfqStream (v1)…');
        rfq = await sv.rfqStream({ partyId, marketId: market, direction: side, quantity: qty }, { timeoutMs: 30000 });
        olog(`   rfqId ${rfq.rfqId} · ${rfq.quotes.length} quote · ${rfq.rejections.length} rejection`);
        quote = rfq.quotes[0];
      }
      if (!quote) { olog('   gak ada quote — stop', COLOR.red); process.exit(1); }
      olog(`   quote dipakai: ${JSON.stringify(quote).slice(0, 260)}`);

      olog('\n2) acceptQuoteAtomicAction…');
      const args = [{ partyId, rfqId: rfq.rfqId, quoteId: quote.quoteId || quote.id }];
      let acc = await sv.swapAction(SWAP.actionIds.acceptQuoteAtomic, args).catch(e => ({ _err: (e && e.message) || String(e) }));
      if (acc && acc._err) {
        olog(`   gagal pakai args {partyId,rfqId,quoteId}: ${acc._err}`, COLOR.yellow);
        olog('   coba bentuk args lain: [quote utuh]…');
        acc = await sv.swapAction(SWAP.actionIds.acceptQuoteAtomic, [{ partyId, rfqId: rfq.rfqId, quote }]).catch(e => ({ _err: (e && e.message) || String(e) }));
      }
      if (!acc || acc._err) { olog(`   GAGAL: ${(acc && acc._err) || 'kosong'}`, COLOR.red); process.exit(1); }
      olog(`   ✓ respons keys: ${Object.keys(acc).join(', ')}`, COLOR.green);
      const want = ['quote', 'quoteSignature', 'ticketCid', 'lpInputHoldingCids', 'userInputHoldingCids', 'baseTransferFactoryCid', 'quoteTransferFactoryCid', 'baseTransferArgs', 'baseAcceptArgs', 'quoteTransferArgs', 'quoteAcceptArgs', 'fees', 'disclosedContracts', 'contractId', 'templateId'];
      olog('\n   cek field yg dibutuhin AtomicDVP_Settle:');
      for (const k of want) {
        const v = acc[k] !== undefined ? acc[k] : (acc.data && acc.data[k]);
        const has = v !== undefined && v !== null;
        olog(`     ${has ? '✓' : '·'} ${k.padEnd(26)} ${has ? (typeof v === 'object' ? `(${Array.isArray(v) ? v.length + ' item' : 'object'})` : String(v).slice(0, 60)) : '-'}`, has ? COLOR.green : COLOR.gray);
      }
      // 3. Konteks transfer/accept per instrument (sumber factoryCid +
      //    instrument-configuration + sisa disclosed). Bentuk args belum pasti →
      //    coba beberapa variasi, laporkan mana yg 200.
      const env = acc.envelope || {};
      const refs = env.utilityAcceptRefs || [];
      const ctxOut = {};
      olog(`\n3) konteks utility (${refs.length} instrument dari utilityAcceptRefs)…`, COLOR.bold);
      for (const ref of refs) {
        const admin = ref.instrumentAdmin, iid = ref.instrumentId;
        olog(`   • ${iid} (admin ${String(admin).slice(0, 22)}…)`);
        // Args PERSIS seperti yg UI kirim ke getTransferFactoryContextAction (capture
        // reqid 492): {receiver, amount, instrumentId:{admin,id}, requestedAt,
        // executeBefore, sender, inputHoldingCids}. inputHoldingCids KOSONG bikin 500
        // (digest beda) — server butuh holding beneran, jadi diambil dari saldo.
        const _now = new Date();
        const _req = _now.toISOString();
        const _exp = new Date(_now.getTime() + 130_000).toISOString();   // quote hidup ~130s
        const lpParty = env.lpPartyId || partyId;
        const q = env.quote || {};
        // sisi mana yg KITA kirim: side Sell → kita kirim base (EDELx), terima quote (cETH).
        const weSendBase = String(q.side || '').toLowerCase() === 'sell';
        const isBase = String(iid).toUpperCase() === 'EDELX';
        const amount = isBase ? String(q.baseAmount || '0') : String(q.quoteAmount || '0');
        const weSend = isBase ? weSendBase : !weSendBase;
        // holding punya kita utk instrument ini (cuma perlu kalau kita yg ngirim)
        let holds = [];
        try {
          const bal = await supaBalances(clients.identityToken, clients.proxy);
          const tok = ((bal && bal.tokens) || []).find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === String(iid).toUpperCase());
          holds = ((tok && tok.unlockedUtxos) || []).map(u => u.contractId).filter(Boolean);
        } catch (_) { }
        olog(`     side=${q.side} · kita ${weSend ? 'KIRIM' : 'TERIMA'} ${iid} ${amount} · ${holds.length} holding`);
        const base = { receiver: weSend ? lpParty : partyId, amount, instrumentId: { admin, id: iid }, requestedAt: _req, executeBefore: _exp, sender: weSend ? partyId : lpParty, inputHoldingCids: weSend ? holds.slice(0, 5) : [] };
        const variants = [
          ['UI-shape (holding asli)', [base]],
          ['UI-shape + lp holdings', [{ ...base, inputHoldingCids: (env.lpInputHoldingCids || []) }]],
          ['UI-shape tanpa holding', [{ ...base, inputHoldingCids: [] }]],
        ];
        for (const [label, args] of variants) {
          // _probeAction: raw RSC, gak throw & gak motong → pesan error server kebaca utuh.
          const p = await sv._probeAction(SWAP.actionIds.utilityTransferFactory, args, 15000);
          const pv = unwrapCtx(p && p.value);   // bentuk baru: {ok:true, context:{…}}
          const ok = p && p.status === 200 && pv && !pv.error && (pv.factoryId || pv.factory || pv.choiceContext || pv.choiceContextData);
          if (ok) {
            olog(`     ✓ ${label} → keys: ${Object.keys(pv).join(', ')}`, COLOR.green);
            ctxOut[iid] = { transferFactory: pv, argsShape: label };
            break;
          }
          const msg = (p && p.value && (p.value.error || p.value.message)) || (p && p.text ? String(p.text).replace(/\s+/g, ' ').slice(0, 220) : '?');
          olog(`     · ${label} [${p && p.status}]: ${String(msg).slice(0, 200)}`);
        }
      }
      const OUT = process.env.OUT || '/tmp/atomic-probe.json';
      try { saveJSON(OUT, { rfqId: rfq.rfqId, quote, accept: acc, utilityCtx: ctxOut }); olog(`\n   dump lengkap → ${OUT}`, COLOR.cyan); } catch (_) { }
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.stack) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'privy-otp') {
    // `node index.js privy-otp <email> send`   → kirim OTP ke email
    // `node index.js privy-otp <email> <kode>` → tukar OTP jadi token, lalu LAPORKAN
    //   apa yang Supanova tahu soal akun itu (partyId + saldo). READ-ONLY di sisi
    //   Silvana — dipakai buat mendiagnosa party yang belum kedaftar (mis. wallet hasil
    //   register di luar alur onboarding web). Token TIDAK disimpan ke session.json.
    (async () => {
      const email = String(argv[1] || '').trim().toLowerCase();
      const code = String(argv[2] || '').trim();
      if (!email || !code) { console.error(paint('pakai: node index.js privy-otp <email> <send|kode>', COLOR.red)); process.exit(1); }
      const proxy = getProxy(email);
      const olog = (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n');
      olog(`email : ${email}`);
      olog(`proxy : ${proxy ? proxy.host + ':' + proxy.port : '(direct)'}`);
      if (code === 'send') {
        await privyInit(email, proxy);
        olog('\n✓ OTP dikirim. Cek inbox, lalu jalankan:', COLOR.green);
        olog(`  node index.js privy-otp ${email} <kode6digit>`, COLOR.bold);
        process.exit(0);
      }
      const auth = await privyAuthenticate(email, code, proxy);
      const tok = auth.identity_token || auth.token || auth.privy_access_token;
      olog(`\n✓ login Privy OK — user ${(auth.user && auth.user.id) || '?'}`, COLOR.green);
      const me = await supaMe(tok, proxy).catch(e => ({ _err: (e && e.message) || String(e) }));
      const pid = me && me.data && me.data.partyId;
      olog(`\nsupaMe → partyId: ${pid || JSON.stringify(me).slice(0, 300)}`, pid ? COLOR.cyan : COLOR.yellow);
      if (pid) {
        const bal = await supaBalances(tok, proxy).catch(e => ({ _err: (e && e.message) || String(e) }));
        if (bal && bal.tokens) {
          olog('saldo:');
          for (const t of bal.tokens) {
            const id = (t.instrumentId && t.instrumentId.id) || '?';
            const un = (t.unlockedUtxos || []).reduce((a, u) => a + Number(u.amount || 0), 0);
            olog(`  ${id}: ${un}`);
          }
        } else olog('saldo: ' + JSON.stringify(bal).slice(0, 200), COLOR.yellow);

        // Cek UserService on-chain. Kalau ADA tapi Silvana bilang party not_found,
        // record-nya bisa dipulihkan lewat server action autoRecoverParty TANPA
        // transaksi baru (gratis). Kalau GAK ADA, party ini memang belum pernah
        // onboarding → butuh transaksi (bayar fee CC), bukan sekadar daftar ulang.
        const canton = new CantonClient({ token: tok, timeoutMs: REQ.timeoutMs, proxy });
        for (const tpl of [
          '#utility-settlement-app-v1:Utility.Settlement.App.V1.Service.User:UserService',
          '#utility-settlement-app-v1:Utility.Settlement.App.V1.Service.User:UserServiceRequest',
        ]) {
          const list = await canton.activeContracts(tpl).catch(e => ({ _err: (e && e.message) || String(e) }));
          const name = tpl.split(':').pop();
          if (Array.isArray(list)) {
            olog(`\n${name} on-chain: ${list.length}`, list.length ? COLOR.green : COLOR.yellow);
            for (const c of list.slice(0, 5)) {
              olog(`  cid: ${c.contractId}`);
              const ca = c.createArgument || {};
              for (const k of Object.keys(ca)) { const v = ca[k]; if (v && typeof v === 'object') continue; olog(`    ${k}: ${v}`); }
            }
          } else olog(`\n${name}: ERROR ${list && list._err}`, COLOR.red);
        }
      }
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'acct-diag') {
    // `node index.js acct-diag [idx]` — diagnosa 1 akun, READ-ONLY, TANPA OTP Privy.
    // Cuma login Silvana pakai passkey (cookie) lalu baca endpoint informasi: siapa
    // user-nya, party/wallet apa yg ke-bind di sisi Silvana, dan kenapa earn-hub task
    // kosong. Dipakai buat kasus "task gak muncul / wallet gak bisa diganti".
    (async () => {
      const idx = Number(argv[1] || 0);
      const a = ACCOUNTS[idx]; if (!a) { console.error(paint(`akun idx ${idx} gak ada`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      const olog = (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n');
      olog(`\n▎ ${a.label || a.email}  (idx ${idx})`, COLOR.bold + COLOR.cyan);
      const sess = acctSession(a.email);
      olog(`session: passkey=${!!sess.passkey} partyId=${sess.partyId || '(kosong)'} userServiceCid=${sess.userServiceCid ? 'ada' : '(kosong)'} privyWalletId=${sess.privyWalletId || '(kosong)'}`);

      const sv = await ensureSilvanaSession(state);
      if (!sv) { console.error(paint('passkey belum di-set — jalankan register/paste dulu', COLOR.red)); process.exit(1); }
      const proxy = getProxy(a.email);
      const hdr = (extra = {}) => ({ 'User-Agent': UA, 'Accept': 'application/json, text/plain, */*', 'Origin': APP_BASE, 'Referer': APP_BASE + '/', ...extra });
      const rest = async (path) => {
        const r = await request('GET', `${APP_BASE}${path}`, { jar: sv.jar, timeoutMs: 15000, proxy, headers: hdr() });
        let j = r.json; if (!j) { try { j = JSON.parse(r.text || ''); } catch (_) { } }
        return { status: r.status, json: j, text: (r.text || '').slice(0, 300) };
      };

      const me = await rest('/api/auth/me');
      olog(`\n/api/auth/me → ${me.status}`, me.status === 200 ? COLOR.green : COLOR.red);
      if (me.json && me.json.user) {
        const u = me.json.user;
        for (const k of Object.keys(u)) {
          const v = u[k];
          if (v && typeof v === 'object') continue;
          olog(`  ${k}: ${v}`);
        }
      } else olog('  ' + me.text, COLOR.yellow);

      // Wallet yg ke-link DI SISI SILVANA (beda dari wallet Privy) — sumbernya sama
      // dengan kartu "Connected Wallets" di /settings. UI nambah wallet lewat
      // POST /api/wallets {partyId} dan HASILNYA DITELAN `.catch(()=>{})`, jadi kalau
      // server nolak (mis. 409 "Wallet already linked to another account") halaman
      // diam saja — makanya perlu dicek dari sini.
      olog(`\n— connected wallets (/api/wallets) —`, COLOR.bold);
      const w = await rest('/api/wallets');
      if (w.status === 200 && Array.isArray(w.json)) {
        if (!w.json.length) olog('  (kosong — akun belum punya wallet ter-link)', COLOR.yellow);
        for (const x of w.json) {
          const match = sess.partyId && x.partyId === sess.partyId;
          olog(`  id=${x.id}  ${x.name}  ${x.partyId}${match ? '  ← cocok partyId di session' : ''}`, match ? COLOR.green : COLOR.gray);
        }
        if (sess.partyId && !w.json.some(x => x.partyId === sess.partyId)) {
          olog(`  ⚠ partyId di session (${sess.partyId.slice(0, 26)}…) TIDAK ada di daftar ini.`, COLOR.red);
          olog(`    Bot bakal dapet task/saldo party lain dari yang dikenal Silvana → swap gak kecatat.`, COLOR.red);
        }
      } else olog(`  /api/wallets → ${w.status} ${w.text}`, COLOR.yellow);

      // Earn-hub: tanpa partyId dan (kalau ada) dengan partyId dari session.
      olog(`\n— earn-hub —`, COLOR.bold);
      for (const p of ['/api/earn-hub/tasks', '/api/earn-hub/stats', ...(sess.partyId ? [`/api/earn-hub/tasks?partyId=${encodeURIComponent(sess.partyId)}`] : [])]) {
        const r = await rest(p);
        const items = r.json && (r.json.items || r.json.tasks);
        olog(`  ${r.status === 200 ? '✓' : '·'} ${p} → ${r.status}${Array.isArray(items) ? ` (${items.length} item)` : ''}`, r.status === 200 ? COLOR.green : COLOR.yellow);
        if (Array.isArray(items) && items.length) for (const t of items.slice(0, 12)) olog(`      ${t.code || t.id || '?'}  ${t.current ?? '?'}/${t.target ?? '?'}  ${t.status || ''}`);
        else if (r.status === 200) olog(`      body: ${JSON.stringify(r.json).slice(0, 300)}`, COLOR.yellow);
      }
      olog('');
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'cancel-order') {
    // `node index.js cancel-order <orderId> [idx]` — bunuh order terminal yg masih
    // nyantol di orderbook. WAJIB ada sejak TiF pindah ke GTC: order yg belum di-cancel
    // TETAP HIDUP di book, dan tiap settlement-nya dibatalin dia KE-MATCH LAGI →
    // proposal PENDING lahir terus-terusan (terpantau live di order 107718813).
    // CATATAN: `/api/orders?mine=true` balik 0 walau order kita masih aktif — jangan
    // percaya endpoint itu buat mastiin order udah mati; lihat proposal PENDING yg
    // muncul lagi sesudah cleanup sebagai tandanya.
    (async () => {
      const orderId = String(argv[1] || '').trim();
      if (!orderId) { console.error(paint('pakai: node index.js cancel-order <orderId> [idx]', COLOR.red)); process.exit(1); }
      const idx = Number(argv[2] || 0);
      const a = ACCOUNTS[idx]; if (!a) { console.error(paint(`akun idx ${idx} gak ada`, COLOR.red)); process.exit(1); }
      const state = makeStates()[idx];
      const { sv, partyId } = await buildSwapClients(state);
      await ensureActionIds(sv, partyId, a.label || a.email);
      const r = await sv.cancelOrder(orderId, partyId);
      process.stdout.write(paint(`cancelOrder ${orderId} → `, COLOR.cyan) + JSON.stringify(r).slice(0, 300) + '\n');
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'cleanup') {
    // `node index.js cleanup [idx|all]` — cancel proposal nyangkut yg 0 dana kita
    // kekunci (stage<9, belum settle, alloc kita kosong, umur >90s). Aman: gak ada
    // dana ke-lock. Cancel via cancelSettlement (V2). NEVER sentuh LOCKED/SETTLED.
    // Dulu hardcode akun ke-0 doang — settlement nyangkut di akun lain gak kesapu.
    (async () => {
      const arg = String(argv[1] || '0');
      const idxs = arg === 'all' ? ACCOUNTS.map((_, i) => i) : [Number(arg) || 0];
      let grand = 0;
      for (const _i of idxs) {
      const a = ACCOUNTS[_i];
      if (!a) { console.error(paint(`akun idx ${_i} gak ada`, COLOR.red)); continue; }
      if (idxs.length > 1) process.stdout.write('\n' + paint(`▎ ${a.label || a.email}`, COLOR.bold + COLOR.cyan) + '\n');
      const state = makeStates()[_i];
      const { sv, canton, partyId, privy } = await buildSwapClients(state);
      const n = await cleanupStaleProposals(sv, canton, partyId, (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n'), privy);
      // Sapuan kedua lewat REST: settlement tahap AWAL (stage<5, PENDING) belum jadi
      // DvpProposal di ledger jadi lolos dari cleanupStaleProposals. Umur >120s biar
      // gak nyenggol settlement yg lagi jalan. 0 dana kita ke-lock di stage ini.
      let nRest = 0;
      const pend = await sv.listSettlementProposals(partyId).catch(() => []);
      for (const p of pend) {
        if (!/PENDING/i.test(String(p.status || ''))) continue;
        if (p.buyer !== partyId && p.seller !== partyId) continue;
        // createdAt REST = protobuf Timestamp {seconds:"...",nanos:N}, BUKAN string ISO
        // (new Date(obj) → Invalid Date → NaN). Pola sama fetchActiveSettlements.
        const createdMs = Number((p.createdAt && p.createdAt.seconds) || 0) * 1000;
        const ageSec = createdMs > 0 ? (Date.now() - createdMs) / 1000 : 1e9;
        if (ageSec < 120) { process.stdout.write(paint(`  skip ${String(p.proposalId).slice(0, 16)}… (baru ${Math.round(ageSec)}s, mungkin lagi jalan)\n`, COLOR.gray)); continue; }
        const st = await sv.swapAction(SWAP.actionIds.pollProposal, [{ settlementId: p.proposalId, partyId }]).catch(() => null);
        const isBuyer = p.buyer === partyId;
        const ourAlloc = st ? (isBuyer ? st.allocationBuyerCid : st.allocationSellerCid) : null;
        if (ourAlloc && ourAlloc !== '$undefined') { process.stdout.write(paint(`  skip ${String(p.proposalId).slice(0, 16)}… — dana KITA ke-lock\n`, COLOR.yellow)); continue; }
        if (st && (st.stage || 0) >= 9) continue;   // settled — jangan sentuh
        await sv.cancelSettlement(p.proposalId, partyId, 'stale pending cleanup').catch(() => { });
        nRest++;
        process.stdout.write(paint(`  cancel PENDING ${String(p.proposalId).slice(0, 16)}… (${p.marketId}, stage ${(st && st.stage) || '?'}, umur ${Math.round(ageSec)}s)\n`, COLOR.yellow));
      }
      process.stdout.write(paint(`cleanup — ${n} DvpProposal (ledger) + ${nRest} PENDING (REST) dibersihin\n`, COLOR.green));
      grand += n + nRest;
      }
      if (idxs.length > 1) process.stdout.write('\n' + paint(`✓ total ${grand} dibersihin dari ${idxs.length} akun\n`, COLOR.bold + COLOR.green));
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
      for (;;) {
      // Menu utama: picker panah, dan BALIK ke menu setelah aksi pendek selesai.
      // Dulu tiap cabang manggil process.exit(0) jadi sekali milih langsung keluar.
      const MENU = [
        ['s', 'swap 1x (RFQ)', 'swap sekali: pilih token asal → tujuan, pilih akun'],
        ['2', 'check balance', 'tabel CC/USDCx/cETH/EDELx + total, auto-refresh'],
        ['3', 'run (OTP urut)', 'login akun 1-per-1 lalu run USDCx'],
        ['4', 'change wallet', 'ganti wallet supa 1 akun'],
        ['5', 'maintenance', 'cleanup DvpProposal stale / reset season'],
        ['6', 'swap back', 'dump token (USDCx/cETH/EDELx) → CC, SEMUA akun'],
        ['7', 'EDELx manual', 'CC→EDELx multi-akun / dump EDELx→CC 1 akun'],
        ['8', 'ping-pong CLOB', 'mode 8 via /terminal (orderbook, fee ~4.3 CC)'],
        ['8r', 'ping-pong RFQ', 'mode 8 via /swap AtomicDVP (fee murah, anti-macet)'],
        ['9', 'bulk back', 'dump ke CC, SEMUA akun (pilih pair)'],
        ['t', 'transfer', 'kirim token ke akun sendiri / party luar'],
        ['w', 'wallet', 'pilih wallet aktif · token fee · tautkan Walley'],
      ];
      const mpk = await pickList({
        title: 'SilvanaBot-Sipal',
        items: MENU.map(([c, l, d]) => ({ label: `${c})`.padEnd(4) + l.padEnd(16), detail: paint(d, COLOR.gray) })),
        hint: '↑/↓ pindah · Enter pilih · q keluar',
      });
      if (!mpk.length) { process.stdout.write(paint('bye 👋\n', COLOR.gray)); process.exit(0); }
      const ans = MENU[mpk[0]][0];
      if (ans === 's') {
        // Swap SEKALI lewat jalur RFQ. User milih token asal -> tujuan -> akun ->
        // jumlah. Sengaja RFQ: fee jauh lebih murah dan gak nyangkut kayak CLOB.
        const { sv: sv0 } = await buildSwapClients(makeStates()[0]);
        const pr = await pickTokenPair(sv0, { title: 'Swap 1x (RFQ)' }).catch(e => { console.error(paint('gagal baca market: ' + e.message, COLOR.red)); return null; });
        if (!pr) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }
        // Arah: kirim base = sell, kirim quote = buy.
        const side = (String(pr.from).toUpperCase() === String(pr.base).toUpperCase()) ? 'sell' : 'buy';
        process.stdout.write(paint(`\n${pr.from} → ${pr.to}  ·  market ${pr.market}  ·  arah ${side}\n`, COLOR.cyan));

        // Saldo token asal tiap akun, biar milihnya gak buta.
        // buildSwapClients itu MAHAL (login Silvana + Privy + auth Walley per akun).
        // Buat sekadar baca saldo cukup token Privy + balancesFor, dan konkurensinya
        // dinaikin. Progres dicetak biar gak kelihatan nge-hang.
        const states = makeStates();
        const bal = new Array(ACCOUNTS.length).fill(null);
        let selesai = 0;
        process.stdout.write(paint(`Baca saldo 0/${ACCOUNTS.length}…`, COLOR.gray));
        await mapLimit(ACCOUNTS.map((_, i) => i), 8, async (i) => {
          try {
            const em = ACCOUNTS[i].email;
            const pakaiWalley = ((acctSession(em) || {}).wallet || {}).kind === 'walley';
            // JANGAN ensurePrivyToken di sini: kalau token expired dia jatuh ke prompt
            // OTP dan seluruh picker menggantung nungguin ketikan. Akun Walley malah
            // gak butuh token Privy sama sekali (saldonya dari ledger Walley).
            let tk = null;
            if (!pakaiWalley) {
              const cached = getValidPrivySession(em);
              if (!cached) { bal[i] = { _err: 'token Privy expired — login dulu (menu 3)' }; selesai++; return; }
              tk = cached.token;
            }
            const b = await balancesFor(em, tk, getProxy(em));
            bal[i] = (b && b.tokens) || [];
          } catch (e) { bal[i] = { _err: ((e && e.message) || String(e)).slice(0, 40) }; }
          selesai++;
          process.stdout.write(`\r` + paint(`Baca saldo ${selesai}/${ACCOUNTS.length}…`, COLOR.gray));
        });
        process.stdout.write('\n');
        const amtOf = (i, tok) => {
          const want = String(instrumentIdOf(tok)).toUpperCase();
          const t = Array.isArray(bal[i]) ? bal[i].find(x => String(x.instrumentId.id).toUpperCase() === want) : null;
          return t ? Number(t.totalUnlockedBalance || 0) : 0;
        };
        const items = ACCOUNTS.map((a, i) => {
          if (!Array.isArray(bal[i])) return { label: (a.label || a.email).padEnd(20), detail: paint(String((bal[i] && bal[i]._err) || 'gagal baca saldo'), COLOR.red), disabled: true, note: '' };
          const v = amtOf(i, pr.from);
          return { label: (a.label || a.email).padEnd(20), detail: paint(`${pr.from} ${v.toFixed(6)}`, v > 0 ? COLOR.green : COLOR.gray), disabled: !(v > 0), note: paint('[kosong]', COLOR.yellow) };
        });
        const adaIsi = items.some(x => !x.disabled);
        if (!adaIsi) {
          const gagal = items.filter(x => /gagal baca/.test(String(x.detail))).length;
          process.stdout.write('\n' + paint(`Gak ada akun yg punya ${pr.from}.`, COLOR.red) + '\n');
          if (gagal) process.stdout.write(paint(`  (${gagal} akun gagal dibaca saldonya)`, COLOR.yellow) + '\n');
          process.stdout.write(paint(`  Cek saldo lewat menu 2, atau pilih token asal lain.\n`, COLOR.gray));
          continue;
        }
        const pilih = await pickList({ title: `Akun yg mau swap ${pr.from} → ${pr.to}:`, items, multi: true });
        if (!pilih.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }

        const amountRaw = (await prompt(paint(`jumlah ${pr.from} per akun (angka, atau ketik max): `, COLOR.bold))).trim();
        if (!amountRaw) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }
        // CEK NILAI USD dulu. Server nolak order di bawah minimum (~$10) dengan
        // "below the minimum order value", dan tanpa cek ini kegagalannya baru muncul
        // satu per satu per akun setelah konfirmasi — 15 kali error yg sama.
        let nilaiUsd = null;
        if (!/^(max|all|semua)$/i.test(amountRaw)) {
          try {
            const uSym = String(pr.from).toUpperCase() === 'USDCX' ? null : `${pr.from}-USDCx`;
            const rate = uSym ? priceOf(await sv0.getPrice(uSym).catch(() => null)) : 1;
            if (rate > 0) nilaiUsd = Number(amountRaw) * rate;
          } catch (_) { }
        }
        // PERINGATAN, bukan penghalang. Ambang $10 itu diukur di EDELx-cETH; market
        // lain bisa beda dan cuma server yg tau pasti. Swap 1x itu manual — biar user
        // yg mutusin, jangan diblokir sepihak.
        const rfqMin = Math.max(0, Number(M8.rfqMinUsd) || 10);
        if (nilaiUsd != null && nilaiUsd < rfqMin) {
          const perlu = (rfqMin / (nilaiUsd / Number(amountRaw))).toFixed(4);
          process.stdout.write('\n' + paint(`⚠ ${amountRaw} ${pr.from} ≈ $${nilaiUsd.toFixed(2)} — di bawah minimum order $${rfqMin} yg terukur di market lain.`, COLOR.yellow) + '\n');
          process.stdout.write(paint(`  Kalau market ini ikut aturan yg sama, server bakal nolak (butuh ~${perlu} ${pr.from}). Lanjut kalau mau tetap coba.\n`, COLOR.gray));
        }
        process.stdout.write('\n' + paint('─'.repeat(64), COLOR.yellow) + '\n');
        process.stdout.write(paint(`SWAP 1x — ${pilih.length} akun · ${amountRaw} ${pr.from}${nilaiUsd != null ? ` (~$${nilaiUsd.toFixed(2)})` : ''} → ${pr.to} · fee ${(SWAP.feeTokens && SWAP.feeTokens[0]) || 'CC'}`, COLOR.bold + COLOR.red) + '\n');
        process.stdout.write(paint('─'.repeat(64), COLOR.yellow) + '\n');
        const conf = (await prompt(paint('Ketik "swap" buat jalan, Enter buat batal: ', COLOR.bold + COLOR.yellow))).trim().toLowerCase();
        if (conf !== 'swap') { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }

        let ok = 0, gagal = 0;
        for (const i of pilih) {
          const a = ACCOUNTS[i], tag = a.label || a.email;
          try {
            const clients = await buildSwapClients(states[i]);
            // userServiceCid: cache dulu, kalau kosong pulihkan dari on-chain (pola
            // yg sama dipakai engine ping-pong).
            let userServiceCid = getUserServiceCid(a.email);
            if (!userServiceCid) {
              const pty = await clients.sv.recoverParty(clients.partyId).catch(() => null);
              if (pty && pty.userServiceCid) { userServiceCid = pty.userServiceCid; patchAcctSession(a.email, { userServiceCid }); }
            }
            if (!userServiceCid) throw new Error('userServiceCid gak ketemu — party belum onboard?');
            // leg mengikuti orientasi market: quantity RFQ selalu dalam BASE.
            const leg = { market: pr.market, baseIsCC: String(pr.base).toUpperCase() === 'CC', tokenToToken: true, tokenId: String(pr.from).toUpperCase(), tokenLabel: pr.from, tokenAdmin: null };
            // qty dalam satuan BASE. Kalau user kirim quote (buy), konversi lewat harga.
            let qty;
            if (/^(max|all|semua)$/i.test(amountRaw)) {
              const punya = amtOf(i, pr.from);
              qty = side === 'sell' ? punya : null;   // buy: qty base dihitung dari harga
              if (side === 'buy') {
                const px = await clients.sv.getPrice(pr.market).catch(() => null);
                const rate = priceOf(px);
                if (!(rate > 0)) throw new Error(`harga ${pr.market} gak kebaca buat hitung max`);
                qty = Math.floor((punya / rate) * 1e6) / 1e6;
              }
            } else {
              const n = Number(amountRaw);
              if (!Number.isFinite(n) || n <= 0) throw new Error(`jumlah '${amountRaw}' gak valid`);
              if (side === 'sell') qty = n;
              else {
                const px = await clients.sv.getPrice(pr.market).catch(() => null);
                const rate = priceOf(px);
                if (!(rate > 0)) throw new Error(`harga ${pr.market} gak kebaca`);
                qty = Math.floor((n / rate) * 1e6) / 1e6;
              }
            }
            if (!(qty > 0)) throw new Error('jumlah hasil hitung nol');
            const ctx = { ...clients, email: a.email, label: tag, userServiceCid, leg, minUsd: M8.minUsd, log: (m) => process.stdout.write(paint(`  [${tag}] ${m}\n`, COLOR.gray)) };
            const r = await swapOnceAtomic(ctx, side, fmt10(String(qty)));
            if (r && r.ok) { ok++; process.stdout.write(paint(`  ✓ ${tag} — ${qty} ${pr.base} (${side}) fee ${r.feeCC}`, COLOR.green) + '\n'); }
            else { gagal++; process.stdout.write(paint(`  ✗ ${tag} — gagal tanpa keterangan`, COLOR.red) + '\n'); }
          } catch (e) { gagal++; process.stdout.write(paint(`  ✗ ${tag} — ${(e && e.message) || e}`, COLOR.red) + '\n'); }
        }
        process.stdout.write('\n' + paint(`selesai — ${ok} sukses, ${gagal} gagal`, gagal ? COLOR.yellow : COLOR.green) + '\n');
        continue;
      }

      if (ans === 'w') {
        const sub = await pickList({
          title: 'Wallet — mau ngapain?',
          items: [
            { label: 'Pilih wallet aktif', detail: paint('tentuin akun mana pakai Supanova / Walley buat swap', COLOR.gray) },
            { label: 'Token fee swap   ', detail: paint('bayar settlement fee pakai CC atau USDCx', COLOR.gray) },
            { label: 'Tautkan Walley   ', detail: paint('hubungin wallet Walley ke akun Silvana (sekali per akun)', COLOR.gray) },
            { label: 'Daftar party ID  ', detail: paint('tabel partyId Supanova & Walley per akun (buat kirim bulk)', COLOR.gray) },
            { label: 'Batas max fee    ', detail: paint('tolak swap kalau fee lewat batas (satuan ikut token fee)', COLOR.gray) },
          ],
        });
        if (!sub.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }

        if (sub[0] === 0) {
          // Pilih wallet aktif per akun. Yg nentuin party mana dipakai bot itu
          // session.json[email].wallet — bukan daftar wallet di Silvana (di sana
          // dua-duanya nempel bareng).
          const ws = loadWalleyWallets();
          const items = ACCOUNTS.map((a, i) => {
            const sess = acctSession(a.email) || {};
            const cur = (sess.wallet && sess.wallet.kind) || 'supanova';
            const walleyPunya = ws.find(x => x.party_id === (sess.wallet || {}).partyId);
            const detail = paint(`aktif: ${cur}`, cur === 'walley' ? COLOR.cyan : COLOR.gray)
              + (walleyPunya ? paint(`  (${walleyPunya.party_hint})`, COLOR.gray) : '');
            return { label: (a.label || a.email).padEnd(20), detail };
          });
          const pilih = await pickList({ title: 'Pilih akun yg mau diubah wallet aktifnya:', items, multi: true });
          if (!pilih.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }
          const kind = await pickList({
            title: 'Pakai wallet mana buat swap?',
            items: [
              { label: 'Supanova', detail: paint('party supa1::… , tanda tangan lewat Privy TEE (default)', COLOR.gray) },
              { label: 'Walley  ', detail: paint('party walley-… , tanda tangan lokal dari seed', COLOR.gray) },
            ],
          });
          if (!kind.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }

          for (const i of pilih) {
            const a = ACCOUNTS[i];
            if (kind[0] === 0) { patchAcctSession(a.email, { wallet: null }); process.stdout.write(paint(`  ${a.label || a.email} → Supanova`, COLOR.green) + '\n'); continue; }
            // Walley: ambil party yg udah ke-link di akun ini.
            let sv2; try { ({ sv: sv2 } = await buildSwapClients(makeStates()[i])); } catch (e) { process.stdout.write(paint(`  ${a.label || a.email} → GAGAL: ${e.message}`, COLOR.red) + '\n'); continue; }
            const linked = await sv2.listWallets().catch(() => []);
            const cand = ws.filter(x => linked.some(l => l.partyId === x.party_id));
            if (!cand.length) { process.stdout.write(paint(`  ${a.label || a.email} → gak ada wallet Walley ter-link. Pakai menu "Tautkan Walley" dulu.`, COLOR.yellow) + '\n'); continue; }
            let w = cand[0];
            if (cand.length > 1) {
              const pk = await pickList({ title: `Wallet Walley buat ${a.label || a.email}:`, items: cand.map(x => ({ label: x.party_hint, detail: paint(String(x.party_id).slice(0, 30) + '…', COLOR.gray) })) });
              if (!pk.length) continue;
              w = cand[pk[0]];
            }
            patchAcctSession(a.email, { wallet: { kind: 'walley', partyId: w.party_id, partyHint: w.party_hint } });
            process.stdout.write(paint(`  ${a.label || a.email} → Walley (${w.party_hint})`, COLOR.green) + '\n');
          }
          process.stdout.write(paint('\nTersimpan di session.json. Swap berikutnya pakai wallet ini.\n', COLOR.cyan));
          continue;
        }

        if (sub[0] === 4) {
          // Batas fee per swap. SATUANNYA ikut token fee yang dipakai — 5 itu ketat
          // buat CC (fee bisa 20) tapi longgar banget buat TUSDT (fee ~0.9), jadi
          // angka lama gak otomatis masuk akal setelah ganti token.
          const unit = (SWAP.feeTokens && SWAP.feeTokens[0]) || 'CC';
          process.stdout.write('\n' + paint(`Token fee sekarang: ${unit}`, COLOR.cyan) + '\n');
          process.stdout.write(paint(`  swap.maxFeeCC      = ${SWAP.maxFeeCC}   (dipakai daytrader & swap 1x)`, COLOR.gray) + '\n');
          process.stdout.write(paint(`  mode8.maxFeeCC     = ${M8.maxFeeCC}   (dipakai ping-pong siang)`, COLOR.gray) + '\n');
          process.stdout.write(paint(`  swap.hardMaxFeeCC  = ${SWAP.hardMaxFeeCC}   (plafon mutlak, gak bisa ditrabas)`, COLOR.gray) + '\n');
          const which = await pickList({
            title: 'Batas mana yg mau diubah?',
            items: [
              { label: 'Keduanya', detail: paint('swap.maxFeeCC + mode8.maxFeeCC sekaligus', COLOR.gray) },
              { label: 'swap saja', detail: paint('cuma swap.maxFeeCC', COLOR.gray) },
              { label: 'mode8 saja', detail: paint('cuma mode8.maxFeeCC', COLOR.gray) },
              { label: 'plafon mutlak', detail: paint('swap.hardMaxFeeCC — berlaku walau yg lain ditrabas', COLOR.gray) },
            ],
          });
          if (!which.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }
          const raw = (await prompt(paint(`batas baru dalam ${unit} (angka): `, COLOR.bold))).trim();
          const n = Number(raw);
          if (!Number.isFinite(n) || n <= 0) { process.stdout.write(paint('angka gak valid — dibatalin.\n', COLOR.red)); continue; }
          try {
            const cfg = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8'));
            cfg.swap = cfg.swap || {}; cfg.mode8 = cfg.mode8 || {};
            if (which[0] === 0 || which[0] === 1) { cfg.swap.maxFeeCC = n; SWAP.maxFeeCC = n; }
            if (which[0] === 0 || which[0] === 2) { cfg.mode8.maxFeeCC = n; M8.maxFeeCC = n; }
            if (which[0] === 3) { cfg.swap.hardMaxFeeCC = n; SWAP.hardMaxFeeCC = n; }
            fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2) + '\n');
            process.stdout.write(paint(`\n✓ tersimpan — swap ${SWAP.maxFeeCC} · mode8 ${M8.maxFeeCC} · plafon ${SWAP.hardMaxFeeCC} (${unit})\n`, COLOR.green));
            if (n > SWAP.hardMaxFeeCC) process.stdout.write(paint(`⚠ batas ${n} di ATAS plafon mutlak ${SWAP.hardMaxFeeCC} — yg berlaku tetap plafonnya.\n`, COLOR.yellow));
          } catch (e) { console.error(paint('gagal nulis config.json: ' + e.message, COLOR.red)); }
          continue;
        }

        if (sub[0] === 3) {
          // Daftar party ID per akun, DIPISAH Supanova vs Walley. Dipakai buat nyiapin
          // kiriman bulk: tinggal copy kolom yg mau dituju.
          process.stdout.write('\n' + paint('Baca party tiap akun…', COLOR.gray) + '\n');
          const ws = loadWalleyWallets();
          const rows = ACCOUNTS.map((a, i) => {
            const sess = acctSession(a.email) || {};
            const aktif = (sess.wallet && sess.wallet.kind) || 'supanova';
            const wPid = (sess.wallet && sess.wallet.partyId) || null;
            // Walley yg ke-link tapi belum jadi wallet aktif tetap ditampilin.
            const wAlt = wPid ? null : (ws.find(x => x.party_id && sess.walleyLinked === x.party_id) || null);
            return { label: a.label || a.email, supa: sess.partyId || null, walley: wPid || (wAlt && wAlt.party_id) || null, aktif };
          });
          const lines = [];
          lines.push('');
          lines.push(paint('AKUN'.padEnd(22) + 'AKTIF'.padEnd(10) + 'PARTY ID', COLOR.bold + COLOR.gray));
          for (const r of rows) {
            lines.push(paint(r.label.padEnd(22), COLOR.bold) + paint(r.aktif.padEnd(10), r.aktif === 'walley' ? COLOR.cyan : COLOR.gray));
            lines.push(paint('  supanova  ', COLOR.gray) + (r.supa ? paint(r.supa, COLOR.white) : paint('—', COLOR.gray)));
            lines.push(paint('  walley    ', COLOR.gray) + (r.walley ? paint(r.walley, COLOR.cyan) : paint('—', COLOR.gray)));
          }
          process.stdout.write(lines.join('\n') + '\n');

          // Versi datar buat copy-paste / kirim bulk.
          const pk = await pickList({
            title: 'Simpan daftar datar (satu partyId per baris) ke file?',
            items: [
              { label: 'Tidak', detail: paint('cukup tampil di layar', COLOR.gray) },
              { label: 'Walley saja', detail: paint('party Walley semua akun', COLOR.gray) },
              { label: 'Supanova saja', detail: paint('party Supanova semua akun', COLOR.gray) },
              { label: 'Dua-duanya', detail: paint('label, supanova, walley (CSV)', COLOR.gray) },
            ],
          });
          if (pk.length && pk[0] > 0) {
            const out = path.join(ROOT, 'party-ids.txt');
            let txt = '';
            if (pk[0] === 1) txt = rows.filter(r => r.walley).map(r => r.walley).join('\n') + '\n';
            else if (pk[0] === 2) txt = rows.filter(r => r.supa).map(r => r.supa).join('\n') + '\n';
            else txt = 'label,supanova,walley\n' + rows.map(r => `${r.label},${r.supa || ''},${r.walley || ''}`).join('\n') + '\n';
            fs.writeFileSync(out, txt);
            process.stdout.write(paint(`\n✓ ditulis ke ${out}\n`, COLOR.green));
          }
          continue;
        }

        if (sub[0] === 1) {
          // Token fee. Ditulis ke config.json biar kepakai juga pas headless/pm2.
          const now = Array.isArray((CONFIG.swap || {}).feeTokens) ? CONFIG.swap.feeTokens : [];
          const ket = { CC: 'default — fee dari saldo CC', USDCx: 'fee dari USDCx, CC gak kepotong', TUSDT: 'fee dari TUSDT (instrument tf-usdt)', USD8: 'fee dari USD8 (instrument UUID di registry)' };
          const pk = await pickList({
            title: `Token buat bayar settlement fee (sekarang: ${now.length ? now.join(',') : 'CC'}):`,
            items: FEE_TOKEN_IDS.map(t => ({ label: String(t).padEnd(8), detail: paint(ket[t] || '', COLOR.gray) })),
          });
          if (!pk.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }
          const sel = FEE_TOKEN_IDS[pk[0]];
          const val = sel === 'CC' ? [] : [sel];
          try {
            const raw = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8'));
            raw.swap = raw.swap || {}; raw.swap.feeTokens = val;
            fs.writeFileSync(CFG_PATH, JSON.stringify(raw, null, 2) + '\n');
            SWAP.feeTokens = val;
            process.stdout.write(paint(`\n✓ feeTokens = ${JSON.stringify(val)} (tersimpan di config.json)\n`, COLOR.green));
          } catch (e) { console.error(paint('gagal nulis config.json: ' + e.message, COLOR.red)); continue; }
          continue;
        }

        // Tautkan wallet Walley ke akun Silvana. Silvana nyimpen BANYAK wallet per akun
        // (kartu "Connected Wallets"), jadi Supanova lama TETAP nempel — ini nambah,
        // bukan ngeganti. Yang nentuin party mana yg dipakai bot itu session.json.
        const ws = loadWalleyWallets();
        if (!ws.length) { console.error(paint(`wallets.jsonl gak kebaca di ${WALLEY_WALLETS_PATH}`, COLOR.red)); continue; }
        process.stdout.write('\n' + paint('Baca wallet yg udah ke-link tiap akun…', COLOR.gray) + '\n');
        const states = makeStates();
        const linked = new Array(ACCOUNTS.length).fill(null);
        await mapLimit(ACCOUNTS.map((_, i) => i), 4, async (i) => {
          try { const { sv } = await buildSwapClients(states[i]); linked[i] = await sv.listWallets(); }
          catch (e) { linked[i] = { _err: (e && e.message) || String(e) }; }
        });
        // Party Walley yg udah kepakai di akun mana pun — jangan ditawarin lagi.
        const dipakai = new Set();
        for (const l of linked) if (Array.isArray(l)) for (const x of l) dipakai.add(x.partyId);

        const items = ACCOUNTS.map((a, i) => {
          const l = linked[i];
          if (!Array.isArray(l)) return { label: (a.label || a.email).padEnd(20), detail: paint('gagal baca wallet', COLOR.red), disabled: true, note: paint('[dilewati]', COLOR.red) };
          const sudah = l.find(x => String(x.partyId || '').startsWith('walley-'));
          const detail = paint(`${l.length} wallet`, COLOR.gray) + (sudah ? paint(`  Walley: ${String(sudah.partyId).split('::')[0]}`, COLOR.green) : paint('  Walley: —', COLOR.yellow));
          return { label: (a.label || a.email).padEnd(20), detail, disabled: !!sudah, note: paint('[udah punya Walley]', COLOR.green) };
        });
        const pilih = await pickList({ title: 'Tautkan Walley — pilih akun (yg udah punya dilewati):', items, multi: true });
        if (!pilih.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }

        // Wallet Walley yg masih bebas.
        const bebas = ws.filter(w => !dipakai.has(w.party_id));
        if (bebas.length < pilih.length) { console.error(paint(`wallet Walley bebas cuma ${bebas.length}, butuh ${pilih.length}`, COLOR.red)); continue; }
        const mode = await pickList({
          title: 'Cara memilih wallet Walley:',
          items: [
            { label: 'Otomatis', detail: paint(`ambil ${pilih.length} wallet bebas pertama (dari ${bebas.length})`, COLOR.gray) },
            { label: 'Manual', detail: paint('pilih sendiri satu per satu', COLOR.gray) },
          ],
        });
        if (!mode.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }

        const pasang = [];
        if (mode[0] === 0) {
          pilih.forEach((ai, k) => pasang.push([ai, bebas[k]]));
        } else {
          const sisa = bebas.slice();
          for (const ai of pilih) {
            const w = await pickList({
              title: `Wallet Walley buat ${ACCOUNTS[ai].label || ACCOUNTS[ai].email}:`,
              items: sisa.map(x => ({ label: String(x.party_hint || '-').padEnd(22), detail: paint(String(x.party_id).slice(0, 30) + '…', COLOR.gray) })),
            });
            if (!w.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }
            pasang.push([ai, sisa[w[0]]]);
            sisa.splice(w[0], 1);
          }
        }

        process.stdout.write('\n' + paint('─'.repeat(70), COLOR.yellow) + '\n');
        process.stdout.write(paint('RENCANA PENAUTAN (Supanova lama TETAP nempel, ini nambah wallet)', COLOR.bold + COLOR.cyan) + '\n');
        for (const [ai, w] of pasang) process.stdout.write(`  ${String(ACCOUNTS[ai].label || ACCOUNTS[ai].email).padEnd(22)} → ${w.party_hint}\n`);
        process.stdout.write(paint('─'.repeat(70), COLOR.yellow) + '\n');
        const conf = (await prompt(paint(`Ketik "link" buat lanjut, Enter buat batal: `, COLOR.bold + COLOR.yellow))).trim().toLowerCase();
        if (conf !== 'link') { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }

        let ok = 0, gagal = 0;
        for (const [ai, w] of pasang) {
          const tag = ACCOUNTS[ai].label || ACCOUNTS[ai].email;
          try {
            const { sv } = await buildSwapClients(states[ai]);
            const r = await sv.linkWallet(w.party_id);
            if (r.ok) { ok++; process.stdout.write(paint(`  ✓ ${tag} → ${w.party_hint}`, COLOR.green) + '\n'); }
            else { gagal++; process.stdout.write(paint(`  ✗ ${tag} → ${r.status} ${JSON.stringify(r.body).slice(0, 120)}`, COLOR.red) + '\n'); }
          } catch (e) { gagal++; process.stdout.write(paint(`  ✗ ${tag} → ${(e && e.message) || e}`, COLOR.red) + '\n'); }
        }
        process.stdout.write('\n' + paint(`selesai — ${ok} tertaut, ${gagal} gagal`, gagal ? COLOR.yellow : COLOR.green) + '\n');
        if (ok) process.stdout.write(paint('Lanjutan: isi CC ke party Walley, lalu `node index.js walley-onboard <idx> <hint> go`\n', COLOR.cyan));
        continue;
      }
      if (ans === 't') {
        // Transfer lewat menu, semuanya pakai picker panah (pickList) — gak ada ngetik
        // indeks lagi. Saldo tiap akun diambil DULUAN biar kelihatan pas milih pengirim;
        // tanpa itu user milih buta lalu baru ketahuan saldonya kosong.
        process.stdout.write('\n' + paint('Ambil saldo semua akun…', COLOR.gray) + '\n');
        const states = makeStates();
        const balOf = new Array(ACCOUNTS.length).fill(null);
        await mapLimit(ACCOUNTS.map((_, i) => i), 5, async (i) => {
          try {
            const tk = await ensurePrivyToken(states[i]);
            const b = await balancesFor(ACCOUNTS[i].email, tk, getProxy(ACCOUNTS[i].email));
            const m = {};
            for (const t of (b && b.tokens) || []) {
              m[t.instrumentId.id] = (t.unlockedUtxos || []).reduce((x, u) => x + (Number(u.amount) || 0), 0);
            }
            balOf[i] = m;
          } catch (e) { balOf[i] = { _err: (e && e.message) || String(e) }; }
        });

        // 1) Token dulu — ambang dust & saldo yg ditampilin tergantung token.
        const TOKENS = ['CC', 'EDELx', 'cETH', 'USDCx'];
        const idOf = (t) => (/^cc$/i.test(t) ? 'Amulet' : t);
        const totalOf = (t) => balOf.reduce((s, m) => s + ((m && Number(m[idOf(t)])) || 0), 0);
        const tokPick = await pickList({
          title: 'Transfer — pilih TOKEN:',
          items: TOKENS.map(t => ({ label: t.padEnd(6), detail: paint(`total ${totalOf(t).toFixed(6)}`, COLOR.gray) })),
        });
        if (!tokPick.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }
        const token = TOKENS[tokPick[0]];
        const instId = idOf(token);

        // Ambang dust dari config. Buat CC ambangnya minimal = fee transfer: ngirim CC
        // di bawah ongkos kirimnya sendiri itu rugi, dan `max` malah bikin saldo kurang.
        const dustCfg = ((CONFIG.swap || {}).transfer || {}).dustMin || {};
        let dustMin = Number(dustCfg[instId]) || 0;
        if (instId === 'Amulet') dustMin = Math.max(dustMin, 16);

        // 2) Akun pengirim — multi-select, saldo tampil, dust ditandai & gak bisa dicentang.
        const items = ACCOUNTS.map((a, i) => {
          const m = balOf[i] || {};
          if (m._err) return { label: (a.label || a.email).padEnd(20), detail: paint('gagal baca saldo', COLOR.red), disabled: true, note: paint('[dilewati]', COLOR.red) };
          const v = Number(m[instId]) || 0;
          // Kolom CC cuma ditempel kalau token yg dikirim BUKAN CC — fee dibayar pakai CC,
          // jadi perlu kelihatan. Kalau tokennya CC sendiri, nempel lagi cuma bikin kembar.
          const detail = paint(`${token} ${v.toFixed(6).padStart(14)}`, COLOR.green)
            + (instId === 'Amulet' ? '' : paint(`   CC ${(Number(m.Amulet) || 0).toFixed(2).padStart(9)}`, COLOR.gray));
          const dust = v <= dustMin;
          return { label: (a.label || a.email).padEnd(20), detail, disabled: dust, note: paint(`[dust ≤ ${dustMin} — dilewati]`, COLOR.yellow) };
        });
        const chosen = await pickList({ title: `Transfer ${token} — pilih akun PENGIRIM:`, items, multi: true });
        if (!chosen.length) { process.stdout.write(paint('dibatalin.\n', COLOR.gray)); continue; }

        // 3) Tujuan + jumlah.
        process.stdout.write(paint('tujuan: partyId lengkap (hint::sidikjari), atau #N / label akun sendiri', COLOR.gray) + '\n');
        const to = (await prompt(paint('tujuan: ', COLOR.bold))).trim();
        const amount = (await prompt(paint(`jumlah ${token} (angka, atau ketik max buat kirim semua): `, COLOR.bold))).trim();

        // 4) Dry-run SEMUA akun dulu. Yang gagal validasi dibuang di sini, jadi gak ada
        //    akun yg baru ketahuan error setelah akun lain terlanjur kekirim.
        const okIdx = [];
        process.stdout.write('\n' + paint(`TAHAP 1/2 — PRATINJAU ${chosen.length} akun. Belum ada yang dikirim; konfirmasi diminta setelah ini.`, COLOR.bold + COLOR.cyan) + '\n');
        for (let k = 0; k < chosen.length; k++) {
          const i = chosen[k];
          process.stdout.write(paint(`\n[${k + 1}/${chosen.length}] ${ACCOUNTS[i].label || ACCOUNTS[i].email}`, COLOR.gray) + '\n');
          try { await transferToken({ idx: i, tokenArg: token, amountArg: amount, toArg: to, go: false }); okIdx.push(i); }
          catch (e) { process.stdout.write(paint(`  DILEWATI: ${(e && e.message) || e}`, COLOR.red) + '\n'); }
        }
        if (!okIdx.length) { console.error(paint('\ngak ada akun yg lolos cek — batal.', COLOR.red)); continue; }
        process.stdout.write('\n' + paint('─'.repeat(64), COLOR.yellow) + '\n');
        process.stdout.write(paint(`TAHAP 2/2 — KIRIM BENERAN (bukan dry-run lagi)`, COLOR.bold + COLOR.red) + '\n');
        process.stdout.write(paint(`  ${okIdx.length} akun · ${amount} ${token} per akun · tujuan ${to}`, COLOR.yellow) + '\n');
        process.stdout.write(paint(`  fee 16 CC per akun ≈ ${okIdx.length * 16} CC total`, COLOR.yellow) + '\n');
        process.stdout.write(paint('─'.repeat(64), COLOR.yellow) + '\n');
        const conf = (await prompt(paint(`Ketik ULANG jumlahnya ("${amount}") buat KIRIM, Enter buat batal: `, COLOR.bold + COLOR.yellow))).trim();
        if (conf !== amount) { process.stdout.write(paint('dibatalin — gak ada yg dikirim.\n', COLOR.gray)); continue; }

        let sukses = 0, gagal = 0;
        for (const i of okIdx) {
          try { await transferToken({ idx: i, tokenArg: token, amountArg: amount, toArg: to, go: true }); sukses++; }
          catch (e) { gagal++; process.stdout.write(paint(`  [${ACCOUNTS[i].label || ACCOUNTS[i].email}] GAGAL: ${(e && e.message) || e}`, COLOR.red) + '\n'); }
        }
        process.stdout.write('\n' + paint(`selesai — ${sukses} terkirim, ${gagal} gagal`, gagal ? COLOR.yellow : COLOR.green) + '\n');
        continue;
      }
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
      if (ans === '8' || ans === '8r') {
        // Ping-pong EDELx↔cETH, SEMUA akun, target-driven dari earn-hub (analog opsi 0/1:
        // dashboard + reschedule harian) via SESSION_ENGINE='pingpong'. Proses swap
        // token↔token (NO CC leg); fee CC terpisah. Parallel per config swap.parallel.
        // DUA JALUR TERPISAH — sengaja gak dicampur:
        //   8  = CLOB /terminal (orderbook). Butuh depth book; fee ~4.3 CC.
        //   8r = RFQ /swap AtomicDVP. LP nge-quote langsung; fee ~1.25 CC; tetap jalan
        //        waktu settlement CLOB mandek (kejadian 26/07 stage 2 seharian).
        PINGPONG_ROUTE = (ans === '8r') ? 'rfq' : 'clob';
        // Pasangan token, dipilih DUA TAHAP (asal lalu tujuan). Enter/q = pakai yg sekarang.
        try {
          const { sv: sv0 } = await buildSwapClients(makeStates()[0]);
          const pr = await pickTokenPair(sv0, { title: `Ping-pong (sekarang ${P8.market})` });
          if (pr) {
            M8.pair = { base: pr.base, quote: pr.quote };
            process.stdout.write(paint(`pasangan → ${P8.market} (mulai dari ${pr.from} → ${pr.to})\n`, COLOR.cyan));
          }
        } catch (e) { process.stdout.write(paint(`(daftar market gak kebaca: ${e.message}) — pakai ${P8.market}\n`, COLOR.yellow)); }
        // Target swap per akun. Kosong = ikut task earn-hub (berhenti di 10/10).
        // Isi angka > 10 = overcap: lanjut swap walau task udah penuh.
        {
          const t = (await prompt(paint('target swap per akun [Enter = ikut task 10/10, atau angka mis. 20]: ', COLOR.bold))).trim();
          const n = Number(t);
          if (t && Number.isFinite(n) && n > 0) {
            const msg = applyOvercapArg(['target=' + n]);
            if (msg) process.stdout.write(paint(msg + '\n', COLOR.yellow));
          }
        }
        SESSION_ENGINE = 'pingpong';
        parallelSwapActive = SWAP.parallel;
        process.stdout.write('\n' + paint(`Engine: PING-PONG EDELx↔cETH [${PINGPONG_ROUTE === 'rfq' ? 'jalur RFQ /swap' : 'jalur CLOB /terminal'}] — SEMUA akun${parallelSwapActive ? ` · PARALLEL x${SWAP.concurrency}` : ''}`, COLOR.bold + COLOR.cyan) + '\n');
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
      return;   // runMain ambil alih (dashboard + cron) — jangan balik ke menu
      }
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else {
    console.error(paint('cmd tidak dikenal: ' + argv[0] + '. Lihat: node index.js help', COLOR.red));
    process.exit(1);
  }
  // Ctrl+C: order GTD/GTC & settlement PENDING yang masih nyantol di-CANCEL dulu —
  // order yang ditinggalkan bisa ke-match ulang dan bikin settlement yatim, sedangkan
  // settlement PENDING ngegantung di akun. Dibatasi 20 detik; Ctrl+C kedua maksa keluar.
  let _sigint = 0;
  process.on('SIGINT', () => {
    if (++_sigint > 1) { process.stdout.write(paint('\npaksa keluar (masih ada yang belum di-cancel)\n', COLOR.yellow)); process.exit(1); }
    const pending = [...INFLIGHT.values()].reduce((n, e) => n + e.orders.size + e.proposals.size, 0);
    if (!pending) { process.stdout.write('\n' + paint('bye 👋', COLOR.gray) + '\n'); process.exit(0); }
    process.stdout.write('\n' + paint(`${pending} order/settlement nyantol → cancel dulu (Ctrl+C lagi = paksa)…`, COLOR.yellow) + '\n');
    const done = (n) => { process.stdout.write(paint(`✓ ${n} dibersihin — bye 👋\n`, COLOR.green)); process.exit(0); };
    const t = setTimeout(() => { process.stdout.write(paint('timeout 20s — keluar, sisanya bakal auto-expire / kesapu sesi berikutnya\n', COLOR.yellow)); process.exit(0); }, 20000);
    cancelInflight((m) => process.stdout.write(paint(m + '\n', COLOR.gray)))
      .then(n => { clearTimeout(t); done(n); })
      .catch(() => { clearTimeout(t); process.exit(0); });
  });
}
