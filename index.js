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
//                           Abaikan reserveCC; smart: tetap sisakan feeBufferCC buat fee.
const SWAP_MODE = String((CONFIG.swap || {}).mode || 'maxReserve').toLowerCase();
const SWAP_MIN_AMOUNT = Number((CONFIG.swap || {}).minAmount || SWAP_MIN);
const SWAP_MAX_AMOUNT = Number((CONFIG.swap || {}).maxAmount || 0); // 0 = tak terbatas
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
  market: 'CC-USDCx',
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
  privyAppId: PRIVY_APP_ID, privyClientId: PRIVY_CLIENT_ID,
  actionIds: {
    forecast: '40676c60700e9ed1236f944d4b41a08bcf91bc9ee2',
    getPrice: '40c4d9517caab6ab995effa94ac9d8b9f234b40cb9',
    estimateFee: '40fbe337a317ee196e4d662061e1cecb8aaa3006fe',
    acceptQuote: '40baa9946599cfdb0da587a64365c4e12945779e59',
    recordEvent: '40af5b2fb87c0eb585f00202017a4d682dbb5eae9a',
    listProposals: '400df0327d9072855e72c45c3fd49d7f93ebeedd4d',
    pollProposal: '40c101001b1336b46e42acc85c5ff73fe93ed9090d',
    getMultiCall: '40a8e24576d1a35a13da0935d1509e6ba3af10def5',
    getUserService: '409cbd8909b14c90e789a5596881a5739c3d38c243',
    prepareDvpFee: '4030273a5aedfa6bedc7a55a08d075991df400286b',
    prepareTransfer: '40c65525e31c405dd14f5ded8cefed4cfad27f096b',
    execSettle: '4041ab040bbaa5c3a983a0997382d0f1170c4e63f3',
    // Untuk allocate token registry (USDCx, dll) — bukan Splice Amulet.
    // Signature: getAllocationFactory(registry, choiceArgs).
    getAllocationFactory: '60e3c0527836f673bf65661fb34a8195a3a848964f',
    // Konfirmasi sisi pembeli/penjual setelah acceptQuote — INI yang trigger
    // generation DvpProposal di ledger Canton. Tanpa ini, polling timeout.
    submitPreconfirmation: '40af23346171bd93df282081a8bc847d682ecec9ff',
  },
  // Package ID untuk Splice.Api.Token.AllocationInstructionV1 — dipakai
  // saat membangun ExerciseCommand AllocationFactory_Allocate.
  allocationInstructionPackageId: '275064aacfe99cea72ee0c80563936129563776f67415ef9f13e4297eecbc520',
  templateIds: {
    dvpProposal: '#utility-settlement-app-v1:Utility.Settlement.App.V1.Model.Dvp:DvpProposal',
    amulet: '#splice-amulet:Splice.Amulet:Amulet',
    allocationFactory: '#utility-registry-app-v0:Utility.Registry.App.V0.Service.AllocationFactory:AllocationFactory',
    instrumentConfiguration: '#utility-registry-v0:Utility.Registry.V0.Configuration.Instrument:InstrumentConfiguration',
  },
};

// ---- UI constants ----
const HIDE_TOKENS = ['hecto', 'cbtc'];
// Token yang ditampilkan di dashboard (id Canton lowercase). 'amulet' = CC.
const SHOW_TOKENS = ['amulet', 'usdcx'];
// Label friendly utk display di dashboard
const TOKEN_LABEL = { amulet: 'CC', usdcx: 'USDCx' };
const MIN_ACTIVITY_LINES = 4;

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

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

function request(method, urlStr, opts = {}) {
  const { headers = {}, body = null, jar = null, timeoutMs = REQ.timeoutMs, proxy = null } = opts;
  return new Promise((resolve, reject) => {
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
  async activeContracts(templateId, opts = {}) {
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
const SWAP_STATE_TREE = encodeURIComponent(JSON.stringify(['', { children: ['swap', { children: ['__PAGE__', {}, null, null] }, null, null] }, null, null, true]));
// Server-action ID Silvana untuk discover party (POST /connect dari halaman /connect).
// Hasilkan { partyId, partyName, userServiceCid, ... } dari on-chain.
const CONNECT_RECOVER_ACTION = '40d678c69abe3b059b9ac71f04ee5e5b3393d56043';
const CONNECT_STATE_TREE = encodeURIComponent(JSON.stringify(['', { children: ['connect', { children: ['__PAGE__', {}, null, null] }, null, null] }, null, null, true]));

class SilvanaClient {
  constructor({ jar, timeoutMs = REQ.timeoutMs, proxy = null } = {}) { this.jar = jar || new CookieJar(); this.timeoutMs = timeoutMs; this.proxy = proxy; }
  _hdr(extra = {}) { return { 'User-Agent': UA, 'Accept': 'application/json, text/plain, */*', 'Accept-Language': 'en-US,en;q=0.9,id;q=0.8', 'Origin': APP_BASE, 'Referer': APP_BASE + '/', ...extra }; }
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
  async swapAction(actionId, args, { timeoutMs } = {}) {
    const r = await request('POST', `${APP_BASE}/swap`, this._opts({
      timeoutMs: timeoutMs || this.timeoutMs,
      headers: this._hdr({ 'Accept': 'text/x-component', 'Content-Type': 'text/plain;charset=UTF-8', 'Referer': APP_BASE + '/swap', 'next-action': actionId, 'next-router-state-tree': SWAP_STATE_TREE }),
      body: JSON.stringify(args || []),
    }));
    if (r.status === 401 || r.status === 403) { const e = new Error(`swapAction ${actionId} status=${r.status}`); e.unauthorized = true; throw e; }
    if (r.status !== 200) throw new Error(`swapAction ${actionId} status=${r.status} body=${(r.text || '').slice(0, 160)}`);
    return actionResult(r.text || '');
  }

  /**
   * Discover party Silvana on-chain (recover dari userService DSO contract).
   * Setara dengan klik halaman /connect di UI, dia balikin party termasuk
   * `userServiceCid` yang dibutuhkan untuk swap finalize.
   *
   * @param {string} partyId  e.g. 'supa1::1220abc...'
   * @returns {object|null}   { partyId, partyName, userServiceCid, ... }
   */
  async recoverParty(partyId) {
    if (!partyId) throw new Error('partyId required');
    const r = await request('POST', `${APP_BASE}/connect`, this._opts({
      timeoutMs: this.timeoutMs,
      headers: this._hdr({
        'Accept': 'text/x-component',
        'Content-Type': 'text/plain;charset=UTF-8',
        'Referer': APP_BASE + '/connect',
        'next-action': CONNECT_RECOVER_ACTION,
        'next-router-state-tree': CONNECT_STATE_TREE,
      }),
      body: JSON.stringify([partyId]),
    }));
    if (r.status === 401 || r.status === 403) { const e = new Error(`connect recover status=${r.status}`); e.unauthorized = true; throw e; }
    if (r.status !== 200) throw new Error(`connect recover status=${r.status} body=${(r.text || '').slice(0, 160)}`);
    const result = actionResult(r.text || '');
    if (result && result.success && result.party) return result.party;
    return null;
  }

  /**
   * Get AllocationFactory + choiceContext untuk allocate utility token (USDCx, dll).
   * Mengembalikan { factoryId, choiceContextData, disclosedContracts }.
   *
   * Hanya untuk utility/registry token (non-Splice). Untuk CC/Amulet,
   * pakai `prepareTransfer` (getTransferFactoryContextAction) yang biasa.
   */
  async getAllocationFactory(registryParty, choiceArgs) {
    const r = await request('POST', `${APP_BASE}/swap`, this._opts({
      timeoutMs: this.timeoutMs,
      headers: this._hdr({
        'Accept': 'text/x-component',
        'Content-Type': 'text/plain;charset=UTF-8',
        'Referer': APP_BASE + '/swap',
        'next-action': SWAP.actionIds.getAllocationFactory,
        'next-router-state-tree': SWAP_STATE_TREE,
      }),
      body: JSON.stringify([registryParty, choiceArgs]),
    }));
    if (r.status === 401 || r.status === 403) { const e = new Error(`getAllocationFactory status=${r.status}`); e.unauthorized = true; throw e; }
    if (r.status !== 200) throw new Error(`getAllocationFactory status=${r.status} body=${(r.text || '').slice(0, 160)}`);
    const result = actionResult(r.text || '');
    if (!result || !result.success || !result.factory) {
      throw new Error(`getAllocationFactory: ${(result && result.error) || 'no factory'}`);
    }
    return {
      factoryId: result.factory.factoryId,
      choiceContextData: result.factory.choiceContext.choiceContextData,
      disclosedContracts: result.factory.choiceContext.disclosedContracts || [],
    };
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
function loadCookies(email) { return acctSession(email).silvanaCookies || {}; }
function saveCookies(email, obj) { patchAcctSession(email, { silvanaCookies: obj }); }
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

// terminal prompt (OTP manual)
function prompt(question) {
  return new Promise((resolve) => {
    global.__paused = true;
    if (useColor) process.stdout.write('\x1b[?25h');
    process.stdout.write('\n\n' + question);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.on('line', (ans) => { rl.close(); global.__paused = false; resolve((ans || '').trim()); });
  });
}

// Pastikan ada identity token Privy yang valid utk akun (refresh / OTP bila perlu).
// Disimpan di session.json[email].privy. OTP dikirim ke privyEmail.
async function ensurePrivyToken(state) {
  const email = state.email;
  const privyEmail = state.privyEmail || email;
  const proxy = pickProxy(privyEmail);
  state.proxyHost = proxy ? `${proxy.host}:${proxy.port}` : null;

  const cached = getValidPrivySession(email);
  if (cached) { state.tokenExpMs = cached.expMs; state.identityExpMs = cached.identityExpMs; return cached.token; }

  const old = acctSession(email).privy;
  if (old && old.refresh_token) {
    const maxRetry = 20, baseDelay = 2000; let lastErr = null;
    for (let attempt = 1; attempt <= maxRetry; attempt++) {
      state.status = 'login'; state.message = `refresh privy (${attempt}/${maxRetry})`; render(global.__states);
      try {
        const fresh = await privyRefreshSession(old.refresh_token, old.privy_access_token, proxy);
        const sess = putPrivySession(email, { ...fresh, token: fresh.token || old.token, refresh_token: fresh.refresh_token || old.refresh_token });
        state.tokenExpMs = sess.expMs; state.identityExpMs = sess.identityExpMs; state.message = '';
        return sess.token;
      } catch (e) {
        lastErr = e;
        if (e && (e.unauthorized || e.notRefreshable)) break; // refresh tak guna → OTP
        if (attempt < maxRetry) { await sleep(Math.min(30_000, baseDelay * Math.min(8, attempt))); }
      }
    }
    if (lastErr) { state.message = `refresh gagal: ${(lastErr.message || '').slice(0, 40)}`; render(global.__states); }
  }

  // OTP manual (IMAP dihapus)
  state.status = 'login'; state.message = 'kirim OTP'; render(global.__states);
  await withRetry(() => privyInit(privyEmail, proxy), 'init OTP', { retry: REQ.retry, delayMs: REQ.retryDelayMs });
  const code = await prompt(`OTP Privy untuk ${privyEmail}: `);
  if (!/^\d{4,8}$/.test(code)) throw new Error('format OTP tidak valid');
  const auth = await withRetry(() => privyAuthenticate(privyEmail, code, proxy), 'authenticate', { retry: REQ.retry, delayMs: REQ.retryDelayMs });
  const sess = putPrivySession(email, auth);
  state.tokenExpMs = sess.expMs; state.identityExpMs = sess.identityExpMs; state.message = '';
  return sess.token;
}

// Pastikan sesi Silvana (cookie) hidup; re-login passkey (dari session.json) bila perlu.
async function ensureSilvanaSession(state) {
  const email = state.email;
  const pk = getPasskey(email);
  if (!pk) return null;
  const proxy = pickProxy(email);
  const jar = new CookieJar(loadCookies(email));
  const client = new SilvanaClient({ jar, timeoutMs: REQ.timeoutMs, proxy });
  // Cek expiry cookie proaktif: kalau sisa > 10 menit, validasi via authMe.
  // Kalau sisa < 10 menit (atau gak ada), langsung re-login passkey.
  const SAFETY_MS = 600_000;
  const exp = silvanaAccessExpMs(email);
  const stillFresh = exp && (exp - Date.now() > SAFETY_MS);
  if (stillFresh) {
    try {
      const me = await client.authMe();
      if (me.authenticated && me.user) { state.silvanaUser = me.user.email || me.user.firstName || 'ok'; saveCookies(email, jar.toObject()); state.silvanaExpMs = silvanaAccessExpMs(email); return client; }
    } catch (_) { }
  }
  state.status = 'login'; state.message = 'silvana re-login passkey'; render(global.__states);
  jar.clear();
  const privateJwk = (typeof pk.privateJwk === 'string') ? JSON.parse(pk.privateJwk) : pk.privateJwk;
  const result = await withRetry(() => client.loginWithPasskey({ email, credentialId: pk.credentialId, userHandle: pk.userHandle, privateJwk }), 'silvana login', { retry: REQ.retry, delayMs: REQ.retryDelayMs });
  state.silvanaUser = (result.user && (result.user.email || result.user.firstName)) || 'ok';
  saveCookies(email, jar.toObject());
  state.silvanaExpMs = silvanaAccessExpMs(email);
  return client;
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
/**
 * Mirror dari frontend Silvana `buildAllocationChoiceArguments`.
 * Membangun struktur arg untuk action `getAllocationFactory` & multi-call.
 */
function buildAllocationChoiceArguments(p) {
  return {
    allocation: {
      settlement: {
        executor: p.settlementOperator,
        settlementRef: { id: p.settlementId, cid: null },
        requestedAt: p.requestedAt,
        allocateBefore: p.allocateBefore,
        settleBefore: p.settleBefore,
        meta: { values: {} },
      },
      transferLegId: p.isBuyer ? '2' : '1',
      transferLeg: {
        sender: p.partyId,
        receiver: p.counterpartyId,
        instrumentId: { admin: p.registryParty, id: p.tokenId },
        amount: p.amount,
        meta: { values: {} },
      },
    },
    inputHoldingCids: p.inputHoldingCids,
    expectedAdmin: p.registryParty,
    extraArgs: { context: { values: {} }, meta: { values: {} } },
    requestedAt: p.requestedAt,
  };
}
async function swapOnce(ctx, direction, quantityCC) {
  let { sv, privy, canton, partyId, userServiceCid, log = () => { }, shouldContinue, onWait } = ctx;
  if (!userServiceCid) throw new Error('userServiceCid belum ada — auto-discovery gagal, cek koneksi/passkey');
  const A = SWAP.actionIds, market = SWAP.market, amount = String(quantityCC), dso = SWAP.dsoPartyId;
  const role = direction === 'sell' ? 'seller' : 'buyer';
  const dirID = direction === 'sell' ? 'jual CC' : 'beli CC';

  const price = await sv.swapAction(A.getPrice, [market]).catch(() => null);
  const px = price && price.data ? String(direction === 'sell' ? price.data.bid : price.data.ask) : '0';
  // FEE PROTECTION (early gate): cek estimasi fee SEBELUM bikin proposal on-chain.
  // Kalau fee > maxFeeCC, batal di sini — gak ada DvpProposal nyangkut.
  const feeEst = await sv.swapAction(A.estimateFee, [{ partyId, marketId: market, baseQuantity: amount, price: px }]).catch(() => null);
  const estFeeCC = extractFeeCC(feeEst);
  if (estFeeCC != null) {
    log(`Estimasi fee ${dirID}: ${estFeeCC} CC (batas ${SWAP.maxFeeCC})`);
    if (estFeeCC > Number(SWAP.maxFeeCC) && !ctx.dryRun) {
      logDebug('fee spike (estimateFee) — abort sebelum proposal', { estFeeCC, max: SWAP.maxFeeCC, feeEst });
      const e = new Error(`fee ${estFeeCC} CC > batas ${SWAP.maxFeeCC} CC`);
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
    log(`Fee quote ${dirID} (${quote.lpName || 'LP'}): ${quoteFeeCC} CC (batas ${SWAP.maxFeeCC})`);
    if (quoteFeeCC > Number(SWAP.maxFeeCC) && !ctx.dryRun) {
      logDebug('fee spike (quote) — abort sebelum acceptQuote', { quoteFeeCC, max: SWAP.maxFeeCC, quote });
      const e = new Error(`fee ${quoteFeeCC} CC > batas ${SWAP.maxFeeCC} CC`);
      e.feeSpike = true; e.feeCC = quoteFeeCC;
      throw e;
    }
  }

  const acc = await sv.swapAction(A.acceptQuote, [{ partyId, rfqId: rfq.rfqId, quoteId: quote.quoteId || quote.id }]);
  if (!acc || !acc.proposalId) throw new Error(`acceptQuote gagal: ${JSON.stringify(acc).slice(0, 120)}`);
  const proposalId = acc.proposalId;

  // Submit preconfirmation — INI trigger generation DvpProposal di ledger.
  // Tanpa step ini, polling DvpProposal akan timeout selamanya.
  const pre = await sv.swapAction(A.submitPreconfirmation, [{
    proposalId, settlementId: proposalId, partyId, accept: true,
  }]);
  logDebug('submitPreconfirmation response', pre);
  if (!pre || pre.success === false) {
    throw new Error(`submitPreconfirmation gagal: ${(pre && pre.error) || 'unknown'}`);
  }

  await sv.swapAction(A.recordEvent, [{ partyId, recordedByRole: role, eventType: `preconfirmation_${role}`, result: 'success', proposalId, metadata: { accept: true, source: 'rfq_accept' } }]).catch(() => { });

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
  for (let i = 0; i < SWAP.pollMaxTries; i++) {
    const list = await canton.activeContracts(SWAP.templateIds.dvpProposal).catch(() => []);
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
    if (i === 0) log('Menunggu DvpProposal muncul di ledger…');
    await sleep(SWAP.pollIntervalMs);
  }
  if (!dvp) {
    logDebug(`DvpProposal lookup failed`, { proposalId, dvpCid, activeCount: lastCount });
    throw new Error(`DvpProposal tidak ditemukan di ledger (dvpCid=${dvpCid.slice(0, 12)}.., active=${lastCount})`);
  }

  const deliv = dvp.terms.deliveries[0], pay = dvp.terms.payments[0], weAreBuyer = (direction === 'buy');
  const ourLeg = weAreBuyer ? { instrument: pay.instrument, amount: pay.amount, legId: '2' } : { instrument: deliv.instrument, amount: deliv.amount, legId: '1' };
  const receiver = dvp.proposer;

  const amulets = await canton.activeContracts(SWAP.templateIds.amulet);
  const ccNeed = weAreBuyer ? SWAP.feeBufferCC : addDp(amount, SWAP.feeBufferCC);
  const inputHoldingCids = selectCcHoldings(amulets, ccNeed);

  const feeCtx = await sv.swapAction(A.prepareDvpFee, [{ partyId, feeType: 'dvp_contract', role, proposalId, inputHoldingCids }]);
  if (!feeCtx || !feeCtx.choiceContextData) throw new Error('prepareDvpFee gagal');

  // FEE PROTECTION (authoritative): feeCtx punya angka fee CC sebenarnya.
  // Batalkan SEBELUM execSettle/prepare/submit → belum ada CC kebayar.
  const realFeeCC = Number(addDp(feeCtx.feeAmountCC || '0', feeCtx.counterpartFeeAmountCC || '0'));
  if (Number.isFinite(realFeeCC)) {
    log(`Fee ${dirID}: ${realFeeCC} CC (batas ${SWAP.maxFeeCC})`);
    if (realFeeCC > Number(SWAP.maxFeeCC) && !ctx.dryRun) {
      logDebug('fee spike (feeCtx) — abort sebelum submit', { realFeeCC, max: SWAP.maxFeeCC });
      const e = new Error(`fee ${realFeeCC} CC > batas ${SWAP.maxFeeCC} CC`);
      e.feeSpike = true; e.feeCC = realFeeCC;
      throw e;
    }
  }

  // DRY-RUN: stop SEBELUM execSettle/submit. Belum ada CC kebayar (cuma proposal
  // nyangkut, auto-expire 12 jam). Laporkan ke-3 angka fee buat verifikasi.
  if (ctx.dryRun) {
    const fees = { estFeeCC, quoteFeeCC, realFeeCC, lp: (quote && quote.lpName) || 'LP' };
    log(`[DRY-RUN] estimateFee=${estFeeCC} | quote(${fees.lp})=${quoteFeeCC} | feeCtx REAL=${realFeeCC} | batas=${SWAP.maxFeeCC}`);
    const e = new Error('dry-run: stop sebelum submit (0 CC kebayar)');
    e.dryRun = true; e.fees = fees;
    throw e;
  }

  // execSettle HARUS dipanggil SEBELUM prepare_transaction (terbukti di 14/14
  // HAR manual yg sukses: prepareDvpFee → execSettle → prepareTransfer → prepare).
  // Ini yg menyiapkan/men-trigger eksekusi settlement di sisi Silvana. Tanpa ini
  // tx Canton tetap ke-submit (valid) TAPI DvP gak pernah finalize → DAY_TRADER
  // gak naik → bot keliatan "stuck submitted tapi gak settle".
  const es = await sv.swapAction(A.execSettle, [{ proposalId, partyId }]).catch(e => ({ _err: (e && e.message) || String(e) }));
  logDebug('execSettle (pre-prepare) response', es);
  if (es && es._err) log(`⚠ execSettle gagal: ${es._err}`);
  else if (es && es.success === false) log('⚠ execSettle success=false');

  let allocate;
  if (weAreBuyer) {
    // Untuk buy: kita bayar USDCx (utility token, bukan Amulet/CC).
    // Path-nya beda: pakai getAllocationFactory + buildAllocationChoiceArguments,
    // bukan prepareTransfer (yang khusus Splice Amulet).
    const bal = await supaBalances(ctx.identityToken || canton.token, ctx.proxy || null);
    const usdcxToken = ((bal && bal.tokens) || []).find(t => String((t.instrumentId && t.instrumentId.id) || '').toUpperCase() === 'USDCX');
    const usdcxHoldings = (usdcxToken && usdcxToken.unlockedUtxos || []).map(u => u.contractId).filter(Boolean);
    if (!usdcxHoldings.length) throw new Error('tidak ada USDCx holding untuk swap buy');
    // Pre-check: balance USDCx total harus ≥ amount yg mau dialokasi
    const totalUsdcx = (usdcxToken.unlockedUtxos || []).reduce((s, u) => s + Number(u.amount || 0), 0);
    const needUsdcx = Number(ourLeg.amount);
    if (totalUsdcx < needUsdcx) {
      const e = new Error(`USDCx kurang: butuh ${needUsdcx.toFixed(4)} hanya punya ${totalUsdcx.toFixed(4)}`);
      e.insufficientBalance = true;
      throw e;
    }

    // Gabungkan CC (untuk fee) + USDCx (untuk allocation) di inputHoldings MultiCall
    for (const h of usdcxHoldings) { if (!inputHoldingCids.includes(h)) inputHoldingCids.push(h); }

    // Build choice args (mirror persis frontend Silvana)
    const choiceArgs = buildAllocationChoiceArguments({
      partyId,
      tokenId: ourLeg.instrument.id,                   // 'USDCx'
      registryParty: ourLeg.instrument.admin,           // decentralized-usdc-...
      amount: fmt10(ourLeg.amount),
      settlementId: proposalId,
      settlementOperator: dvp.executor,
      counterpartyId: receiver,
      isBuyer: true,
      requestedAt: dvp.terms.createdAt,
      allocateBefore: dvp.terms.allocateBefore,
      settleBefore: dvp.terms.settleBefore,
      inputHoldingCids: usdcxHoldings,
    });

    // Server-action: get factory + choice context
    const fac = await sv.getAllocationFactory(ourLeg.instrument.admin, choiceArgs);
    if (!fac || !fac.factoryId) throw new Error('getAllocationFactory tidak balikin factory');

    // Pastikan disclosed contracts punya synchronizerId (server kadang kosongkan)
    const disclosed = (fac.disclosedContracts || []).map(d => ({
      ...d,
      synchronizerId: d.synchronizerId || SWAP.synchronizerId,
    }));

    allocate = {
      instrument: ourLeg.instrument,
      amount: ourLeg.amount,
      legId: ourLeg.legId,
      factoryCid: fac.factoryId,
      contextValues: (fac.choiceContextData && fac.choiceContextData.values) || {},
      disclosed,
    };
  } else {
    const t = await sv.swapAction(A.prepareTransfer, [{ sender: partyId, receiver, amount: ourLeg.amount, instrumentId: ourLeg.instrument, inputHoldingCids }]);
    if (!t || !t.factoryId) throw new Error('prepareTransfer gagal');
    allocate = { instrument: ourLeg.instrument, amount: ourLeg.amount, legId: ourLeg.legId, factoryCid: t.factoryId, contextValues: t.choiceContextData.values, disclosed: t.disclosedContracts };
  }

  const body = buildMultiCallAccept({ party: partyId, inputHoldingCids, multiCall, userServiceCid, feeCtx, proposalId, dvpProposalCid: dvpCid, dvpTerms: dvp.terms, executor: dvp.executor, receiver, dso, allocate });
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
  // (execSettle sudah dipanggil SEBELUM prepare_transaction — lihat di atas.
  //  Tidak dipanggil lagi di sini; di flow manual web hanya 1x, pre-prepare.)
  return { ok: true, direction, proposalId, submissionId: sub.submissionId, completed: !!completion };
}

// ============================================================================
//  Dashboard (ANSI, adaptif tmux)
// ============================================================================
const useColor = process.stdout.isTTY !== false;
const c = (code) => useColor ? `\x1b[${code}m` : '';
const COLOR = { reset: c(0), dim: c(2), bold: c(1), red: c(31), green: c(32), yellow: c(33), blue: c(34), mag: c(35), cyan: c(36), white: c(37), gray: c(90) };
const paint = (txt, ...codes) => codes.join('') + txt + COLOR.reset;
function visLen(s) { return s.replace(/\x1b\[[0-9;]*m/g, '').length; }
function pad(s, w, side = 'right') { const len = visLen(s); if (len >= w) return s; const sp = ' '.repeat(w - len); return side === 'right' ? s + sp : sp + s; }

let W = 44, ROWS = 24;
function computeLayout() {
  const cols = process.stdout.columns || 0, rows = process.stdout.rows || 0;
  ROWS = rows > 0 ? rows : 24;
  W = cols > 0 ? Math.max(30, Math.min(cols, 100)) : 44;
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
function progressBar(cur, max, width = 12) { const filled = max > 0 ? Math.max(0, Math.min(width, Math.round((cur / max) * width))) : 0; return paint('▓'.repeat(filled), COLOR.green) + paint('░'.repeat(width - filled), COLOR.gray); }
/** Format sisa waktu sampai expMs jadi "47m" / "2h" / "expired" */
function expIn(expMs) {
  if (!expMs) return paint('-', COLOR.gray);
  const ms = Number(expMs) - Date.now();
  if (ms <= 0) return paint('expired', COLOR.red);
  const m = Math.round(ms / 60000);
  if (m < 60) return paint(m + 'm', m < 5 ? COLOR.yellow : COLOR.cyan);
  const h = Math.round(m / 60);
  if (h < 48) return paint(h + 'h', COLOR.cyan);
  return paint(Math.round(h / 24) + 'd', COLOR.cyan);
}
/** Render dua field, KEDUANYA rata kiri dengan gap tetap. Kalau gak muat,
 *  tumpuk jadi dua baris (tetap rata kiri). */
function row2(left, right) {
  const inner = W - 4; // total inner width tanpa border
  const GAP = 3;
  if (visLen(left) + GAP + visLen(right) <= inner) {
    return row(left + ' '.repeat(GAP) + right);
  }
  return row(left) + '\n' + row(right); // gak muat → tumpuk, dua-duanya rata kiri
}

function renderHeader() {
  return [line(), row(paint('SilvanaBot V1.1 Auto Swap ', COLOR.bold + COLOR.cyan)), row(paint(new Date().toLocaleString('id-ID'), COLOR.gray))].join('\n');
}
function statusBadge(state) {
  const d = state.dayTrader;
  if (state.status === 'error') return paint('● Error', COLOR.red);
  if (d && d.count >= d.target) return paint('● Selesai ✓', COLOR.green);
  if (dtSessionRunning) return paint('● Swap…', COLOR.yellow);
  if (state.status === 'login') return paint('● Login…', COLOR.yellow);
  if (state.status === 'ok') return paint('● Aktif', COLOR.green);
  return paint('● Siap', COLOR.gray);
}
function renderAccount(state) {
  const lines = [sep()];
  // baris 1: label kiri, status kanan
  lines.push(row2(paint(state.label || '-', COLOR.bold), statusBadge(state)));

  // baris 2: progress kiri, count kanan
  const d = state.dayTrader;
  if (d) {
    const left = progressBar(d.count, d.target);
    const right = paint(`${d.count}/${d.target}`, d.count >= d.target ? COLOR.green : COLOR.bold) + paint(' swap', COLOR.gray);
    lines.push(row2(left, right));
  } else {
    lines.push(row(paint('DAY_TRADER  —  (memuat…)', COLOR.gray)));
  }

  // baris balance: CC | USDCx (2 kolom)
  const bals = (Array.isArray(state.balances) ? state.balances : []).filter(b => {
    const id = String((b.instrumentId && b.instrumentId.id) || '').toLowerCase();
    if (HIDE_TOKENS.includes(id)) return false;
    return SHOW_TOKENS.length ? SHOW_TOKENS.includes(id) : true;
  });
  const balCells = bals.map(b => {
    const rawId = (b.instrumentId && b.instrumentId.id) || '?';
    const label = TOKEN_LABEL[String(rawId).toLowerCase()] || rawId;
    const unlocked = Number(b.totalUnlockedBalance ?? b.totalBalance ?? 0);
    const total = Number(b.totalBalance ?? 0);
    const locked = total - unlocked;
    let s = paint(label, COLOR.bold) + paint(' ', COLOR.gray) + paint(fmtNum(unlocked), COLOR.green);
    if (locked > 1e-8) s += paint(' (+' + fmtNum(locked) + ')', COLOR.gray);
    return s;
  });
  if (balCells.length === 2) {
    lines.push(row2(balCells[0], balCells[1]));
  } else {
    balCells.forEach(c => lines.push(row(c)));
  }

  // baris session info: silv expiry kiri, supa expiry kanan
  const silv = expIn(state.silvanaExpMs);
  const supa = expIn(state.tokenExpMs);
  lines.push(row2(
    paint('silv ', COLOR.gray) + silv,
    paint('supa ', COLOR.gray) + supa
  ));

  if (state.status === 'error' && state.message) lines.push(row(paint('⚠ ' + state.message, COLOR.red)));
  return lines.join('\n');
}
function renderFooter() {
  const jam = String(SCHED.hour).padStart(2, '0') + ':' + String(SCHED.minute).padStart(2, '0');
  return [sep(), row(paint('Jadwal harian ', COLOR.gray) + paint(jam + ' WIB', COLOR.cyan) + paint('   ·   Ctrl+C berhenti', COLOR.gray))].join('\n');
}
const ACTIVITY = []; const ACTIVITY_MAX = 1000;
const DEBUG_LOG_PATH = path.join(ROOT, 'swap-debug.log');
function logDebug(label, data) {
  try {
    const line = `[${new Date().toISOString()}] ${label}\n${typeof data === 'string' ? data : JSON.stringify(data, null, 2)}\n\n`;
    fs.appendFileSync(DEBUG_LOG_PATH, line);
  } catch (_) { }
}
function logActivity(msg, color) {
  const ts = new Date().toLocaleTimeString('id-ID');
  ACTIVITY.push(paint(ts + ' ', COLOR.gray) + (color ? paint(msg, color) : msg));
  if (ACTIVITY.length > ACTIVITY_MAX) ACTIVITY.splice(0, ACTIVITY.length - ACTIVITY_MAX);
  if (global.__states) render(global.__states);
}
function renderActivityLog(maxLines) {
  const lines = [sep(), row(paint('▎ aktivitas', COLOR.bold + COLOR.cyan))];
  const slice = ACTIVITY.slice(-Math.max(1, maxLines));
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
  states.forEach(s => out.push(renderAccount(s)));
  out.push(renderFooter());
  const used = out.join('\n').split('\n').length;
  const avail = Math.max(MIN_ACTIVITY_LINES, ROWS - used - 3);
  out.push(renderActivityLog(avail));
  process.stdout.write(out.join('\n') + '\n');
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
      const dt = parseDayTrader(tasks && tasks.items);
      if (dt) state.dayTrader = { count: dt.current, target: dt.target };
    }
    state.status = 'ok'; state.message = '';
  } catch (e) { state.status = 'error'; state.message = (e && e.message) || String(e); }
  render(global.__states);
}
async function tickAll(states) { for (const s of states) await tickAccount(s); }

// ============================================================================
//  DAY_TRADER engine — API-driven, anti-overcap (no local count file)
// ============================================================================
let dtSessionRunning = false;
function makeStates() {
  return ACCOUNTS.map((a, i) => ({ label: a.label || `akun-${i + 1}`, email: a.email, privyEmail: a.privyEmail || null, status: 'idle', message: '', balances: null, dayTrader: null }));
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
  const proxy = pickProxy(state.privyEmail || email);
  const identityToken = await ensurePrivyToken(state);
  const pat = (acctSession(email).privy || {}).privy_access_token;
  if (!pat) throw new Error('privy_access_token tidak ada di session');
  const sv = await ensureSilvanaSession(state);
  if (!sv) throw new Error('passkey belum di-set (paste dulu)');
  const me = await supaMe(identityToken, proxy);
  const partyId = me.data && me.data.partyId;
  if (!partyId) throw new Error('partyId tidak ditemukan');

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

  const canton = new CantonClient({ token: identityToken, timeoutMs: REQ.timeoutMs, proxy });
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
  const list = await sv.swapAction(SWAP.actionIds.listProposals, [partyId]).catch(() => null);
  if (!list || !Array.isArray(list.proposals)) return [];
  const now = Date.now();
  const out = [];
  for (const p of list.proposals) {
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
/**
 * Reject proposal nyangkut yg AMAN dibuang: stage<9 (belum settle), belum
 * rejected, DAN alloc sisi kita kosong (0 dana kita ke-lock). Ini sampah dari
 * abort fee-spike / feecheck — preconfirmed tapi gak pernah allocate.
 * Reject via submitPreconfirmation accept:false. NEVER sentuh yg dana kita
 * kekunci (LOCKED) atau udah SETTLED — itu bisa bikin rugi.
 * Return jumlah yg berhasil di-reject.
 */
async function cleanupStaleProposals(sv, partyId, log = () => { }) {
  const raw = await sv.swapAction(SWAP.actionIds.listProposals, [partyId]).catch(() => null);
  const all = (raw && Array.isArray(raw.proposals)) ? raw.proposals : [];
  let rejected = 0;
  for (const p of all) {
    const st = await sv.swapAction(SWAP.actionIds.pollProposal, [{ settlementId: p.proposalId, partyId }]).catch(() => null);
    if (!st) continue;
    const stage = st.stage || 0;
    if (stage >= 9) continue;                                   // settled — jangan sentuh
    if (st.buyerRejected || st.sellerRejected) continue;        // udah rejected
    const isBuyer = p.buyer === partyId;
    const ourAlloc = isBuyer ? st.allocationBuyerCid : st.allocationSellerCid;
    if (ourAlloc && ourAlloc !== '$undefined') continue;       // dana kita kekunci — SKIP
    const role = isBuyer ? 'buyer' : 'seller';
    const r = await sv.swapAction(SWAP.actionIds.submitPreconfirmation, [{
      proposalId: p.proposalId, settlementId: p.proposalId, partyId, accept: false,
    }]).catch(e => ({ _err: (e && e.message) || String(e) }));
    if (r && !r._err && r.success !== false) {
      rejected++;
      await sv.swapAction(SWAP.actionIds.recordEvent, [{ partyId, recordedByRole: role, eventType: `preconfirmation_${role}`, result: 'rejected', proposalId: p.proposalId, metadata: { accept: false, source: 'cleanup' } }]).catch(() => { });
      log(`  rejected ${p.proposalId.slice(0, 16)}… (stage ${stage}, ${isBuyer ? 'BUY' : 'SELL'} ${p.baseQuantity})`, COLOR.yellow);
    } else {
      log(`  gagal reject ${p.proposalId.slice(0, 16)}…: ${(r && r._err) || (r && r.error) || 'unknown'}`, COLOR.red);
    }
  }
  return rejected;
}
// fetch saldo → update state.balances (utk dashboard) + return saldo USDCx unlocked
async function refreshBalances(state, token, proxy) {
  try {
    const b = await supaBalances(token, proxy);
    if (b && b.tokens) state.balances = b.tokens;
    const t = (b && b.tokens || []).find(x => String((x.instrumentId && x.instrumentId.id) || '').toUpperCase() === 'USDCX');
    return t ? Number(t.totalUnlockedBalance || t.totalBalance || 0) : 0;
  } catch (_) { return 0; }
}
// CC (Amulet) unlocked dari state.balances yg terakhir di-refresh.
function ccUnlockedFrom(state) {
  const t = (Array.isArray(state.balances) ? state.balances : []).find(x => String((x.instrumentId && x.instrumentId.id) || '').toUpperCase() === 'AMULET');
  return t ? Number(t.totalUnlockedBalance || t.totalBalance || 0) : 0;
}
async function runDayTraderSession(reason) {
  if (dtSessionRunning) { logActivity(`Sesi masih berjalan, lewati (${reason || ''})`, COLOR.gray); return; }
  dtSessionRunning = true;
  logActivity(`Mulai cek & auto-swap (${reason || 'manual'})`, COLOR.cyan);
  try {
    for (let i = 0; i < ACCOUNTS.length; i++) {
      const a = ACCOUNTS[i], tag = a.label || a.email;
      const state = (global.__states && global.__states[i]) || makeStates()[i];
      try {
        state.status = 'login'; render(global.__states);
        let clients = await buildSwapClients(state);
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
        await refreshBalances(state, identityToken, proxy); render(global.__states);

        // Auto-cleanup sampah proposal nyangkut (0 dana kelock) dari sesi/feecheck
        // sebelumnya. Cegah numpuk + unlock balance kalau ada yg stale.
        const cleaned = await cleanupStaleProposals(sv, partyId).catch(() => 0);
        if (cleaned) logActivity(`[${tag}] cleanup ${cleaned} proposal nyangkut (0 dana kelock)`, COLOR.gray);

        const dt = await fetchDayTrader(sv, partyId);
        if (!dt) { logActivity(`[${tag}] DAY_TRADER tak terbaca dari API → tidak swap`, COLOR.yellow); continue; }
        state.dayTrader = { count: dt.current, target: dt.target }; render(global.__states);
        if (dt.completed || dt.current >= dt.target) { logActivity(`[${tag}] DAY_TRADER ${dt.current}/${dt.target} sudah penuh ✓`, COLOR.green); continue; }

        const need = dt.target - dt.current; // ANTI-OVERCAP: jumlah swap pasti dari API
        logActivity(`[${tag}] DAY_TRADER ${dt.current}/${dt.target} — perlu ${need} swap lagi`, COLOR.cyan);

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

          const chk = await fetchDayTrader(sv, partyId).catch(() => null);
          if (chk) { state.dayTrader = { count: chk.current, target: chk.target }; render(global.__states); if (chk.completed || chk.current >= chk.target) { logActivity(`[${tag}] DAY_TRADER ${chk.current}/${chk.target} ✓ — berhenti`, COLOR.green); break; } }

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
            const priceRes = await sv.swapAction(SWAP.actionIds.getPrice, [SWAP.market]).catch(() => null);
            ask = (priceRes && priceRes.data && Number(priceRes.data.ask)) || 0;
          } catch (_) { ask = 0; }

          const usdcxBudget = usdc * 0.95;                            // buffer slippage/fee
          const buyCapCC = ask > 0 ? floor4(usdcxBudget / ask) : 0;    // kapasitas CC dari USDCx
          const feeBuf = Math.max(0, Number(SWAP.feeBufferCC) || 0);   // CC disisain buat fee (smart)
          const maxAmt = SWAP_MAX_AMOUNT > 0 ? SWAP_MAX_AMOUNT : Infinity;

          // Hitung amount per mode.
          //   maxReserve: rata kanan, sisakan reserveCC, di-cap maxAmount per swap.
          //   minmax:     amount ACAK [minAmount..maxAmount], abaikan reserve, sisakan feeBufferCC.
          let maxSellCC, maxBuyCC, canSell, canBuy, modeLabel;
          if (SWAP_MODE === 'minmax') {
            // floor batas bawah = minAmount, batas atas = maxAmount (atau saldo).
            const lo = Math.max(0, SWAP_MIN_AMOUNT);
            const hi = SWAP_MAX_AMOUNT > 0 ? Math.max(lo, SWAP_MAX_AMOUNT) : lo;
            const target = floor4(lo + Math.random() * (hi - lo)); // acak per swap
            const sellCapCC = floor4(ccUnlocked - feeBuf);         // sisakan CC buat fee
            maxSellCC = floor4(Math.min(target, sellCapCC));
            maxBuyCC = floor4(Math.min(target, buyCapCC));
            canSell = sellCapCC >= lo && maxSellCC >= minSwap;
            canBuy = buyCapCC >= lo && maxBuyCC >= minSwap && ccUnlocked >= feeBuf;
            modeLabel = `minmax ${lo}..${SWAP_MAX_AMOUNT || '∞'}`;
          } else {
            // maxReserve (default): rata kanan, cap maxAmount.
            maxSellCC = floor4(Math.min(ccUnlocked - reserve, maxAmt));
            maxBuyCC = floor4(Math.min(buyCapCC, maxAmt));
            canSell = maxSellCC >= minSwap;
            canBuy = maxBuyCC >= minSwap && ccUnlocked >= reserve; // perlu CC buat fee
            modeLabel = `maxReserve cap ${SWAP_MAX_AMOUNT || '∞'} sisa ${reserve}`;
          }

          let amountCC, direction;
          const forcedDir = global.__forceDir || SWAP.forceDirection || null;
          if (forcedDir === 'sell') { direction = 'sell'; amountCC = String(maxSellCC); logActivity(`[${tag}] arah dipaksa: sell (override)`, COLOR.gray); }
          else if (forcedDir === 'buy') { direction = 'buy'; amountCC = String(maxBuyCC); logActivity(`[${tag}] arah dipaksa: buy (override)`, COLOR.gray); }
          else if (canBuy) { direction = 'buy'; amountCC = String(maxBuyCC); }   // prefer buy → balik ke CC
          else if (canSell) { direction = 'sell'; amountCC = String(maxSellCC); }
          else {
            // Dua-duanya gak cukup. Banyak CC mungkin masih kelock di settlement →
            // tunggu sebentar lalu cek ulang; kalau tetap, stop sesi (server unlock sendiri).
            logActivity(`[${tag}] saldo gak cukup utk swap (CC unlocked ${floor4(ccUnlocked)}, USDCx ${floor4(usdc)}, mode ${modeLabel}). Tunggu unlock…`, COLOR.yellow);
            lowFeeStreak++;
            if (lowFeeStreak >= MAX_LOW_FEE) { logActivity(`[${tag}] Stop sesi: saldo kurang setelah ${MAX_LOW_FEE}x. Tunggu settlement unlock / top-up.`, COLOR.red); break; }
            await sleep(Math.min(90, 30 * lowFeeStreak) * 1000);
            continue;
          }
          logActivity(`[${tag}] ${direction} ${amountCC} CC (${modeLabel})`, COLOR.gray);

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

            // Poll DAY_TRADER bertahap: 15s, 20s, lalu 30s (3x). Berhenti begitu
            // count naik on-chain (settle bisa telat). Total tunggu max 125s.
            const SYNC_WAITS = [15000, 20000, 30000, 30000, 30000];
            let realDt = null;
            for (let r = 0; r < SYNC_WAITS.length; r++) {
              const w = SYNC_WAITS[r];
              logActivity(`[${tag}] Sync DAY_TRADER… (cek ${r + 1}/${SYNC_WAITS.length}, tunggu ${Math.round(w / 1000)}s)`, COLOR.gray);
              await sleep(w);
              realDt = await fetchDayTrader(sv, partyId).catch(() => null);
              if (realDt) state.dayTrader = { count: realDt.current, target: realDt.target };
              await refreshBalances(state, identityToken, proxy);
              render(global.__states);
              if (realDt && realDt.current > baseCount) break; // sudah settle on-chain
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
                throw e;
              }
            }
            throw lastErr;
          };

          try {
            const beforeApi = (state.dayTrader && Number(state.dayTrader.count)) || 0;
            const label = direction === 'sell' ? 'jual CC→USDCx' : 'beli USDCx→CC';
            const res = await swapWithRetry(direction, amountCC, label);
            if (res && res.ok) {
              const realDt = await handleSuccess(label);
              if (realDt && realDt.current > beforeApi) {
                done = Math.max(done + 1, realDt.current - startApi);
                stuck = 0;
                lowFeeStreak = 0;
                logActivity(`[${tag}] ✓ confirmed on-chain (DAY_TRADER ${realDt.current}/${realDt.target})`, COLOR.green);
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
                    if (wdt && (wdt.completed || wdt.current >= wdt.target)) {
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
            // FEE PROTECTION: fee > maxFeeCC. JANGAN swap (walau daily belum kelar).
            // Tunggu feeSpikeWaitSec lalu retry — done TIDAK naik, ulang sampai fee turun.
            if (e && e.feeSpike) {
              const waitS = Math.max(60, Number(SWAP.feeSpikeWaitSec) || 300);
              logActivity(`[${tag}] fee spike ${e.feeCC} CC > ${SWAP.maxFeeCC} CC — TUNDA swap, cek lagi ${Math.round(waitS / 60)} mnt`, COLOR.yellow);
              // Bersihin proposal yg dibuat attempt barusan (0 dana kelock) biar retry gak numpuk.
              const c = await cleanupStaleProposals(sv, partyId).catch(() => 0);
              if (c) logActivity(`[${tag}] cleanup ${c} proposal sisa fee-spike`, COLOR.gray);
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
            // Kalau buy gagal karena USDCx kurang, fallback ke sell otomatis
            if (e && e.insufficientBalance && direction === 'buy') {
              logActivity(`[${tag}] ${e.message} → coba sell sebagai gantinya`, COLOR.yellow);
              try {
                const res2 = await swapWithRetry('sell', amountCC, 'jual CC→USDCx');
                if (res2 && res2.ok) {
                  await handleSuccess('jual CC→USDCx');
                  continue;
                }
              } catch (e2) {
                if (e2 && e2.noLiquidity) { logActivity(`[${tag}] likuiditas sell belum ada, retry…`, COLOR.gray); await sleep(SWAP.delayBetweenSwapsSec * 1000); continue; }
                logActivity(`[${tag}] swap sell juga gagal: ${shortSwapReason(e2)}`, COLOR.red);
              }
            } else {
              logActivity(`[${tag}] swap ${direction} gagal: ${shortSwapReason(e)}`, COLOR.red);
            }
            if (process.env.SWAP_DEBUG && e && e.stack) console.error('[swap-error-stack]', e.stack);
            await sleep(SWAP.delayBetweenSwapsSec * 1000);
          }
        }
        const fin = await fetchDayTrader(sv, partyId).catch(() => null);
        if (fin) { state.dayTrader = { count: fin.current, target: fin.target }; logActivity(`[${tag}] Selesai: DAY_TRADER ${fin.current}/${fin.target}${fin.current >= fin.target ? ' ✓' : ''}`, fin.current >= fin.target ? COLOR.green : COLOR.yellow); }
        render(global.__states);
      } catch (e) { state.status = 'error'; state.message = (e && e.message) || String(e); logActivity(`[${tag}] error: ${(e && e.message) || e}`, COLOR.red); }
    }
    logActivity('Sesi selesai — berhenti sampai jadwal berikutnya.', COLOR.cyan);
  } finally { dtSessionRunning = false; }
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
//  Main + sub-command paste
// ============================================================================
async function runMain() {
  const states = makeStates();
  global.__states = states;
  process.stdout.on('resize', () => { try { render(global.__states); } catch (_) { } });
  render(states);
  await tickAll(states);
  if (argv[0] === 'once') process.exit(0);

  scheduleDaily({ hour: Number(SCHED.hour) || 7, minute: Number(SCHED.minute) || 0, timezone: SCHED.timezone || 'Asia/Jakarta', fn: async (why) => { await runDayTraderSession(why); if (!dtSessionRunning) await tickAll(states).catch(() => { }); } });
  runDayTraderSession('startup').then(() => tickAll(states).catch(() => { })).catch(e => logActivity('sesi startup error: ' + e.message, COLOR.red));

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
module.exports = { render, makeStates, logActivity, computeLayout, runDayTraderSession, parseDayTrader };

if (require.main === module) {
  if (argv[0] === 'help' || argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(`
Usage:
  node index.js           dashboard + auto DAY_TRADER (swap sampai target, ulang tiap ${SCHED.hour}:00 WIB)
  node index.js once      render dashboard + fetch data sekali, lalu exit (tanpa swap)
  node index.js swap      jalankan SATU sesi DAY_TRADER lalu exit
  node index.js feecheck [sell|buy] [amt]  cek fee live tanpa swap (dry-run, 0 CC, auto-cleanup)
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
  } else if (argv[0] === 'swap') {
    // `node index.js swap [sell|buy]` — arg kedua paksa arah (test SELL).
    if (argv[1] === 'sell' || argv[1] === 'buy') global.__forceDir = argv[1];
    (async () => { global.__states = makeStates(); render(global.__states); await runDayTraderSession('manual'); process.exit(0); })().catch(e => { console.error(paint('FATAL: ' + e.message, COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'proposals') {
    // `node index.js proposals` — list settlement/DvpProposal aktif (read-only).
    // Buat ngecek apakah feecheck/skip-spike ninggalin proposal nyangkut.
    (async () => {
      const a = ACCOUNTS[0];
      if (!a) { console.error(paint('accounts.json kosong', COLOR.red)); process.exit(1); }
      const state = makeStates()[0];
      const { sv, partyId } = await buildSwapClients(state);
      const raw = await sv.swapAction(SWAP.actionIds.listProposals, [partyId]).catch(() => null);
      const all = (raw && Array.isArray(raw.proposals)) ? raw.proposals : [];
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
  } else if (argv[0] === 'cleanup') {
    // `node index.js cleanup` — reject proposal nyangkut yg 0 dana kita kekunci
    // (stage<9, belum settle, belum reject, alloc kita kosong). Aman: gak ada dana
    // ke-lock. Coba submitPreconfirmation accept:false. NEVER sentuh LOCKED/SETTLED.
    (async () => {
      const a = ACCOUNTS[0];
      if (!a) { console.error(paint('accounts.json kosong', COLOR.red)); process.exit(1); }
      const state = makeStates()[0];
      const { sv, partyId } = await buildSwapClients(state);
      const n = await cleanupStaleProposals(sv, partyId, (m, c) => process.stdout.write(paint(m, c || COLOR.gray) + '\n'));
      process.stdout.write(paint(`\ncleanup selesai — ${n} proposal di-reject\n`, COLOR.green));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else if (argv[0] === 'feecheck') {
    // `node index.js feecheck [sell|buy] [amount]` — dry-run: flow swap ASLI sampai
    // feeCtx lalu STOP sebelum submit. Log 3 angka fee. 0 CC kebayar.
    const dir = (argv[1] === 'buy') ? 'buy' : 'sell';
    const amt = String(argv[2] || SWAP_MIN_AMOUNT || '11');
    (async () => {
      const a = ACCOUNTS[0];
      if (!a) { console.error(paint('accounts.json kosong', COLOR.red)); process.exit(1); }
      const state = makeStates()[0];
      process.stdout.write(paint(`feecheck (dry-run): ${dir} ${amt} CC — ${a.label || a.email}\n`, COLOR.cyan));
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
      const n = await cleanupStaleProposals(clients.sv, clients.partyId).catch(() => 0);
      if (n) process.stdout.write(paint(`  ${n} proposal nyangkut dibersihin\n`, COLOR.green));
      process.exit(0);
    })().catch(e => { console.error(paint('FATAL: ' + ((e && e.message) || e), COLOR.red)); process.exit(1); });
  } else {
    if (!ACCOUNTS.length) { console.error(paint('accounts.json kosong. Jalankan: node index.js register', COLOR.red)); process.exit(1); }
    runMain().catch(e => { console.error(paint('FATAL: ' + (e && e.stack || e), COLOR.red)); process.exit(1); });
  }
  process.on('SIGINT', () => { process.stdout.write('\n' + paint('bye 👋', COLOR.gray) + '\n'); process.exit(0); });
}
