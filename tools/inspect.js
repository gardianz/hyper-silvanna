#!/usr/bin/env node
/**
 * Inspeksi Silvana pakai Chromium (Playwright) + cookie dari session.json.
 *
 * Kenapa begini: Silvana login pakai passkey, dan passkey itu nempel di perangkat
 * — gak bisa dipindah ke browser WSL. Tapi bot udah nyimpen cookie sesi hasil
 * login passkey di session.json, jadi cookie-nya tinggal disuntik dan browser
 * langsung dalam keadaan login. Gak perlu passkey, gak perlu Chrome Windows.
 *
 * Chromium diambil dari cache Playwright yg udah keunduh (`playwright install
 * chromium`). Paket `playwright`-nya sendiri gak ditaruh di dependencies bot —
 * dicari dari cache npx / node_modules global biar package.json tetep cuma
 * node-cron.
 *
 * Pakai:
 *   node tools/inspect.js <emailAtauIdxAkun> [url] [--headed] [--keep=detik]
 *
 * Semua request next-action + /api/* direkam ke tools/inspect-out.json,
 * lengkap dengan request body-nya — itu yg dipakai buat bedah parameter yg
 * gak kelihatan dari bundle (mis. token fee mana yg dipilih UI).
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.dirname(__dirname);
const OUT = path.join(__dirname, 'inspect-out.json');
const APP = 'https://app.silvana.one';

// ── cari paket playwright tanpa nambah dependency ke bot ─────────────────────
function loadPlaywright() {
  const cands = [];
  try {
    const npx = path.join(process.env.HOME || '', '.npm', '_npx');
    for (const d of fs.readdirSync(npx)) cands.push(path.join(npx, d, 'node_modules', 'playwright'));
  } catch (_) { }
  try { cands.push(execSync('npm root -g', { encoding: 'utf8' }).trim() + '/playwright'); } catch (_) { }
  cands.push(path.join(ROOT, 'node_modules', 'playwright'));
  for (const c of cands) {
    try { if (fs.existsSync(path.join(c, 'package.json'))) return require(c); } catch (_) { }
  }
  console.error('paket playwright gak ketemu.\nJalanin dulu: npx playwright install chromium');
  process.exit(1);
}

function pickAccount(arg) {
  const accs = JSON.parse(fs.readFileSync(path.join(ROOT, 'accounts.json'), 'utf8')).accounts;
  if (/^\d+$/.test(String(arg))) return accs[Number(arg)];
  return accs.find(a => a.email === arg || a.label === arg);
}

(async () => {
  const who = process.argv[2];
  if (!who) { console.error('pakai: node tools/inspect.js <emailAtauIdx> [url] [--headed] [--keep=detik]'); process.exit(1); }
  const acct = pickAccount(who);
  if (!acct) { console.error(`akun '${who}' gak ada di accounts.json`); process.exit(1); }
  const url = (process.argv[3] && !process.argv[3].startsWith('--')) ? process.argv[3] : APP + '/swap';
  const headed = process.argv.includes('--headed');
  const keepArg = process.argv.find(a => a.startsWith('--keep='));
  const keepSec = keepArg ? Number(keepArg.split('=')[1]) : (headed ? 300 : 25);

  const sess = JSON.parse(fs.readFileSync(path.join(ROOT, 'session.json'), 'utf8'))[acct.email];
  if (!sess || !sess.silvanaCookies) { console.error(`session.json gak punya silvanaCookies buat ${acct.email}`); process.exit(1); }

  const { chromium } = loadPlaywright();
  // Versi paket playwright (dari cache npx) sering BEDA sama build browser yg
  // keunduh, jadi resolusi otomatisnya nyari folder yg gak ada. Tunjuk binernya
  // langsung: ambil chromium-* dengan nomor build tertinggi di cache.
  const launchOpts = { headless: !headed, args: ['--no-sandbox', '--disable-dev-shm-usage'] };
  try {
    const cache = path.join(process.env.HOME || '', '.cache', 'ms-playwright');
    const best = fs.readdirSync(cache)
      .filter(d => /^chromium-\d+$/.test(d))
      .sort((a, b) => Number(b.split('-')[1]) - Number(a.split('-')[1]))[0];
    const exe = best && path.join(cache, best, 'chrome-linux64', 'chrome');
    if (exe && fs.existsSync(exe)) { launchOpts.executablePath = exe; console.log('chromium:', best); }
  } catch (_) { }
  const browser = await chromium.launch(launchOpts);
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });

  // Suntik cookie sesi Silvana → langsung login tanpa passkey.
  const cookies = Object.entries(sess.silvanaCookies).map(([name, value]) => ({
    name, value: String(value), domain: 'app.silvana.one', path: '/', httpOnly: false, secure: true, sameSite: 'Lax',
  }));
  await ctx.addCookies(cookies);
  console.log(`cookie disuntik: ${cookies.map(c => c.name).join(', ')}`);

  // Rekam SEMUA next-action + /api/*, termasuk request body-nya.
  const rec = [];
  ctx.on('request', (req) => {
    const u = req.url();
    if (!/app\.silvana\.one/.test(u)) return;
    const h = req.headers();
    const isAction = !!h['next-action'];
    if (!isAction && !/\/api\//.test(u)) return;
    let body = null;
    try { body = req.postData(); } catch (_) { }
    rec.push({ t: Date.now(), method: req.method(), url: u, nextAction: h['next-action'] || null, body: body ? String(body).slice(0, 4000) : null });
  });
  ctx.on('response', async (res) => {
    const u = res.url();
    if (!/app\.silvana\.one/.test(u)) return;
    const hit = rec.find(r => r.url === u && r.status === undefined);
    if (!hit) return;
    hit.status = res.status();
    try { hit.resp = (await res.text()).slice(0, 3000); } catch (_) { }
  });

  const page = await ctx.newPage();
  page.on('console', m => { const t = m.text(); if (/error|fail/i.test(t)) console.log('  [console]', t.slice(0, 160)); });
  console.log(`buka ${url} …`);
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto:', e.message));
  await page.waitForTimeout(4000);
  console.log('judul :', await page.title().catch(() => '?'));
  console.log('url   :', page.url());

  if (headed) console.log(`\nbrowser KEBUKA — lakuin aksinya manual (mis. toggle fee USDCx lalu Swap). Nutup otomatis ${keepSec}s lagi.`);
  await page.waitForTimeout(keepSec * 1000);

  fs.writeFileSync(OUT, JSON.stringify(rec, null, 1));
  console.log(`\n${rec.length} request direkam → ${OUT}`);
  for (const r of rec.filter(x => x.nextAction).slice(-12)) {
    console.log(`  ${String(r.status || '?').padStart(3)} action=${String(r.nextAction).slice(0, 12)}… ${String(r.body || '').replace(/\s+/g, ' ').slice(0, 120)}`);
  }
  await browser.close();
})().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
