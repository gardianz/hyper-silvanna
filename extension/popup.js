// Popup: jalanin register.js di tab app.silvana.one yang aktif, lalu tampilkan payload
// + tombol copy/download. Sengaja TANPA kirim ke jaringan mana pun — payload berisi
// private key passkey, jadi cuma boleh pindah lewat clipboard/file punya user sendiri.
const $ = (id) => document.getElementById(id);
const ORIGIN = 'https://app.silvana.one';

function setStatus(msg, kind) {
  const el = $('status');
  el.textContent = msg;
  el.className = kind || 'info';
}
function showSteps(steps) {
  const ul = $('steps');
  ul.innerHTML = '';
  for (const s of (steps || [])) { const li = document.createElement('li'); li.textContent = s; ul.appendChild(li); }
  ul.hidden = !(steps && steps.length);
}

$('go').addEventListener('click', async () => {
  $('go').disabled = true;
  $('result').style.display = 'none';
  showSteps([]);
  setStatus('Menyiapkan…', 'info');
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || !tab.url.startsWith(ORIGIN)) {
      setStatus('Buka tab ' + ORIGIN + ' dan pastikan sudah login, lalu klik lagi.', 'err');
      return;
    }
    setStatus('Membuat passkey & mendaftarkan ke Silvana…', 'info');
    const res = await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['register.js'] });
    const out = res && res[0] && res[0].result;
    if (!out) { setStatus('Script tidak mengembalikan hasil — reload tab Silvana lalu coba lagi.', 'err'); return; }
    showSteps(out.steps);
    if (!out.ok) { setStatus('GAGAL: ' + out.error, 'err'); return; }

    $('json').value = JSON.stringify(out.payload);
    $('result').style.display = 'block';
    setStatus('✓ Passkey terdaftar untuk ' + out.payload.email, 'ok');
  } catch (e) {
    setStatus('GAGAL: ' + ((e && e.message) || e), 'err');
  } finally {
    $('go').disabled = false;
  }
});

$('copy').addEventListener('click', async () => {
  const v = $('json').value;
  try {
    await navigator.clipboard.writeText(v);
    setStatus('✓ Tersalin. Di mesin bot: node index.js paste → tempel → Enter.', 'ok');
  } catch (_) {
    // Clipboard API bisa ditolak — fallback select manual.
    $('json').removeAttribute('readonly');
    $('json').select();
    document.execCommand('copy');
    $('json').setAttribute('readonly', '');
    setStatus('Tersalin (fallback). Kalau masih gagal, copy manual dari kotak di atas.', 'info');
  }
});

$('dl').addEventListener('click', () => {
  let email = 'passkey';
  try { email = (JSON.parse($('json').value).email || 'passkey').replace(/[^a-z0-9._-]/gi, '_'); } catch (_) { }
  const url = URL.createObjectURL(new Blob([$('json').value], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'silvana-passkey-' + email + '.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
});
