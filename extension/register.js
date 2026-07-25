// Dijalankan lewat chrome.scripting.executeScript di tab app.silvana.one (isolated
// world — fetch tetap bawa cookie same-origin, jadi `credentials:'include'` jalan).
//
// Isinya PORT PERSIS dari REGISTER_SNIPPET di index.js (jangan diubah sepihak: dua-duanya
// harus menghasilkan payload yang sama, karena `node index.js paste` yang membacanya).
// Beda cuma outputnya: snippet console nge-print 1 baris JSON buat dicopy manual,
// yang ini balikin object ke popup.
//
// File ini HARUS berakhir dengan expression yang mengevaluasi ke Promise —
// executeScript nunggu promise itu dan naruh hasilnya di result[0].result.
(async () => {
  const out = { ok: false, error: null, payload: null, steps: [] };
  const step = (m) => out.steps.push(m);
  try {
    const TE = new TextEncoder();
    const b64u = (b) => btoa(String.fromCharCode.apply(null, new Uint8Array(b))).split('+').join('-').split('/').join('_').split('=').join('');
    const b64uDec = (s) => { s = s.split('-').join('+').split('_').join('/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
    const concat = (...a) => { let n = 0; for (const x of a) n += x.length; const o = new Uint8Array(n); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
    // CBOR minimal — cukup buat authData + attestationObject fmt:'none'.
    const cint = (n) => { if (n >= 0 && n <= 23) return new Uint8Array([n]); if (n < 0 && n >= -24) return new Uint8Array([0x20 | (-1 - n)]); if (n >= 24 && n <= 255) return new Uint8Array([0x18, n]); throw new Error('cbor int'); };
    const cstr = (b) => { const l = b.length; if (l <= 23) return concat(new Uint8Array([0x40 | l]), b); if (l <= 255) return concat(new Uint8Array([0x58, l]), b); return concat(new Uint8Array([0x59, (l >> 8) & 0xff, l & 0xff]), b); };
    const cmap = (p) => concat(new Uint8Array([0xa0 | p.length]), ...p.flat());
    const ctstr = (s) => { const b = TE.encode(s); return concat(new Uint8Array([0x60 | b.length]), b); };

    let me;
    try {
      const r = await fetch('/api/auth/me', { credentials: 'include' });
      if (!r.ok) throw 0;
      me = (await r.json()).user;
    } catch (_) { throw new Error('Belum login di app.silvana.one — login dulu di tab ini, lalu ulangi.'); }
    if (!me || !me.email) throw new Error('Respons /api/auth/me tidak ada email — pastikan benar-benar sudah login.');
    step('user: ' + me.email);

    // Path options beda-beda antar deploy → coba berurutan sampai ada yang 200.
    const candidates = ['/api/passkeys/register/options', '/api/auth/passkey/registration/options', '/api/auth/webauthn/register/options', '/api/passkeys/options'];
    let optsR = null, usedPath = '';
    for (const p of candidates) {
      try {
        const r = await fetch(p, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' } });
        if (r.ok) { optsR = r; usedPath = p; break; }
      } catch (_) { }
    }
    if (!optsR) throw new Error('Endpoint register/options tak ketemu — cek Network tab saat klik Add Passkey di UI Silvana.');
    const opts = await optsR.json();
    step('options: ' + usedPath);
    const verifyPath = usedPath.replace('/options', '/verify');

    // Passkey KUSTOM: keypair digenerate di sini, private key-nya kita pegang sendiri
    // (itu yang bikin bot bisa login tanpa Touch ID). Attestation 'none' + authData
    // dirakit manual — Silvana tidak memverifikasi attestation.
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const credIdRaw = crypto.getRandomValues(new Uint8Array(32));
    const credIdB64 = b64u(credIdRaw);
    const clientDataJSON = TE.encode(JSON.stringify({ type: 'webauthn.create', challenge: opts.challenge, origin: location.origin, crossOrigin: false }));
    const rpId = (opts.rp && opts.rp.id) || 'silvana.one';
    const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', TE.encode(rpId)));
    const x = b64uDec(pubJwk.x), y = b64uDec(pubJwk.y);
    const coseKey = cmap([[cint(1), cint(2)], [cint(3), cint(-7)], [cint(-1), cint(1)], [cint(-2), cstr(x)], [cint(-3), cstr(y)]]);
    const authData = concat(rpIdHash, new Uint8Array([0x45]), new Uint8Array([0, 0, 0, 0]), new Uint8Array(16), new Uint8Array([0, credIdRaw.length]), credIdRaw, coseKey);
    const attestationObject = concat(new Uint8Array([0xa3]), ctstr('fmt'), ctstr('none'), ctstr('attStmt'), new Uint8Array([0xa0]), ctstr('authData'), cstr(authData));
    const credential = { id: credIdB64, rawId: credIdB64, type: 'public-key', authenticatorAttachment: 'platform', transports: ['internal'], response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject) } };

    const verR = await fetch(verifyPath, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: me.email, credential }) });
    const verT = await verR.text();
    if (!verR.ok) throw new Error('register/verify gagal ' + verR.status + ': ' + verT.slice(0, 300));
    step('register OK (' + verR.status + ')');

    const userHandle = (opts.user && opts.user.id) || '';
    out.payload = { email: me.email, label: (me.email || '').split('@')[0], silvanaPasskey: { credentialId: credIdB64, userHandle, privateJwk: privJwk } };
    out.ok = true;
  } catch (e) {
    out.error = (e && e.message) || String(e);
  }
  return out;
})();
