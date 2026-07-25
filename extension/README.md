# SilvanaBot — Register Passkey (ekstensi Chrome)

Pengganti alur lama yang ribet (buka DevTools → ketik "allow pasting" → paste script panjang
→ copy JSON dari Console). Sekarang: **klik ikon → Daftarkan Passkey → Copy JSON**.

## Pasang (sekali saja)

1. Buka `chrome://extensions` (Brave: `brave://extensions`, Edge: `edge://extensions`).
2. Aktifkan **Developer mode** (pojok kanan atas).
3. **Load unpacked** → pilih folder `extension/` ini.
4. Pin ikonnya biar gampang diklik.

## Pakai (per akun)

1. Buka `https://app.silvana.one` dan **login** akun yang mau didaftarkan.
2. Klik ikon ekstensi → **Daftarkan Passkey**.
3. Muncul JSON + tombol **Copy JSON** (atau **Download .json**).
4. Di mesin bot:
   ```bash
   node index.js paste              # tempel JSON-nya, Enter
   node index.js paste hasil.json   # kalau tadi pilih Download lalu di-scp ke VPS
   ```

Ganti akun di browser, ulangi dari langkah 1.

## Kenapa hasilnya tidak dikirim otomatis ke bot

Payload berisi **private key** passkey — itu yang bikin bot bisa login tanpa Touch ID.
Ekstensi ini sengaja **tidak** mengirim ke jaringan mana pun; satu-satunya jalan keluar
adalah clipboard atau file yang kamu kendalikan sendiri. Kalau bot jalan di VPS, localhost
di browser juga tidak nyambung ke sana, jadi auto-post tidak akan membantu.

Jaga JSON itu seperti menjaga seed phrase: siapa pun yang punya bisa login sebagai akun itu.
Jangan tempel ke chat, issue, atau paste-bin.

## Isi folder

| file | fungsi |
| --- | --- |
| `manifest.json` | MV3, izin minimal: `scripting` + `activeTab` + host `app.silvana.one` |
| `popup.html` / `popup.js` | UI, jalankan script, tampilkan hasil, copy/download |
| `register.js` | logika register — port persis dari `REGISTER_SNIPPET` di `index.js` |

`register.js` harus tetap sinkron dengan `REGISTER_SNIPPET`: keduanya menghasilkan payload
`{email, label, silvanaPasskey:{credentialId, userHandle, privateJwk}}` yang sama, karena
`node index.js paste` yang membacanya.

## Kalau gagal

| pesan | sebabnya |
| --- | --- |
| `Buka tab https://app.silvana.one …` | tab aktif bukan Silvana |
| `Belum login di app.silvana.one` | sesi habis — login ulang di tab itu |
| `Endpoint register/options tak ketemu` | Silvana ganti path. Buka Network tab saat klik "Add Passkey" di UI, lalu tambahkan path barunya ke array `candidates` di `register.js` **dan** ke `REGISTER_SNIPPET` di `index.js` |
| `register/verify gagal 4xx` | akun sudah punya passkey dengan nama sama / sesi tidak valid |

Script Console lama tetap ada sebagai fallback: `node index.js register`.
