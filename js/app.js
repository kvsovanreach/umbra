/* aiclab encrypted chat — UI + wiring, crypto-terminal edition.
 * Innovations: live key-fingerprint identicons, connect handshake, click-to-peek
 * ciphertext, and a scramble-decrypt reveal for incoming messages.
 */
(function () {
  const $ = (id) => document.getElementById(id);
  const util = nacl.util;
  const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const S = { uuid: null, secret: null, keypair: null, peer: null, peerPub: null, myPub: null,
              db: null, auth: null, cid: null, es: null, msgs: new Map(), view: new Map(),
              peeking: new Set(), animate: new Set(), pendingImage: null, loaded: false,
              peerRead: 0, verified: false, typingThrottle: 0, typingTimer: null, readThrottle: 0 };

  // ---------- key fingerprint + identicon ----------
  function fpHex(pubB64) {
    const h = nacl.hash(util.decodeBase64(pubB64));
    const hex = [...h.slice(0, 4)].map((b) => b.toString(16).padStart(2, '0')).join('');
    return (hex.slice(0, 4) + '·' + hex.slice(4, 8)).toUpperCase();
  }
  function drawIdenticon(canvas, pubB64) {
    const ctx = canvas.getContext('2d');
    const N = 9;
    if (!pubB64) { ctx.clearRect(0, 0, N, N); return; }
    const h = nacl.hash(util.decodeBase64(pubB64));
    const hue = (h[0] / 255) * 360, hue2 = (hue + 40 + (h[1] / 255) * 80) % 360;
    ctx.fillStyle = '#0a0e15'; ctx.fillRect(0, 0, N, N);
    for (let x = 0; x <= 4; x++) {
      for (let y = 0; y < N; y++) {
        const b = h[(x * N + y) % 64];
        if (b & 1) {
          ctx.fillStyle = `hsl(${b & 2 ? hue : hue2}, 70%, ${55 + (b % 20)}%)`;
          ctx.fillRect(x, y, 1, 1);
          ctx.fillRect(N - 1 - x, y, 1, 1); // mirror
        }
      }
    }
  }

  // live fingerprint as the user types (PBKDF2 is ~100ms, so debounce + latest-wins)
  let fpSeq = 0, fpTimer = null;
  function refreshMyKey() {
    const uuid = $('uuid').value.trim(), secret = $('secret').value;
    if (!uuid || !secret) { $('myFp').textContent = '— — — —'; $('myFp').classList.remove('busy'); drawIdenticon($('myIdenticon'), null); return; }
    $('myFp').textContent = 'deriving…';
    clearTimeout(fpTimer);
    fpTimer = setTimeout(async () => {
      const seq = ++fpSeq;
      try {
        const kp = await CryptoBox.keypairFrom(uuid, secret);
        if (seq !== fpSeq) return; // a newer keystroke superseded this
        const pub = CryptoBox.publicKeyB64(kp);
        $('myFp').textContent = fpHex(pub);
        drawIdenticon($('myIdenticon'), pub);
      } catch (e) { $('myFp').textContent = '— — — —'; }
    }, 250);
  }
  $('secret').addEventListener('input', refreshMyKey);
  $('uuid').addEventListener('input', refreshMyKey);

  // ---------- login prefill ----------
  const saved = JSON.parse(localStorage.getItem('aiclab') || '{}');
  if (saved.uuid) $('uuid').value = saved.uuid;
  if (saved.peer) $('peer').value = saved.peer;
  $('dburl').value = saved.dburl || (window.FIREBASE_CONFIG && window.FIREBASE_CONFIG.databaseURL) || '';
  if (saved.uuid || saved.peer) $('remember').checked = true;
  // full 122-bit UUID. short ids are guessable, and guessing a PAIR of uuids
  // yields the conversation id — plus anyone can squat an unclaimed /users/{uuid}
  // public key (write-once) and silently become the peer your partner encrypts to.
  const randomUUID = () => {
    if (crypto.randomUUID) return crypto.randomUUID();
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; // v4, variant 1
    const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
  $('genUuid').addEventListener('click', () => { $('uuid').value = randomUUID(); });

  // ---------- handshake ----------
  async function hsStep(text, ms) {
    const el = document.createElement('div');
    el.className = 'step';
    el.innerHTML = `<span>◇</span><span>${text}</span>`;
    $('handshake').appendChild(el);
    await sleep(ms || 260);
    el.querySelector('span:first-child').outerHTML = '<span class="tick">✓</span>';
    return el;
  }

  // ---------- connect ----------
  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('loginErr'); err.textContent = ''; $('handshake').innerHTML = '';
    const uuid = $('uuid').value.trim(), secret = $('secret').value, peer = $('peer').value.trim(), dburl = $('dburl').value.trim();
    if (!uuid || !secret || !peer) { err.textContent = 'uuid, secret and peer are required'; return; }
    if (!dburl || dburl.includes('YOUR-PROJECT')) { err.textContent = 'set your firebase database url (advanced)'; return; }
    if (uuid === peer) { err.textContent = 'your uuid and peer uuid must differ'; return; }

    $('connect').disabled = true; $('connect').textContent = 'ESTABLISHING…';
    try {
      S.uuid = uuid; S.secret = secret; S.peer = peer;
      await hsStep('deriving keypair · PBKDF2-250k · X25519…', 340);
      S.keypair = await CryptoBox.keypairFrom(uuid, secret);

      S.auth = FireAuth((window.FIREBASE_CONFIG || {}).apiKey);
      if (S.auth.enabled()) {
        await hsStep('anonymous auth · acquiring token…');
        await S.auth.signIn();
      }
      S.db = FireDB(dburl, () => S.auth.token());

      await hsStep(`publishing public key → /users/${uuid}…`);
      await S.db.publishPublicKey(uuid, CryptoBox.publicKeyB64(S.keypair));

      await hsStep('fetching peer public key…');
      S.peerPub = await S.db.getPublicKey(peer);
      if (!S.peerPub) {
        err.textContent = `peer "${peer}" hasn't joined — they must open the app once to publish their key`;
        $('connect').disabled = false; $('connect').textContent = 'ESTABLISH SECURE CHANNEL'; return;
      }
      await hsStep('ECDH shared secret established', 340);

      S.cid = CryptoBox.conversationId(uuid, peer);
      if ($('remember').checked) localStorage.setItem('aiclab', JSON.stringify({ uuid, peer, dburl }));
      else localStorage.removeItem('aiclab');
      await sleep(240);
      enterChat();
    } catch (ex) {
      err.textContent = 'failed: ' + ex.message;
      $('connect').disabled = false; $('connect').textContent = 'ESTABLISH SECURE CHANNEL';
    }
  });

  // ---------- chat ----------
  function enterChat() {
    $('login').classList.add('hidden');
    $('chat').classList.remove('hidden');
    S.myPub = CryptoBox.publicKeyB64(S.keypair);
    $('peerName').textContent = S.peer;
    $('peerFp').textContent = fpHex(S.peerPub);
    $('meFp').textContent = fpHex(S.myPub);
    drawIdenticon($('peerIdenticon'), S.peerPub);
    initVerification();
    $('statusDot').classList.add('on');
    S.msgs.clear(); S.loaded = false; S.peerRead = 0;
    $('messages').innerHTML = '<div class="sys">◇ loading encrypted history…</div>';

    S.es = S.db.stream(S.cid, {
      onMessage: (id, m) => {
        const isNew = !S.msgs.has(id);
        S.msgs.set(id, m);
        if (isNew && S.loaded && m.from !== S.uuid) S.animate.add(id);
        render();
      },
      onTyping: (uuid, ts) => { if (uuid === S.peer) showTyping(ts); },
      onRead: (uuid, ts) => { if (uuid === S.peer) { S.peerRead = Math.max(S.peerRead, ts || 0); render(); } },
    }, (up) => $('statusDot').classList.toggle('on', up));

    S.db.getMessages(S.cid).then((list) => {
      list.forEach((m) => S.msgs.set(m.id, m));
      S.loaded = true; render();
    }).catch(() => { S.loaded = true; });
  }

  // ---------- verification ----------
  const vKey = () => `aiclab-verify::${S.uuid}::${S.peer}`;
  function initVerification() {
    const stored = localStorage.getItem(vKey());
    S.mitm = !!(stored && stored !== S.peerPub); // key changed since verified
    S.verified = !!(stored && stored === S.peerPub);
    updateVerifyBadge();
  }
  function updateVerifyBadge() {
    const b = $('verifyBadge');
    if (S.verified) { b.className = 'verify verified'; b.textContent = '✓ VERIFIED'; }
    else if (S.mitm) { b.className = 'verify unverified'; b.textContent = '⚠ KEY CHANGED'; }
    else { b.className = 'verify unverified'; b.textContent = '! UNVERIFIED'; }
  }
  function openVerifyModal() {
    drawIdenticon($('vMe'), S.myPub);
    drawIdenticon($('vPeer'), S.peerPub);
    $('vPeerLbl').textContent = S.peer;
    $('vPeerName').textContent = S.peer;
    $('mitmWarn').classList.toggle('hidden', !S.mitm);
    const groups = CryptoBox.safetyNumber(S.myPub, S.peerPub);
    $('safetyNumber').innerHTML = groups.map((g) => `<span>${g}</span>`).join('');
    $('markVerified').textContent = S.verified ? 'VERIFIED ✓ (tap to un-verify)' : 'MARK AS VERIFIED';
    $('verifyModal').classList.remove('hidden');
  }
  $('openVerify').addEventListener('click', openVerifyModal);
  $('closeVerify').addEventListener('click', () => $('verifyModal').classList.add('hidden'));
  $('markVerified').addEventListener('click', () => {
    if (S.verified) { localStorage.removeItem(vKey()); S.verified = false; }
    else { localStorage.setItem(vKey(), S.peerPub); S.verified = true; S.mitm = false; }
    updateVerifyBadge(); $('verifyModal').classList.add('hidden');
  });

  // ---------- typing indicator ----------
  function showTyping(ts) {
    if (!ts || Date.now() - ts > 5000) { $('typing').classList.add('hidden'); return; }
    $('typingName').textContent = S.peer;
    $('typing').classList.remove('hidden');
    clearTimeout(S.typingTimer);
    S.typingTimer = setTimeout(() => $('typing').classList.add('hidden'), 4500);
  }

  function render() {
    const box = $('messages');
    const items = [...S.msgs.entries()].sort((a, b) => (a[1].ts || 0) - (b[1].ts || 0));
    if (!items.length) { box.innerHTML = '<div class="sys">no messages yet — say hello · end-to-end encrypted</div>'; return; }
    S.view.clear();
    box.innerHTML = items.map(([id, m]) => {
      const mine = m.from === S.uuid;
      const env = CryptoBox.decryptEnvelope(m, S.keypair.secretKey, S.peerPub);
      const read = mine && m.ts && m.ts <= S.peerRead;
      const status = mine ? `<span class="status ${read ? 'read' : ''}">${read ? '✓✓' : '✓'}</span>` : '';
      const time = m.ts ? `<span class="time">${fmtTime(m.ts)}${status}</span>` : '';
      const cipherStr = ((m.n || '') + (m.c || '')).slice(0, 120) + '…';
      const cipherHTML = `<div class="cipher"><span class="lbl">CIPHERTEXT · nonce+box (b64)</span>${esc(cipherStr)}</div>${time}`;
      let plainHTML;
      if (!env) plainHTML = `🔒 unable to decrypt${time}`;
      else if (env.t === 'image') plainHTML = `<img src="data:${esc(env.mime || 'image/jpeg')};base64,${env.body}"/>${time}`;
      else plainHTML = `<span class="body">${esc(env.body || '')}</span>${time}`;
      S.view.set(id, { plain: plainHTML, cipher: cipherHTML, text: env && env.t === 'text' ? env.body : null });
      const cls = 'msg ' + (mine ? 'out' : 'in') + (env ? '' : ' bad');
      const show = S.peeking.has(id) ? cipherHTML : plainHTML;
      return `<div class="${cls}" data-id="${id}">${show}</div>`;
    }).join('');
    box.scrollTop = box.scrollHeight;

    // scramble-decrypt reveal for freshly-arrived incoming text
    S.animate.forEach((id) => {
      const v = S.view.get(id);
      if (!v || !v.text) return;
      const el = box.querySelector(`[data-id="${id}"] .body`);
      if (el) scramble(el, v.text);
    });
    S.animate.clear();
    maybeMarkRead();
  }

  // mark everything up to the latest message as read (throttled; privacy-gated)
  function maybeMarkRead() {
    if (!S.msgs.size || !S.cid || !S.shareStatus) return;
    let latest = 0; S.msgs.forEach((m) => { if (m.ts > latest) latest = m.ts; });
    if (latest > S.readThrottle) {
      S.readThrottle = latest;
      S.db.setRead(S.cid, S.uuid, latest).catch(() => {});
    }
  }

  // send typing pings while composing (throttled; privacy-gated)
  $('msgInput').addEventListener('input', () => {
    const now = Date.now();
    if (S.cid && S.shareStatus && now - S.typingThrottle > 1800) {
      S.typingThrottle = now;
      S.db.setTyping(S.cid, S.uuid, now).catch(() => {});
    }
  });

  // ---------- privacy toggle ----------
  S.shareStatus = localStorage.getItem('aiclab-share-status') !== '0';
  $('shareStatus').checked = S.shareStatus;
  $('shareStatus').addEventListener('change', (e) => {
    S.shareStatus = e.target.checked;
    localStorage.setItem('aiclab-share-status', S.shareStatus ? '1' : '0');
  });
  $('settingsBtn').addEventListener('click', (e) => { e.stopPropagation(); $('settingsPop').classList.toggle('hidden'); });
  document.addEventListener('click', (e) => { if (!e.target.closest('.settings-wrap')) $('settingsPop').classList.add('hidden'); });

  // click a message to toggle ciphertext view
  $('messages').addEventListener('click', (e) => {
    const el = e.target.closest('.msg'); if (!el) return;
    const id = el.dataset.id; const v = S.view.get(id); if (!v) return;
    if (S.peeking.has(id)) { S.peeking.delete(id); el.innerHTML = v.plain; }
    else { S.peeking.add(id); el.innerHTML = v.cipher; }
  });

  function scramble(el, finalText) {
    const pool = '!<>-_\\/[]{}=+*^?#________01', chars = [...finalText];
    let frame = 0; const total = chars.length + 14;
    const timer = setInterval(() => {
      el.textContent = chars.map((c, i) => {
        if (i < frame - 12) return c;
        if (c === ' ') return ' ';
        return pool[Math.floor(Math.random() * pool.length)];
      }).join('');
      if (frame++ >= total) { clearInterval(timer); el.textContent = finalText; }
    }, 28);
  }

  async function send(envelope) {
    const payload = CryptoBox.encryptEnvelope(envelope, S.keypair.secretKey, S.peerPub);
    await S.db.sendMessage(S.cid, { from: S.uuid, to: S.peer, ts: Date.now(), ...payload });
  }

  $('composer').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (S.pendingImage) { const img = S.pendingImage; clearPreview(); await send(img).catch((ex) => alert('send failed: ' + ex.message)); return; }
    const input = $('msgInput'), text = input.value.trim();
    if (!text) return;
    input.value = '';
    S.typingThrottle = 0; if (S.shareStatus) S.db.setTyping(S.cid, S.uuid, 0).catch(() => {}); // stop "typing…"
    try { await send({ t: 'text', body: text }); }
    catch (ex) { input.value = text; alert('send failed: ' + ex.message); }
  });

  // ---------- images ----------
  $('attach').addEventListener('click', () => $('fileInput').click());
  $('fileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0]; e.target.value = ''; if (!file) return;
    try {
      const { base64, mime } = await downscaleImage(file, 1024, 0.8);
      S.pendingImage = { t: 'image', mime, body: base64 };
      $('imgPreview').classList.remove('hidden');
      $('imgPreview').innerHTML = `<img src="data:${mime};base64,${base64}"/><span class="lbl">image ready · will be encrypted on send</span><button id="cancelImg">cancel</button>`;
      $('cancelImg').addEventListener('click', clearPreview);
    } catch (ex) { alert('image error: ' + ex.message); }
  });
  function clearPreview() { S.pendingImage = null; $('imgPreview').classList.add('hidden'); $('imgPreview').innerHTML = ''; }
  function downscaleImage(file, maxDim, quality) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        let { width, height } = img; const scale = Math.min(1, maxDim / Math.max(width, height));
        width = Math.round(width * scale); height = Math.round(height * scale);
        const cv = document.createElement('canvas'); cv.width = width; cv.height = height;
        cv.getContext('2d').drawImage(img, 0, 0, width, height);
        const mime = 'image/jpeg';
        resolve({ base64: cv.toDataURL(mime, quality).split(',')[1], mime });
      };
      img.onerror = () => reject(new Error('could not read image'));
      img.src = URL.createObjectURL(file);
    });
  }

  // ---------- logout ----------
  $('logout').addEventListener('click', () => {
    if (S.es) S.es.close();
    if (S.auth) S.auth.stop();
    S.secret = null; S.keypair = null; S.msgs.clear(); S.view.clear(); S.peeking.clear();
    $('chat').classList.add('hidden'); $('login').classList.remove('hidden');
    $('connect').disabled = false; $('connect').textContent = 'ESTABLISH SECURE CHANNEL';
    $('handshake').innerHTML = ''; $('secret').value = ''; refreshMyKey();
  });
})();
