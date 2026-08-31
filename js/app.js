/* Umbra — UI + wiring, crypto-terminal edition.
 * Innovations: live key-fingerprint identicons, connect handshake, click-to-peek
 * ciphertext, and a scramble-decrypt reveal for incoming messages.
 */
(function () {
  const $ = (id) => document.getElementById(id);
  const util = nacl.util;
  const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const PAGE = 50;   // messages per page, initial and per "load older"

  const S = { uuid: null, secret: null, keypair: null, peer: null, peerPub: null, myPub: null,
              db: null, auth: null, cid: null, es: null, msgs: new Map(), view: new Map(),
              peeking: new Set(), animate: new Set(), pendingImage: null, loaded: false,
              peerRead: 0, verified: false, typingThrottle: 0, typingTimer: null, readThrottle: 0,
              peerState: 'active', peerWatch: null,
              dec: new Map(), oldestKey: null, hasMore: false, loadingMore: false };

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
  function liveFingerprint(getUuid, getSecret, fpEl, canvas) {
    let seq = 0, timer = null;
    return function () {
      const uuid = getUuid(), secret = getSecret();
      if (!uuid || !secret) { fpEl.textContent = '— — — —'; drawIdenticon(canvas, null); return; }
      fpEl.textContent = 'deriving…';
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const mine = ++seq;
        try {
          const kp = await CryptoBox.keypairFrom(uuid, secret);
          if (mine !== seq) return; // a newer keystroke superseded this
          const pub = CryptoBox.publicKeyB64(kp);
          fpEl.textContent = fpHex(pub);
          drawIdenticon(canvas, pub);
        } catch (e) { fpEl.textContent = '— — — —'; }
      }, 250);
    };
  }
  const refreshMyKey = liveFingerprint(
    () => $('uuid').value.trim(), () => $('secret').value, $('myFp'), $('myIdenticon'));
  const refreshUnlockKey = liveFingerprint(
    () => (savedIdentity() || {}).uuid, () => $('unlockSecret').value, $('unlockFp'), $('unlockIdenticon'));
  $('secret').addEventListener('input', refreshMyKey);
  $('uuid').addEventListener('input', refreshMyKey);
  $('unlockSecret').addEventListener('input', refreshUnlockKey);

  // ---------- session memory ----------
  // Identity only — the secret is NEVER written anywhere. sessionStorage survives a
  // refresh but dies with the tab; localStorage is the opt-in "remember" checkbox.
  const SKEY = 'umbra-session', LKEY = 'aiclab';
  const readJSON = (store, k) => { try { return JSON.parse(store.getItem(k) || '{}'); } catch (e) { return {}; } };
  const complete = (v) => !!(v && v.uuid && v.peer && v.dburl);
  function savedIdentity() {
    const s1 = readJSON(sessionStorage, SKEY); if (complete(s1)) return s1;
    const s2 = readJSON(localStorage, LKEY);   if (complete(s2)) return s2;
    return null;
  }
  function rememberIdentity(v, persist) {
    const rec = JSON.stringify({ uuid: v.uuid, peer: v.peer, dburl: v.dburl });
    try { sessionStorage.setItem(SKEY, rec); } catch (e) { /* private mode */ }
    if (persist) localStorage.setItem(LKEY, rec); else localStorage.removeItem(LKEY);
  }
  function forgetIdentity() {
    try { sessionStorage.removeItem(SKEY); } catch (e) {}
    localStorage.removeItem(LKEY);
  }

  const VIEWS = { login: $('login'), unlock: $('unlock'), chat: $('chat') };
  const show = (name) => Object.keys(VIEWS).forEach((k) => VIEWS[k].classList.toggle('hidden', k !== name));

  // ---------- login prefill ----------
  const saved = readJSON(localStorage, LKEY);
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
  async function hsStep(target, text, ms) {
    const el = document.createElement('div');
    el.className = 'step';
    el.innerHTML = `<span>◇</span><span>${text}</span>`;
    target.appendChild(el);
    await sleep(ms || 260);
    el.querySelector('span:first-child').outerHTML = '<span class="tick">✓</span>';
    return el;
  }

  // ---------- connect ----------
  // Shared by the full login form and the unlock (returning session) form.
  // `ui` names the elements to drive so each form reports into its own card.
  async function establish(vals, ui) {
    const { uuid, secret, peer, dburl } = vals;
    ui.err.textContent = ''; ui.hs.innerHTML = '';
    if (!uuid || !secret || !peer) { ui.err.textContent = 'uuid, secret and peer are required'; return; }
    if (!dburl || dburl.includes('YOUR-PROJECT')) { ui.err.textContent = 'set your firebase database url (advanced)'; return; }
    if (uuid === peer) { ui.err.textContent = 'your uuid and peer uuid must differ'; return; }

    ui.btn.disabled = true; ui.btn.textContent = ui.busy;
    const fail = (msg) => { ui.err.textContent = msg; ui.btn.disabled = false; ui.btn.textContent = ui.idle; };
    const step = (text, ms) => hsStep(ui.hs, text, ms);
    try {
      S.uuid = uuid; S.secret = secret; S.peer = peer;
      await step('deriving keypair · PBKDF2-250k · X25519…', 340);
      S.keypair = await CryptoBox.keypairFrom(uuid, secret);

      S.auth = FireAuth((window.FIREBASE_CONFIG || {}).apiKey);
      if (S.auth.enabled()) {
        await step('anonymous auth · acquiring token…');
        await S.auth.signIn();
      }
      S.db = FireDB(dburl, () => S.auth.token());

      // access gate — the DB rule is the real enforcement, this is for a clear message
      await step('checking account access…');
      const acct = await S.db.getStatus(uuid);
      // default-deny: only an explicit 'active' gets through. Anything else —
      // including "the allowlist rules aren't published" — is refused, so the
      // gate can never silently disappear because of a config gap.
      if (acct.state !== 'active') {
        return fail(
          acct.state === 'disabled' ? 'this uuid has been disabled — contact the operator to re-enable it'
          : acct.state === 'unlisted' ? 'this uuid is not registered — ask the operator to add it to the allowlist'
          : acct.state === 'denied' ? 'access control is not configured — the allowlist rules have not been published to this database'
          : acct.state === 'error' ? 'could not verify access — check your connection and try again'
          : `this uuid is not active (status: ${acct.state})`);
      }

      // Pre-flight: if this uuid already holds a key, it must be the one we just
      // derived. The write rule enforces this anyway, but checking first lets us
      // say "wrong secret" instead of a message that conflates several causes.
      const myPub = CryptoBox.publicKeyB64(S.keypair);
      const onFile = await S.db.getPublicKey(uuid);
      if (onFile && onFile !== myPub) {
        return fail('wrong secret for this uuid — it is already bound to a different key. check your passphrase.');
      }

      await step(`publishing public key → /users/${uuid}…`);
      try {
        await S.db.publishPublicKey(uuid, CryptoBox.publicKeyB64(S.keypair));
      } catch (ex) {
        if (/\b401\b|permission denied/i.test(ex.message)) {
          return fail('key publish refused — either this uuid is not enabled, or it already holds a different key (wrong secret?)');
        }
        throw ex;
      }

      await step('fetching peer public key…');
      S.peerPub = await S.db.getPublicKey(peer);
      if (!S.peerPub) return fail(`peer "${peer}" hasn't joined — they must open the app once to publish their key`);
      await step('checking peer access…');
      S.peerState = (await S.db.getStatus(peer)).state;

      await step('ECDH shared secret established', 340);

      S.cid = CryptoBox.conversationId(uuid, peer);
      rememberIdentity(vals, vals.remember);
      await sleep(240);
      enterChat();
    } catch (ex) {
      fail('failed: ' + ex.message);
    }
  }

  $('loginForm').addEventListener('submit', (e) => {
    e.preventDefault();
    establish({
      uuid: $('uuid').value.trim(), secret: $('secret').value,
      peer: $('peer').value.trim(), dburl: $('dburl').value.trim(),
      remember: $('remember').checked,
    }, { err: $('loginErr'), hs: $('handshake'), btn: $('connect'),
         busy: 'ESTABLISHING…', idle: 'ESTABLISH SECURE CHANNEL' });
  });

  // ---------- unlock (returning session) ----------
  function showUnlock(id, reason) {
    const lr = $('lockReason');
    if (reason) { lr.textContent = reason; lr.classList.remove('hidden'); }
    else { lr.textContent = ''; lr.classList.add('hidden'); }
    $('unlockUuid').textContent = id.uuid; $('unlockUuid').title = id.uuid;
    $('unlockPeer').textContent = id.peer; $('unlockPeer').title = id.peer;
    $('unlockSecret').value = '';
    $('unlockErr').textContent = ''; $('unlockHandshake').innerHTML = '';
    $('unlockBtn').disabled = false; $('unlockBtn').textContent = 'UNLOCK';
    refreshUnlockKey();
    show('unlock');
    setTimeout(() => $('unlockSecret').focus(), 60);
  }

  $('unlockForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const id = savedIdentity();
    if (!id) return show('login');
    establish({ uuid: id.uuid, peer: id.peer, dburl: id.dburl,
                secret: $('unlockSecret').value,
                remember: complete(readJSON(localStorage, LKEY)) },
      { err: $('unlockErr'), hs: $('unlockHandshake'), btn: $('unlockBtn'),
        busy: 'UNLOCKING…', idle: 'UNLOCK' });
  });

  $('switchIdentity').addEventListener('click', () => {
    forgetIdentity();
    $('uuid').value = ''; $('peer').value = ''; $('secret').value = '';
    $('dburl').value = (window.FIREBASE_CONFIG && window.FIREBASE_CONFIG.databaseURL) || '';
    $('remember').checked = false;
    refreshMyKey();
    show('login');
  });

  // ---------- chat ----------
  function enterChat() {
    show('chat');
    S.myPub = CryptoBox.publicKeyB64(S.keypair);
    $('peerName').textContent = S.peer;
    $('peerFp').textContent = fpHex(S.peerPub);
    $('meFp').textContent = fpHex(S.myPub);
    $('meId').textContent = S.uuid.length > 14 ? S.uuid.slice(0, 8) + '…' : S.uuid;
    $('meId').title = S.uuid;
    drawIdenticon($('peerIdenticon'), S.peerPub);
    initVerification();
    renderPeerAlert();
    clearInterval(S.peerWatch);
    S.peerWatch = setInterval(refreshPeerState, 90000);
    armIdle();
    $('statusDot').classList.add('on');
    S.msgs.clear(); S.dec.clear(); S.loaded = false; S.peerRead = 0;
    S.oldestKey = null; S.hasMore = false; S.loadingMore = false;
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
    }, (up) => {
      $('statusDot').classList.toggle('on', up);
      $('statusText').textContent = up ? 'live' : 'offline';   // the dot alone read as connected
    }, PAGE);

    S.db.getMessages(S.cid, PAGE).then((list) => {
      list.forEach((m) => S.msgs.set(m.id, m));
      S.oldestKey = list.length ? list[0].id : null;
      S.hasMore = list.length >= PAGE;   // a full page suggests there is more behind it
      S.loaded = true; render({ toBottom: true });
    }).catch(() => { S.loaded = true; render({ toBottom: true }); });
  }

  // ---------- peer access notice ----------
  // 'denied'/'error' are our own config or network problems, not the peer's —
  // stay quiet rather than cry wolf. Anything else means the peer can't write.
  function renderPeerAlert() {
    const el = $('peerAlert'), st = S.peerState;
    if (st === 'active' || st === 'denied' || st === 'error') { el.classList.add('hidden'); el.innerHTML = ''; return; }
    const who = `<b>${esc(S.peer.length > 14 ? S.peer.slice(0, 10) + '…' : S.peer)}</b>`;
    const msg = st === 'disabled'
      ? `${who} has been disabled by the operator — they can't send or reply until re-enabled.`
      : st === 'unlisted'
        ? `${who} is no longer approved for access — they can't send or reply.`
        : `${who} is not active (status: ${esc(st)}) — they can't send or reply.`;
    el.innerHTML = `<span>⚠</span><span>${msg} Your messages are still encrypted and stored for them.</span>`;
    el.classList.remove('hidden');
  }

  async function refreshPeerState() {
    if (!S.db || !S.peer) return;
    try {
      const st = (await S.db.getStatus(S.peer)).state;
      if (st !== S.peerState) { S.peerState = st; renderPeerAlert(); }
    } catch (e) { /* transient — keep showing whatever we last knew */ }
  }

  // re-check when the tab comes back into focus, so a peer disabled mid-session surfaces
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshPeerState(); });

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

  // opts.toBottom  — jump to newest (first load, own message)
  // opts.keepScroll — anchor the viewport after prepending older messages
  function render(opts) {
    const box = $('messages');
    const o = opts || {};
    const wasNearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
    const prevH = box.scrollHeight, prevTop = box.scrollTop;

    const items = [...S.msgs.entries()].sort((a, b) => (a[1].ts || 0) - (b[1].ts || 0));
    const more = S.hasMore
      ? `<button type="button" class="load-more" id="loadMore"${S.loadingMore ? ' disabled' : ''}>` +
        `${S.loadingMore ? 'loading…' : `↑ load ${PAGE} older messages`}</button>`
      : '';
    if (!items.length) {
      box.innerHTML = more + '<div class="sys">no messages yet — say hello · end-to-end encrypted</div>';
      return;
    }
    S.view.clear();
    box.innerHTML = more + items.map(([id, m]) => {
      const mine = m.from === S.uuid;
      // decryption is the expensive part of a render, and a message never
      // changes once written — so open each one only the first time we see it
      let env = S.dec.get(id);
      if (env === undefined) { env = CryptoBox.decryptEnvelope(m, S.keypair.secretKey, S.peerPub); S.dec.set(id, env); }
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

    // Prepending older messages must not move the reader, and an arriving
    // message must not yank someone who has scrolled up to read history.
    if (o.keepScroll) box.scrollTop = prevTop + (box.scrollHeight - prevH);
    else if (o.toBottom || wasNearBottom) box.scrollTop = box.scrollHeight;
    else box.scrollTop = prevTop;

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

  async function loadOlder() {
    if (S.loadingMore || !S.hasMore || !S.oldestKey) return;
    S.loadingMore = true; render({ keepScroll: true });
    try {
      const older = await S.db.getMessagesBefore(S.cid, S.oldestKey, PAGE);
      older.forEach((m) => S.msgs.set(m.id, m));
      if (older.length) S.oldestKey = older[0].id;
      S.hasMore = older.length >= PAGE;
    } catch (ex) {
      S.hasMore = true;   // leave the control up so it can be retried
    }
    S.loadingMore = false;
    render({ keepScroll: true });
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
    if (e.target.id === 'loadMore') { loadOlder(); return; }
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
    render({ toBottom: true });   // your own message always scrolls into view
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

  // ---------- auto-lock ----------
  // Locking drops the keypair from memory; the identity stays remembered, so
  // resuming costs one passphrase. Timers alone are not enough: background tabs
  // throttle them and sleep stops them, so elapsed time is re-checked on return.
  const IDLE_MS = 30 * 60 * 1000;   // lock after this much inactivity
  const WARN_MS = 60 * 1000;        // start counting down this long before
  const IDLE_MSG = 'locked after 30 minutes of inactivity — enter your secret to resume';
  let idleTimer = null, warnTimer = null, ticker = null, lastActive = 0;

  const inChat = () => !VIEWS.chat.classList.contains('hidden');

  function disarmIdle() {
    clearTimeout(idleTimer); clearTimeout(warnTimer); clearInterval(ticker);
    idleTimer = warnTimer = ticker = null;
    $('idleWarn').classList.add('hidden'); $('idleWarn').innerHTML = '';
  }
  function armIdle() {
    disarmIdle();
    lastActive = Date.now();
    warnTimer = setTimeout(showIdleWarning, IDLE_MS - WARN_MS);
    idleTimer = setTimeout(() => lockSession(IDLE_MSG), IDLE_MS);
  }
  function showIdleWarning() {
    const el = $('idleWarn');
    const paint = () => {
      const left = Math.max(0, Math.ceil((lastActive + IDLE_MS - Date.now()) / 1000));
      el.innerHTML = `<span>⏻</span><span>locking in <b>${left}s</b> — your keys will be dropped from memory. move or type to stay unlocked.</span>`;
    };
    paint();
    el.classList.remove('hidden');
    clearInterval(ticker); ticker = setInterval(paint, 1000);
  }
  function noteActivity() {
    if (!inChat()) return;
    if (Date.now() - lastActive < 5000) return; // throttle; the timer is already fresh
    armIdle();
  }
  ['pointerdown', 'keydown', 'wheel', 'touchstart', 'input'].forEach((ev) =>
    document.addEventListener(ev, noteActivity, { passive: true }));
  document.addEventListener('visibilitychange', () => {
    if (document.hidden || !inChat()) return;
    const idle = Date.now() - lastActive;
    if (idle >= IDLE_MS) lockSession(IDLE_MSG);
    else if (idle >= IDLE_MS - WARN_MS) showIdleWarning();
  });

  // ---------- leave (lock the session) ----------
  // Drops every key from memory. The identity is kept so you land on the unlock
  // card rather than retyping two UUIDs; "use a different identity" clears it.
  function lockSession(reason) {
    if (S.es) { S.es.close(); S.es = null; }
    if (S.auth) S.auth.stop();
    clearInterval(S.peerWatch); S.peerWatch = null;
    disarmIdle();
    S.peerState = 'active'; $('peerAlert').classList.add('hidden'); $('peerAlert').innerHTML = '';
    S.secret = null; S.keypair = null; S.peerPub = null;
    S.msgs.clear(); S.view.clear(); S.peeking.clear(); S.dec.clear();
    S.oldestKey = null; S.hasMore = false; S.loadingMore = false;
    $('messages').innerHTML = '';
    $('msgInput').value = ''; clearPreview();
    $('connect').disabled = false; $('connect').textContent = 'ESTABLISH SECURE CHANNEL';
    $('handshake').innerHTML = ''; $('secret').value = ''; refreshMyKey();
    const id = savedIdentity();
    if (id) showUnlock(id, reason);
    else { show('login'); if (reason) $('loginErr').textContent = reason; }
  }
  $('logout').addEventListener('click', () => lockSession(null));

  // ---------- boot ----------
  // A refresh lands here: identity is remembered, the secret never is, so all we
  // ask for is the passphrase that re-derives the key.
  const resuming = savedIdentity();
  if (resuming) showUnlock(resuming); else show('login');
})();
