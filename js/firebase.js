/* Firebase Realtime Database — raw REST client (no SDK).
 *
 * `tokenProvider` is a function returning the current auth idToken (or null).
 * It's read per-request so refreshed tokens are always used. The live stream
 * reconnects with a fresh token if the server revokes auth (token expiry).
 */
window.FireDB = function (databaseURL, tokenProvider) {
  const base = databaseURL.replace(/\/$/, '');
  const auth = () => {
    const t = tokenProvider && tokenProvider();
    return t ? `?auth=${encodeURIComponent(t)}` : '';
  };

  async function _req(method, path, body) {
    const res = await fetch(`${base}/${path}.json${auth()}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
    return res.status === 204 ? null : res.json();
  }

  return {
    publishPublicKey: (uuid, publicKey) =>
      _req('PUT', `users/${uuid}`, { publicKey, updated: Date.now() }),

    getPublicKey: async (uuid) => {
      const u = await _req('GET', `users/${uuid}`);
      return u && u.publicKey ? u.publicKey : null;
    },

    // Admin-controlled allowlist. Clients may read their own entry but can never
    // write it (rules deny; the Console and Admin SDK bypass rules). This is a UX
    // nicety only — the real gate is the .write rule on /users/{uuid}, so a client
    // that skips or fakes this check still cannot publish a key.
    //   active     → approved
    //   disabled   → explicitly turned off
    //   unlisted   → no entry yet (never approved)
    //   unreadable → allowlist rules not deployed; defer to the write attempt
    getStatus: async (uuid) => {
      try {
        const a = await _req('GET', `allowlist/${uuid}`);
        if (!a) return { state: 'unlisted', label: null };
        return { state: a.status === 'active' ? 'active' : (a.status || 'disabled'), label: a.label || null };
      } catch (e) {
        return { state: 'unreadable', label: null };
      }
    },

    sendMessage: (cid, msg) => _req('POST', `conversations/${cid}/messages`, msg),
    setTyping: (cid, uuid, ts) => _req('PUT', `conversations/${cid}/typing/${uuid}`, ts),
    setRead: (cid, uuid, ts) => _req('PUT', `conversations/${cid}/read/${uuid}`, ts),

    getMessages: async (cid) => {
      const map = await _req('GET', `conversations/${cid}/messages`);
      if (!map) return [];
      return Object.entries(map).map(([id, m]) => ({ id, ...m }))
        .sort((a, b) => (a.ts || 0) - (b.ts || 0));
    },

    // one live stream over the whole conversation, routed to handlers:
    //   h.onMessage(id, msg) · h.onTyping(uuid, ts) · h.onRead(uuid, ts)
    stream: function (cid, h, onState) {
      let es = null, closed = false, retry = 0;
      const eachMap = (m, fn) => m && typeof m === 'object' && Object.entries(m).forEach(([k, v]) => fn(k, v));
      const route = (path, data) => {
        if (path === '/') {
          eachMap(data.messages, (id, m) => m && m.c && h.onMessage(id, m));
          eachMap(data.typing, (u, t) => h.onTyping(u, t));
          eachMap(data.read, (u, t) => h.onRead(u, t));
          return;
        }
        const parts = path.split('/').filter(Boolean); // [section, key]
        const [section, key] = parts;
        if (section === 'messages') {
          if (key) { if (data && data.c) h.onMessage(key, data); }
          else eachMap(data, (id, m) => m && m.c && h.onMessage(id, m));
        } else if (section === 'typing') {
          if (key) h.onTyping(key, data); else eachMap(data, h.onTyping);
        } else if (section === 'read') {
          if (key) h.onRead(key, data); else eachMap(data, h.onRead);
        }
      };
      const open = () => {
        if (closed) return;
        es = new EventSource(`${base}/conversations/${cid}.json${auth()}`);
        const handle = (e) => {
          retry = 0; onState && onState(true);
          let p; try { p = JSON.parse(e.data); } catch (_) { return; }
          if (!p || p.data == null) return;
          route(p.path, p.data);
        };
        es.addEventListener('put', handle);
        es.addEventListener('patch', handle);
        es.addEventListener('auth_revoked', () => { es.close(); reconnect(); });
        es.onerror = () => { onState && onState(false); es.close(); reconnect(); };
      };
      const reconnect = () => { if (closed) return; retry = Math.min(retry + 1, 6); setTimeout(open, 1000 * retry); };
      open();
      return { close: () => { closed = true; if (es) es.close(); } };
    },
  };
};
