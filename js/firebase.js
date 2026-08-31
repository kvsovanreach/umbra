/* Firebase Realtime Database — raw REST client (no SDK).
 *
 * `tokenProvider` is a function returning the current auth idToken (or null).
 * It's read per-request so refreshed tokens are always used. The live stream
 * reconnects with a fresh token if the server revokes auth (token expiry).
 */
window.FireDB = function (databaseURL, tokenProvider) {
  const base = databaseURL.replace(/\/$/, '');
  const qs = (extra) => {
    const t = tokenProvider && tokenProvider();
    const parts = [];
    if (t) parts.push('auth=' + encodeURIComponent(t));
    if (extra) parts.push(extra);
    return parts.length ? '?' + parts.join('&') : '';
  };

  async function _req(method, path, body, query) {
    const res = await fetch(`${base}/${path}.json${qs(query)}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
    return res.status === 204 ? null : res.json();
  }

  // Messages are POSTed, so their keys are Firebase push ids — lexicographically
  // ordered by creation time. Paging on $key therefore needs no .indexOn, unlike
  // ordering on ts, and it can't be skewed by a client's clock.
  const byKey = (map) => !map ? []
    : Object.keys(map).sort().map((id) => Object.assign({ id }, map[id]));

  // one reconnecting EventSource; `route(path, data)` receives each put/patch
  function _es(path, query, route, onState) {
    let es = null, closed = false, retry = 0;
    const open = () => {
      if (closed) return;
      es = new EventSource(`${base}/${path}.json${qs(query)}`);
      const handle = (e) => {
        retry = 0; if (onState) onState(true);
        let p; try { p = JSON.parse(e.data); } catch (_) { return; }
        // null data means a removal — e.g. the limitToLast window sliding past an
        // older message. We keep what we already have, so there is nothing to do.
        if (!p || p.data == null) return;
        route(p.path, p.data);
      };
      es.addEventListener('put', handle);
      es.addEventListener('patch', handle);
      es.addEventListener('auth_revoked', () => { es.close(); reconnect(); });
      es.onerror = () => { if (onState) onState(false); es.close(); reconnect(); };
    };
    const reconnect = () => { if (closed) return; retry = Math.min(retry + 1, 6); setTimeout(open, 1000 * retry); };
    open();
    return { close: () => { closed = true; if (es) es.close(); } };
  }
  const childOf = (path) => path.split('/').filter(Boolean)[0];

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
    //   active   → approved
    //   disabled → explicitly turned off
    //   unlisted → no entry yet (never approved)
    //   denied   → allowlist rules not published, so access control isn't configured
    //   error    → transient (network/5xx)
    // Callers must treat everything except 'active' as refused. A gate that
    // no-ops when its backing config is missing is worse than no gate at all.
    getStatus: async (uuid) => {
      try {
        const a = await _req('GET', `allowlist/${uuid}`);
        if (!a) return { state: 'unlisted', label: null };
        return { state: a.status === 'active' ? 'active' : (a.status || 'disabled'), label: a.label || null };
      } catch (e) {
        const denied = /\b40[13]\b|permission denied/i.test(e.message);
        return { state: denied ? 'denied' : 'error', label: null };
      }
    },

    sendMessage: (cid, msg) => _req('POST', `conversations/${cid}/messages`, msg),
    setTyping: (cid, uuid, ts) => _req('PUT', `conversations/${cid}/typing/${uuid}`, ts),
    setRead: (cid, uuid, ts) => _req('PUT', `conversations/${cid}/read/${uuid}`, ts),

    // newest page — the last `limit` messages, oldest-first
    getMessages: async (cid, limit) =>
      byKey(await _req('GET', `conversations/${cid}/messages`, null,
        `orderBy=%22%24key%22&limitToLast=${limit || 50}`)),

    // older page — the `limit` messages immediately before `beforeKey`.
    // endAt is inclusive, so ask for one extra and drop the boundary itself.
    getMessagesBefore: async (cid, beforeKey, limit) => {
      const n = (limit || 50) + 1;
      const rows = byKey(await _req('GET', `conversations/${cid}/messages`, null,
        `orderBy=%22%24key%22&endAt=%22${encodeURIComponent(beforeKey)}%22&limitToLast=${n}`));
      return rows.filter((m) => m.id !== beforeKey);
    },

    // Three scoped streams instead of one on the whole conversation. The old
    // single stream re-sent every message in the thread on each connect, which
    // is what made a long history expensive; the messages stream is now bounded
    // by the same window as the initial page.
    //   h.onMessage(id, msg) · h.onTyping(uuid, ts) · h.onRead(uuid, ts)
    stream: function (cid, h, onState, windowSize) {
      const eachMap = (m, fn) => m && typeof m === 'object' && Object.keys(m).forEach((k) => fn(k, m[k]));
      const subs = [
        // only this one drives the connection indicator; the other two would
        // fight over it and flicker
        _es(`conversations/${cid}/messages`, `orderBy=%22%24key%22&limitToLast=${windowSize || 50}`,
          (path, data) => {
            const id = childOf(path);
            if (id) { if (data && data.c) h.onMessage(id, data); }
            else eachMap(data, (k, m) => m && m.c && h.onMessage(k, m));
          }, onState),
        _es(`conversations/${cid}/typing`, '', (path, data) => {
          const u = childOf(path);
          if (u) h.onTyping(u, data); else eachMap(data, h.onTyping);
        }),
        _es(`conversations/${cid}/read`, '', (path, data) => {
          const u = childOf(path);
          if (u) h.onRead(u, data); else eachMap(data, h.onRead);
        }),
      ];
      return { close: () => subs.forEach((s) => s.close()) };
    },
  };
};
