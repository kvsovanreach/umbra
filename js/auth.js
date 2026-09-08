/* Firebase Anonymous Auth via REST (no SDK).
 *
 * Signs in anonymously to obtain an idToken, passed as `?auth=` on all database
 * requests so the hardened rules (which require auth != null) accept them.
 *
 * The anonymous refresh token is PERSISTED (localStorage) and reused on the next
 * visit, so this device keeps a STABLE auth.uid across sessions. That stable uid
 * is what the rules bind each UUID to (write-once), which is how a message's
 * `from` can be tied to the device that owns that identity — closing the
 * sender-spoofing hole. The refresh token is an anonymous session credential
 * only; it decrypts nothing and is unrelated to your E2E secret.
 *
 * If no apiKey is configured it's a no-op (token()/uid() return null) and the
 * app runs against open rules.
 */
window.FireAuth = function (apiKey) {
  let idToken = null, refreshToken = null, localId = null, timer = null;
  const AUTHKEY = 'umbra-auth';

  // exchange a refresh token for a fresh idToken, keeping the SAME uid
  async function _useRefreshToken(rt) {
    const r = await fetch(`https://securetoken.googleapis.com/v1/token?key=${apiKey}`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(rt)}` });
    if (!r.ok) return false;
    const d = await r.json();
    if (!d.id_token) return false;
    idToken = d.id_token; refreshToken = d.refresh_token; localId = d.user_id;
    try { localStorage.setItem(AUTHKEY, refreshToken); } catch (e) {}
    _scheduleRefresh(parseInt(d.expires_in || '3600', 10));
    return true;
  }

  async function signIn() {
    if (!apiKey || apiKey.includes('YOUR-')) return null; // no auth configured
    let saved = null; try { saved = localStorage.getItem(AUTHKEY); } catch (e) {}
    if (saved) { try { if (await _useRefreshToken(saved)) return idToken; } catch (e) { /* stale token → fresh sign-up */ } }
    const r = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${apiKey}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ returnSecureToken: true }) });
    if (!r.ok) throw new Error('anonymous sign-in failed: ' + (await r.text()));
    const d = await r.json();
    idToken = d.idToken; refreshToken = d.refreshToken; localId = d.localId;
    try { localStorage.setItem(AUTHKEY, refreshToken); } catch (e) {}
    _scheduleRefresh(parseInt(d.expiresIn || '3600', 10));
    return idToken;
  }

  async function _refresh() {
    if (!refreshToken) return;
    try { await _useRefreshToken(refreshToken); } catch (e) { /* keep old token; next request may retrigger */ }
  }

  function _scheduleRefresh(sec) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(_refresh, Math.max(30, sec - 300) * 1000); // refresh 5 min early
  }

  return {
    signIn,
    token: () => idToken,
    uid: () => localId,
    enabled: () => !!(apiKey && !apiKey.includes('YOUR-')),
    stop: () => timer && clearTimeout(timer),
  };
};
