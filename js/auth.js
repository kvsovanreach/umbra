/* Firebase Anonymous Auth via REST (no SDK).
 *
 * Signs in anonymously to obtain an idToken, which is passed as `?auth=` on all
 * database requests so the hardened rules (which require auth != null) accept
 * them. Auto-refreshes before the 1h token expiry. If no apiKey is configured,
 * it's a no-op (token() returns null) and the app runs against open rules.
 */
window.FireAuth = function (apiKey) {
  let idToken = null, refreshToken = null, timer = null;

  async function signIn() {
    if (!apiKey || apiKey.includes('YOUR-')) return null; // no auth configured
    const r = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${apiKey}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ returnSecureToken: true }) });
    if (!r.ok) throw new Error('anonymous sign-in failed: ' + (await r.text()));
    const d = await r.json();
    idToken = d.idToken; refreshToken = d.refreshToken;
    _scheduleRefresh(parseInt(d.expiresIn || '3600', 10));
    return idToken;
  }

  async function _refresh() {
    if (!refreshToken) return;
    try {
      const r = await fetch(`https://securetoken.googleapis.com/v1/token?key=${apiKey}`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken)}` });
      const d = await r.json();
      if (d.id_token) {
        idToken = d.id_token; refreshToken = d.refresh_token;
        _scheduleRefresh(parseInt(d.expires_in || '3600', 10));
      }
    } catch (e) { /* keep old token; next request may fail and retrigger */ }
  }

  function _scheduleRefresh(sec) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(_refresh, Math.max(30, sec - 300) * 1000); // refresh 5 min early
  }

  return {
    signIn,
    token: () => idToken,
    enabled: () => !!(apiKey && !apiKey.includes('YOUR-')),
    stop: () => timer && clearTimeout(timer),
  };
};
