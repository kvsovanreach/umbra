/* Firebase config. These values are safe to expose publicly — security comes
 * from the end-to-end encryption + your database rules, not from hiding them.
 *
 *  databaseURL : Realtime Database URL (Build → Realtime Database)
 *  apiKey      : Web API key (Project settings → General). Enables anonymous
 *                auth so the hardened, auth-required rules accept requests.
 *                Leave the placeholder to run against open/demo rules instead.
 */
window.FIREBASE_CONFIG = {
  databaseURL: 'https://aiclab-demo-default-rtdb.asia-southeast1.firebasedatabase.app',
  apiKey: 'AIzaSyC7RKiETn8X1Yo1dKnQ_TbYJnNeQTyR1Aw',
};

/* ------------------------------------------------------------------------
 * Hello to whoever just opened devtools looking for the "leaked" key. 👋
 * Yes, it's real. Yes, it's meant to be there. Explanation below.
 * ---------------------------------------------------------------------- */
(function () {
  const big = 'font:700 20px ui-monospace,SFMono-Regular,monospace;color:#4de0d6;text-shadow:0 0 12px rgba(77,224,214,.45)';
  const st = (c, w) => `color:${c};font:${w || 400} 12px ui-monospace,SFMono-Regular,monospace;line-height:1.65`;

  console.log('%c◐ umbra::e2e', big);
  console.log('%cYou found the API key. Congratulations — go ahead and take it.\nScreenshot it. Post it. We\'ll wait.', st('#ffcf6b', 700));
  console.log(
    '%cIt is an identifier, not a credential. It cannot read the database, cannot\n' +
    'bypass a single security rule, and cannot decrypt one byte of anything.\n\n' +
    '  · messages are sealed in your browser — X25519 ECDH + XSalsa20-Poly1305\n' +
    '  · the key comes from a passphrase — PBKDF2-SHA256, 250,000 iterations\n' +
    '  · that passphrase is never stored, never transmitted, never leaves the device\n' +
    '  · the server only ever holds { from, to, ts, nonce, ciphertext }\n' +
    '  · conversation paths are hashes of BOTH uuids — nothing to enumerate\n' +
    '  · public keys are write-once — there is no key to substitute',
    st('#dfe7f2'));
  console.log('%cThis is a feature, not a bug. 🙂', st('#43e5a0', 700));

  // a genuine challenge — real box, real random key, thrown away on the next line
  try {
    const me = nacl.box.keyPair(), you = nacl.box.keyPair();
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const box = nacl.box(nacl.util.decodeUTF8('you are not supposed to be able to read this'), nonce, you.publicKey, me.secretKey);
    console.log(
      '%cWant a crack at it? Freshly minted just now, key already discarded:\n\n' +
      '  nonce  ' + nacl.util.encodeBase64(nonce) + '\n' +
      '  box    ' + nacl.util.encodeBase64(box),
      st('#7d8ba6'));
  } catch (e) { /* nacl not loaded — no challenge, no harm */ }

  console.log('%cOpen it and you\'ve broken Curve25519. Please publish a paper, don\'t DM me. 🏆', st('#a48bff', 700));
  console.log('%csource: https://github.com/kvsovanreach/demo-chat', st('#4a5468'));
})();
