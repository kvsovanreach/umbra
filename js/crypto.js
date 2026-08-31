/* End-to-end crypto — TweetNaCl `box` (X25519 ECDH + XSalsa20-Poly1305)
 * with HARDENED key derivation.
 *
 * Your keypair is derived from (UUID + secret) via PBKDF2-SHA256 (250k
 * iterations, UUID as salt). vs. a bare hash this makes brute-forcing a weak
 * passphrase ~hundreds of thousands of times slower, and the UUID salt means an
 * attacker must attack each identity separately (no rainbow tables).
 *
 * Conversation IDs are a HASH of the two UUIDs, so the database path can't be
 * guessed or enumerated without already knowing both participants.
 */
window.CryptoBox = (function () {
  const util = nacl.util;
  const subtle = (window.crypto && window.crypto.subtle) || null;
  const ITERATIONS = 250000;

  async function keypairFrom(uuid, secret) {
    if (!subtle) throw new Error('WebCrypto unavailable (needs HTTPS or localhost)');
    const enc = new TextEncoder();
    const base = await subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits']);
    const salt = enc.encode('aiclab::v2::' + uuid);
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, base, 256);
    return nacl.box.keyPair.fromSecretKey(new Uint8Array(bits));
  }

  function publicKeyB64(keypair) {
    return util.encodeBase64(keypair.publicKey);
  }

  function _encrypt(bytes, mySecretKey, theirPublicKeyB64) {
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const box = nacl.box(bytes, nonce, util.decodeBase64(theirPublicKeyB64), mySecretKey);
    return { n: util.encodeBase64(nonce), c: util.encodeBase64(box) };
  }
  function _decrypt(payload, mySecretKey, theirPublicKeyB64) {
    try {
      return nacl.box.open(util.decodeBase64(payload.c), util.decodeBase64(payload.n),
        util.decodeBase64(theirPublicKeyB64), mySecretKey);
    } catch (e) { return null; }
  }

  // sealed envelopes hide message type + mime inside the ciphertext
  function encryptEnvelope(envelope, mySecretKey, theirPublicKeyB64) {
    return _encrypt(util.decodeUTF8(JSON.stringify(envelope)), mySecretKey, theirPublicKeyB64);
  }
  function decryptEnvelope(payload, mySecretKey, theirPublicKeyB64) {
    const opened = _decrypt(payload, mySecretKey, theirPublicKeyB64);
    if (!opened) return null;
    try { return JSON.parse(util.encodeUTF8(opened)); } catch (e) { return null; }
  }

  // hashed conversation id (hex, path-safe) — not guessable without both UUIDs
  function conversationId(a, b) {
    const joined = [a, b].map((s) => s.trim()).sort().join('__');
    const h = nacl.hash(util.decodeUTF8('aiclab-conv::' + joined));
    return [...h.slice(0, 20)].map((x) => x.toString(16).padStart(2, '0')).join('');
  }

  // mutual safety number from BOTH public keys — identical for both peers,
  // regardless of order. Compare out-of-band to defeat man-in-the-middle.
  function safetyNumber(pubA_b64, pubB_b64) {
    const both = [pubA_b64, pubB_b64].sort().join('|');
    const h = nacl.hash(util.decodeUTF8('aiclab-safety::' + both)); // 64 bytes
    const groups = [];
    for (let g = 0; g < 12; g++) {
      let n = 0;
      for (let i = 0; i < 5; i++) n = (n * 256 + h[(g * 5 + i) % 64]) % 100000;
      groups.push(String(n).padStart(5, '0'));
    }
    return groups; // 12 groups of 5 digits
  }

  return { keypairFrom, publicKeyB64, encryptEnvelope, decryptEnvelope, conversationId, safetyNumber };
})();
