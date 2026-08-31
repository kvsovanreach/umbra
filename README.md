# aiclab · end-to-end encrypted chat

A **serverless** chat app: static frontend on **GitHub Pages**, **Firebase Realtime
Database** as the datastore (raw `fetch` — no SDK, no backend), and **end-to-end
encryption** so the database only ever holds ciphertext.

Text + images. You log in with a **UUID** (public identity) and a **secret key**
(private passphrase); it shows your encrypted history and lets you chat live.

---

## Security model (hardened)

- **TweetNaCl `box`** = X25519 ECDH + XSalsa20-Poly1305 (authenticated public-key encryption).
- **Key derivation: PBKDF2-SHA256, 250 000 iterations, salted with your UUID.**
  A weak passphrase is now hundreds of thousands of times more expensive to
  brute-force, and the per-UUID salt kills rainbow tables.
- You publish only your **public key** to `/users/{uuid}`. Peers derive the same
  shared key via ECDH; Firebase sees only `{from, to, ts, nonce, ciphertext}`.
- **Conversation IDs are a hash of both UUIDs**, so database paths can't be
  guessed or enumerated without already knowing both participants.
- Message **type + mime are encrypted** too (sealed JSON envelopes).
- **Anonymous Firebase Auth** gates every request; **rules forbid enumeration,
  make public keys write-once (anti key-substitution), and messages append-only.**

---

## Setup

### 1. Realtime Database
Firebase Console → **Build → Realtime Database → Create** → start in locked mode.
Copy the URL, e.g. `https://your-project-default-rtdb.firebaseio.com`.

### 2. Enable Anonymous Auth
**Build → Authentication → Sign-in method → Anonymous → Enable.**

### 3. Hardened database rules
**Realtime Database → Rules**, paste and Publish:

```json
{
  "rules": {
    ".read": false,
    ".write": false,
    "users": {
      "$uuid": {
        ".read": "auth != null",
        ".write": "auth != null && (!data.exists() || newData.child('publicKey').val() === data.child('publicKey').val())",
        ".validate": "newData.hasChildren(['publicKey','updated']) && newData.child('publicKey').isString() && newData.child('publicKey').val().length <= 64"
      }
    },
    "conversations": {
      "$cid": {
        ".read": "auth != null",
        "messages": {
          "$mid": {
            ".write": "auth != null && !data.exists()",
            ".validate": "newData.hasChildren(['from','to','ts','n','c']) && newData.child('n').isString() && newData.child('c').isString() && newData.child('c').val().length <= 400000"
          }
        },
        "typing": { "$uuid": { ".write": "auth != null", ".validate": "newData.isNumber()" } },
        "read":   { "$uuid": { ".write": "auth != null", ".validate": "newData.isNumber()" } }
      }
    }
  }
}
```

What these enforce:
- **No enumeration** — top-level read/write denied; you can only read a user or
  conversation if you already know its exact (hashed) key.
- **Write-once public keys** — once a UUID publishes a key it can't be changed,
  which blocks man-in-the-middle key substitution.
- **Append-only, immutable messages** — existing messages can't be edited/deleted.
- **Shape + size validation** — no arbitrary or oversized junk writes.
- **Auth required** — disable the Anonymous provider to instantly cut all access.

### 4. Point the app at your project — edit `js/config.js`
```js
window.FIREBASE_CONFIG = {
  databaseURL: 'https://your-project-default-rtdb.firebaseio.com',
  apiKey: 'AIza…your web api key',   // Project settings → General → Web API Key
};
```

Both values are **public by design** — they ship in the JS and anyone can read them
out of the network tab. A Firebase Web API key is an identifier, not a credential:
it can't read your database or bypass rules. Security comes from the rules above
plus the E2E crypto, never from hiding these.

What it *does* allow is unlimited anonymous token minting, so:
- **Restrict the key** — Cloud Console → APIs & Services → Credentials → your
  browser key → *HTTP referrers* → `https://<you>.github.io/*`. A speed bump
  (referrers are forgeable), not a wall.
- **Stay on the Spark plan**, or set a budget alert on Blaze — an open sign-up
  endpoint plus append-only storage is a cost surface.
- **Kill switch** — disabling the Anonymous provider cuts all access instantly.

### 5. Deploy to GitHub Pages
```bash
git init && git add . && git commit -m "aiclab encrypted chat"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```
**Settings → Pages → Deploy from branch → main / root** → live at
`https://<you>.github.io/<repo>/`. (HTTPS is required — WebCrypto/PBKDF2 needs a
secure context, which GitHub Pages provides.)

---

## Usage
1. Hit **gen** for your UUID — don't type a name. **Never use a guessable id like
   `alice`.** The conversation path is a hash of both UUIDs, so a guessable pair
   is the one thing standing between a stranger and your (encrypted) history —
   see *Why the UUID matters* below. `gen` emits a full 122-bit v4 UUID.
2. Add a **secret key** (long, unique) and the **peer's UUID** → **Establish
   secure channel**. Your key fingerprint renders live as you type.
3. The peer must open the app once (their UUID + secret) to publish their key.
   Expect a "peer hasn't joined" error on the very first connect — that attempt
   still publishes *your* key. Have them connect, then retry.
4. **Verify once.** Tap the peer's identicon in the header and compare the safety
   number out-of-band (call, in person). This is what catches a substituted key.
5. Chat. Everything is encrypted in-browser; click any bubble to peek its ciphertext.
6. Same UUID + same secret = same identity on any device (keys are derived, not
   stored). Nothing is recoverable if you lose either — **keep your UUID**, since
   a 36-char id is no longer something you'll memorise.

---

## What's protected vs. what isn't (honest)

**Protected**
- Message content — infeasible to decrypt without the key (and PBKDF2 makes weak
  passphrases far harder to crack).
- Key substitution / MITM — public keys are write-once, so an *established*
  identity's key can never be swapped. (Claiming an unused UUID is a separate
  problem — see *Identity squatting* below.)
- Bulk scraping / enumeration — blocked by rules + hashed paths.
- Tampering — messages are immutable; each is authenticated (Poly1305).
- Network sniffing — GitHub Pages is HTTPS.
- Your secret — never stored or transmitted; derived in-browser each session.

**Still exposed / limitations**
- **Metadata** — a party who already knows both UUIDs can compute the conversation
  id, read (undecryptable) ciphertext, and see timestamps/sizes. True metadata
  privacy needs a backend.
- **Identity squatting** — public keys are write-once, which blocks substitution but
  also means an *unclaimed* UUID can be taken. If someone publishes a key at your
  UUID before you do, you can never claim it, and a peer who looks you up gets
  **their** key and encrypts to them. Only unguessable UUIDs prevent this, and only
  safety-number verification detects it.
- **No forward secrecy** — keys are static; a leaked secret exposes past messages.
- **Spam by known participants** — anyone authed who knows a conversation id could
  append messages; content stays encrypted, but you can't cryptographically prove
  "sender = this UUID" without a backend. Messages are append-only, so injected
  junk renders as "unable to decrypt" permanently — it cannot be deleted.
- **Anyone can mint an auth token** — the Web API key is public by design, and the
  Anonymous provider is open to the world. Auth proves nothing about *who* is
  asking; it only enables the rules. Add App Check if this outgrows a demo.
- **Passphrase strength still matters** — PBKDF2 raises the cost, it doesn't make a
  trivial passphrase safe. Use a long, unique one.

### Why the UUID matters

Every risk above is gated on UUID guessability. A generated UUID is 122 bits, and a
conversation id hashes **both**, so an attacker needs ~244 bits to compute a path —
not brute-forceable. Type `alice` and all of it collapses to a dictionary guess.

This is only as strong as the weaker of the two ids: if your peer uses `bob`, your
conversation is exposed regardless of how good your own UUID is. Tell them to hit
`gen` too.

Good for private, low-stakes chat and learning real E2E crypto. Not a Signal
replacement (which adds forward secrecy, verified identities, and a trusted server).

---

## Files
```
index.html      login + chat UI (crypto-terminal design, JetBrains Mono)
css/style.css   styling
js/config.js    your Firebase URL + API key
js/crypto.js    E2E crypto — PBKDF2 key derivation, nacl.box, hashed conv ids
js/auth.js      anonymous Firebase Auth (REST) + token refresh
js/firebase.js  raw REST client + live EventSource stream (auto-reconnect)
js/app.js       UI wiring, identicons, ciphertext peek, scramble reveal
lib/            vendored TweetNaCl + util (self-contained)
```
