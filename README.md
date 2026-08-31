<div align="center">

<img src="assets/favicon.svg" width="104" height="104" alt="Umbra" />

# Umbra

**The datastore only ever sees ciphertext.**

Serverless, end-to-end encrypted chat. A static frontend, no backend, no SDK, no build step —
your keys are derived in the browser and never leave the device.

<br />

![vanilla JS](https://img.shields.io/badge/vanilla_JS-ES2020-f7df1e?style=flat-square&logo=javascript&logoColor=f7df1e&labelColor=0e131d)
![TweetNaCl](https://img.shields.io/badge/TweetNaCl-X25519_·_Poly1305-a48bff?style=flat-square&labelColor=0e131d)
![WebCrypto](https://img.shields.io/badge/WebCrypto-PBKDF2_250k-4de0d6?style=flat-square&labelColor=0e131d)
![Firebase](https://img.shields.io/badge/Firebase-Realtime_DB-ffcf6b?style=flat-square&logo=firebase&logoColor=ffcf6b&labelColor=0e131d)
![GitHub Pages](https://img.shields.io/badge/GitHub_Pages-deployed-43e5a0?style=flat-square&logo=githubpages&logoColor=43e5a0&labelColor=0e131d)
![dependencies](https://img.shields.io/badge/dependencies-0-5b8cff?style=flat-square&labelColor=0e131d)
![backend](https://img.shields.io/badge/backend-none-ff6b81?style=flat-square&labelColor=0e131d)

<br />

**[Live demo](https://umbra.sovanreach.com/)** ·
[How it works](#how-it-works) ·
[Security model](#security-model) ·
[Setup](#setup) ·
[Threat model](#what-is-and-isnt-protected)

<br />

<img src="assets/screenshot.png" width="880" alt="Umbra login and chat screens" />

</div>

---

## Why "Umbra"

The *umbra* is the innermost part of a shadow — the region where the light source is
blocked **completely**, not merely dimmed. That is the design goal here. The database is
not trusted-but-monitored; it is in total shadow. It holds `{from, to, ts, nonce, ciphertext}`
and cannot read a single message, because the key that would open them never reaches it.

---

## How it works

Identity is **derived, never stored**. Your UUID plus your passphrase produce an X25519
keypair through PBKDF2; the same pair reappears on any device from the same two inputs, and
nothing sensitive is ever persisted or transmitted.

```mermaid
sequenceDiagram
    autonumber
    participant A as Alice · browser
    participant DB as Firebase RTDB
    participant B as Bob · browser

    Note over A,B: PBKDF2-SHA256(secret, salt = uuid, 250k) → X25519 keypair
    A->>DB: PUT /users/{uuidA} · publicKey only
    B->>DB: PUT /users/{uuidB} · publicKey only
    A->>DB: GET /users/{uuidB}
    DB-->>A: Bob's public key
    Note over A: ECDH → shared secret (never transmitted)
    A->>DB: POST /conversations/{hash(uuidA,uuidB)}/messages
    Note right of A: { from, to, ts, nonce, ciphertext }
    DB-->>B: EventSource live stream
    Note over B: box.open() → plaintext
    Note over DB: holds ciphertext, and only ciphertext
```

Message **type and mime are sealed inside** the ciphertext as a JSON envelope, so the store
cannot even distinguish an image from a line of text.

---

## Security model

| Layer | Mechanism |
|---|---|
| Cipher | XSalsa20-Poly1305 — authenticated encryption |
| Key exchange | X25519 ECDH via TweetNaCl `box` |
| Key derivation | PBKDF2-SHA256, **250 000 iterations**, salted per-UUID |
| Conversation paths | `hash(sorted(uuidA, uuidB))` truncated to 40 hex — unguessable, unenumerable |
| Identity binding | Public keys are **write-once**, blocking key substitution |
| Membership | Operator allowlist — a UUID cannot publish a key until approved by hand |
| Verification | Signal-style 12-group safety number + TOFU key-change alert |
| Transport | HTTPS, required — WebCrypto refuses to run outside a secure context |

The per-UUID salt means an attacker must attack each identity separately: no rainbow tables,
and a weak passphrase costs 250 000× more to grind than a bare hash would.

---

## Setup

### 1 · Realtime Database

Firebase Console → **Build → Realtime Database → Create** → start in **locked mode**.
Copy the URL, e.g. `https://your-project-default-rtdb.firebaseio.com`.

### 2 · Anonymous Auth

**Build → Authentication → Sign-in method → Anonymous → Enable.**

### 3 · Database rules

**Realtime Database → Rules** → paste the contents of [`firebase.rules.json`](firebase.rules.json) and **Publish**:

```json
{
  "rules": {
    ".read": false,
    ".write": false,

    "allowlist": {
      "$uuid": {
        ".read": "auth != null",
        ".write": false
      }
    },

    "users": {
      "$uuid": {
        ".read": "auth != null",
        ".write": "auth != null && root.child('allowlist').child($uuid).child('status').val() === 'active' && (!data.exists() || newData.child('publicKey').val() === data.child('publicKey').val())",
        ".validate": "newData.hasChildren(['publicKey','updated']) && newData.child('publicKey').isString() && newData.child('publicKey').val().length <= 64"
      }
    },

    "conversations": {
      "$cid": {
        ".read": "auth != null",
        "messages": {
          "$mid": {
            ".write": "auth != null && !data.exists() && root.child('allowlist').child(newData.child('from').val()).child('status').val() === 'active'",
            ".validate": "newData.hasChildren(['from','to','ts','n','c']) && newData.child('n').isString() && newData.child('c').isString() && newData.child('c').val().length <= 400000"
          }
        },
        "typing": {
          "$uuid": {
            ".write": "auth != null && root.child('allowlist').child($uuid).child('status').val() === 'active'",
            ".validate": "newData.isNumber()"
          }
        },
        "read": {
          "$uuid": {
            ".write": "auth != null && root.child('allowlist').child($uuid).child('status').val() === 'active'",
            ".validate": "newData.isNumber()"
          }
        }
      }
    }
  }
}
```

These enforce: **no enumeration** (the root is denied; you must already know an exact hashed
key), **write-once public keys** (no MITM key substitution), **append-only immutable
messages**, **shape and size validation**, **auth on every request** — so disabling the
Anonymous provider is an instant kill switch — and an **operator allowlist**, below.

### 3b · Approving users

Anonymous auth lets *anyone* obtain a token, so the rules gate the one action that matters:
publishing a public key. A UUID cannot establish a channel until you approve it by hand.

The allowlist lives at its own path with `".write": false`, so **no client can ever edit it** —
not even its own entry. The Firebase Console and Admin SDK bypass rules, so that is where you
manage it. Putting the flag under `/users/{uuid}` would not work: clients write that path, and
a disabled user could simply mark themselves active.

To approve someone, **Realtime Database → Data**, add under `allowlist`:

```json
{
  "allowlist": {
    "3f7a91c4-2b8e-4d15-9c03-7ae6f1b28d40": {
      "status": "active",
      "label": "Sovanreach · phone",
      "added": 1756600000000
    }
  }
}
```

| `status` | Effect |
|---|---|
| `"active"` | May publish a key, send messages, and broadcast typing/read |
| `"disabled"` | Blocked — flip it back to `"active"` to restore |
| *(no entry)* | Never approved; blocked |

Changes take effect on the user's **next** action — the rules are evaluated per request, so a
user you disable can no longer send, though a session already open keeps *reading* until they
reload. To cut someone off instantly and completely, disable the Anonymous provider (which
stops everyone) or delete their `/users/{uuid}` entry from the Console.

**Their peer is told.** Rather than watching someone go silent for no reason, the other side of
the conversation shows a standing notice — *"… has been disabled by the operator — they can't
send or reply until re-enabled"* — checked at connect, again whenever the tab regains focus,
and on a 90-second poll. Re-enable the user and the notice clears on the next check. Messages
sent to a disabled peer are still encrypted and stored, and arrive once they are back.

The client shows a specific message — *"this uuid is not registered"* — and **fails closed**:
only an explicit `"active"` is admitted. If the allowlist rules have not been published, the
client says so and refuses rather than waving everyone through, so the gate cannot silently
disappear because of a config gap. That is still only a courtesy, though — the real gate is
the `.write` rule on `/users/{uuid}`, keyed on the **path** rather than on anything the client
sends, so a modified client cannot publish a key either way.

> **Order matters.** Because the client fails closed, publishing this JS *before* the rules
> means nobody can connect — they will see *"access control is not configured"*. Add your
> allowlist entries, publish the rules, then connect.

> **One honest limit:** the rule on `messages` checks the `from` field, which the *sender*
> supplies. A disabled user who already knows a conversation id could still append by putting
> an approved UUID in `from`. Content stays encrypted and unforgeable either way — as noted
> under [the threat model](#what-is-and-isnt-protected), proving "sender = this UUID"
> needs a backend. The key-publishing gate is not spoofable; this one is.

### 4 · Point the app at your project

Edit [`js/config.js`](js/config.js):

```js
window.FIREBASE_CONFIG = {
  databaseURL: 'https://your-project-default-rtdb.firebaseio.com',
  apiKey: 'AIza…your web api key',   // Project settings → General → Web API Key
};
```

> **Both values are public by design.** They ship in the JS and anyone can read them from the
> network tab. A Firebase Web API key is an *identifier, not a credential* — it cannot read the
> database or bypass a rule. Security comes from the rules above plus the encryption, never
> from hiding these. Open the browser console for the long version.

What the key *does* allow is unlimited anonymous token minting, so:

- **Restrict it** — Cloud Console → Credentials → your browser key → *Websites* → add
  `https://<you>.github.io/*`, `http://localhost:8000/*`, and **every custom domain you
  serve from** — a domain that isn't listed fails at "acquiring token". Keep **Identity
  Toolkit API** allowed or sign-in breaks. A speed bump, not a wall: referrers are forgeable.
- **Stay on Spark**, or set a budget alert on Blaze.
- **Add [App Check](https://firebase.google.com/docs/app-check)** if this outgrows a demo — it
  is the only real answer to a forgeable referrer.

### 5 · Run locally

WebCrypto needs a secure context, so `file://` will not work:

```bash
python3 -m http.server 8000
# → http://localhost:8000
```

### 6 · Deploy

```bash
git push -u origin main
```

**Settings → Pages → Deploy from a branch → `main` / `root`.** HTTPS is automatic.

**Custom domain (optional).** Set it under *Settings → Pages*, which commits a `CNAME` file,
then point DNS at Pages with a `CNAME` record to `<you>.github.io`. Two things to expect:

- GitHub starts **301-redirecting** the `github.io` path to your domain the moment `CNAME`
  lands, so a misconfigured domain takes the old URL down with it.
- If DNS sits behind a proxy (Cloudflare's orange cloud), leave it **DNS-only** until the
  certificate is issued — Pages validates over HTTP and the proxy blocks it. Afterwards you
  can proxy with SSL/TLS set to *Full (strict)*.
- Add the domain to the **API key referrer list** before you switch, or every login breaks.

---

## Usage

1. Press **gen** for your UUID — **never type a guessable name like `alice`.** Conversation
   paths hash *both* UUIDs, so a guessable pair is the one thing between a stranger and your
   encrypted history. See [Why the UUID matters](#why-the-uuid-matters).
   Send that UUID to the operator so they can [approve it](#3b--approving-users); until then
   the handshake stops at *"this uuid is not enabled for access"*.
2. Add a long, unique **secret key** and your **peer's UUID** → **Establish secure channel**.
   Your key fingerprint renders live as you type.
3. Your peer opens the app once to publish their key. The first connect fails with
   *"peer hasn't joined"* — expected; it still published *your* key. Have them connect, then retry.
4. **Verify once.** Tap the peer's identicon and compare the safety number over a call or in
   person. This is what catches a substituted key.
5. Chat. Click any bubble to reveal its raw ciphertext.

> Same UUID + same secret = same identity anywhere. Nothing is recoverable if you lose
> either — **keep your UUID**, since a 36-character id is not something you will memorise.

**Refreshing the page** shows a lock screen asking only for your passphrase — the two UUIDs
and the database URL are remembered, the secret never is. Your key fingerprint appears as you
type, so a mistyped passphrase is visible *before* you connect. **leave** locks the session the
same way; *use a different identity* clears the remembered ids and returns the full form.

Identity is held in `sessionStorage` (survives a refresh, dies with the tab) and additionally
in `localStorage` when **remember uuid & peer** is ticked (survives a browser restart). The
passphrase is written to neither, at any point.

---

## What is (and isn't) protected

<table>
<tr><td width="50%" valign="top">

**✅ Protected**

- **Message content** — infeasible without the key
- **Key substitution** — public keys are write-once, so an *established* identity's key can never be swapped
- **Enumeration** — blocked by rules and hashed paths
- **Tampering** — messages are immutable and Poly1305-authenticated
- **Sniffing** — HTTPS end to end
- **Your secret** — never stored, never transmitted

</td><td width="50%" valign="top">

**⚠️ Still exposed**

- **Metadata** — anyone who knows both UUIDs can compute the path and see timestamps and sizes
- **Identity squatting** — an *unclaimed* UUID can be taken; your peer would then encrypt to the squatter
- **No forward secrecy** — keys are static; a leaked secret exposes past messages
- **Spam** — any authed client that can compute a path may append; injected junk is permanent
- **Open sign-up** — auth proves nothing about *who* is asking, though the allowlist gates what an anonymous token may actually do

</td></tr>
</table>

### Why the UUID matters

Every residual risk above is gated on UUID guessability. A generated UUID carries **122 bits**
of entropy, and a conversation id hashes **both** — roughly 244 bits to compute a path, which
is not brute-forceable. Type `alice` and all of it collapses to a dictionary guess.

It is only as strong as the *weaker* of the two ids: if your peer uses `bob`, your conversation
is exposed no matter how good your own UUID is. Tell them to press **gen** too.

Good for private, low-stakes chat and for learning real E2E cryptography. **Not** a Signal
replacement — that adds forward secrecy, verified identities, and a trusted server.

---

## Project layout

```
index.html          login + chat UI, single document
css/style.css       crypto-terminal design system · fully responsive
js/config.js        Firebase URL + API key (public by design)
js/crypto.js        PBKDF2 derivation, nacl.box, hashed conv ids, safety numbers
js/auth.js          anonymous Firebase Auth over REST + token refresh
js/firebase.js      raw REST client + live EventSource stream, auto-reconnect
js/app.js           UI wiring, identicons, ciphertext peek, scramble reveal
lib/                vendored TweetNaCl + util — the only dependencies, both offline
assets/             icon set and screenshots
firebase.rules.json database rules, including the operator allowlist
```

No package manager, no bundler, no transpiler. Clone it and open it.

---

<div align="center">
<sub>Built with TweetNaCl · served from GitHub Pages · the server still sees nothing</sub>
</div>
