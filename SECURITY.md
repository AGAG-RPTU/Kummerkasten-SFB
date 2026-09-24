# Security of the Kummerkasten

This document explains what the Kummerkasten protects, how, what it does not
protect, and how anyone can check that the running site is the published
code. The website links here from its footer and its privacy section.

## In short

- Messages are encrypted in the sender's browser. Only the sender (with their
  codeword) and the trusted persons listed on the front page can read them.
  The server, its operator, the hosting provider and anyone who steals the
  database see only ciphertext.
- The sender stays anonymous towards the application: no account, no cookies,
  no IP addresses stored by the application, times rounded to the hour.
- The weak point of every web application with browser-side encryption is the
  code itself: whoever runs the server could deliver altered JavaScript that
  leaks secrets. This cannot be prevented from the server side. It can be
  checked (`tools/verify.sh`) and, for trusted persons, avoided entirely by
  running the pages from a verified copy (`tools/local.py`). Both are
  described [below](#checking-the-code-the-site-delivers).
- The code has been reviewed during development (see [Reviews](#reviews)); it
  has not had an independent professional audit.

## What it protects against

| Threat | Protection |
|---|---|
| Server operator, hosting provider or database thief reading messages | Encryption in the browser; the server never holds a key |
| Network eavesdroppers | HTTPS with HSTS; content is encrypted in addition |
| Someone writing into or deleting a conversation without its codeword | Every message and deletion is signed with a key derived from the codeword |
| Someone reading a conversation without its codeword | A conversation is found by an identifier derived from the codeword, 256 bits |
| Guessing a codeword from a stolen database | 62-bit codewords behind Argon2id with 64 MiB per guess |
| A trusted person's key being swapped on the server | Public keys are in git (`public/keys.json`) and checked by `tools/verify.sh` |
| One trusted person deleting a conversation alone | Deletion needs the signed vote of every trusted person holding its key |
| Spam and floods | Proof of work per conversation, optional access password, per-conversation and site-wide limits |
| Third-party tracking | No external resources, no cookies, no analytics; a strict Content Security Policy |

## What it does not protect against

- **Altered code from the server.** See the next section.
- **A compromised device.** Malware, browser extensions or someone with access
  to the computer can read what the browser shows.
- **Metadata.** The server sees when a conversation receives messages (to the
  hour), how many, their size rounded up to 512 bytes, and which trusted
  person replies. The hosting provider's web server logs record IP addresses
  and exact times for about 15 days; combined with the database, they can
  link an IP address to a conversation. Notification emails go out at once
  and show the exact time a message arrived. For strong anonymity, use the
  Tor Browser.
- **Loss of a codeword or passphrase.** Whoever has a codeword can read, write
  and delete that conversation. Whoever has a trusted person's passphrase can
  read all conversations addressed to them, past ones included; there is no
  forward secrecy.
- **Availability.** The server can withhold or drop messages, and a
  determined attacker can slow down or block new conversations for a while.
- **Trusted persons themselves.** They read the messages by design.

## Checking the code the site delivers

### `tools/verify.sh`: does the site serve the published commit?

The footer of every page names the deployed commit and links to it on GitHub.
To check that the site delivers exactly that commit:

```sh
git clone https://github.com/AGAG-RPTU/Kummerkasten-SFB
cd Kummerkasten-SFB
tools/verify.sh https://kummerkasten.coxeter.de/
```

It fetches every file a browser loads (pages, scripts, the stylesheet, the
logo, the vendored libsodium and `keys.json`) and compares each byte for
byte with the commit. It ends with `All files match` and a digest: one
SHA-256 over all files. Anyone can compute the digest of a commit offline
with `tools/verify.sh --digest <commit>` and compare it with a digest someone
else reported.

**Limit:** this proves what the site sent to the computer running the check.
A malicious operator could send the published code to everyone except one
targeted visitor. Only a check inside the visitor's own browser can rule that
out; see [WEBCAT](#outlook-webcat).

### `tools/local.py`: run the pages from a verified copy

A trusted person's passphrase opens every conversation addressed to them, so
it is the most valuable secret. Trusted persons can avoid trusting the
server's JavaScript altogether:

```sh
git clone https://github.com/AGAG-RPTU/Kummerkasten-SFB
cd Kummerkasten-SFB
git log -1               # inspect or verify what you run
tools/local.py https://kummerkasten.coxeter.de/
```

Then open <http://localhost:8770/staff>. Pages, scripts and `keys.json` come
from the checkout; only API requests go to the site, and they carry only
ciphertext, public keys and signatures. It needs Python 3 and nothing else,
and it listens on the local machine only. Senders can use it the same way
(`/write`, `/conversation`).

The checkout should be the commit the site runs (the tool says so if not):
the site accepts new conversations only when they are encrypted for exactly
the trusted persons in its own `keys.json`.

### The vendored libsodium

`public/vendor/` holds libsodium.js 0.8.4 from npm, with one import path
patched for browsers. `tools/vendor.sh` reproduces these files from npm byte
for byte; `public/vendor/SHA256SUMS` lists their hashes.

### Outlook: WEBCAT

[WEBCAT](https://github.com/freedomofpress/webcat) by the Freedom of the Press
Foundation, built for SecureDrop, checks every file in the browser against a
signed, publicly logged manifest before anything runs. That closes the gap
above. It is an alpha for Firefox as of September 2026. The Kummerkasten is
designed to fit it: static files only, no inline scripts, a strict CSP.

## How it works

### Keys

```
 sender:  codeword (6 words) ──Argon2id, 64 MiB──► seed ──KDF──┬─ conv_id     (finds the conversation)
                                                               ├─ Ed25519 key (signs the sender's messages)
                                                               └─ K           (encrypts the conversation)

 trusted person:  passphrase (8 words) ──Argon2id, 256 MiB──► seed ──KDF──┬─ X25519 key  (receives K)
                                                                          └─ Ed25519 key (signs replies)
```

- Codewords and passphrases are generated in the browser from the EFF short
  wordlist (1296 words): 62 and 83 bits. Every word is unique in its first
  three letters, so typos are caught.
- Argon2id runs with 3 passes. The sender salt is fixed, since the codeword
  must find its conversation before anything is known; an attacker with the
  database can therefore test each guess against all conversations at once,
  which costs log2 of their number in bits. The trusted persons' salt
  includes their id.
- The subkeys come from libsodium's `crypto_kdf_derive_from_key` with
  separate contexts for senders and trusted persons.
- K is sealed (`crypto_box_seal`) to the X25519 key of every trusted person in
  `keys.json` when the conversation starts. A trusted person added later
  cannot read earlier conversations; one who replaces their key loses access
  to their earlier ones.

### Messages

- XChaCha20-Poly1305 with a random 24-byte nonce. The associated data binds
  each message to its conversation, position and author, so the server cannot
  move or relabel messages.
- The plaintext is padded to a multiple of 512 bytes.
- Every write is signed. A message's signature covers its conversation,
  position, author and a hash of the ciphertext; the server checks it and
  enforces a gapless order. Trusted persons' requests (list, resolve,
  delete vote) are signed with a timestamp valid for 5 minutes, and resolving
  or voting also names the last message, so a replay fails once the
  conversation changed.

### What the server stores

| Stored | Visible to the server |
|---|---|
| Conversation | identifier derived from the codeword, a public number, status, times rounded to the hour, the sender's public signing key |
| Per trusted person | K sealed to their key |
| Message | ciphertext, position, author (sender or which trusted person), time rounded to the hour |
| Proof of work | a spent challenge's random identifier until about an hour after it expired |
| Counters | how many conversations and notifications this hour, site-wide |

Tables are stored in key order, not insertion order. Conversations are deleted
30 days after being marked resolved and at the latest 365 days after the last
message; senders can delete theirs at any time, trusted persons only
unanimously.

### Spam protection

Before a new conversation, the browser solves a challenge the server signed
with HMAC: 16 puzzles of 17 leading zero bits of SHA-256, about 3 seconds on
a laptop, done while the sender writes. Each challenge counts once. Every 5
new conversations in an hour add one bit. A shared access password can be
switched on in addition. Per conversation, messages, bytes and sender
messages per hour are limited; senders are refused when the database is
full, trusted persons are not; notification mails beyond an hourly budget
become one summary.

### The site

- Only files from the site itself load: `default-src 'self'`, scripts
  `'self'` plus `'wasm-unsafe-eval'` for libsodium's WebAssembly; no inline
  scripts or styles; `frame-ancestors 'none'`; `Referrer-Policy: no-referrer`;
  HSTS.
- Pages that hold decrypted content reload instead of being restored from the
  browser's back/forward cache.
- The application stores nothing in the browser except the language choice.

## Reviews

- September 2026: three independent adversarial reviews during development,
  AI-assisted, of the protocol, of the server and deployment, and of the
  browser side. No way was found to read messages, forge signatures or bypass
  the proof of work or the unanimous deletion. The availability, linkability
  and browser findings were fixed in commit `77bfb7d`.
- No independent professional audit yet.

## Reporting a vulnerability

Please write to Max Horn, mhorn@rptu.de, before publishing details. Mention
whether the issue affects the live site.
