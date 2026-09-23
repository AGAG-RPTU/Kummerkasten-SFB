// Browser-side cryptography. The server only ever sees conv_id, public keys,
// sealed keys, ciphertexts and signatures.
//
//   codeword ──Argon2id──► seed ──kdf──┬─ 1: conv_id     (read capability)
//                                      ├─ 2: Ed25519 seed (authorises writes)
//                                      └─ 3: K            (conversation key)
//
//   staff passphrase ──Argon2id──► seed ──kdf──┬─ 1: X25519 seed (K is sealed to it)
//                                              └─ 2: Ed25519 seed
//
// Every string that is signed or used as associated data starts with
// PROTOCOL, so a signature for one purpose never verifies for another.

import sodium from '../vendor/libsodium-wrappers.js';
import { WORDLIST } from './wordlist.js';

export const PROTOCOL = 'kk1';
export const CODEWORD_WORDS = 6;       // 6 × log2(1296) = 62 bit
export const PASSPHRASE_WORDS = 8;     // 8 × log2(1296) = 83 bit
export const STAFF_ID_PATTERN = /^(?!sender$)[a-z][a-z0-9_]{0,31}$/;

const SENDER_ARGON = { ops: 3, mem: 64 * 1024 * 1024 };
const STAFF_ARGON = { ops: 3, mem: 256 * 1024 * 1024 };
const SENDER_KDF_CONTEXT = 'KKSFB_v1';
const STAFF_KDF_CONTEXT = 'KKSFBstf';
const PAD_BLOCK = 512;
const KEY_BYTES = 32;

export const ready = sodium.ready;

// Words are unique in their first three letters, which is what input matching
// relies on.
const WORD_PREFIX = 3;
const wordByPrefix = new Map(WORDLIST.map((w) => [w.slice(0, WORD_PREFIX), w]));

// ---------------------------------------------------------------- words

export function generateWords(count) {
  const words = [];
  for (let i = 0; i < count; i++) {
    words.push(WORDLIST[sodium.randombytes_uniform(WORDLIST.length)]);
  }
  return words.join(' ');
}

// Accepts any case and any mix of whitespace, '-', ',', '.', '_' between
// words. A token resolves to a word if it is a prefix of at least three letters
// of that word, or the word with extra trailing letters (typo at the end).
// Returns { words, unknown } where unknown lists unresolved tokens.
export function parseWords(input) {
  const tokens = input.toLowerCase().split(/[\s\-,._]+/).filter(Boolean);
  const words = [];
  const unknown = [];
  for (const token of tokens) {
    const word = wordByPrefix.get(token.slice(0, WORD_PREFIX));
    if (word && token.length >= WORD_PREFIX && (word.startsWith(token) || token.startsWith(word))) {
      words.push(word);
    } else {
      unknown.push(token);
    }
  }
  return { words, unknown };
}

export function completeWord(prefix) {
  const word = wordByPrefix.get(prefix.toLowerCase().slice(0, WORD_PREFIX));
  return word && word.startsWith(prefix.toLowerCase()) ? word : null;
}

// ---------------------------------------------------------------- keys

function argon2(secret, saltLabel, params) {
  const salt = sodium.crypto_generichash(sodium.crypto_pwhash_SALTBYTES, saltLabel);
  return sodium.crypto_pwhash(KEY_BYTES, secret, salt, params.ops, params.mem,
    sodium.crypto_pwhash_ALG_ARGON2ID13);
}

function subkey(seed, id, context) {
  return sodium.crypto_kdf_derive_from_key(KEY_BYTES, id, context, seed);
}

// words: array from parseWords, so every spelling of a codeword derives the same keys
export function deriveSender(words) {
  const seed = argon2(words.join(' '), `${PROTOCOL}/sender`, SENDER_ARGON);
  return {
    convId: sodium.to_hex(subkey(seed, 1, SENDER_KDF_CONTEXT)),
    sign: sodium.crypto_sign_seed_keypair(subkey(seed, 2, SENDER_KDF_CONTEXT)),
    key: subkey(seed, 3, SENDER_KDF_CONTEXT),
  };
}

export function deriveStaff(words, staffId) {
  const seed = argon2(words.join(' '), `${PROTOCOL}/staff/${staffId}`, STAFF_ARGON);
  return {
    box: sodium.crypto_box_seed_keypair(subkey(seed, 1, STAFF_KDF_CONTEXT)),
    sign: sodium.crypto_sign_seed_keypair(subkey(seed, 2, STAFF_KDF_CONTEXT)),
  };
}

export function sealKey(key, boxPublicKeyB64) {
  return toB64(sodium.crypto_box_seal(key, fromB64(boxPublicKeyB64)));
}

export function openSealedKey(sealedB64, boxKeyPair) {
  return sodium.crypto_box_seal_open(fromB64(sealedB64), boxKeyPair.publicKey, boxKeyPair.privateKey);
}

// Short human-comparable digest of a public key, e.g. "3f2a 91c0 …"
export function fingerprint(publicKeyB64) {
  const hex = sodium.to_hex(sodium.crypto_generichash(10, fromB64(publicKeyB64)));
  return hex.match(/.{4}/g).join(' ');
}

// ---------------------------------------------------------------- messages

function messageAd(convId, seq, author) {
  return `${PROTOCOL}|${convId}|${seq}|${author}`;
}

// Nonce is prepended to the ciphertext. Padding hides the exact length.
export function encryptMessage(key, convId, seq, author, content) {
  const plain = sodium.pad(sodium.from_string(JSON.stringify(content)), PAD_BLOCK);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plain, messageAd(convId, seq, author), null, nonce, key);
  const out = new Uint8Array(nonce.length + cipher.length);
  out.set(nonce);
  out.set(cipher, nonce.length);
  return toB64(out);
}

const MESSAGE_FIELDS = ['body', 'subject', 'category', 'name', 'contact'];

// Throws if the ciphertext was altered or relabelled with another seq/author,
// or if it does not hold a message: anyone with the shared password can
// encrypt arbitrary JSON, and the pages must not trip over it.
export function decryptMessage(key, convId, seq, author, ciphertextB64) {
  const data = fromB64(ciphertextB64);
  const n = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, data.subarray(n), messageAd(convId, seq, author), data.subarray(0, n), key);
  const content = JSON.parse(sodium.to_string(sodium.unpad(plain, PAD_BLOCK)));
  const valid = content !== null && typeof content === 'object' && !Array.isArray(content)
    && typeof content.body === 'string'
    && MESSAGE_FIELDS.every((f) => content[f] === undefined || typeof content[f] === 'string');
  if (!valid) {
    throw new Error('not a message');
  }
  return Object.fromEntries(MESSAGE_FIELDS.filter((f) => f in content).map((f) => [f, content[f]]));
}

// ---------------------------------------------------------------- signatures
// These strings must match the ones verified in private/app.php.

export function appendStatement(convId, seq, author, ciphertextB64) {
  const digest = sodium.to_hex(sodium.crypto_hash_sha256(fromB64(ciphertextB64)));
  return `${PROTOCOL}/append|${convId}|${seq}|${author}|${digest}`;
}

export function senderDeleteStatement(convId, timestamp) {
  return `${PROTOCOL}/delete|${convId}|${timestamp}`;
}

export function staffListStatement(staffId, timestamp) {
  return `${PROTOCOL}/list|${staffId}|${timestamp}`;
}

export function staffCloseStatement(staffId, publicId, lastSeq, timestamp) {
  return `${PROTOCOL}/close|${staffId}|${publicId}|${lastSeq}|${timestamp}`;
}

export function sign(statement, signKeyPair) {
  return toB64(sodium.crypto_sign_detached(statement, signKeyPair.privateKey));
}

// ---------------------------------------------------------------- encoding

export function toB64(bytes) {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

export function fromB64(text) {
  return sodium.from_base64(text, sodium.base64_variants.ORIGINAL);
}
