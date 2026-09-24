// Proof of work against spam, instead of or in addition to the SFB access
// password. The server issues a signed challenge { salt, bits, count, expires };
// for each i < count the client finds a nonce with
//
//   SHA-256(`${salt}|${i}|${nonce}`) starting with `bits` zero bits.
//
// Many small puzzles instead of one big one keep the solving time close to its
// mean. Must match verify_pow() in private/app.php.

import sodium from '../vendor/libsodium-wrappers.js';

export const ready = sodium.ready;

export function leadingZeroBits(hash) {
  let bits = 0;
  for (const byte of hash) {
    if (byte !== 0) {
      return bits + Math.clz32(byte) - 24;
    }
    bits += 8;
  }
  return bits;
}

// onProgress(fraction) is called after each solved puzzle.
export function solve({ salt, bits, count }, onProgress = () => {}) {
  const nonces = [];
  for (let i = 0; i < count; i++) {
    const prefix = `${salt}|${i}|`;
    let nonce = 0;
    while (leadingZeroBits(sodium.crypto_hash_sha256(prefix + nonce)) < bits) {
      nonce++;
    }
    nonces.push(nonce);
    onProgress((i + 1) / count);
  }
  return nonces;
}
