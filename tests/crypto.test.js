import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as kk from '../public/js/crypto.js';
import { WORDLIST } from '../public/js/wordlist.js';
import { solve, leadingZeroBits } from '../public/js/pow.js';

const CODEWORD = ['aardvark', 'yoyo', 'zucchini', 'banana', 'lucidity', 'oyster'];

before(() => kk.ready);

test('wordlist has 1296 words, unique in the first three letters', () => {
  assert.equal(WORDLIST.length, 1296);
  assert.equal(new Set(WORDLIST.map((w) => w.slice(0, 3))).size, 1296);
  assert.ok(WORDLIST.every((w) => /^[a-z]+$/.test(w)));
});

test('generated words parse back to themselves', () => {
  const text = kk.generateWords(kk.CODEWORD_WORDS);
  const { words, unknown } = kk.parseWords(text);
  assert.equal(words.join(' '), text);
  assert.deepEqual(unknown, []);
});

test('parseWords normalises case, separators and prefixes', () => {
  const { words, unknown } = kk.parseWords('  AardVark-yo,ZUCC. ban_lucidityy\noyst ');
  assert.deepEqual(unknown, ['yo']);
  assert.deepEqual(words, ['aardvark', 'zucchini', 'banana', 'lucidity', 'oyster']);
});

test('parseWords rejects unknown words', () => {
  assert.deepEqual(kk.parseWords('aardvark qqqq').unknown, ['qqqq']);
  assert.deepEqual(kk.parseWords('aarx').unknown, ['aarx']);
});

test('completeWord', () => {
  assert.equal(kk.completeWord('zuc'), 'zucchini');
  assert.equal(kk.completeWord('Zucch'), 'zucchini');
  assert.equal(kk.completeWord('zu'), null);
  assert.equal(kk.completeWord('zucx'), null);
});

test('sender derivation is matches PHP libsodium (vector)', () => {
  const a = kk.deriveSender(CODEWORD);
  const b = kk.deriveSender(kk.parseWords('aardvark YOYO zucchini banana lucidity oyster').words);
  assert.equal(a.convId, b.convId);
  assert.equal(a.convId.length, 64);
  assert.equal(a.convId, 'e36856beea17329c544b3da15580f17ca01529988b77c682f549e1021b377fa8');
  assert.notEqual(kk.toB64(a.key), kk.toB64(a.sign.privateKey.subarray(0, 32)));
});

test('staff key is sealed to and opened by staff', () => {
  const staff = kk.deriveStaff(['aardvark'], 'hannah');
  const key = kk.deriveSender(CODEWORD).key;
  const sealed = kk.sealKey(key, kk.toB64(staff.box.publicKey));
  assert.deepEqual(kk.openSealedKey(sealed, staff.box), key);
});

test('staff derivation depends on staff id', () => {
  const a = kk.deriveStaff(['aardvark'], 'hannah');
  const b = kk.deriveStaff(['aardvark'], 'gabriela');
  assert.notDeepEqual(a.box.publicKey, b.box.publicKey);
});

test('message round-trip, padding, tamper detection', () => {
  const { convId, key } = kk.deriveSender(CODEWORD);
  const content = { subject: 'Hi', body: 'ä'.repeat(10) };
  const ct = kk.encryptMessage(key, convId, 1, 'sender', content);
  assert.deepEqual(kk.decryptMessage(key, convId, 1, 'sender', ct), content);

  // 512-byte padding + 24 nonce + 16 tag
  assert.equal(kk.fromB64(ct).length, 512 + 40);

  assert.throws(() => kk.decryptMessage(key, convId, 2, 'sender', ct));
  assert.throws(() => kk.decryptMessage(key, convId, 1, 'hannah', ct));
  const bytes = kk.fromB64(ct);
  bytes[30] ^= 1;
  assert.throws(() => kk.decryptMessage(key, convId, 1, 'sender', kk.toB64(bytes)));
});

test('nonces differ between encryptions', () => {
  const { convId, key } = kk.deriveSender(CODEWORD);
  const a = kk.encryptMessage(key, convId, 1, 'sender', { body: 'x' });
  const b = kk.encryptMessage(key, convId, 1, 'sender', { body: 'x' });
  assert.notEqual(a, b);
});

test('fingerprint format', () => {
  const fp = kk.fingerprint(kk.toB64(new Uint8Array(32)));
  assert.match(fp, /^([0-9a-f]{4} ){4}[0-9a-f]{4}$/);
});

test('decryptMessage rejects plaintexts that are not messages', () => {
  const { convId, key } = kk.deriveSender(CODEWORD);
  for (const content of [null, 'text', [], { body: 5 }, { body: 'x', subject: {} }]) {
    const ct = kk.encryptMessage(key, convId, 1, 'sender', content);
    assert.throws(() => kk.decryptMessage(key, convId, 1, 'sender', ct), undefined, JSON.stringify(content));
  }
});

test('staff ids cannot collide with the sender', () => {
  assert.ok(kk.STAFF_ID_PATTERN.test('hannah'));
  assert.ok(!kk.STAFF_ID_PATTERN.test('sender'));
});

test('leadingZeroBits', () => {
  assert.equal(leadingZeroBits(Uint8Array.of(0x80)), 0);
  assert.equal(leadingZeroBits(Uint8Array.of(0x01)), 7);
  assert.equal(leadingZeroBits(Uint8Array.of(0, 0x10)), 11);
  assert.equal(leadingZeroBits(Uint8Array.of(0, 0)), 16);
});

test('proof-of-work solutions match the PHP check', () => {
  const challenge = { salt: 'c'.repeat(32), bits: 8, count: 3 };
  const nonces = solve(challenge);
  const php = execFileSync('php', ['-r', `
    require '${new URL('../private/app.php', import.meta.url).pathname}';
    foreach (json_decode($argv[1]) as $i => $n) echo leading_zero_bits(hash('sha256', "${challenge.salt}|$i|$n", true)), ' ';`,
    JSON.stringify(nonces)]).toString().trim().split(' ').map(Number);
  assert.ok(php.every((b) => b >= challenge.bits), php.join());
});
