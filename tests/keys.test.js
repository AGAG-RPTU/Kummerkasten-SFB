// Checks the committed public/keys.json, so a malformed entry or a missing
// notification address fails before it is deployed.

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as kk from '../public/js/crypto.js';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const KEY_BYTES = 32;

const { staff } = JSON.parse(readFileSync(new URL('../public/keys.json', import.meta.url), 'utf8'));

before(() => kk.ready);

test('keys.json entries are complete and well-formed', () => {
  for (const entry of staff) {
    assert.match(entry.id, kk.STAFF_ID_PATTERN, `id of ${entry.id}`);
    assert.ok(typeof entry.name === 'string' && entry.name.trim(), `name of ${entry.id}`);
    assert.match(entry.email ?? '', EMAIL_PATTERN, `email of ${entry.id}`);
    assert.equal(kk.fromB64(entry.box).length, KEY_BYTES, `box key of ${entry.id}`);
    assert.equal(kk.fromB64(entry.sign).length, KEY_BYTES, `sign key of ${entry.id}`);
  }
});

test('keys.json ids are unique', () => {
  const ids = staff.map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length);
});
