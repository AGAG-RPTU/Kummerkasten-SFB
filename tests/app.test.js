// Unit tests for helpers in private/app.php, run through the PHP CLI.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const APP = new URL('../private/app.php', import.meta.url).pathname;

function php(code) {
  return execFileSync('php', ['-r', `require '${APP}'; ${code}`]).toString();
}

test('stored times round to the nearest hour, half past rounds down', () => {
  const at = (h, m, s = 0) => Date.UTC(2026, 8, 24, h, m, s) / 1000;
  const cases = [[at(1, 31), at(2, 0)], [at(2, 30), at(2, 0)], [at(2, 30, 1), at(3, 0)], [at(2, 0), at(2, 0)], [at(1, 30), at(1, 0)]];
  const out = php(`foreach ([${cases.map(([t]) => t).join(',')}] as $t) echo rounded_hour($t), ' ';`).trim().split(' ').map(Number);
  assert.deepEqual(out, cases.map(([, expected]) => expected));
});
