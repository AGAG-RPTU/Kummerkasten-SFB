// Unit tests for helpers in private/app.php, run through the PHP CLI.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const APP = `${ROOT}private/app.php`;

function php(code, ...args) {
  return execFileSync('php', ['-r', `require '${APP}'; ${code}`, '--', ...args]).toString();
}

test('stored times round to the nearest hour, half past rounds down', () => {
  const at = (h, m, s = 0) => Date.UTC(2026, 8, 24, h, m, s) / 1000;
  const cases = [[at(1, 31), at(2, 0)], [at(2, 30), at(2, 0)], [at(2, 30, 1), at(3, 0)], [at(2, 0), at(2, 0)], [at(1, 30), at(1, 0)]];
  const out = php(`foreach ([${cases.map(([t]) => t).join(',')}] as $t) echo rounded_hour($t), ' ';`).trim().split(' ').map(Number);
  assert.deepEqual(out, cases.map(([, expected]) => expected));
});

test('an old database is rebuilt without rowids, keeping its rows', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kk-migrate-'));
  const db = join(dir, 'db.sqlite');
  const oldSchema = execFileSync('git', ['show', 'f2cf1fc:private/schema.sql'], { cwd: ROOT }).toString();
  const out = php(`
    $db = new PDO('sqlite:${db}');
    $db->exec($argv[1]);
    $db->exec("INSERT INTO conversations VALUES ('c1', 123456, 'open', 0, 0, NULL, 'pk')");
    $db->exec("INSERT INTO messages VALUES ('c1', 1, 'sender', 0, 'ct')");
    $db->exec("INSERT INTO used_challenges VALUES ('s1', 7200)");
    $db = null;
    $db = open_db('${db}', '${ROOT}private/schema.sql');
    echo json_encode([
      'version' => $db->query('PRAGMA user_version')->fetchColumn(),
      'rowid' => $db->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND sql NOT LIKE '%WITHOUT ROWID%'")->fetchColumn(),
      'index' => $db->query("SELECT tbl_name FROM sqlite_master WHERE name = 'conversations_updated_at'")->fetchColumn(),
      'rows' => $db->query("SELECT c.public_id, m.ciphertext FROM conversations c JOIN messages m USING (conv_id)")->fetchAll(PDO::FETCH_NUM),
      'fk' => $db->query("SELECT \\"table\\" FROM pragma_foreign_key_list('messages')")->fetchColumn(),
    ]);`, oldSchema);
  assert.deepEqual(JSON.parse(out), { version: 2, rowid: 0, index: 'conversations', rows: [[123456, 'ct']], fk: 'conversations' });
});
