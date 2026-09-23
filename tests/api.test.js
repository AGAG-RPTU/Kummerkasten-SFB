// Runs the PHP API under `php -S` with a throwaway config and database. Mail goes to
// a file via sendmail_path, so nothing leaves the machine.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import * as kk from '../public/js/crypto.js';

const ROOT = new URL('..', import.meta.url).pathname;
const PASSWORD = 'sfb-secret';
const MESSAGE_LIMIT = 6;
const SECRET_TEXT = 'nobody-but-staff-may-read-this';

let server;
let url;
let dir;
let staff;          // { hannah: keys, gabriela: keys }
let sender;         // deriveSender result
let publicId;

async function api(body) {
  const res = await fetch(url, { method: 'POST', body: JSON.stringify(body) });
  return { status: res.status, data: await res.json() };
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function createRequest(s, overrides = {}) {
  const ciphertext = kk.encryptMessage(s.key, s.convId, 1, 'sender', { subject: 'Hi', body: SECRET_TEXT });
  return {
    action: 'create',
    password: PASSWORD,
    conv_id: s.convId,
    sender_sign_pk: kk.toB64(s.sign.publicKey),
    sealed_keys: Object.fromEntries(Object.entries(staff).map(
      ([id, k]) => [id, kk.sealKey(s.key, kk.toB64(k.box.publicKey))])),
    ciphertext,
    signature: kk.sign(kk.appendStatement(s.convId, 1, 'sender', ciphertext), s.sign),
    ...overrides,
  };
}

function appendRequest(convId, key, seq, author, signKeys, content = { body: 'more' }) {
  const ciphertext = kk.encryptMessage(key, convId, seq, author, content);
  return {
    action: 'append', conv_id: convId, seq, author, ciphertext,
    signature: kk.sign(kk.appendStatement(convId, seq, author, ciphertext), signKeys),
  };
}

function staffList(id, timestamp = now()) {
  return api({
    action: 'staff_list', staff_id: id, timestamp,
    signature: kk.sign(kk.staffListStatement(id, timestamp), staff[id].sign),
  });
}

before(async () => {
  await kk.ready;
  staff = {
    hannah: kk.deriveStaff(['aardvark'], 'hannah'),
    gabriela: kk.deriveStaff(['abandoned'], 'gabriela'),
  };
  sender = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);

  dir = mkdtempSync(join(tmpdir(), 'kk-test-'));
  writeFileSync(join(dir, 'keys.json'), JSON.stringify({
    staff: Object.entries(staff).map(([id, k]) => ({
      id, name: id, box: kk.toB64(k.box.publicKey), sign: kk.toB64(k.sign.publicKey),
    })),
  }));
  const hash = execFileSync('php', ['-r', `echo password_hash('${PASSWORD}', PASSWORD_DEFAULT);`]).toString();
  writeFileSync(join(dir, 'config.php'), `<?php return [
    'db' => '${dir}/db.sqlite',
    'keys_file' => '${dir}/keys.json',
    'password_hash' => '${hash}',
    'site_url' => 'https://example.org/kk/',
    'staff_email' => ['hannah' => 'h@example.org', 'gabriela' => 'g@example.org'],
    'mail_from' => 'kk@example.org',
    'ntfy_url' => null,
    'retention' => ['closed_days' => 30, 'inactive_days' => 365],
    'limits' => ['creates_per_hour' => 100, 'messages_per_conversation' => ${MESSAGE_LIMIT}],
  ];`);

  const port = 18000 + Math.floor(Math.random() * 1000);
  url = `http://127.0.0.1:${port}/api.php`;
  server = spawn('php', ['-d', `sendmail_path=cat >> ${dir}/mail.log`, '-S', `127.0.0.1:${port}`, '-t', join(ROOT, 'public')], {
    env: { ...process.env, KK_CONFIG: join(dir, 'config.php') },
    stdio: 'ignore',
  });
  for (let i = 0; i < 50; i++) {
    try {
      await fetch(url);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error('php -S did not start');
});

after(() => server?.kill());

test('GET is rejected', async () => {
  const res = await fetch(url);
  assert.equal(res.status, 405);
});

test('create with wrong password', async () => {
  const { status } = await api(createRequest(sender, { password: 'nope' }));
  assert.equal(status, 401);
});

test('create must seal the key for every staff member', async () => {
  const req = createRequest(sender);
  delete req.sealed_keys.gabriela;
  assert.equal((await api(req)).status, 400);
});

test('create with a signature by another key', async () => {
  const other = kk.deriveSender(['aardvark']);
  const req = createRequest(sender, { sender_sign_pk: kk.toB64(other.sign.publicKey) });
  assert.equal((await api(req)).status, 403);
});

test('create and read back', async () => {
  const { status, data } = await api(createRequest(sender));
  assert.equal(status, 200);
  publicId = data.public_id;
  assert.ok(publicId >= 100000 && publicId <= 999999);

  const got = await api({ action: 'get', conv_id: sender.convId });
  assert.equal(got.status, 200);
  assert.equal(got.data.messages.length, 1);
  const m = got.data.messages[0];
  assert.equal(m.created_at % 3600, 0);
  assert.equal(kk.decryptMessage(sender.key, sender.convId, m.seq, m.author, m.ciphertext).body, SECRET_TEXT);

  assert.equal((await api(createRequest(sender))).status, 409);
});

test('get unknown conversation', async () => {
  assert.equal((await api({ action: 'get', conv_id: '0'.repeat(64) })).status, 404);
});

test('append enforces seq and signature', async () => {
  const { convId, key, sign } = sender;
  assert.equal((await api(appendRequest(convId, key, 2, 'sender', sign))).status, 200);
  assert.equal((await api(appendRequest(convId, key, 2, 'sender', sign))).status, 409);
  assert.equal((await api(appendRequest(convId, key, 4, 'sender', sign))).status, 409);

  // sender cannot write as staff, staff cannot write as sender
  assert.equal((await api(appendRequest(convId, key, 3, 'hannah', sign))).status, 403);
  assert.equal((await api(appendRequest(convId, key, 3, 'sender', staff.hannah.sign))).status, 403);
  assert.equal((await api(appendRequest(convId, key, 3, 'nobody', sign))).status, 400);
});

test('staff list rejects stale timestamps and foreign keys', async () => {
  assert.equal((await staffList('hannah', now() - 3600)).status, 403);
  const ts = now();
  const forged = await api({
    action: 'staff_list', staff_id: 'hannah', timestamp: ts,
    signature: kk.sign(kk.staffListStatement('hannah', ts), staff.gabriela.sign),
  });
  assert.equal(forged.status, 403);
});

test('staff reads, replies, and sender sees the reply', async () => {
  const { status, data } = await staffList('hannah');
  assert.equal(status, 200);
  const conv = data.conversations.find((c) => c.public_id === publicId);
  const key = kk.openSealedKey(conv.sealed_key, staff.hannah.box);
  const first = conv.messages[0];
  assert.equal(kk.decryptMessage(key, conv.conv_id, 1, first.author, first.ciphertext).body, SECRET_TEXT);

  const reply = appendRequest(conv.conv_id, key, 3, 'hannah', staff.hannah.sign, { body: 'reply' });
  assert.equal((await api(reply)).status, 200);

  const got = await api({ action: 'get', conv_id: sender.convId });
  const m = got.data.messages[2];
  assert.equal(m.author, 'hannah');
  assert.equal(kk.decryptMessage(sender.key, sender.convId, 3, 'hannah', m.ciphertext).body, 'reply');
});

test('close needs a close signature; sender append reopens', async () => {
  const ts = now();
  const wrongPurpose = await api({
    action: 'staff_close', staff_id: 'gabriela', public_id: publicId, last_seq: 3, timestamp: ts,
    signature: kk.sign(kk.staffListStatement('gabriela', ts), staff.gabriela.sign),
  });
  assert.equal(wrongPurpose.status, 403);

  const closed = await api({
    action: 'staff_close', staff_id: 'gabriela', public_id: publicId, last_seq: 3, timestamp: ts,
    signature: kk.sign(kk.staffCloseStatement('gabriela', publicId, 3, ts), staff.gabriela.sign),
  });
  assert.equal(closed.status, 200);
  assert.equal((await api({ action: 'get', conv_id: sender.convId })).data.status, 'closed');

  await api(appendRequest(sender.convId, sender.key, 4, 'sender', sender.sign));
  assert.equal((await api({ action: 'get', conv_id: sender.convId })).data.status, 'open');
});

test('notifications carry no content', () => {
  const mail = readFileSync(join(dir, 'mail.log'), 'utf8');
  assert.match(mail, new RegExp(`New conversation #${publicId}`));
  assert.match(mail, /To: h@example.org/);
  assert.ok(!mail.includes(SECRET_TEXT));
  assert.ok(!mail.includes(sender.convId));
});

test('database holds no plaintext', () => {
  const db = readFileSync(join(dir, 'db.sqlite'));
  assert.ok(!db.includes(SECRET_TEXT));
});

test('sender deletes the conversation', async () => {
  const ts = now();
  const bad = await api({
    action: 'delete', conv_id: sender.convId, timestamp: ts,
    signature: kk.sign(kk.senderDeleteStatement(sender.convId, ts), staff.hannah.sign),
  });
  assert.equal(bad.status, 403);

  const ok = await api({
    action: 'delete', conv_id: sender.convId, timestamp: ts,
    signature: kk.sign(kk.senderDeleteStatement(sender.convId, ts), sender.sign),
  });
  assert.equal(ok.status, 200);
  assert.equal((await api({ action: 'get', conv_id: sender.convId })).status, 404);
  assert.equal((await staffList('hannah')).data.conversations.length, 0);
});

function newConversation() {
  const s = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
  return api(createRequest(s)).then(({ status, data }) => {
    assert.equal(status, 200);
    return { ...s, publicId: data.public_id };
  });
}

function closeRequest(id, publicId, lastSeq, timestamp = now()) {
  return {
    action: 'staff_close', staff_id: id, public_id: publicId, last_seq: lastSeq, timestamp,
    signature: kk.sign(kk.staffCloseStatement(id, publicId, lastSeq, timestamp), staff[id].sign),
  };
}

test('wrong passwords never lock out the right one', async () => {
  for (let i = 0; i < 8; i++) {
    assert.equal((await api({ action: 'create', password: 'x' })).status, 401);
  }
  await newConversation();
});

test('close must name the current last message', async () => {
  const c = await newConversation();
  await api(appendRequest(c.convId, c.key, 2, 'sender', c.sign));
  assert.equal((await api(closeRequest('hannah', c.publicId, 1))).status, 409);
  assert.equal((await api(closeRequest('hannah', c.publicId, 2))).status, 200);
});

test('staff without a sealed key cannot touch a conversation', async () => {
  const c = await newConversation();
  const keysFile = join(dir, 'keys.json');
  const original = readFileSync(keysFile, 'utf8');
  staff.carol = kk.deriveStaff(['zucchini'], 'carol');
  const keys = JSON.parse(original);
  keys.staff.push({ id: 'carol', name: 'carol', box: kk.toB64(staff.carol.box.publicKey), sign: kk.toB64(staff.carol.sign.publicKey) });
  writeFileSync(keysFile, JSON.stringify(keys));
  try {
    assert.equal((await api(closeRequest('carol', c.publicId, 1))).status, 403);
    assert.equal((await api(appendRequest(c.convId, c.key, 2, 'carol', staff.carol.sign))).status, 403);
  } finally {
    writeFileSync(keysFile, original);
    delete staff.carol;
  }
});

test('messages per conversation are capped', async () => {
  const c = await newConversation();
  for (let seq = 2; seq <= MESSAGE_LIMIT; seq++) {
    assert.equal((await api(appendRequest(c.convId, c.key, seq, 'sender', c.sign))).status, 200);
  }
  assert.equal((await api(appendRequest(c.convId, c.key, MESSAGE_LIMIT + 1, 'sender', c.sign))).status, 403);
});

test('sender messages notify at most once an hour until staff reply', async () => {
  const c = await newConversation();
  const count = () => readFileSync(join(dir, 'mail.log'), 'utf8')
    .split(`Subject: [Kummerkasten] New message in conversation #${c.publicId}`).length - 1;

  await api(appendRequest(c.convId, c.key, 2, 'sender', c.sign));
  assert.equal(count(), 0);     // creation already notified this hour

  await api(appendRequest(c.convId, c.key, 3, 'hannah', staff.hannah.sign));
  await api(appendRequest(c.convId, c.key, 4, 'sender', c.sign));
  await api(appendRequest(c.convId, c.key, 5, 'sender', c.sign));
  assert.equal(count(), 2);     // one mail to each of the two staff
});
