// Runs the PHP API under `php -S` with a throwaway config and database. Mail goes to
// a file via sendmail_path, so nothing leaves the machine.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import * as kk from '../public/js/crypto.js';
import { solve } from '../public/js/pow.js';

const ROOT = new URL('..', import.meta.url).pathname;
const PASSWORD = 'sfb-secret';
const MESSAGE_LIMIT = 6;
const POW = { bits: 4, count: 4, ttl: 600 };
const POW_SECRET = 'a'.repeat(64);
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

async function solvedChallenge() {
  const { data } = await api({ action: 'challenge' });
  return { ...data, nonces: solve(data) };
}

// Signs a challenge the way the server does, to forge edge cases.
function signedChallenge({ salt = 'b'.repeat(32), bits = POW.bits, count = POW.count, expires = now() + 60 } = {}) {
  const signature = createHmac('sha256', POW_SECRET).update(`kk1/pow|${salt}|${bits}|${count}|${expires}`).digest('hex');
  const challenge = { salt, bits, count, expires, signature };
  return { ...challenge, nonces: solve(challenge) };
}

async function createRequest(s, overrides = {}) {
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
    pow: await solvedChallenge(),
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

let passwordHash;

// Defaults keep the limits out of the way; tests that probe a limit override it.
const LIMITS = {
  creates_per_hour: 100,
  messages_per_conversation: MESSAGE_LIMIT,
  conversation_bytes: 1000000,
  sender_messages_per_hour: 100,
  database_bytes: 1000000000,
};

function phpArray(obj) {
  return `[${Object.entries(obj).map(([k, v]) => `'${k}' => ${v}`).join(', ')}]`;
}

function writeConfig({ password = true, limits = {}, pow = {} } = {}) {
  writeFileSync(join(dir, 'config.php'), `<?php return [
    'db' => '${dir}/db.sqlite',
    'keys_file' => '${dir}/keys.json',
    'password_hash' => ${password ? `'${passwordHash}'` : 'null'},
    'pow' => ${phpArray({ ...POW, step: 1000, ...pow })},
    'pow_secret' => '${POW_SECRET}',
    'site_url' => 'https://example.org/kk/',
    'mail_from' => 'kk@example.org',
    'ntfy_url' => null,
    'retention' => ['closed_days' => 30, 'inactive_days' => 365],
    'limits' => ${phpArray({ ...LIMITS, ...limits })},
  ];`);
}

// Runs a query on the test database through PHP (no sqlite3 CLI needed).
function dbQuery(sql) {
  return JSON.parse(execFileSync('php', ['-r',
    `echo json_encode((new PDO('sqlite:${dir}/db.sqlite'))->query($argv[1])->fetchAll(PDO::FETCH_ASSOC));`, sql]).toString());
}

const NEWS = 'New activity';
const REMINDER = 'Reminder: a message waits for an answer';
const HOURS = 3600;

// Mails to one trusted person; their addresses are set up in before().
function mailsTo(id, subject = '') {
  const start = `To: ${id[0]}@example.org\r\nSubject: [Kummerkasten] ${subject}`;
  return readFileSync(join(dir, 'mail.log'), 'utf8').replaceAll(/\r?\n/g, '\r\n').split(start).length - 1;
}

// As if every outstanding notification had been mailed this long ago.
function ageNotifications(seconds) {
  dbQuery(`UPDATE pending_notifications SET mailed_at = mailed_at - ${seconds}`);
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
      id, name: id, email: `${id[0]}@example.org`, box: kk.toB64(k.box.publicKey), sign: kk.toB64(k.sign.publicKey),
    })),
  }));
  passwordHash = execFileSync('php', ['-r', `echo password_hash('${PASSWORD}', PASSWORD_DEFAULT);`]).toString();
  writeConfig();


  const port = 18000 + Math.floor(Math.random() * 1000);
  url = `http://127.0.0.1:${port}/api.php`;
  // opcache would keep serving a rewritten config.php
  server = spawn('php', ['-d', 'opcache.enable=0', '-d', `sendmail_path=cat >> ${dir}/mail.log`, '-S', `127.0.0.1:${port}`, '-t', join(ROOT, 'public')], {
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
  const { status } = await api(await createRequest(sender, { password: 'nope' }));
  assert.equal(status, 401);
});

test('recipients must be known trusted persons, at least one', async () => {
  assert.equal((await api(await createRequest(sender, { sealed_keys: {} }))).status, 400);
  const req = await createRequest(sender);
  req.sealed_keys.nobody = req.sealed_keys.hannah;
  assert.equal((await api(req)).status, 400);
});

test('create with a signature by another key', async () => {
  const other = kk.deriveSender(['aardvark']);
  const req = await createRequest(sender, { sender_sign_pk: kk.toB64(other.sign.publicKey) });
  assert.equal((await api(req)).status, 403);
});

test('create and read back', async () => {
  const { status, data } = await api(await createRequest(sender));
  assert.equal(status, 200);
  publicId = data.public_id;
  assert.ok(publicId >= 100000 && publicId <= 999999);

  const got = await api({ action: 'get', conv_id: sender.convId });
  assert.equal(got.status, 200);
  assert.equal(got.data.messages.length, 1);
  const m = got.data.messages[0];
  assert.equal(m.created_at % 3600, 0);
  assert.equal(kk.decryptMessage(sender.key, sender.convId, m.seq, m.author, m.ciphertext).body, SECRET_TEXT);

  assert.equal((await api(await createRequest(sender))).status, 409);
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
  assert.equal(conv.messages, undefined);
  assert.equal(conv.last_seq, 2);
  assert.equal(conv.last_author, 'sender');
  const key = kk.openSealedKey(conv.sealed_key, staff.hannah.box);
  const first = (await api({ action: 'get', conv_id: conv.conv_id })).data.messages[0];
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
  assert.ok(mailsTo('hannah', NEWS) >= 1);
  assert.ok(!mail.includes(SECRET_TEXT));
  assert.ok(!mail.includes(sender.convId));
  assert.ok(!mail.includes(String(publicId)));
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

async function newConversation() {
  const s = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
  const { status, data } = await api(await createRequest(s));
  assert.equal(status, 200);
  return { ...s, publicId: data.public_id };
}

function closeRequest(id, publicId, lastSeq, timestamp = now()) {
  return {
    action: 'staff_close', staff_id: id, public_id: publicId, last_seq: lastSeq, timestamp,
    signature: kk.sign(kk.staffCloseStatement(id, publicId, lastSeq, timestamp), staff[id].sign),
  };
}

test('wrong passwords never lock out the right one', async () => {
  const s = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
  for (let i = 0; i < 8; i++) {
    assert.equal((await api(await createRequest(s, { password: 'x' }))).status, 401);
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

test('a trusted person gets one mail, then none until they log in', async () => {
  await staffList('hannah');
  await staffList('gabriela');
  const before = [mailsTo('hannah'), mailsTo('gabriela')];
  const sent = () => [mailsTo('hannah') - before[0], mailsTo('gabriela') - before[1]];

  const c = await newConversation();
  assert.deepEqual(sent(), [1, 1]);

  await api(appendRequest(c.convId, c.key, 2, 'sender', c.sign));
  await newConversation();
  assert.deepEqual(sent(), [1, 1]);

  await staffList('hannah');
  await api(appendRequest(c.convId, c.key, 3, 'sender', c.sign));
  assert.deepEqual(sent(), [2, 1]);
});

function voteRequest(id, c, lastSeq, vote) {
  const timestamp = now();
  return {
    action: 'staff_delete_vote', staff_id: id, public_id: c.publicId, last_seq: lastSeq, vote, timestamp,
    signature: kk.sign(kk.staffDeleteVoteStatement(id, c.publicId, lastSeq, vote, timestamp), staff[id].sign),
  };
}

async function votesOf(c) {
  const conv = (await staffList('hannah')).data.conversations.find((x) => x.public_id === c.publicId);
  return conv?.delete_votes;
}

test('create needs a valid, unused proof of work', async () => {
  const s = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
  assert.equal((await api(await createRequest(s, { pow: undefined }))).status, 400);

  const pow = await solvedChallenge();
  assert.equal((await api(await createRequest(s, { pow: { ...pow, signature: '0'.repeat(64) } }))).status, 403);
  assert.equal((await api(await createRequest(s, { pow: { ...pow, nonces: pow.nonces.map((n) => n + 1) } }))).status, 403);
  assert.equal((await api(await createRequest(s, { pow: signedChallenge({ expires: now() - 1 }) }))).status, 403);
  assert.equal((await api(await createRequest(s, { pow: signedChallenge({ bits: POW.bits - 1 }) }))).status, 403);

  assert.equal((await api(await createRequest(s, { pow }))).status, 200);
  const other = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
  assert.equal((await api(await createRequest(other, { pow }))).status, 403);
});

test('the password can be switched off', async () => {
  assert.equal((await api({ action: 'challenge' })).data.password_required, true);
  writeConfig({ password: false });
  try {
    assert.equal((await api({ action: 'challenge' })).data.password_required, false);
    const s = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
    assert.equal((await api(await createRequest(s, { password: undefined }))).status, 200);
  } finally {
    writeConfig();
  }
});

test('deletion needs every trusted person, votes reset on new messages', async () => {
  const c = await newConversation();

  assert.deepEqual((await api(voteRequest('hannah', c, 1, true))).data, { deleted: false });
  assert.deepEqual(await votesOf(c), ['hannah']);
  await api(voteRequest('hannah', c, 1, false));
  assert.deepEqual(await votesOf(c), []);

  await api(voteRequest('hannah', c, 1, true));
  await api(appendRequest(c.convId, c.key, 2, 'sender', c.sign));
  assert.deepEqual(await votesOf(c), []);
  assert.equal((await api(voteRequest('gabriela', c, 1, true))).status, 409);

  assert.deepEqual((await api(voteRequest('hannah', c, 2, true))).data, { deleted: false });
  assert.deepEqual((await api(voteRequest('gabriela', c, 2, true))).data, { deleted: true });
  assert.equal((await api({ action: 'get', conv_id: c.convId })).status, 404);
});

test('a removed trusted person does not block deletion', async () => {
  const c = await newConversation();
  const keysFile = join(dir, 'keys.json');
  const original = readFileSync(keysFile, 'utf8');
  const keys = JSON.parse(original);
  keys.staff = keys.staff.filter((e) => e.id !== 'gabriela');
  writeFileSync(keysFile, JSON.stringify(keys));
  try {
    assert.deepEqual((await api(voteRequest('hannah', c, 1, true))).data, { deleted: true });
  } finally {
    writeFileSync(keysFile, original);
  }
});

test('IDs with a trailing newline are rejected', async () => {
  assert.equal((await api({ action: 'get', conv_id: `${'0'.repeat(64)}\n` })).status, 400);
});

test('a conversation is capped in total bytes', async () => {
  const size = 552;     // 512 padded + 24 nonce + 16 tag
  writeConfig({ limits: { conversation_bytes: size * 5 } });
  try {
    const c = await newConversation();
    for (let seq = 2; seq <= 5; seq++) {
      assert.equal((await api(appendRequest(c.convId, c.key, seq, 'hannah', staff.hannah.sign))).status, 200);
    }
    assert.equal((await api(appendRequest(c.convId, c.key, 6, 'hannah', staff.hannah.sign))).status, 413);
  } finally {
    writeConfig();
  }
});

test('sender messages per conversation and hour are limited', async () => {
  writeConfig({ limits: { sender_messages_per_hour: 3 } });
  try {
    const c = await newConversation();
    assert.equal((await api(appendRequest(c.convId, c.key, 2, 'sender', c.sign))).status, 200);
    assert.equal((await api(appendRequest(c.convId, c.key, 3, 'sender', c.sign))).status, 200);
    assert.equal((await api(appendRequest(c.convId, c.key, 4, 'sender', c.sign))).status, 429);
    assert.equal((await api(appendRequest(c.convId, c.key, 4, 'hannah', staff.hannah.sign))).status, 200);
  } finally {
    writeConfig();
  }
});

test('a full database refuses senders but not trusted persons', async () => {
  const c = await newConversation();
  writeConfig({ limits: { database_bytes: 1 } });
  try {
    const s = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
    assert.equal((await api(await createRequest(s))).status, 507);
    assert.equal((await api(appendRequest(c.convId, c.key, 2, 'sender', c.sign))).status, 507);
    assert.equal((await api(appendRequest(c.convId, c.key, 2, 'hannah', staff.hannah.sign))).status, 200);
  } finally {
    writeConfig();
  }
});

test('the proof of work gets harder as new conversations pile up', async () => {
  writeConfig({ pow: { step: 2 } });
  try {
    const { data } = await api({ action: 'challenge' });
    assert.ok(data.bits > POW.bits, `bits ${data.bits}`);
    const s = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
    assert.equal((await api(await createRequest(s, { pow: signedChallenge() }))).status, 403);
  } finally {
    writeConfig();
  }
});

test('marking as resolved tells the other trusted persons', async () => {
  const c = await newConversation();
  await staffList('hannah');
  await staffList('gabriela');
  const before = [mailsTo('hannah'), mailsTo('gabriela')];
  assert.equal((await api(closeRequest('hannah', c.publicId, 1))).status, 200);
  assert.deepEqual([mailsTo('hannah'), mailsTo('gabriela')], [before[0], before[1] + 1]);
});

test('spent challenges keep only a coarse expiry', async () => {
  await newConversation();
  for (const { expires } of dbQuery('SELECT expires FROM used_challenges')) {
    assert.equal(expires % 3600, 0);
  }
});

test('tables keep no insertion order', () => {
  const tables = dbQuery("SELECT name, sql FROM sqlite_master WHERE type = 'table'");
  assert.ok(tables.length >= 6);
  for (const { name, sql } of tables) {
    assert.match(sql, /WITHOUT ROWID/, name);
  }
});

function rekeyRequest(id, publicId, sealedKey, signKeys, timestamp = now()) {
  return {
    action: 'staff_rekey', staff_id: id, public_id: publicId, sealed_key: sealedKey, timestamp,
    signature: kk.sign(kk.staffRekeyStatement(id, publicId, sealedKey, timestamp), signKeys),
  };
}

test('after a key change, the current key takes over conversations sealed to the previous one', async () => {
  const c = await newConversation();
  const keysFile = join(dir, 'keys.json');
  const original = readFileSync(keysFile, 'utf8');
  const previous = staff.hannah;
  const current = kk.deriveStaff(['zebra'], 'hannah');
  const keys = JSON.parse(original);
  Object.assign(keys.staff.find((e) => e.id === 'hannah'),
    { box: kk.toB64(current.box.publicKey), sign: kk.toB64(current.sign.publicKey) });
  writeFileSync(keysFile, JSON.stringify(keys));
  staff.hannah = current;
  try {
    const listed = (await staffList('hannah')).data.conversations.find((x) => x.public_id === c.publicId);
    assert.throws(() => kk.openSealedKey(listed.sealed_key, current.box));
    const key = kk.openSealedKey(listed.sealed_key, previous.box);
    const resealed = kk.sealKey(key, kk.toB64(current.box.publicKey));

    // Only the current key may do it; a leaked previous passphrase is not enough.
    assert.equal((await api(rekeyRequest('hannah', c.publicId, resealed, previous.sign))).status, 403);
    // Nobody can replace another person's copy.
    assert.equal((await api(rekeyRequest('hannah', c.publicId, resealed, staff.gabriela.sign))).status, 403);

    assert.equal((await api(rekeyRequest('hannah', c.publicId, resealed, current.sign))).status, 200);
    const after = (await staffList('hannah')).data.conversations.find((x) => x.public_id === c.publicId);
    assert.deepEqual(kk.openSealedKey(after.sealed_key, current.box), key);

    // Gabriela's copy is untouched.
    const theirs = (await staffList('gabriela')).data.conversations.find((x) => x.public_id === c.publicId);
    assert.deepEqual(kk.openSealedKey(theirs.sealed_key, staff.gabriela.box), key);
  } finally {
    writeFileSync(keysFile, original);
    staff.hannah = previous;
  }
});

test('a conversation for some trusted persons reaches only them', async () => {
  await staffList('hannah');
  await staffList('gabriela');
  const before = [mailsTo('hannah'), mailsTo('gabriela')];
  const sent = () => [mailsTo('hannah') - before[0], mailsTo('gabriela') - before[1]];

  const s = kk.deriveSender(kk.parseWords(kk.generateWords(kk.CODEWORD_WORDS)).words);
  const req = await createRequest(s);
  delete req.sealed_keys.gabriela;
  const { status, data } = await api(req);
  assert.equal(status, 200);
  const id = data.public_id;
  assert.deepEqual(sent(), [1, 0]);

  assert.deepEqual((await api({ action: 'get', conv_id: s.convId })).data.recipients, ['hannah']);
  const hannahs = (await staffList('hannah')).data.conversations.find((c) => c.public_id === id);
  assert.deepEqual(hannahs.recipients, ['hannah']);
  assert.equal((await staffList('gabriela')).data.conversations.find((c) => c.public_id === id), undefined);
  assert.equal((await api(appendRequest(s.convId, s.key, 2, 'gabriela', staff.gabriela.sign))).status, 403);

  // Both logged in just above, so each would be mailed again.
  await api(appendRequest(s.convId, s.key, 2, 'hannah', staff.hannah.sign));
  assert.deepEqual(sent(), [1, 0]);
  await api(appendRequest(s.convId, s.key, 3, 'sender', s.sign));
  assert.deepEqual(sent(), [2, 0]);
});

test('a reminder follows a day later, while a message waits for an answer', async () => {
  dbQuery("UPDATE conversations SET status = 'closed'");
  await staffList('hannah');
  await staffList('gabriela');
  const c = await newConversation();
  const before = [mailsTo('hannah', REMINDER), mailsTo('gabriela', REMINDER)];
  const reminded = () => [mailsTo('hannah', REMINDER) - before[0], mailsTo('gabriela', REMINDER) - before[1]];

  ageNotifications(22 * HOURS);
  await api({ action: 'challenge' });
  assert.deepEqual(reminded(), [0, 0]);

  // A reminder must not show when the sender came back to look.
  ageNotifications(3 * HOURS);
  await api({ action: 'get', conv_id: c.convId });
  assert.deepEqual(reminded(), [0, 0]);

  await api({ action: 'challenge' });
  assert.deepEqual(reminded(), [1, 1]);
  await api({ action: 'challenge' });
  assert.deepEqual(reminded(), [1, 1]);

  // Logging in must not remind the person who just did.
  ageNotifications(25 * HOURS);
  await staffList('gabriela');
  assert.deepEqual(reminded(), [2, 1]);

  await api(appendRequest(c.convId, c.key, 2, 'gabriela', staff.gabriela.sign));
  ageNotifications(25 * HOURS);
  await api({ action: 'challenge' });
  assert.deepEqual(reminded(), [2, 1]);     // answered, nothing waits
});

test('a day after the last mail, news is mailed again without a login', async () => {
  await staffList('hannah');
  const c = await newConversation();
  const before = mailsTo('hannah', NEWS);

  await api(appendRequest(c.convId, c.key, 2, 'sender', c.sign));
  assert.equal(mailsTo('hannah', NEWS), before);

  ageNotifications(25 * HOURS);
  await api(appendRequest(c.convId, c.key, 3, 'gabriela', staff.gabriela.sign));
  assert.equal(mailsTo('hannah', NEWS), before + 1);
});
