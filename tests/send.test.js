// The first message must never start two conversations, even when a
// response is lost and the sender tries again.

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import * as kk from '../public/js/crypto.js';
import { ApiError, NetworkError, isNetworkError } from '../public/js/api.js';
import { createDraft, sendDraft, sendReply } from '../public/js/send.js';

let staff;

before(async () => {
  await kk.ready;
  const keys = kk.deriveStaff(['aardvark'], 'hannah');
  staff = [{ id: 'hannah', name: 'Hannah', box: kk.toB64(keys.box.publicKey), sign: kk.toB64(keys.sign.publicKey) }];
});

// Stands in for api.call; `loseResponses` create calls are stored but then
// fail as if the connection dropped.
function fakeServer({ loseResponses = 0 } = {}) {
  const conversations = new Map();
  const server = {
    conversations,
    creates: 0,
    async call(action, body) {
      if (action === 'get') {
        const conv = conversations.get(body.conv_id);
        if (!conv) throw new ApiError(404, 'not found');
        return conv;
      }
      if (action === 'create') {
        server.creates++;
        if (conversations.has(body.conv_id)) throw new ApiError(409, 'conversation exists');
        conversations.set(body.conv_id, {
          messages: [{ seq: 1, author: 'sender', ciphertext: body.ciphertext }],
        });
        if (loseResponses-- > 0) throw new NetworkError('Failed to fetch');
        return { public_id: 123456 };
      }
      throw new Error(`unexpected ${action}`);
    },
  };
  return server;
}

const pow = async () => ({ salt: 'x', nonces: [] });
const content = { subject: 'Hi', body: 'first' };

test('a lost response followed by a retry keeps one conversation and one codeword', async () => {
  const server = fakeServer({ loseResponses: 1 });
  const draft = createDraft();
  await assert.rejects(sendDraft(draft, { content, staff, pow }, server.call));

  const result = await sendDraft(draft, { content, staff, pow }, server.call);
  assert.equal(server.conversations.size, 1);
  assert.equal(server.creates, 1);
  assert.deepEqual(result.earlier, content);
});

test('an edited retry reports the version that arrived', async () => {
  const server = fakeServer({ loseResponses: 1 });
  const draft = createDraft();
  await assert.rejects(sendDraft(draft, { content, staff, pow }, server.call));

  const result = await sendDraft(draft, { content: { ...content, body: 'edited' }, staff, pow }, server.call);
  assert.equal(server.conversations.size, 1);
  assert.deepEqual(result.earlier, content);
});

test('a retry after a failure that stored nothing sends normally', async () => {
  const server = fakeServer();
  const draft = createDraft();
  const failing = async () => { throw new ApiError(401, 'wrong password'); };
  await assert.rejects(sendDraft(draft, { content, staff, pow }, failing));

  const result = await sendDraft(draft, { content, staff, pow }, server.call);
  assert.equal(server.conversations.size, 1);
  assert.equal(result.earlier, null);
});

// A conversation with one message, served by a fake that loses the first
// append response but stores the message.
async function replyServer({ loseResponses = 0 } = {}) {
  const server = fakeServer();
  const draft = createDraft();
  await sendDraft(draft, { content, staff, pow }, server.call);
  const conv = server.conversations.get(draft.sender.convId);
  const inner = server.call;
  server.appends = 0;
  server.call = async (action, body) => {
    if (action !== 'append') return inner(action, body);
    server.appends++;
    if (body.seq !== conv.messages.length + 1) throw new ApiError(409, 'conversation changed, reload');
    conv.messages.push({ seq: body.seq, author: body.author, ciphertext: body.ciphertext });
    if (loseResponses-- > 0) throw new NetworkError('Failed to fetch');
    return { seq: body.seq };
  };
  return { server, conv, sender: draft.sender };
}

test('a reply whose response was lost is recognised on retry, not sent twice', async () => {
  const { server, conv, sender } = await replyServer({ loseResponses: 1 });
  const reply = { convId: sender.convId, key: sender.key, author: 'sender', signKeys: sender.sign, body: 'again' };
  await sendReply({ ...reply, lastSeq: 1 }, server.call);
  assert.equal(conv.messages.length, 2);

  // The page still thinks the last message is seq 1 and tries again.
  await sendReply({ ...reply, lastSeq: 1 }, server.call);
  assert.equal(conv.messages.length, 2);
});

test('a reply that conflicts with someone else\'s message is reported', async () => {
  const { server, conv, sender } = await replyServer();
  conv.messages.push({ seq: 2, author: 'hannah', ciphertext: 'x' });
  const reply = { convId: sender.convId, key: sender.key, author: 'sender', signKeys: sender.sign, body: 'mine' };
  await assert.rejects(sendReply({ ...reply, lastSeq: 1 }, server.call), (err) => err.status === 409);
});

test('only failed requests count as network errors', () => {
  assert.ok(isNetworkError(new NetworkError('x')));
  assert.ok(!isNetworkError(new TypeError('x is not a function')));
});

test('transferKeys reseals only what the previous key opens', async () => {
  const { transferKeys } = await import('../public/js/rekey.js');
  const previous = kk.deriveStaff(['aardvark'], 'hannah');
  const current = kk.deriveStaff(['zebra'], 'hannah');
  const key = kk.deriveSender(['banana']).key;
  const convs = [
    { public_id: 1, key: null, sealed_key: kk.sealKey(key, kk.toB64(previous.box.publicKey)) },
    { public_id: 2, key: null, sealed_key: kk.toB64(new Uint8Array(80)) },          // garbage
    { public_id: 3, key, sealed_key: kk.sealKey(key, kk.toB64(current.box.publicKey)) }, // already current
  ];
  const sent = [];
  const call = async (action, body) => { sent.push({ action, ...body }); return {}; };

  const moved = await transferKeys({ staffId: 'hannah', convs, previous, current }, call);
  assert.equal(moved, 1);
  assert.deepEqual(sent.map((s) => [s.action, s.public_id]), [['staff_rekey', 1]]);
  assert.deepEqual(kk.openSealedKey(sent[0].sealed_key, current.box), key);
});
