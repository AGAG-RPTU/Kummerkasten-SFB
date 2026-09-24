// The first message must never start two conversations, even when a
// response is lost and the sender tries again.

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import * as kk from '../public/js/crypto.js';
import { ApiError } from '../public/js/api.js';
import { createDraft, sendDraft } from '../public/js/send.js';

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
        if (loseResponses-- > 0) throw new TypeError('Failed to fetch');
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
