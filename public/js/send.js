// Sends messages so that a lost response never duplicates one. For a new
// conversation the codeword is fixed per draft, not per attempt, and a retry
// first asks whether the earlier attempt arrived; replies likewise check
// before reporting a failure.

import * as kk from './crypto.js';
import { ApiError, isNetworkError } from './api.js';

export function createDraft() {
  const words = kk.generateWords(kk.CODEWORD_WORDS);
  return { words, sender: kk.deriveSender(words.split(' ')), tried: false };
}

// The first message stored under the draft's codeword, or null if none.
async function arrived(draft, call) {
  const { convId, key } = draft.sender;
  try {
    const first = (await call('get', { conv_id: convId })).messages[0];
    return kk.decryptMessage(key, convId, first.seq, first.author, first.ciphertext);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      return null;
    }
    throw err;
  }
}

// pow() yields a solved challenge; it is only awaited when a request is sent.
// Resolves to { earlier }: null when this attempt created the conversation,
// otherwise the content of an earlier attempt that had arrived.
export async function sendDraft(draft, { content, staff, password, pow }, call) {
  if (draft.tried) {
    const earlier = await arrived(draft, call);
    if (earlier) {
      return { earlier };
    }
  }

  const solved = await pow();
  const { sender } = draft;
  const ciphertext = kk.encryptMessage(sender.key, sender.convId, 1, 'sender', content);
  draft.tried = true;
  try {
    await call('create', {
      password,
      pow: solved,
      conv_id: sender.convId,
      sender_sign_pk: kk.toB64(sender.sign.publicKey),
      sealed_keys: Object.fromEntries(staff.map((s) => [s.id, kk.sealKey(sender.key, s.box)])),
      ciphertext,
      signature: kk.sign(kk.appendStatement(sender.convId, 1, 'sender', ciphertext), sender.sign),
    });
  } catch (err) {
    // An earlier attempt still in flight may have won the race.
    if (err instanceof ApiError && err.status === 409) {
      const earlier = await arrived(draft, call);
      if (earlier) {
        return { earlier };
      }
    }
    throw err;
  }
  return { earlier: null };
}

// Sends a reply as message lastSeq + 1. After a lost response or a conflict,
// checks whether that message is already this reply, so a retry never posts
// it twice. Throws if the reply did not arrive.
export async function sendReply({ convId, key, author, signKeys, body, lastSeq }, call) {
  const seq = lastSeq + 1;
  const ciphertext = kk.encryptMessage(key, convId, seq, author, { body });
  try {
    await call('append', {
      conv_id: convId, seq, author, ciphertext,
      signature: kk.sign(kk.appendStatement(convId, seq, author, ciphertext), signKeys),
    });
    return;
  } catch (err) {
    if (!isNetworkError(err) && !(err instanceof ApiError && err.status === 409)) {
      throw err;
    }
    const stored = (await call('get', { conv_id: convId })).messages.find((m) => m.seq === seq);
    if (!stored || stored.author !== author || !sameBody(key, convId, stored, body)) {
      throw err;
    }
  }
}

function sameBody(key, convId, message, body) {
  try {
    return kk.decryptMessage(key, convId, message.seq, message.author, message.ciphertext).body === body;
  } catch {
    return false;
  }
}
