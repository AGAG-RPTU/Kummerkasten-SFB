import { initPage } from './site.js';
import { t, formatTime, onLanguageChange } from './i18n.js';
import * as kk from './crypto.js';
import { call, loadStaff, now, ApiError } from './api.js';
import { sendReply } from './send.js';
import { transferKeys } from './rekey.js';
import { $, h, status, nextPaint, apiErrorText, attachWordFeedback, messageView } from './ui.js';

initPage();
const refreshFeedback = attachWordFeedback($('passphrase'), $('feedback'), kk.PASSPHRASE_WORDS);
const refreshRekeyFeedback = attachWordFeedback($('old-passphrase'), $('rekey-feedback'), kk.PASSPHRASE_WORDS);

let staff = [];
let me = null;          // { id, name, keys }, in memory only
let convs = [];         // staff_list result with opened keys and fetched messages
const expanded = new Set();
const drafts = new Map();   // public_id -> unsent reply, kept across reloads

// Parallel 'get' requests while loading the list.
const FETCH_BATCH = 4;

await kk.ready;
staff = await loadStaff();
$('who').replaceChildren(...staff.map((s) => h('option', { value: s.id }, s.name)));

$('unlock').addEventListener('submit', async (event) => {
  event.preventDefault();
  const entry = staff.find((s) => s.id === $('who').value);
  const { words } = kk.parseWords($('passphrase').value);
  status($('unlock-status'), 'info', t('status.deriving'));
  await nextPaint();

  const keys = kk.deriveStaff(words, entry.id);
  if (kk.toB64(keys.box.publicKey) !== entry.box) {
    status($('unlock-status'), 'error', t('err.passphrase', { name: entry.name }));
    return;
  }
  me = { id: entry.id, name: entry.name, keys };
  showWhoami();
  $('passphrase').value = '';
  refreshFeedback();
  status($('unlock-status'), '');
  $('unlock').hidden = true;
  $('inbox').hidden = false;
  await load();
});

async function load() {
  status($('inbox-status'), 'info', t('status.loading'));
  try {
    const timestamp = now();
    const data = await call('staff_list', {
      staff_id: me.id, timestamp,
      signature: kk.sign(kk.staffListStatement(me.id, timestamp), me.keys.sign),
    });
    convs = data.conversations.map((c) => ({ ...c, key: openKey(c), messages: [] }));
    for (let i = 0; i < convs.length; i += FETCH_BATCH) {
      await Promise.all(convs.slice(i, i + FETCH_BATCH).map(fetchMessages));
    }
    status($('inbox-status'), '');
    render();
  } catch (err) {
    status($('inbox-status'), 'error', apiErrorText(err));
  }
}

// Conversations the current key cannot open are usually still sealed to the
// person's previous key, after they changed their passphrase.
function showRekey() {
  const sealedElsewhere = convs.filter((c) => !c.key).length;
  $('rekey').hidden = !sealedElsewhere;
  $('rekey-notice').textContent = t('staff.rekey.notice', { n: sealedElsewhere });
}

$('rekey').addEventListener('submit', async (event) => {
  event.preventDefault();
  const { words } = kk.parseWords($('old-passphrase').value);
  status($('rekey-status'), 'info', t('status.deriving'));
  await nextPaint();
  try {
    const previous = kk.deriveStaff(words, me.id);
    const moved = await transferKeys({ staffId: me.id, convs, previous, current: me.keys }, call);
    if (!moved) {
      status($('rekey-status'), 'error', t('staff.rekey.none'));
      return;
    }
    $('old-passphrase').value = '';
    refreshRekeyFeedback();
    await load();
    status($('inbox-status'), 'info', t('staff.rekey.done', { n: moved }));
  } catch (err) {
    status($('rekey-status'), 'error', apiErrorText(err));
  }
});

// The list carries metadata only; messages come per conversation. A failed
// fetch leaves that conversation empty rather than failing the whole list.
async function fetchMessages(c) {
  try {
    c.messages = (await call('get', { conv_id: c.conv_id })).messages;
  } catch {
    c.messages = [];
  }
}

// A garbage sealed key (anyone who can start a conversation can send one) must
// not take down the whole list; such a conversation shows as unreadable.
function openKey(c) {
  try {
    return kk.openSealedKey(c.sealed_key, me.keys.box);
  } catch {
    return null;
  }
}

function decrypt(c, m) {
  if (!c.key) {
    return { body: t('err.decrypt') };
  }
  try {
    return kk.decryptMessage(c.key, c.conv_id, m.seq, m.author, m.ciphertext);
  } catch {
    return { body: t('err.decrypt') };
  }
}

function authorName(id) {
  if (id === 'sender') {
    return t('staff.requester');
  }
  return staff.find((s) => s.id === id)?.name ?? id;
}

function render() {
  showRekey();
  if (!convs.length) {
    $('convs').replaceChildren(h('p', { class: 'note' }, t('staff.none')));
    return;
  }
  $('convs').replaceChildren(...convs.map(renderConversation));
}

function renderConversation(c) {
  const contents = c.messages.map((m) => decrypt(c, m));
  const first = contents[0] ?? { body: t('err.decrypt') };
  const awaiting = c.last_author === 'sender';
  const badge = c.status === 'closed'
    ? h('span', { class: 'badge' }, t('staff.closed'))
    : h('span', { class: `badge ${awaiting ? 'awaiting' : ''}` }, t(awaiting ? 'staff.awaiting' : 'staff.open'));

  const thread = c.messages.map((m, i) => {
    const content = contents[i];
    const meta = i === 0
      ? [[t('staff.category'), content.category && t(`cat.${content.category}`)],
        [t('staff.name'), content.name], [t('staff.contact'), content.contact]].filter(([, v]) => v)
      : [];
    return messageView({
      author: authorName(m.author),
      when: formatTime(m.created_at),
      mine: m.author !== 'sender',
      meta,
      subject: content.subject,
      body: content.body,
    });
  });

  const voted = c.delete_votes.includes(me.id);
  const missing = c.delete_voters.filter((id) => !c.delete_votes.includes(id));
  const votes = c.delete_votes.length
    ? h('p', { class: 'note' }, t('staff.deleteVotes', {
      voted: c.delete_votes.map(authorName).join(', '),
      missing: missing.map(authorName).join(', '),
    }))
    : null;

  const replyBody = c.key && c.messages.length ? h('textarea', {
    maxlength: '20000', required: '', 'aria-label': t('conv.reply'),
    oninput: (e) => drafts.set(c.public_id, e.target.value),
  }) : null;
  if (replyBody) {
    replyBody.value = drafts.get(c.public_id) ?? '';
  }
  const replyStatus = h('p', { class: 'status', hidden: '' });
  const form = h('form', { class: 'card', autocomplete: 'off', onsubmit: (e) => reply(e, c, replyBody, replyStatus) },
    replyBody,
    h('div', { class: 'actions' },
      replyBody ? h('button', { type: 'submit' }, t('conv.send')) : null,
      c.status === 'closed' ? null
        : h('button', { type: 'button', class: 'secondary', onclick: () => close(c, replyStatus) }, t('staff.close')),
      h('button', { type: 'button', class: 'danger', onclick: () => voteDelete(c, !voted, replyStatus) },
        t(voted ? 'staff.unvoteDelete' : 'staff.voteDelete'))),
    votes,
    replyStatus);

  const details = h('details', {},
    h('summary', {},
      h('span', { class: 'id' }, `#${c.public_id}`),
      h('span', { class: 'subject' }, first.subject || t('staff.noSubject')),
      badge,
      h('span', { class: 'when' }, formatTime(c.updated_at))),
    h('div', { class: 'thread' }, ...thread),
    form);
  details.open = expanded.has(c.public_id);
  details.addEventListener('toggle', () => {
    if (details.open) {
      expanded.add(c.public_id);
    } else {
      expanded.delete(c.public_id);
    }
  });
  return details;
}

async function reply(event, c, textarea, replyStatus) {
  event.preventDefault();
  const body = textarea.value.trim();
  if (!body) {
    return;
  }
  status(replyStatus, 'info', t('status.sending'));
  try {
    await sendReply({
      convId: c.conv_id, key: c.key, author: me.id, signKeys: me.keys.sign, body, lastSeq: c.messages.at(-1).seq,
    }, call);
    drafts.delete(c.public_id);
    await load();
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      await load();
    }
    status(replyStatus, 'error', apiErrorText(err));
  }
}

async function close(c, replyStatus) {
  const timestamp = now();
  const lastSeq = c.messages.at(-1).seq;
  try {
    await call('staff_close', {
      staff_id: me.id, public_id: c.public_id, last_seq: lastSeq, timestamp,
      signature: kk.sign(kk.staffCloseStatement(me.id, c.public_id, lastSeq, timestamp), me.keys.sign),
    });
    await load();
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      await load();
    }
    status(replyStatus, 'error', apiErrorText(err));
  }
}

// Deletion needs the votes of all trusted persons; see staff_delete_vote()
// in private/app.php.
async function voteDelete(c, vote, replyStatus) {
  if (vote && !confirm(t('staff.deleteConfirm'))) {
    return;
  }
  const timestamp = now();
  const lastSeq = c.messages.at(-1).seq;
  try {
    await call('staff_delete_vote', {
      staff_id: me.id, public_id: c.public_id, last_seq: lastSeq, vote, timestamp,
      signature: kk.sign(kk.staffDeleteVoteStatement(me.id, c.public_id, lastSeq, vote, timestamp), me.keys.sign),
    });
    await load();
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      await load();
    }
    status(replyStatus, 'error', apiErrorText(err));
  }
}

$('refresh').addEventListener('click', load);

$('lock').addEventListener('click', () => {
  me = null;
  convs = [];
  expanded.clear();
  drafts.clear();
  $('old-passphrase').value = '';
  refreshRekeyFeedback();
  status($('rekey-status'), '');
  $('rekey').hidden = true;
  $('convs').replaceChildren();
  $('inbox').hidden = true;
  $('unlock').hidden = false;
});

function showWhoami() {
  $('whoami').textContent = me
    ? t('staff.whoami', { name: me.name, id: me.id, fingerprint: kk.fingerprint(kk.toB64(me.keys.box.publicKey)) })
    : '';
}

onLanguageChange(() => {
  showWhoami();
  refreshRekeyFeedback();
  render();
  refreshFeedback();
});
