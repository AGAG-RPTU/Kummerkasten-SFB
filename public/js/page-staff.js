import { initPage } from './site.js';
import { t, formatTime, onLanguageChange } from './i18n.js';
import * as kk from './crypto.js';
import { call, loadStaff, now, ApiError } from './api.js';
import { $, h, status, nextPaint, apiErrorText, attachWordFeedback, messageView } from './ui.js';

initPage();
const refreshFeedback = attachWordFeedback($('passphrase'), $('feedback'), kk.PASSPHRASE_WORDS);

let staff = [];
let me = null;          // { id, name, keys }, in memory only
let convs = [];         // staff_list result with opened keys
const expanded = new Set();

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
    convs = data.conversations.map((c) => ({ ...c, key: openKey(c) }));
    status($('inbox-status'), '');
    render();
  } catch (err) {
    status($('inbox-status'), 'error', apiErrorText(err));
  }
}

// A garbage sealed key (anyone with the shared password can send one) must
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
  if (!convs.length) {
    $('convs').replaceChildren(h('p', { class: 'note' }, t('staff.none')));
    return;
  }
  $('convs').replaceChildren(...convs.map(renderConversation));
}

function renderConversation(c) {
  const contents = c.messages.map((m) => decrypt(c, m));
  const first = contents[0];
  const awaiting = c.messages.at(-1).author === 'sender';
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

  const replyBody = c.key ? h('textarea', { maxlength: '20000', required: '', 'aria-label': t('conv.reply') }) : null;
  const replyStatus = h('p', { class: 'status', hidden: '' });
  const form = h('form', { class: 'card', onsubmit: (e) => reply(e, c, replyBody, replyStatus) },
    replyBody,
    h('div', { class: 'actions' },
      c.key ? h('button', { type: 'submit' }, t('conv.send')) : null,
      c.status === 'closed' ? null
        : h('button', { type: 'button', class: 'secondary', onclick: () => close(c, replyStatus) }, t('staff.close'))),
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
  const seq = c.messages.at(-1).seq + 1;
  const ciphertext = kk.encryptMessage(c.key, c.conv_id, seq, me.id, { body });
  status(replyStatus, 'info', t('status.sending'));
  try {
    await call('append', {
      conv_id: c.conv_id, seq, author: me.id, ciphertext,
      signature: kk.sign(kk.appendStatement(c.conv_id, seq, me.id, ciphertext), me.keys.sign),
    });
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

$('refresh').addEventListener('click', load);

$('lock').addEventListener('click', () => {
  me = null;
  convs = [];
  expanded.clear();
  $('convs').replaceChildren();
  $('inbox').hidden = true;
  $('unlock').hidden = false;
});

onLanguageChange(() => {
  render();
  refreshFeedback();
});
