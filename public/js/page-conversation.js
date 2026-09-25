import { initPage } from './site.js';
import { t, formatTime, onLanguageChange } from './i18n.js';
import * as kk from './crypto.js';
import { call, loadStaff, now, ApiError } from './api.js';
import { sendReply } from './send.js';
import { $, status, nextPaint, apiErrorText, attachWordFeedback, messageView } from './ui.js';

initPage();
const refreshFeedback = attachWordFeedback($('codeword'), $('feedback'), kk.CODEWORD_WORDS);

let staffNames = {};
let sender = null;      // keys derived from the codeword, held in memory only
let conv = null;        // last response of 'get'

$('unlock').addEventListener('submit', async (event) => {
  event.preventDefault();
  const { words, unknown } = kk.parseWords($('codeword').value);
  if (unknown.length || words.length !== kk.CODEWORD_WORDS) {
    status($('unlock-status'), 'error', t('err.codeword'));
    return;
  }

  status($('unlock-status'), 'info', t('status.deriving'));
  await nextPaint();
  try {
    await kk.ready;
    staffNames = Object.fromEntries((await loadStaff()).map((s) => [s.id, s.name]));
    sender = kk.deriveSender(words);
    await load();
    status($('unlock-status'), '');
    $('codeword').value = '';
    $('unlock').hidden = true;
    $('conversation').hidden = false;
  } catch (err) {
    sender = null;
    status($('unlock-status'), 'error', apiErrorText(err));
  }
});

async function load() {
  conv = await call('get', { conv_id: sender.convId });
  render();
}

function render() {
  if (!conv) {
    return;
  }
  const views = conv.messages.map((m) => {
    let content;
    try {
      content = kk.decryptMessage(sender.key, sender.convId, m.seq, m.author, m.ciphertext);
    } catch {
      content = { body: t('err.decrypt') };
    }
    const mine = m.author === 'sender';
    const meta = m.seq === 1
      ? [[t('staff.category'), content.category && t(`cat.${content.category}`)],
        [t('staff.name'), content.name], [t('staff.contact'), content.contact]].filter(([, v]) => v)
      : [];
    return messageView({
      author: mine ? t('conv.you') : (staffNames[m.author] ?? m.author),
      when: formatTime(m.created_at),
      mine,
      meta,
      subject: content.subject,
      body: content.body,
    });
  });
  $('thread').replaceChildren(...views);
  $('readers').textContent = t('conv.readers', {
    names: conv.recipients.map((id) => staffNames[id] ?? id).join(', '),
  });

  const onlySender = conv.messages.every((m) => m.author === 'sender');
  const note = conv.status === 'closed' ? t('conv.closed') : onlySender ? t('conv.noReply') : '';
  $('thread-note').textContent = note;
  $('thread-note').hidden = !note;
}

$('reply').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = $('reply-body').value.trim();
  if (!body) {
    return;
  }
  status($('reply-status'), 'info', t('status.sending'));
  try {
    await sendReply({
      convId: sender.convId, key: sender.key, author: 'sender', signKeys: sender.sign, body,
      lastSeq: conv.messages.at(-1).seq,
    }, call);
    $('reply-body').value = '';
    status($('reply-status'), '');
    await load();
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      await load();
    }
    status($('reply-status'), 'error', apiErrorText(err));
  }
});

$('delete').addEventListener('click', async () => {
  if (!confirm(t('conv.deleteConfirm'))) {
    return;
  }
  const timestamp = now();
  try {
    await call('delete', {
      conv_id: sender.convId, timestamp,
      signature: kk.sign(kk.senderDeleteStatement(sender.convId, timestamp), sender.sign),
    });
    lock();
    status($('unlock-status'), 'info', t('conv.deleted'));
  } catch (err) {
    status($('reply-status'), 'error', apiErrorText(err));
  }
});

$('lock').addEventListener('click', lock);

// Hidden by default against onlookers; the word check then shows counts only.
$('show-codeword').addEventListener('change', () => {
  $('codeword').type = $('show-codeword').checked ? 'text' : 'password';
  refreshFeedback();
});

function lock() {
  sender = null;
  conv = null;
  $('thread').replaceChildren();
  $('reply-body').value = '';
  status($('reply-status'), '');
  $('conversation').hidden = true;
  $('unlock').hidden = false;
  $('show-codeword').checked = false;
  $('codeword').type = 'password';
  refreshFeedback();
}

onLanguageChange(() => {
  render();
  refreshFeedback();
});
