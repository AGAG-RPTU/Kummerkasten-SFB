import { initPage } from './site.js';
import { t } from './i18n.js';
import * as kk from './crypto.js';
import { call, loadStaff } from './api.js';
import { $, h, status, nextPaint, apiErrorText } from './ui.js';

initPage();

let codeword = null;
let saved = false;

$('form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = $('body').value.trim();
  if (!body) {
    status($('status'), 'error', t('err.empty'));
    return;
  }

  $('send').disabled = true;
  status($('status'), 'info', t('status.encrypting'));
  await nextPaint();
  try {
    await kk.ready;
    const staff = await loadStaff();
    if (!staff.length) {
      throw new Error(t('err.notConfigured'));
    }

    const words = kk.generateWords(kk.CODEWORD_WORDS);
    const sender = kk.deriveSender(words.split(' '));
    const content = { category: $('category').value, subject: $('subject').value.trim(), body };
    for (const field of ['name', 'contact']) {
      const value = $(field).value.trim();
      if (value) {
        content[field] = value;
      }
    }
    const ciphertext = kk.encryptMessage(sender.key, sender.convId, 1, 'sender', content);

    status($('status'), 'info', t('status.sending'));
    await call('create', {
      password: $('password').value,
      conv_id: sender.convId,
      sender_sign_pk: kk.toB64(sender.sign.publicKey),
      sealed_keys: Object.fromEntries(staff.map((s) => [s.id, kk.sealKey(sender.key, s.box)])),
      ciphertext,
      signature: kk.sign(kk.appendStatement(sender.convId, 1, 'sender', ciphertext), sender.sign),
    });

    codeword = words;
    showCodeword();
  } catch (err) {
    status($('status'), 'error', err.status ? apiErrorText(err) : err.message);
    $('send').disabled = false;
  }
});

function showCodeword() {
  $('form').hidden = true;
  $('codeword').replaceChildren(...codeword.split(' ').map((w) => h('li', {}, w)));
  $('done').hidden = false;
  $('done').scrollIntoView();
}

$('copy').addEventListener('click', async () => {
  await navigator.clipboard.writeText(codeword);
  $('copy').textContent = t('done.copied');
});

$('download').addEventListener('click', () => {
  const url = new URL('conversation.html', location.href).href;
  const blob = new Blob([t('done.file', { codeword, url })], { type: 'text/plain' });
  const a = h('a', { href: URL.createObjectURL(blob), download: 'kummerkasten-codeword.txt' });
  a.click();
  URL.revokeObjectURL(a.href);
});

$('saved').addEventListener('change', () => {
  saved = $('saved').checked;
  $('next').hidden = !saved;
});

// The codeword exists only on this page until the sender has saved it.
window.addEventListener('beforeunload', (event) => {
  if (codeword && !saved) {
    event.preventDefault();
    event.returnValue = t('done.leave');
  }
});
