import { initPage } from './site.js';
import { t, onLanguageChange } from './i18n.js';
import * as kk from './crypto.js';
import { $, status, nextPaint, attachWordFeedback } from './ui.js';

initPage();
const refreshFeedback = attachWordFeedback($('retype'), $('feedback'), kk.PASSPHRASE_WORDS);
onLanguageChange(refreshFeedback);

let passphrase = null;

$('generate').addEventListener('click', async () => {
  await kk.ready;
  passphrase = kk.generateWords(kk.PASSPHRASE_WORDS);
  $('passphrase').textContent = passphrase;
  $('copy').textContent = t('setup.copy');
  $('passphrase-box').hidden = false;
  $('result').hidden = true;
  $('retype').value = '';
  refreshFeedback();
});

$('copy').addEventListener('click', async () => {
  await navigator.clipboard.writeText(passphrase);
  $('copy').textContent = t('done.copied');
});

$('copy-entry').addEventListener('click', async () => {
  await navigator.clipboard.writeText($('entry').textContent);
  $('copy-entry').textContent = t('done.copied');
});

// Entering it again proves the passphrase was saved before any key is published.
$('form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const id = $('staff-id').value.trim();
  if (!kk.STAFF_ID_PATTERN.test(id)) {
    status($('status'), 'error', t('err.id'));
    return;
  }
  const { words } = kk.parseWords($('retype').value);
  if (words.join(' ') !== passphrase) {
    status($('status'), 'error', t('err.retype'));
    return;
  }

  status($('status'), 'info', t('status.deriving'));
  await nextPaint();
  const keys = kk.deriveStaff(words, id);
  const entry = {
    id,
    name: $('staff-name').value.trim(),
    email: $('staff-email').value.trim(),
    box: kk.toB64(keys.box.publicKey),
    sign: kk.toB64(keys.sign.publicKey),
  };
  status($('status'), '');
  $('entry').textContent = JSON.stringify(entry, null, 2);
  $('copy-entry').textContent = t('setup.copyEntry');
  $('fingerprint').textContent = kk.fingerprint(entry.box);
  $('passphrase-box').hidden = true;
  $('passphrase').textContent = '';
  $('result').hidden = false;
  passphrase = null;
});
