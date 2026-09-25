import { initPage } from './site.js';
import { t, onLanguageChange } from './i18n.js';
import * as kk from './crypto.js';
import { loadStaff } from './api.js';
import { $, status, nextPaint, attachWordFeedback } from './ui.js';

initPage();
const refreshFeedback = attachWordFeedback($('retype'), $('feedback'), kk.PASSPHRASE_WORDS);
onLanguageChange(refreshFeedback);

let passphrase = null;

// Checks the user name while it is typed: allowed characters, and whether
// keys.json already has it (fine only when changing one's own passphrase).
let takenIds = [];
loadStaff().then((staff) => {
  takenIds = staff.map((s) => s.id);
  checkId();
}).catch(() => {});

function checkId() {
  const id = $('staff-id').value.trim();
  const message = !id ? '' : !kk.STAFF_ID_PATTERN.test(id) ? t('err.id') : takenIds.includes(id) ? t('setup.idTaken') : '';
  $('staff-id-check').textContent = message;
  $('staff-id-check').className = `hint ${message ? 'bad' : ''}`;
  $('staff-id-check').hidden = !message;
}
$('staff-id').addEventListener('input', checkId);
onLanguageChange(checkId);

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
  $('retype').value = '';
  $('result').hidden = false;
  passphrase = null;
});
