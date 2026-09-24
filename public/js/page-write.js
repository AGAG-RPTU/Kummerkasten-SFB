import { initPage } from './site.js';
import { t, onLanguageChange } from './i18n.js';
import * as kk from './crypto.js';
import { call, loadStaff, now, isNetworkError } from './api.js';
import { createDraft, sendDraft } from './send.js';
import { $, h, status, nextPaint, apiErrorText } from './ui.js';

initPage();

// Seconds a solved challenge must still be valid when it is sent.
const POW_MARGIN = 60;

let codeword = null;
let draft = null;                   // one codeword per message, however many attempts
let saved = false;
let pow = null;                     // promise of a solved challenge
let powProgress = 0;
let powDone = false;

// Access link: write.html#pw=... fills in the password. The fragment never
// reaches the server; drop it from the address bar so it is not shared on.
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has('pw')) {
  $('password').value = fragment.get('pw');
  history.replaceState(null, '', location.pathname);
}

// Fetches a challenge and solves it in a worker while the sender writes.
// The response also says whether the SFB access password is switched on.
function startPow() {
  powProgress = 0;
  powDone = false;
  showPowState();
  pow = call('challenge').then((challenge) => {
    $('password-box').hidden = !challenge.password_required;
    $('password').required = challenge.password_required;
    const { salt, bits, count, expires, signature } = challenge;
    return new Promise((resolve, reject) => {
      const worker = new Worker(new URL('./pow-worker.js', import.meta.url), { type: 'module' });
      worker.onmessage = ({ data }) => {
        if (data.nonces) {
          worker.terminate();
          powDone = true;
          showPowState();
          resolve({ salt, bits, count, expires, signature, nonces: data.nonces });
        } else {
          powProgress = data.progress;
          showPowState();
        }
      };
      worker.onerror = (event) => {
        worker.terminate();
        reject(new Error(event.message));
      };
      worker.postMessage({ salt, bits, count });
    });
  });
  pow.catch(() => {});    // reported when the sender submits
}

function showPowState() {
  $('pow-status').textContent = powDone
    ? t('pow.done')
    : t('pow.working', { pct: Math.round(powProgress * 100) });
}

startPow();
onLanguageChange(showPowState);

// Awaited by sendDraft() only when a request actually goes out.
async function solvedPow() {
  if (!powDone) {
    status($('status'), 'info', t('pow.waiting'));
  }
  let solved = await pow;
  if (solved.expires - now() < POW_MARGIN) {
    startPow();
    solved = await pow;
  }
  status($('status'), 'info', t('status.sending'));
  return solved;
}

function sameContent(a, b) {
  return [...new Set([...Object.keys(a), ...Object.keys(b)])].every((k) => a[k] === b[k]);
}

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

    const content = { category: $('category').value, subject: $('subject').value.trim(), body };
    for (const field of ['name', 'contact']) {
      const value = $(field).value.trim();
      if (value) {
        content[field] = value;
      }
    }

    draft ??= createDraft();
    const { earlier } = await sendDraft(draft, { content, staff, password: $('password').value, pow: solvedPow }, call);

    codeword = draft.words;
    $('earlier').hidden = !earlier || sameContent(earlier, content);
    showCodeword();
  } catch (err) {
    status($('status'), 'error', err.status || isNetworkError(err) ? apiErrorText(err) : err.message);
    $('send').disabled = false;
    startPow();     // the server spends a challenge on every attempt
  }
});

function showCodeword() {
  $('form').hidden = true;
  $('codeword').textContent = codeword;
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
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);     // some browsers read it after click()
});

$('saved').addEventListener('change', () => {
  saved = $('saved').checked;
  $('next').disabled = !saved;
});

$('next').addEventListener('click', () => {
  location.href = 'conversation.html';
});

// The codeword exists only on this page until the sender has saved it.
window.addEventListener('beforeunload', (event) => {
  if (codeword && !saved) {
    event.preventDefault();
    event.returnValue = t('done.leave');
  }
});
