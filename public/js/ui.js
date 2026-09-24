// DOM helpers shared by the pages. User content is only ever set via
// textContent, never innerHTML.

import { t } from './i18n.js';
import { parseWords } from './crypto.js';
import { ApiError } from './api.js';

export function $(id) {
  return document.getElementById(id);
}

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') {
      el.className = v;
    } else if (k.startsWith('on')) {
      el.addEventListener(k.slice(2), v);
    } else {
      el.setAttribute(k, v);
    }
  }
  el.append(...children.filter((c) => c !== null && c !== undefined));
  return el;
}

// kind: 'info' | 'error' | '' (hides the box)
export function status(el, kind, text = '') {
  el.textContent = text;
  el.className = `status ${kind}`;
  el.hidden = !kind;
}

// Argon2 blocks the main thread; let the status message paint first. The
// timeout covers background tabs, where animation frames never fire.
export function nextPaint() {
  return new Promise((resolve) => {
    requestAnimationFrame(() => setTimeout(resolve, 0));
    setTimeout(resolve, 100);
  });
}

export function apiErrorText(err) {
  if (err instanceof ApiError) {
    if (err.status === 401) return t('err.password');
    if (err.status === 429) return t('err.rate');
    if (err.status === 404) return t('err.notFound');
    if (err.status === 409) return t('err.conflict');
  }
  return t('err.generic', { msg: err.message });
}

// Feedback text for a codeword/passphrase field, or null when it is empty.
// With reveal false only counts are given, never the words themselves.
export function wordFeedback(value, expected, { reveal }) {
  if (!value.trim()) {
    return null;
  }
  const { words, unknown } = parseWords(value);
  return {
    ok: words.length === expected && !unknown.length,
    recognised: reveal
      ? t('conv.recognised', { n: words.length, total: expected, words: words.join(' ') })
      : t('words.recognisedCount', { n: words.length, total: expected }),
    unknown: !unknown.length ? null
      : reveal ? t('conv.unknown', { words: unknown.join(', ') })
        : t('words.unknownCount', { n: unknown.length }),
  };
}

// Live feedback under a codeword/passphrase field. Password fields get
// counts only, so the feedback never shows what the field hides.
export function attachWordFeedback(input, output, expected) {
  const update = () => {
    const feedback = wordFeedback(input.value, expected, { reveal: input.type !== 'password' });
    output.replaceChildren();
    if (!feedback) {
      return;
    }
    output.append(h('span', { class: feedback.ok ? 'ok' : '' }, feedback.recognised));
    if (feedback.unknown) {
      output.append(h('br'), h('span', { class: 'bad' }, feedback.unknown));
    }
  };
  input.addEventListener('input', update);
  return update;
}

// Message bubble; `mine` aligns it to the reader's side.
export function messageView({ author, when, mine, meta = [], subject, body }) {
  return h('article', { class: `msg ${mine ? 'mine' : ''}` },
    h('header', {}, h('strong', {}, author), ' · ', h('time', {}, when)),
    meta.length ? h('dl', { class: 'meta' }, ...meta.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])) : null,
    subject ? h('h3', {}, subject) : null,
    h('p', { class: 'body' }, body),
  );
}
