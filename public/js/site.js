// Header/footer wiring shared by every page.

import { applyI18n, toggleLang } from './i18n.js';

// Public repository, linked in the footer so visitors can compare files.
export const SOURCE_URL = '';

// Warning banner on every page until the site is fit for real use.
const PREVIEW = true;

export function initPage() {
  if (PREVIEW) {
    const banner = document.createElement('p');
    banner.className = 'preview';
    banner.setAttribute('role', 'note');
    banner.dataset.i18nHtml = 'preview';
    document.querySelector('main').prepend(banner);
  }
  applyI18n();
  document.getElementById('lang-toggle').addEventListener('click', toggleLang);

  const source = document.getElementById('source-link');
  source.hidden = !SOURCE_URL;
  source.href = SOURCE_URL;

  // version.txt is written at deploy time (see README)
  fetch('version.txt').then((r) => (r.ok ? r.text() : '')).then((v) => {
    if (v.trim()) {
      document.getElementById('version').textContent = v.trim();
    }
  }).catch(() => {});
}
