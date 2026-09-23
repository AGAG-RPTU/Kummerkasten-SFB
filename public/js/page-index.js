import { initPage } from './site.js';
import { t, onLanguageChange } from './i18n.js';
import { ready, fingerprint } from './crypto.js';
import { loadStaff } from './api.js';
import { $, h } from './ui.js';

initPage();

let staff = [];

function render() {
  $('people').replaceChildren(...staff.map((s) => h('li', {},
    h('strong', {}, s.name), h('br'),
    h('code', {}, `${t('index.fingerprint')}: ${fingerprint(s.box)}`))));
}

await ready;
staff = await loadStaff();
render();
onLanguageChange(render);
