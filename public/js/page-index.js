import { initPage } from './site.js';
import { t, onLanguageChange } from './i18n.js';
import { ready, fingerprint } from './crypto.js';
import { call, loadStaff } from './api.js';
import { $, h } from './ui.js';

initPage();

let staff = [];

function render() {
  if (!staff.length) {
    $('people').replaceChildren(h('li', { class: 'note' }, t('index.people.none')));
    return;
  }
  $('people').replaceChildren(...staff.map((s) => h('li', {},
    h('strong', {}, s.name), h('br'),
    h('code', {}, `${t('index.fingerprint')}: ${fingerprint(s.box)}`))));
}

// The server says whether the SFB access password is switched on.
call('challenge').then((c) => {
  $('how-password').hidden = !c.password_required;
}).catch(() => {});

await ready;
staff = await loadStaff();
render();
onLanguageChange(render);
