// The committed pages must be what pages/ builds, so an edit to a page or
// the layout without `node tools/build-pages.js` fails here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildPages } from '../tools/build-pages.js';

test('public/*.html match pages/ built with the layout', () => {
  for (const [name, html] of Object.entries(buildPages())) {
    const committed = readFileSync(new URL(`../public/${name}.html`, import.meta.url), 'utf8');
    assert.equal(committed, html, `public/${name}.html is stale; run node tools/build-pages.js`);
  }
});
