// Builds public/<name>.html from pages/layout.html and pages/<name>.html, so
// the header and footer exist once. The output is committed: the site serves
// plain files that tools/verify.sh can compare with git.
//   node tools/build-pages.js
//
// A page starts with <!-- title: ...; script: ... -->; the script is
// js/page-<script>.js. In the layout, {{title}}, {{script}} and {{content}}
// are replaced, and {{current:<name>}} marks the nav link of the current page.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const PAGES = new URL('../pages/', import.meta.url);
const PUBLIC = new URL('../public/', import.meta.url);
const LAYOUT = 'layout.html';
const META = /^<!--\s*(.*?)\s*-->\n/;

function parseMeta(name, source) {
  const match = source.match(META);
  if (!match) {
    throw new Error(`pages/${name}.html lacks the <!-- title: ...; script: ... --> line`);
  }
  const meta = Object.fromEntries(match[1].split(';').map((pair) => {
    const [key, ...value] = pair.split(':');
    return [key.trim(), value.join(':').trim()];
  }));
  return { meta, content: source.slice(match[0].length) };
}

// { name: html } for every page
export function buildPages() {
  const layout = readFileSync(new URL(LAYOUT, PAGES), 'utf8');
  const pages = {};
  for (const file of readdirSync(PAGES).filter((f) => f.endsWith('.html') && f !== LAYOUT)) {
    const name = file.slice(0, -'.html'.length);
    const { meta, content } = parseMeta(name, readFileSync(new URL(file, PAGES), 'utf8'));
    pages[name] = layout
      .replace(/\{\{current:([a-z]+)\}\}/g, (_, page) => (page === name ? ' aria-current="page"' : ''))
      .replace('{{title}}', meta.title)
      .replace('{{script}}', meta.script)
      .replace('{{content}}', () => content);
  }
  return pages;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  for (const [name, html] of Object.entries(buildPages())) {
    writeFileSync(new URL(`${name}.html`, PUBLIC), html);
  }
}
