import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { ready } from '../public/js/crypto.js';
import { wordFeedback } from '../public/js/ui.js';
import { formatTime } from '../public/js/i18n.js';

before(() => ready);

test('word feedback for a hidden field reveals no words', () => {
  const feedback = wordFeedback('aardvark abandoned qqqq', 8, { reveal: false });
  const text = JSON.stringify(feedback);
  for (const secret of ['aardvark', 'abandoned', 'qqqq']) {
    assert.ok(!text.includes(secret), text);
  }
  assert.match(feedback.recognised, /2/);
  assert.match(feedback.unknown, /1/);
});

test('word feedback for a visible field names the words', () => {
  const feedback = wordFeedback('aard qqqq', 6, { reveal: true });
  assert.match(feedback.recognised, /aardvark/);
  assert.match(feedback.unknown, /qqqq/);
  assert.equal(feedback.ok, false);
  assert.equal(wordFeedback('', 6, { reveal: true }), null);
});

test('times read as approximate hours', () => {
  const ts = Date.UTC(2026, 8, 24, 12) / 1000;
  const zone = { timeZone: 'Europe/Berlin' };
  const plain = (text) => text.replace(/\s/g, ' ');
  assert.equal(plain(formatTime(ts, { locale: 'de', ...zone })), '24. Sept. 2026, ca. 14 Uhr');
  assert.equal(plain(formatTime(ts, { locale: 'en', ...zone })), 'Sep 24, 2026, around 2 PM');
});
