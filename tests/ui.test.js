import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { ready } from '../public/js/crypto.js';
import { wordFeedback } from '../public/js/ui.js';

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
