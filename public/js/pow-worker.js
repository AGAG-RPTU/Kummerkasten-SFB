// Solves a proof-of-work challenge off the main thread, so the page stays
// responsive while the sender writes.

import { ready, solve } from './pow.js';

self.onmessage = async ({ data: challenge }) => {
  await ready;
  const nonces = solve(challenge, (progress) => self.postMessage({ progress }));
  self.postMessage({ nonces });
};
