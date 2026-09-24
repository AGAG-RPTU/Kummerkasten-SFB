// Creates private/data/dev/ with two dev trusted persons and SFB access
// password "dev", then prints how to start the local server. Never deploy these keys.
//   node tools/dev-env.js

import { mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as kk from '../public/js/crypto.js';

const DIR = new URL('../private/data/dev/', import.meta.url).pathname;
const PASSWORD = 'dev';
const STAFF = [
  { id: 'alice', name: 'Alice Example', passphrase: 'aardvark abandoned abbreviate abdomen abhorrence abiding abnormal abrasion' },
  { id: 'bob', name: 'Bob Example', passphrase: 'zigzagged zillion zipping zirconium zodiac zombie zookeeper zucchini' },
];

await kk.ready;
mkdirSync(DIR, { recursive: true });

const entries = STAFF.map(({ id, name, passphrase }) => {
  const keys = kk.deriveStaff(kk.parseWords(passphrase).words, id);
  return { id, name, email: `${id}@example.org`, box: kk.toB64(keys.box.publicKey), sign: kk.toB64(keys.sign.publicKey) };
});
writeFileSync(`${DIR}keys.json`, JSON.stringify({ staff: entries }, null, 2));

const hash = execFileSync('php', ['-r', `echo password_hash('${PASSWORD}', PASSWORD_DEFAULT);`]).toString();
writeFileSync(`${DIR}config.php`, `<?php
return [
    'db' => __DIR__ . '/kummerkasten.sqlite',
    'keys_file' => __DIR__ . '/keys.json',
    'password_hash' => '${hash}',
    'pow' => ['bits' => 17, 'count' => 16, 'ttl' => 7200],
    'pow_secret' => '${randomBytes(32).toString('hex')}',
    'site_url' => 'http://localhost:8765/',
    'mail_from' => 'kummerkasten@example.org',
    'ntfy_url' => null,
    'retention' => ['closed_days' => 30, 'inactive_days' => 365],
    'limits' => ['creates_per_hour' => 1000, 'messages_per_conversation' => 200],
];
`);

console.log(`Dev environment in ${DIR}
SFB access password: ${PASSWORD}
${STAFF.map((s) => `${s.id}: ${s.passphrase}`).join('\n')}

Start (mail is written to ${DIR}mail.log):
  KK_CONFIG=${DIR}config.php php -d 'sendmail_path=cat >> ${DIR}mail.log' -S localhost:8765 -t public tools/dev-router.php`);
