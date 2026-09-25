// Takes over conversations after a trusted person's key changed: the previous
// passphrase's key opens each conversation key locally, the current key seals
// it again, and the server replaces the stored copy (staff_rekey in
// private/app.php).

import * as kk from './crypto.js';
import { now } from './api.js';

// convs: staff_list entries; those with key null are candidates. Returns how
// many were moved; conversations the previous key cannot open are skipped.
export async function transferKeys({ staffId, convs, previous, current }, call) {
  let moved = 0;
  for (const c of convs.filter((x) => !x.key)) {
    let key;
    try {
      key = kk.openSealedKey(c.sealed_key, previous.box);
    } catch {
      continue;
    }
    const sealedKey = kk.sealKey(key, kk.toB64(current.box.publicKey));
    const timestamp = now();
    await call('staff_rekey', {
      staff_id: staffId, public_id: c.public_id, sealed_key: sealedKey, timestamp,
      signature: kk.sign(kk.staffRekeyStatement(staffId, c.public_id, sealedKey, timestamp), current.sign),
    });
    moved++;
  }
  return moved;
}
