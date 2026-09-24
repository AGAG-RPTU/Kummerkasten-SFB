// Thin client for api.php and the static keys.json.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Better an error to retry than a request that hangs on a flaky connection.
const TIMEOUT_MS = 30000;

export async function call(action, body = {}) {
  const res = await fetch('api.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, ...body }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  let data;
  try {
    data = await res.json();
  } catch {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
  if (!res.ok) {
    throw new ApiError(res.status, data.error ?? `HTTP ${res.status}`);
  }
  return data;
}

// [{ id, name, box, sign }]
export async function loadStaff() {
  const res = await fetch('keys.json', { cache: 'no-cache' });
  return (await res.json()).staff;
}

// No response at all: offline, dropped connection or timeout.
export function isNetworkError(err) {
  return err instanceof TypeError || err?.name === 'TimeoutError';
}

export function now() {
  return Math.floor(Date.now() / 1000);
}
