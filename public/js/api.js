// Thin client for api.php and the static keys.json.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// No response at all: offline, dropped connection or timeout.
export class NetworkError extends Error {}

// Better an error to retry than a request that hangs on a flaky connection.
const TIMEOUT_MS = 30000;

export async function call(action, body = {}) {
  let res;
  try {
    res = await fetch('api.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, ...body }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    throw new NetworkError(err.message);
  }
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

// [{ id, name, email, box, sign }]
export async function loadStaff() {
  const res = await fetch('keys.json', { cache: 'no-store' });
  return (await res.json()).staff;
}

export function isNetworkError(err) {
  return err instanceof NetworkError;
}

export function now() {
  return Math.floor(Date.now() / 1000);
}
