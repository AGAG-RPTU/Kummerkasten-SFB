// Thin client for api.php and the static keys.json.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export async function call(action, body = {}) {
  const res = await fetch('api.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, ...body }),
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

export function now() {
  return Math.floor(Date.now() / 1000);
}
