export const API_URL = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

export async function apiFetch(path: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers);
  const token = localStorage.getItem('sentinelapi_token');
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  try {
    return await fetch(`${API_URL}${path}`, { ...options, headers });
  } catch (error) {
    throw new Error('Cannot connect to SentinelAPI backend. Check that the API is running.', { cause: error });
  }
}

export async function apiJson<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await apiFetch(path, options);
  const responseText = await response.text();
  let data: Record<string, unknown> = {};
  try {
    data = responseText ? JSON.parse(responseText) : {};
  } catch {
    data = {};
  }
  if (!response.ok) {
    const backendError = typeof data.error === 'string' ? data.error : '';
    throw new Error(backendError || `Request failed with status ${response.status}`);
  }
  return data as T;
}