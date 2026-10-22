// NetScope — typed API client

const getApiBase = (): string => {
  const envBase = process.env.NEXT_PUBLIC_API_URL;
  if (envBase) {
    try {
      return new URL(envBase).href.replace(/\/+$/, '');
    } catch {
      if (typeof window !== 'undefined') {
        return `${window.location.protocol}//${envBase}`.replace(/\/+$/, '');
      }
      return `http://${envBase}`.replace(/\/+$/, '');
    }
  }
  if (typeof window !== 'undefined') {
    return `${window.location.protocol}//${window.location.hostname}:8000`;
  }
  return 'http://127.0.0.1:8000';
};

class ApiClient {
  private baseUrl: string;
  private defaultTimeoutMs: number;

  constructor(timeoutMs = 120_000) {
    this.baseUrl = getApiBase();
    this.defaultTimeoutMs = timeoutMs;
  }

  private async request<T>(
    path: string,
    options: RequestInit = {},
    timeoutMs?: number
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      timeoutMs ?? this.defaultTimeoutMs
    );

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });

      if (!response.ok) {
        let detail = `HTTP ${response.status}`;
        try {
          const err = await response.json();
          detail = err.detail || detail;
        } catch {
          // ignore json parse error
        }
        throw new Error(detail);
      }

      return response.json() as Promise<T>;
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error(`Request timed out after ${(timeoutMs ?? this.defaultTimeoutMs) / 1000}s`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  async get<T>(path: string, timeoutMs?: number): Promise<T> {
    return this.request<T>(path, { method: 'GET' }, timeoutMs);
  }

  async post<T>(path: string, body: unknown, timeoutMs?: number): Promise<T> {
    return this.request<T>(
      path,
      { method: 'POST', body: JSON.stringify(body) },
      timeoutMs
    );
  }
}

export const apiClient = new ApiClient();
