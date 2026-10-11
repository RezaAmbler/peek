import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { InternalAxiosRequestConfig } from 'axios';
import { apiClient, API_BASE_URL } from './client';
import { comparisonsApi } from './comparisons';

describe('comparisonsApi.downloadPdf', () => {
  const originalAdapter = apiClient.defaults.adapter;
  let request: InternalAxiosRequestConfig | undefined;

  beforeEach(() => {
    request = undefined;
    apiClient.defaults.adapter = async (config) => {
      request = config;
      return { data: new Blob(['%PDF-1.4']), status: 200, statusText: 'OK', headers: {}, config };
    };
  });

  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
    localStorage.clear();
  });

  it('requests the PDF through the shared client: configured base URL, bearer token, blob body', async () => {
    localStorage.setItem('access_token', 'jwt-123');

    const blob = await comparisonsApi.downloadPdf('cmp-1');

    expect(blob).toBeInstanceOf(Blob);
    expect(request?.baseURL).toBe(API_BASE_URL);
    expect(request?.url).toBe('/api/reports/comparison/cmp-1/pdf');
    expect(request?.responseType).toBe('blob');
    expect(request?.headers.Authorization).toBe('Bearer jwt-123');
  });

  it('rejects instead of saving an error body as a PDF', async () => {
    apiClient.defaults.adapter = async (config) =>
      Promise.reject(Object.assign(new Error('Request failed'), { config, response: { status: 404 } }));

    await expect(comparisonsApi.downloadPdf('missing')).rejects.toThrow('Request failed');
  });
});
