import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { InternalAxiosRequestConfig } from 'axios';
import { apiClient, API_BASE_URL } from './client';
import { comparisonsApi, comparisonExportFilename, ComparisonExportFormat } from './comparisons';

describe('comparisonsApi.downloadReport', () => {
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

  it('requests the report through the shared client: configured base URL, bearer token, blob body', async () => {
    localStorage.setItem('access_token', 'jwt-123');

    const blob = await comparisonsApi.downloadReport('cmp-1', 'pdf-detailed');

    expect(blob).toBeInstanceOf(Blob);
    expect(request?.baseURL).toBe(API_BASE_URL);
    expect(request?.url).toBe('/api/reports/comparison/cmp-1/pdf/detailed');
    expect(request?.responseType).toBe('blob');
    expect(request?.headers.Authorization).toBe('Bearer jwt-123');
  });

  it.each<[ComparisonExportFormat, string, Record<string, string> | undefined, string]>([
    ['pdf-executive', 'pdf/executive', undefined, 'comparison_0a1b2c3d_executive_summary.pdf'],
    ['pdf-detailed', 'pdf/detailed', undefined, 'comparison_0a1b2c3d_report.pdf'],
    ['html', 'html', undefined, 'comparison_0a1b2c3d_report.html'],
    ['csv-changes', 'csv/changes', undefined, 'comparison_0a1b2c3d_changes.csv'],
    ['csv-vulnerabilities', 'csv/changes', { category: 'vulnerability' }, 'comparison_0a1b2c3d_vulnerability_changes.csv'],
    ['csv-ports', 'csv/changes', { category: 'port' }, 'comparison_0a1b2c3d_port_changes.csv'],
    ['csv-summary', 'csv/summary', undefined, 'comparison_0a1b2c3d_summary.csv'],
  ])('%s is fetched from %s', async (format, path, params, filename) => {
    const id = '0a1b2c3d-0000-4000-8000-000000000001';

    await comparisonsApi.downloadReport(id, format);

    expect(request?.url).toBe(`/api/reports/comparison/${id}/${path}`);
    expect(request?.params).toEqual(params);
    expect(request?.responseType).toBe('blob');
    expect(comparisonExportFilename(id, format)).toBe(filename);
  });

  it('rejects instead of saving an error body as a report', async () => {
    apiClient.defaults.adapter = async (config) =>
      Promise.reject(Object.assign(new Error('Request failed'), { config, response: { status: 404 } }));

    await expect(comparisonsApi.downloadReport('missing', 'html')).rejects.toThrow('Request failed');
  });
});
