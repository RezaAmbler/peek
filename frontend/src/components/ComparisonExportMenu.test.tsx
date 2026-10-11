import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ComparisonExportMenu } from './ComparisonExportMenu';
import { comparisonsApi } from '../api/comparisons';

const COMPARISON_ID = '0a1b2c3d-0000-4000-8000-000000000001';

describe('ComparisonExportMenu', () => {
  let saved: Array<{ download: string; href: string }>;

  beforeEach(() => {
    saved = [];
    // jsdom has no ResizeObserver; the headless UI menu observes its button while open
    vi.stubGlobal('ResizeObserver', class {
      observe() {}
      unobserve() {}
      disconnect() {}
    });
    window.URL.createObjectURL = vi.fn(() => 'blob:report');
    window.URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      saved.push({ download: this.download, href: this.href });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('offers the same formats as the scan report menu once opened', async () => {
    render(<ComparisonExportMenu comparisonId={COMPARISON_ID} />);
    expect(screen.queryByRole('menuitem')).not.toBeInTheDocument();

    await userEvent.click(screen.getByTestId('comparison-export-button'));

    expect(screen.getAllByRole('menuitem').map((item) => item.textContent)).toEqual([
      'PDF - Executive Summary',
      'PDF - Detailed Report',
      'HTML Report',
      'CSV - All Changes',
      'CSV - Vulnerability Changes',
      'CSV - Port Changes',
      'CSV - Summary',
    ]);
  });

  it.each([
    ['PDF - Executive Summary', 'pdf-executive', 'comparison_0a1b2c3d_executive_summary.pdf'],
    ['HTML Report', 'html', 'comparison_0a1b2c3d_report.html'],
    ['CSV - Vulnerability Changes', 'csv-vulnerabilities', 'comparison_0a1b2c3d_vulnerability_changes.csv'],
  ])('%s downloads through the API client and saves a named file', async (label, format, filename) => {
    const download = vi.spyOn(comparisonsApi, 'downloadReport').mockResolvedValue(new Blob(['report']));
    render(<ComparisonExportMenu comparisonId={COMPARISON_ID} />);

    await userEvent.click(screen.getByTestId('comparison-export-button'));
    await userEvent.click(screen.getByRole('menuitem', { name: label }));

    expect(download).toHaveBeenCalledWith(COMPARISON_ID, format);
    await waitFor(() => expect(saved).toEqual([{ download: filename, href: 'blob:report' }]));
    expect(window.URL.revokeObjectURL).toHaveBeenCalledWith('blob:report');
  });

  it('tells the user when the export fails instead of saving a file', async () => {
    vi.spyOn(comparisonsApi, 'downloadReport').mockRejectedValue(new Error('Request failed'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {});
    render(<ComparisonExportMenu comparisonId={COMPARISON_ID} />);

    await userEvent.click(screen.getByTestId('comparison-export-button'));
    await userEvent.click(screen.getByRole('menuitem', { name: 'CSV - Summary' }));

    await waitFor(() =>
      expect(alert).toHaveBeenCalledWith('Failed to export comparison report. Please try again.')
    );
    expect(saved).toEqual([]);
  });
});
