import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { Footer, buildDetails } from './Footer';

function mockHealth(body: object) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => body }));
}

describe('buildDetails', () => {
  it('drops missing and "unknown" values', () => {
    expect(buildDetails({ version: '2.2.1', git_branch: 'unknown', git_commit: null })).toEqual([]);
    expect(buildDetails({ version: '2.2.1', git_branch: 'main', git_commit: '' })).toEqual(['main']);
    expect(buildDetails({ version: '2.2.1', git_branch: 'main', git_commit: 'abc1234' })).toEqual(['main', 'abc1234']);
  });
});

describe('Footer', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('shows version, branch and commit', async () => {
    mockHealth({ status: 'ok', version: '2.2.1', git_branch: 'main', git_commit: 'abc1234' });
    render(<Footer />);

    await waitFor(() => expect(screen.getByTestId('footer')).toHaveTextContent('v2.2.1 · main @ abc1234'));
  });

  it('shows only the version when build info is unavailable', async () => {
    mockHealth({ status: 'ok', version: '2.2.1', git_branch: 'unknown' });
    render(<Footer />);

    await waitFor(() => expect(screen.getByTestId('footer')).toHaveTextContent('v2.2.1'));
    expect(screen.getByTestId('footer')).not.toHaveTextContent('unknown');
    expect(screen.queryByTestId('footer-build')).not.toBeInTheDocument();
  });

  it('credits Nmap with a link, even before build info loads', () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    render(<Footer />);

    const link = screen.getByRole('link', { name: 'This system uses the Nmap Security Scanner' });
    expect(link).toHaveAttribute('href', 'https://nmap.org/');
  });

  it('is part of the page flow, not a fixed overlay', () => {
    mockHealth({ status: 'ok', version: '2.2.1' });
    render(<Footer />);

    expect(screen.getByTestId('footer').className).not.toContain('fixed');
  });
});
