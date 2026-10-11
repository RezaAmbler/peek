import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { NmapCredit } from './NmapCredit';

describe('NmapCredit', () => {
  it('shows the notice as a link to nmap.org', () => {
    render(<NmapCredit />);

    const link = screen.getByRole('link', { name: 'This system uses the Nmap Security Scanner' });
    expect(link).toHaveAttribute('href', 'https://nmap.org/');
    expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
  });
});
