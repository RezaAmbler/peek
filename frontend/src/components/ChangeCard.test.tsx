import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ChangeCard } from './ChangeCard';
import { Change } from '../api/comparisons';

const baseChange: Change = {
  type: 'NEW_VULNERABILITY',
  severity: 'CRITICAL',
  category: 'vulnerability',
  ip_address: '10.0.0.5',
  template_id: 'CVE-2024-9999',
  description: 'New vulnerability detected: Example RCE',
};

describe('ChangeCard', () => {
  it('labels a GENUINELY_NEW vulnerability change clearly', () => {
    render(<ChangeCard change={{ ...baseChange, classification: 'GENUINELY_NEW', fingerprint: 'fp-1' }} />);
    expect(screen.getByTestId('change-genuinely-new-tag')).toHaveTextContent('NEW');
    expect(screen.queryByTestId('change-suppressed-tag')).not.toBeInTheDocument();
  });

  it('de-emphasizes a SUPPRESSED vulnerability change instead of treating it as alarming', () => {
    render(<ChangeCard change={{ ...baseChange, classification: 'SUPPRESSED', fingerprint: 'fp-2' }} />);
    const tag = screen.getByTestId('change-suppressed-tag');
    expect(tag).toHaveTextContent('suppressed (triaged)');
    expect(screen.getByTestId('change-card').className).toMatch(/opacity-70/);
    expect(screen.queryByTestId('change-genuinely-new-tag')).not.toBeInTheDocument();
  });

  it('renders a normal change without suppression styling when classification is absent', () => {
    render(<ChangeCard change={baseChange} />);
    expect(screen.queryByTestId('change-suppressed-tag')).not.toBeInTheDocument();
    expect(screen.getByTestId('change-card').className).not.toMatch(/opacity-70/);
  });
});
