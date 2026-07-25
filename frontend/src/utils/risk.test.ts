import { describe, it, expect } from 'vitest';
import { sortByRiskScoreDesc } from './risk';

describe('sortByRiskScoreDesc', () => {
  it('sorts items by risk_score descending', () => {
    const items = [
      { id: 'a', risk_score: 10 },
      { id: 'b', risk_score: 90 },
      { id: 'c', risk_score: 50 },
    ];
    expect(sortByRiskScoreDesc(items).map(i => i.id)).toEqual(['b', 'c', 'a']);
  });

  it('sorts null/undefined risk_score entries last, regardless of value', () => {
    const items = [
      { id: 'unscored-1', risk_score: null },
      { id: 'low', risk_score: 5 },
      { id: 'unscored-2', risk_score: undefined },
      { id: 'high', risk_score: 95 },
    ];
    expect(sortByRiskScoreDesc(items).map(i => i.id)).toEqual([
      'high',
      'low',
      'unscored-1',
      'unscored-2',
    ]);
  });

  it('does not mutate the input array', () => {
    const items = [{ id: 'a', risk_score: 1 }, { id: 'b', risk_score: 2 }];
    const original = [...items];
    sortByRiskScoreDesc(items);
    expect(items).toEqual(original);
  });
});
