// Shared risk-prioritization helpers (SOC hardening).

/**
 * Sort items by risk_score descending. Items with a null/undefined risk_score sort last,
 * so the highest-priority findings surface first while unscored items don't get lost.
 * Returns a new array; does not mutate the input.
 */
export function sortByRiskScoreDesc<T extends { risk_score?: number | null }>(items: T[]): T[] {
  return [...items].sort((a, b) => {
    const aScore = typeof a.risk_score === 'number' ? a.risk_score : -1;
    const bScore = typeof b.risk_score === 'number' ? b.risk_score : -1;
    return bScore - aScore;
  });
}
