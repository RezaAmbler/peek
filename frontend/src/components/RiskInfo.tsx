import { ReactNode, useId } from 'react';

/**
 * Keyboard- and screen-reader-accessible info badge with a tooltip.
 *
 * The visible chip is a real <button> (so it's focusable and jsx-a11y clean);
 * the tooltip shows on hover AND keyboard focus (group-hover / group-focus-within)
 * and is wired to the trigger via aria-describedby.
 *
 * Copy for the risk signals is centralized in RISK_TOOLTIPS below so it stays in
 * sync with backend compute_risk_score (see enrichment_service.py).
 */
export function InfoBadge({
  label,
  className,
  tooltip,
  testId,
}: {
  label: ReactNode;
  className: string;
  tooltip: ReactNode;
  testId?: string;
}) {
  const id = useId();
  return (
    <span className="relative inline-flex group">
      <button
        type="button"
        aria-describedby={id}
        data-testid={testId}
        className={`${className} cursor-help focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-indigo-500 dark:focus:ring-offset-gray-800`}
      >
        {label}
      </button>
      <span
        role="tooltip"
        id={id}
        className="pointer-events-none absolute left-0 top-full z-30 mt-1 hidden w-64 rounded-md bg-gray-900 p-2 text-xs font-normal leading-snug text-gray-100 shadow-lg group-hover:block group-focus-within:block dark:bg-gray-700"
      >
        {tooltip}
      </span>
    </span>
  );
}

export const RISK_TOOLTIPS = {
  kev: 'KEV — CISA Known Exploited Vulnerabilities. This CVE has confirmed, active exploitation in the wild. Treat as urgent regardless of CVSS.',
  exploit: 'A public exploit is known — the CVE is KEV-listed or the detection template implies a working exploit (exploit / RCE).',
  cvss: 'CVSS — Common Vulnerability Scoring System (NVD). Severity of impact if exploited, 0–10.',
  epss: 'EPSS — Exploit Prediction Scoring System (FIRST.org). Probability this CVE is exploited in the wild within the next 30 days.',
  risk: 'Risk score (0–100): a prioritization blend of impact and likelihood. base = CVSS×10 (or the severity rating if no CVSS), scaled by ×(1 + EPSS), then ×1.5 + 25 if KEV-listed or a known exploit exists.',
} as const;

/**
 * Collapsible reference legend for the risk-signal columns. Native <details> is
 * keyboard-accessible and needs no extra ARIA.
 */
export function RiskLegend() {
  return (
    <details className="mt-4 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/40 text-sm">
      <summary className="cursor-pointer select-none px-4 py-3 font-medium text-gray-700 dark:text-gray-300">
        How risk is scored — legend
      </summary>
      <div className="px-4 pb-4 space-y-3 text-gray-600 dark:text-gray-400">
        <dl className="space-y-2">
          <div>
            <dt className="font-semibold text-gray-800 dark:text-gray-200">Risk score (0–100)</dt>
            <dd>
              A prioritization score combining impact and likelihood so real-world
              exploitability outranks a raw severity label. Computed as{' '}
              <code className="text-xs">base × (1 + EPSS)</code>, then{' '}
              <code className="text-xs">× 1.5 + 25</code> when KEV-listed or a known
              exploit exists (capped at 100). <code className="text-xs">base</code> is{' '}
              <code className="text-xs">CVSS × 10</code>, or the finding&apos;s severity
              rating when no CVSS is available.
            </dd>
          </div>
          <div>
            <dt className="font-semibold text-gray-800 dark:text-gray-200">CVSS</dt>
            <dd>Common Vulnerability Scoring System (NVD) — severity of impact, 0–10.</dd>
          </div>
          <div>
            <dt className="font-semibold text-gray-800 dark:text-gray-200">EPSS</dt>
            <dd>
              Exploit Prediction Scoring System (FIRST.org) — probability the CVE is
              exploited in the wild within the next 30 days.
            </dd>
          </div>
          <div>
            <dt className="font-semibold text-gray-800 dark:text-gray-200">KEV</dt>
            <dd>
              CISA Known Exploited Vulnerabilities — a KEV badge means confirmed active
              exploitation in the wild; prioritize it.
            </dd>
          </div>
        </dl>
        <p className="text-xs text-gray-500 dark:text-gray-500">
          Sources: NVD (CVSS), FIRST (EPSS), CISA (KEV). Enrichment runs after each scan;
          fields may be empty for findings without a resolvable CVE.
        </p>
      </div>
    </details>
  );
}
