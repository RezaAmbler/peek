export const NMAP_CREDIT_TEXT = 'This system uses the Nmap Security Scanner';
export const NMAP_URL = 'https://nmap.org/';

/**
 * Credit notice required by the Nmap Public Source License (NPSL v0.95 §6) for
 * a system that runs Nmap scans for its users. The whole notice is the link.
 */
export function NmapCredit({ className = '' }: { className?: string }) {
  return (
    <a
      href={NMAP_URL}
      target="_blank"
      rel="noopener noreferrer"
      className={`underline hover:text-indigo-600 dark:hover:text-indigo-400 ${className}`}
      data-testid="nmap-credit"
    >
      {NMAP_CREDIT_TEXT}
    </a>
  );
}
