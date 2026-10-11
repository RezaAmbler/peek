import { useEffect, useState } from 'react';
import { API_BASE_URL } from '../api/client';

export interface BuildInfo {
  version: string;
  git_branch?: string | null;
  git_commit?: string | null;
}

/** Build details worth showing: placeholders such as "unknown" are dropped. */
export function buildDetails(info: BuildInfo): string[] {
  return [info.git_branch, info.git_commit]
    .map((value) => (value ?? '').trim())
    .filter((value) => value !== '' && value.toLowerCase() !== 'unknown');
}

export function Footer() {
  const [buildInfo, setBuildInfo] = useState<BuildInfo | null>(null);

  useEffect(() => {
    const fetchBuildInfo = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/health`);
        if (response.ok) {
          setBuildInfo(await response.json());
        }
      } catch {
        // Silently fail - footer is non-critical
      }
    };
    fetchBuildInfo();
  }, []);

  const details = buildInfo ? buildDetails(buildInfo) : [];

  // In the page flow (not fixed): it can never cover or be clipped by page
  // content. Pages use min-h-page so page + footer fill the viewport exactly.
  return (
    <footer
      className="h-10 flex items-center justify-end px-4 sm:px-6 lg:px-8 text-xs text-gray-400 dark:text-gray-500 bg-gray-50 dark:bg-gray-900"
      data-component="Footer"
      data-testid="footer"
    >
      {buildInfo && (
        <span className="font-mono whitespace-nowrap">
          v{buildInfo.version}
          {details.length > 0 && (
            <>
              {' · '}
              <span className="text-indigo-500 dark:text-indigo-400" data-testid="footer-build">
                {details.join(' @ ')}
              </span>
            </>
          )}
        </span>
      )}
    </footer>
  );
}
