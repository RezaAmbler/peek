import { useEffect, useState } from 'react';

interface HealthInfo {
  version: string;
  git_branch: string;
}

export function Footer() {
  const [healthInfo, setHealthInfo] = useState<HealthInfo | null>(null);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const apiBase = import.meta.env.VITE_API_URL !== undefined
          ? import.meta.env.VITE_API_URL
          : 'http://localhost:8000';
        const response = await fetch(`${apiBase}/api/health`);
        if (response.ok) {
          const data = await response.json();
          setHealthInfo(data);
        }
      } catch {
        // Silently fail - footer is non-critical
      }
    };
    fetchHealth();
  }, []);

  if (!healthInfo) return null;

  return (
    <footer
      className="fixed bottom-0 right-0 p-2 text-xs text-gray-400 bg-gray-50/80 backdrop-blur-sm rounded-tl"
      data-component="Footer"
      data-testid="footer"
    >
      <span className="font-mono">
        v{healthInfo.version} · <span className="text-indigo-500">{healthInfo.git_branch}</span>
      </span>
    </footer>
  );
}
