import { useState } from 'react';
import { NSEFinding } from '../api/scans';

interface NSEFindingsSectionProps {
  findings: NSEFinding[];
  hostFilter?: string | null;
}

// Severity colors with dark mode
const severityColors: Record<string, string> = {
  critical: 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200 border-red-300 dark:border-red-700',
  high: 'bg-orange-100 dark:bg-orange-900/40 text-orange-800 dark:text-orange-200 border-orange-300 dark:border-orange-700',
  medium: 'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-800 dark:text-yellow-200 border-yellow-300 dark:border-yellow-700',
  low: 'bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-200 border-blue-300 dark:border-blue-700',
  info: 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600',
};

function NSEFindingCard({ finding }: { finding: NSEFinding }) {
  const [expanded, setExpanded] = useState(false);
  const severityStyle = severityColors[finding.severity?.toLowerCase() || 'info'] || severityColors.info;

  return (
    <div
      className={`border rounded-lg p-4 ${severityStyle}`}
      data-component="NSEFindingCard"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-xs font-medium rounded bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300">
              NSE
            </span>
            <span className="font-semibold">{finding.script_id}</span>
            {finding.severity && (
              <span className={`px-2 py-0.5 text-xs font-medium rounded uppercase ${severityStyle}`}>
                {finding.severity}
              </span>
            )}
          </div>
          <p className="text-sm opacity-80">
            {finding.ip_address}:{finding.port}/{finding.protocol}
            {finding.service_name && ` (${finding.service_name})`}
            {finding.device_name && ` - ${finding.device_name}`}
          </p>
        </div>
        {finding.raw_output && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300"
          >
            {expanded ? 'Hide' : 'Show Output'}
          </button>
        )}
      </div>

      {/* Profile name */}
      {finding.profile_name && (
        <p className="mt-2 text-xs opacity-70">
          Profile: <span className="font-medium">{finding.profile_name}</span>
        </p>
      )}

      {/* Expanded output */}
      {expanded && finding.raw_output && (
        <div className="mt-3 p-3 bg-gray-900 rounded overflow-x-auto">
          <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap">
            {finding.raw_output}
          </pre>
        </div>
      )}

      {/* Elements (parsed key-value data) */}
      {finding.elements && Object.keys(finding.elements).length > 0 && (
        <div className="mt-3">
          <p className="text-xs font-semibold opacity-80 mb-1">Extracted Data:</p>
          <div className="bg-gray-50 dark:bg-gray-800/50 rounded p-2 text-xs">
            {Object.entries(finding.elements).map(([key, value]) => (
              <div key={key} className="flex gap-2">
                <span className="font-medium opacity-70">{key}:</span>
                <span className="font-mono">
                  {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Error */}
      {finding.error && (
        <p className="mt-2 text-xs text-red-600 dark:text-red-400">Error: {finding.error}</p>
      )}
    </div>
  );
}

export function NSEFindingsSection({ findings, hostFilter }: NSEFindingsSectionProps) {
  const [show, setShow] = useState(true);

  // Filter by host
  const filteredFindings = hostFilter
    ? findings.filter(f => f.ip_address === hostFilter)
    : findings;

  // Group by port/service
  const groupedByPort = filteredFindings.reduce((acc, finding) => {
    const key = `${finding.ip_address}:${finding.port}`;
    if (!acc[key]) {
      acc[key] = {
        ip: finding.ip_address,
        port: finding.port,
        protocol: finding.protocol,
        service: finding.service_name,
        device: finding.device_name,
        findings: [],
      };
    }
    acc[key].findings.push(finding);
    return acc;
  }, {} as Record<string, { ip: string; port: number; protocol: string; service?: string; device?: string; findings: NSEFinding[] }>);

  if (findings.length === 0) return null;

  return (
    <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="NSEFindingsSection">
      <button
        onClick={() => setShow(!show)}
        className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white">
            NSE Script Results ({hostFilter ? `${filteredFindings.length} of ${findings.length}` : findings.length})
          </h2>
          <span className="px-2 py-0.5 text-xs font-medium rounded bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300">
            NMAP SCRIPTS
          </span>
        </div>
        <svg
          className={`w-5 h-5 text-gray-500 dark:text-gray-400 transform transition-transform ${show ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {show && (
        <div className="p-6">
          {filteredFindings.length > 0 ? (
            <div className="space-y-6">
              {Object.entries(groupedByPort).map(([key, group]) => (
                <div key={key}>
                  <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2 flex items-center gap-2">
                    <span className="font-mono">{group.ip}:{group.port}/{group.protocol}</span>
                    {group.service && (
                      <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">{group.service}</span>
                    )}
                    <span className="text-gray-400 dark:text-gray-500">({group.findings.length} scripts)</span>
                  </h3>
                  <div className="space-y-2 ml-4">
                    {group.findings.map(finding => (
                      <NSEFindingCard key={finding.id} finding={finding} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 dark:text-gray-400 text-center py-4">No NSE script results for selected host</p>
          )}
        </div>
      )}
    </div>
  );
}
