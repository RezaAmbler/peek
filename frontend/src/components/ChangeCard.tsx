import { Change } from '../api/comparisons';

interface ChangeCardProps {
  change: Change;
}

// Helper function to parse JSON reference arrays into clickable URLs
const parseReferences = (ref: string | null | undefined): string[] => {
  if (!ref || ref === 'null') return [];
  try {
    const parsed = JSON.parse(ref);
    return Array.isArray(parsed) ? parsed.filter(Boolean) : [parsed];
  } catch {
    // If not JSON, treat as single URL if it starts with http
    return ref.startsWith('http') ? [ref] : [];
  }
};

// Helper to shorten URL for display
const formatUrlForDisplay = (url: string): string => {
  try {
    const parsed = new URL(url);
    return parsed.hostname + parsed.pathname;
  } catch {
    return url;
  }
};

export function ChangeCard({ change }: ChangeCardProps) {
  const typeIcons: Record<string, string> = {
    NEW_PORT: '🔴',
    CLOSED_PORT: '🟢',
    VERSION_UPDATE: '🟡',
    NEW_VULNERABILITY: '🔴',
    FIXED_VULNERABILITY: '🟢',
    SSH_SECURITY_IMPROVED: '🟢',
    SSH_SECURITY_DEGRADED: '🔴',
  };

  const severityColors: Record<string, string> = {
    CRITICAL: 'bg-red-100 dark:bg-red-900/40 border-red-500 text-red-900 dark:text-red-200',
    HIGH: 'bg-orange-100 dark:bg-orange-900/40 border-orange-500 text-orange-900 dark:text-orange-200',
    MEDIUM: 'bg-yellow-100 dark:bg-yellow-900/40 border-yellow-500 text-yellow-900 dark:text-yellow-200',
    LOW: 'bg-blue-100 dark:bg-blue-900/40 border-blue-500 text-blue-900 dark:text-blue-200',
    INFO: 'bg-gray-100 dark:bg-gray-700 border-gray-500 text-gray-900 dark:text-gray-200',
    POSITIVE: 'bg-green-100 dark:bg-green-900/40 border-green-500 text-green-900 dark:text-green-200',
  };

  const icon = typeIcons[change.type] || '📝';
  const colorClass = severityColors[change.severity] || severityColors.INFO;

  return (
    <div className={`p-4 rounded-lg border-l-4 ${colorClass}`} data-component="ChangeCard" data-testid="change-card">
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-3 flex-1">
          <span className="text-2xl">{icon}</span>
          <div className="flex-1">
            <p className="font-semibold" data-testid="change-description">{change.description}</p>
            <p className="text-sm mt-1">
              {change.device_name && `${change.device_name} - `}
              {change.ip_address}
              {change.port && `:${change.port}`}
            </p>

            {/* Port details for NEW_PORT and CLOSED_PORT */}
            {(change.type === 'NEW_PORT' || change.type === 'CLOSED_PORT') && (
              <p className="text-sm mt-2 font-mono text-gray-700 dark:text-gray-300">
                {change.port}/{change.protocol}
                {(change.version || change.product || change.service_name) && ' — '}
                {change.version && <span>{change.version}</span>}
                {change.product && <span> {change.product}</span>}
                {change.service_name && <span className="text-gray-500 dark:text-gray-400"> ({change.service_name})</span>}
              </p>
            )}

            {/* Version update details */}
            {change.type === 'VERSION_UPDATE' && (
              <p className="text-sm mt-2 font-mono">
                {change.old_version} → {change.new_version}
              </p>
            )}

            {/* Vulnerability details */}
            {(change.type === 'NEW_VULNERABILITY' || change.type === 'FIXED_VULNERABILITY') && (
              <div className="mt-2">
                <span className="text-xs font-mono bg-gray-200 dark:bg-gray-600 px-2 py-1 rounded">
                  {change.template_id}
                </span>
                {/* Only show matched_at if it adds info beyond simple ip:port */}
                {change.matched_at && !change.matched_at.match(/^\d+\.\d+\.\d+\.\d+:\d+$/) && (
                  <p className="text-xs text-gray-600 dark:text-gray-400 mt-1 break-all">
                    {change.matched_at}
                  </p>
                )}
                {change.vuln_description && (
                  <p className="text-sm text-gray-700 dark:text-gray-300 mt-2">
                    {change.vuln_description}
                  </p>
                )}
                {/* Parse and render references as clickable links */}
                {parseReferences(change.reference).length > 0 && (
                  <div className="mt-1">
                    {parseReferences(change.reference).map((url, idx) => (
                      <a
                        key={idx}
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-600 dark:text-blue-400 hover:underline block break-all"
                      >
                        {formatUrlForDisplay(url)}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Associated vulnerabilities for CLOSED_PORT */}
            {change.type === 'CLOSED_PORT' && change.associated_vulnerabilities && change.associated_vulnerabilities.length > 0 && (
              <div className="mt-3 p-2 bg-green-50 dark:bg-green-900/30 rounded border border-green-200 dark:border-green-700">
                <p className="text-xs font-semibold text-green-800 dark:text-green-300 mb-1">
                  🛡️ {change.associated_vulnerabilities.length} {change.associated_vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'} also fixed:
                </p>
                <ul className="text-xs text-green-700 dark:text-green-300 space-y-1">
                  {change.associated_vulnerabilities.map((vuln, idx) => (
                    <li key={idx} className="flex items-center space-x-2">
                      <span className={`px-1 py-0.5 rounded text-xs font-medium ${
                        vuln.severity === 'critical' ? 'bg-red-200 dark:bg-red-800 text-red-800 dark:text-red-200' :
                        vuln.severity === 'high' ? 'bg-orange-200 dark:bg-orange-800 text-orange-800 dark:text-orange-200' :
                        vuln.severity === 'medium' ? 'bg-yellow-200 dark:bg-yellow-800 text-yellow-800 dark:text-yellow-200' :
                        'bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200'
                      }`}>
                        {vuln.severity}
                      </span>
                      <span>{vuln.name}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* SSH audit details */}
            {(change.type === 'SSH_SECURITY_IMPROVED' || change.type === 'SSH_SECURITY_DEGRADED') && (
              <p className="text-sm mt-2">
                Issues: {change.old_vuln_count} → {change.new_vuln_count}
              </p>
            )}
          </div>
        </div>

        <span className={`px-2 py-1 text-xs font-bold rounded uppercase ${
          change.severity === 'POSITIVE' ? 'bg-green-600 text-white' :
          change.severity === 'CRITICAL' ? 'bg-red-600 text-white' :
          change.severity === 'HIGH' ? 'bg-orange-600 text-white' :
          change.severity === 'MEDIUM' ? 'bg-yellow-600 text-white' :
          'bg-gray-600 text-white'
        }`}>
          {change.severity}
        </span>
      </div>
    </div>
  );
}
