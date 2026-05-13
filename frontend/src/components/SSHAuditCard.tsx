import { SSHAudit } from '../api/scans';

interface SSHAuditCardProps {
  audit: SSHAudit;
}

export function SSHAuditCard({ audit }: SSHAuditCardProps) {
  if (audit.connection_failed) {
    return (
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border-l-4 border-red-500" data-component="SSHAuditCard" data-testid="ssh-audit-card-failed">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {audit.ip_address}:{audit.port}
          </h3>
          <span className="px-2 py-1 text-xs font-semibold rounded bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
            Connection Failed
          </span>
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400">{audit.failure_reason}</p>
      </div>
    );
  }

  const hasVulnerabilities = audit.vulnerabilities && audit.vulnerabilities.length > 0;
  const hasRecommendations = audit.recommendations && audit.recommendations.length > 0;

  return (
    <div className={`bg-white dark:bg-gray-800 shadow rounded-lg p-6 border-l-4 ${
      hasVulnerabilities ? 'border-red-500' : 'border-green-500'
    }`} data-component="SSHAuditCard" data-testid="ssh-audit-card">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {audit.ip_address}:{audit.port}
          </h3>
          {audit.device_name && (
            <p className="text-sm text-gray-500 dark:text-gray-400">{audit.device_name}</p>
          )}
        </div>
        <span className={`px-2 py-1 text-xs font-semibold rounded ${
          hasVulnerabilities
            ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
            : 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
        }`}>
          {hasVulnerabilities ? 'Issues Found' : 'Secure'}
        </span>
      </div>

      {/* Banner & Version */}
      {audit.banner && (
        <div className="mb-4 bg-gray-50 dark:bg-gray-700 p-3 rounded">
          <p className="text-xs font-mono text-gray-700 dark:text-gray-300">{audit.banner}</p>
          {audit.ssh_version && (
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Protocol: SSH-{audit.ssh_version}</p>
          )}
        </div>
      )}

      {/* Vulnerabilities */}
      {hasVulnerabilities && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-red-800 dark:text-red-300 mb-2">
            ⚠️ Security Issues ({audit.vulnerabilities!.length})
          </h4>
          <ul className="space-y-2">
            {audit.vulnerabilities!.map((vuln, idx) => (
              <li key={idx} className="bg-red-50 dark:bg-red-900/30 p-2 rounded text-sm text-red-900 dark:text-red-200">
                <span className="font-semibold">{vuln.cve || 'Issue'}:</span>{' '}
                {vuln.description}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommendations */}
      {hasRecommendations && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-yellow-800 dark:text-yellow-300 mb-2">
            💡 Recommendations ({audit.recommendations!.length})
          </h4>
          <ul className="space-y-1">
            {audit.recommendations!.slice(0, 5).map((rec, idx) => (
              <li key={idx} className="bg-yellow-50 dark:bg-yellow-900/30 p-2 rounded text-sm text-yellow-900 dark:text-yellow-200">
                <span className="font-semibold capitalize">{rec.action}:</span>{' '}
                {rec.item}
              </li>
            ))}
            {audit.recommendations!.length > 5 && (
              <li className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                ... and {audit.recommendations!.length - 5} more
              </li>
            )}
          </ul>
        </div>
      )}

      {/* Algorithms (collapsible) */}
      <details className="mt-4">
        <summary className="cursor-pointer text-sm font-semibold text-gray-700 dark:text-gray-300">
          View Algorithms
        </summary>
        <div className="mt-2 space-y-2 text-xs">
          {audit.key_exchange_algorithms && audit.key_exchange_algorithms.length > 0 && (
            <div>
              <span className="font-semibold text-gray-700 dark:text-gray-300">Key Exchange:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {audit.key_exchange_algorithms.map((algo, idx) => (
                  <span key={idx} className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">
                    {algo}
                  </span>
                ))}
              </div>
            </div>
          )}
          {audit.encryption_algorithms && audit.encryption_algorithms.length > 0 && (
            <div>
              <span className="font-semibold text-gray-700 dark:text-gray-300">Encryption:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {audit.encryption_algorithms.map((algo, idx) => (
                  <span key={idx} className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">
                    {algo}
                  </span>
                ))}
              </div>
            </div>
          )}
          {audit.mac_algorithms && audit.mac_algorithms.length > 0 && (
            <div>
              <span className="font-semibold text-gray-700 dark:text-gray-300">MAC:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {audit.mac_algorithms.map((algo, idx) => (
                  <span key={idx} className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">
                    {algo}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </details>
    </div>
  );
}
