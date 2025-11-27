import { Change } from '../api/comparisons';

interface ChangeCardProps {
  change: Change;
}

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
    CRITICAL: 'bg-red-100 border-red-500 text-red-900',
    HIGH: 'bg-orange-100 border-orange-500 text-orange-900',
    MEDIUM: 'bg-yellow-100 border-yellow-500 text-yellow-900',
    LOW: 'bg-blue-100 border-blue-500 text-blue-900',
    INFO: 'bg-gray-100 border-gray-500 text-gray-900',
    POSITIVE: 'bg-green-100 border-green-500 text-green-900',
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

            {/* Version update details */}
            {change.type === 'VERSION_UPDATE' && (
              <p className="text-sm mt-2 font-mono">
                {change.old_version} → {change.new_version}
              </p>
            )}

            {/* Vulnerability details */}
            {(change.type === 'NEW_VULNERABILITY' || change.type === 'FIXED_VULNERABILITY') && (
              <div className="mt-2">
                <span className="text-xs font-mono bg-gray-200 px-2 py-1 rounded">
                  {change.template_id}
                </span>
                {change.matched_at && (
                  <p className="text-xs text-gray-600 mt-1 break-all">
                    {change.matched_at}
                  </p>
                )}
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
