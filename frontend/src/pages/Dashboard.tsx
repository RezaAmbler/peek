import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Navigation } from '../components/Navigation';
import { statsApi, DashboardStats } from '../api/stats';
import { formatDistanceToNow } from 'date-fns';

// Parse UTC timestamp from backend (may or may not have 'Z' suffix)
function parseUTC(dateString: string): Date {
  if (!dateString.endsWith('Z') && !dateString.includes('+')) {
    return new Date(dateString + 'Z');
  }
  return new Date(dateString);
}

const statusColors: Record<string, { bg: string; text: string }> = {
  pending: { bg: 'bg-gray-100 dark:bg-gray-700', text: 'text-gray-800 dark:text-gray-200' },
  queued: { bg: 'bg-blue-100 dark:bg-blue-900', text: 'text-blue-800 dark:text-blue-200' },
  running: { bg: 'bg-yellow-100 dark:bg-yellow-900', text: 'text-yellow-800 dark:text-yellow-200' },
  completed: { bg: 'bg-green-100 dark:bg-green-900', text: 'text-green-800 dark:text-green-200' },
  failed: { bg: 'bg-red-100 dark:bg-red-900', text: 'text-red-800 dark:text-red-200' },
  cancelled: { bg: 'bg-gray-100 dark:bg-gray-700', text: 'text-gray-800 dark:text-gray-200' },
};

const severityColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500', text: 'text-white', border: 'border-red-500' },
  high: { bg: 'bg-orange-500', text: 'text-white', border: 'border-orange-500' },
  medium: { bg: 'bg-yellow-500', text: 'text-white', border: 'border-yellow-500' },
  low: { bg: 'bg-blue-500', text: 'text-white', border: 'border-blue-500' },
  info: { bg: 'bg-gray-500', text: 'text-white', border: 'border-gray-500' },
  unknown: { bg: 'bg-gray-400', text: 'text-white', border: 'border-gray-400' },
};

function StatCard({ title, value, subtitle, icon, color }: {
  title: string;
  value: number | string;
  subtitle?: string;
  icon: React.ReactNode;
  color: string;
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <div className="flex items-center">
        <div className={`p-3 rounded-full ${color}`}>
          {icon}
        </div>
        <div className="ml-4">
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</p>
          <p className="text-2xl font-semibold text-gray-900 dark:text-white">{value}</p>
          {subtitle && (
            <p className="text-xs text-gray-400 dark:text-gray-500">{subtitle}</p>
          )}
        </div>
      </div>
    </div>
  );
}

function VulnerabilitySummary({ stats }: { stats: DashboardStats }) {
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const sortedVulns = [...stats.vulnerabilities_by_severity].sort(
    (a, b) => severityOrder.indexOf(a.severity.toLowerCase()) - severityOrder.indexOf(b.severity.toLowerCase())
  );

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Vulnerabilities by Severity</h3>
      {sortedVulns.length === 0 ? (
        <p className="text-gray-500 dark:text-gray-400 text-sm">No vulnerabilities found</p>
      ) : (
        <div className="space-y-3">
          {sortedVulns.map(({ severity, count }) => {
            const colors = severityColors[severity.toLowerCase()] || severityColors.unknown;
            const percentage = stats.total_vulnerabilities > 0
              ? Math.round((count / stats.total_vulnerabilities) * 100)
              : 0;
            return (
              <div key={severity}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="capitalize text-gray-700 dark:text-gray-300">{severity}</span>
                  <span className="text-gray-500 dark:text-gray-400">{count}</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div
                    className={`${colors.bg} h-2 rounded-full transition-all`}
                    style={{ width: `${percentage}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ScanStatusSummary({ stats }: { stats: DashboardStats }) {
  const running = stats.scans_by_status.find(s => s.status === 'running')?.count || 0;
  const completed = stats.scans_by_status.find(s => s.status === 'completed')?.count || 0;
  const failed = stats.scans_by_status.find(s => s.status === 'failed')?.count || 0;

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Scan Status</h3>
      <div className="grid grid-cols-3 gap-4 text-center">
        <div>
          <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{running}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400">Running</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-green-600 dark:text-green-400">{completed}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400">Completed</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-red-600 dark:text-red-400">{failed}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400">Failed</div>
        </div>
      </div>
    </div>
  );
}

function RecentScansTable({ scans }: { scans: DashboardStats['recent_scans'] }) {
  if (scans.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Recent Scans</h3>
        <p className="text-gray-500 dark:text-gray-400 text-sm">No scans yet. Create your first scan to get started.</p>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white">Recent Scans</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Config / Run
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Ports
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Vulns
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Created
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            {scans.map((scan) => {
              const colors = statusColors[scan.status] || statusColors.pending;
              return (
                <tr key={scan.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <Link
                      to="/scans/$scanId"
                      params={{ scanId: scan.id }}
                      className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-900 dark:hover:text-indigo-300 font-medium"
                    >
                      {scan.config_name || 'Unknown Config'}
                    </Link>
                    <span className="text-gray-500 dark:text-gray-400 text-sm ml-2">
                      Run #{scan.run_number}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${colors.bg} ${colors.text}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    {scan.total_open_ports}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    {scan.total_vulnerabilities}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {formatDistanceToNow(parseUTC(scan.created_at), { addSuffix: true })}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="px-6 py-3 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
        <Link
          to="/scans"
          className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-900 dark:hover:text-indigo-300"
        >
          View all scans →
        </Link>
      </div>
    </div>
  );
}

function QuickActions() {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Quick Actions</h3>
      <div className="space-y-3">
        <Link
          to="/scans/new"
          className="flex items-center px-4 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
        >
          <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Scan
        </Link>
        <Link
          to="/configs"
          className="flex items-center px-4 py-3 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
        >
          <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          Manage Configs
        </Link>
        <Link
          to="/scheduled-scans"
          className="flex items-center px-4 py-3 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
        >
          <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Scheduled Scans
        </Link>
      </div>
    </div>
  );
}

function TopVulnerableHosts({ hosts }: { hosts: DashboardStats['top_vulnerable_hosts'] }) {
  if (hosts.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Top Vulnerable Hosts</h3>
        <p className="text-gray-500 dark:text-gray-400 text-sm">No vulnerable hosts found</p>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Top Vulnerable Hosts</h3>
      <div className="space-y-3">
        {hosts.map((host, index) => (
          <div key={`${host.ip_address}-${index}`} className="flex items-center justify-between">
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {host.device_name || host.ip_address}
              </p>
              {host.device_name && (
                <p className="text-xs text-gray-500 dark:text-gray-400">{host.ip_address}</p>
              )}
            </div>
            <div className="flex items-center gap-2 ml-4">
              {host.critical_count > 0 && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
                  {host.critical_count} crit
                </span>
              )}
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                {host.vulnerability_count} total
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

const serviceColors: Record<string, string> = {
  http: 'bg-blue-500',
  https: 'bg-blue-600',
  ssh: 'bg-green-500',
  ftp: 'bg-yellow-500',
  mysql: 'bg-orange-500',
  postgresql: 'bg-indigo-500',
  redis: 'bg-red-500',
  mongodb: 'bg-green-600',
  smtp: 'bg-purple-500',
  dns: 'bg-cyan-500',
};

function ServicesBreakdown({ services }: { services: DashboardStats['services_breakdown'] }) {
  if (services.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Services Discovered</h3>
        <p className="text-gray-500 dark:text-gray-400 text-sm">No services discovered yet</p>
      </div>
    );
  }

  const maxCount = Math.max(...services.map(s => s.count));

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Services Discovered</h3>
      <div className="space-y-2">
        {services.map(({ service_name, count }) => {
          const percentage = maxCount > 0 ? Math.round((count / maxCount) * 100) : 0;
          const color = serviceColors[service_name.toLowerCase()] || 'bg-gray-500';
          return (
            <div key={service_name}>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-700 dark:text-gray-300">{service_name}</span>
                <span className="text-gray-500 dark:text-gray-400">{count}</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className={`${color} h-2 rounded-full transition-all`}
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ActivitySparkline({ data }: { data: DashboardStats['scans_by_day'] }) {
  // Generate last 7 days with counts (fill in zeros for missing days)
  const today = new Date();
  const days: { date: string; count: number; label: string }[] = [];

  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().split('T')[0];
    const dayData = data.find(item => item.date === dateStr);
    days.push({
      date: dateStr,
      count: dayData?.count || 0,
      label: d.toLocaleDateString('en-US', { weekday: 'short' }),
    });
  }

  const maxCount = Math.max(...days.map(d => d.count), 1);
  const totalScans = days.reduce((sum, d) => sum + d.count, 0);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white">7-Day Activity</h3>
        <span className="text-sm text-gray-500 dark:text-gray-400">{totalScans} scans</span>
      </div>
      <div className="flex items-end justify-between h-24 gap-1">
        {days.map(({ date, count, label }) => {
          const height = maxCount > 0 ? Math.max((count / maxCount) * 100, count > 0 ? 10 : 0) : 0;
          return (
            <div key={date} className="flex-1 flex flex-col items-center">
              <div className="w-full flex items-end justify-center h-16">
                <div
                  className={`w-full max-w-[24px] rounded-t transition-all ${
                    count > 0 ? 'bg-indigo-500' : 'bg-gray-200 dark:bg-gray-700'
                  }`}
                  style={{ height: `${height}%`, minHeight: count > 0 ? '4px' : '2px' }}
                  title={`${date}: ${count} scans`}
                />
              </div>
              <span className="text-xs text-gray-400 dark:text-gray-500 mt-1">{label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function Dashboard() {
  const { data: stats, isLoading, error } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: statsApi.getDashboard,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900" data-component="DashboardPage">
      <Navigation />

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 sm:px-0">
          {/* Header */}
          <div className="mb-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Overview of your security scanning activity
            </p>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
            </div>
          ) : error ? (
            <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg p-4">
              <p className="text-red-800 dark:text-red-200">Failed to load dashboard data</p>
            </div>
          ) : stats ? (
            <>
              {/* Stats Cards - Row 1 */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <StatCard
                  title="Total Scans"
                  value={stats.total_scans}
                  icon={
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                  }
                  color="bg-indigo-500"
                />
                <StatCard
                  title="Total Vulnerabilities"
                  value={stats.total_vulnerabilities}
                  icon={
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  }
                  color="bg-red-500"
                />
                <StatCard
                  title="Critical Vulns"
                  value={stats.vulnerabilities_by_severity.find(v => v.severity.toLowerCase() === 'critical')?.count || 0}
                  icon={
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  }
                  color="bg-rose-600"
                />
              </div>

              {/* Stats Cards - Row 2 */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <StatCard
                  title="Total Ports"
                  value={stats.total_ports}
                  icon={
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                  }
                  color="bg-cyan-500"
                />
                <StatCard
                  title="Scan Configs"
                  value={stats.total_configs}
                  icon={
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                  }
                  color="bg-purple-500"
                />
                <StatCard
                  title="Active Schedules"
                  value={stats.active_schedules}
                  subtitle={stats.next_scheduled_run ? `Next: ${formatDistanceToNow(parseUTC(stats.next_scheduled_run), { addSuffix: true })}` : undefined}
                  icon={
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  }
                  color="bg-green-500"
                />
              </div>

              {/* Middle Row: Status + Vulnerabilities + Quick Actions */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                <ScanStatusSummary stats={stats} />
                <VulnerabilitySummary stats={stats} />
                <QuickActions />
              </div>

              {/* Insights Row: Top Hosts + Services + Activity */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                <TopVulnerableHosts hosts={stats.top_vulnerable_hosts} />
                <ServicesBreakdown services={stats.services_breakdown} />
                <ActivitySparkline data={stats.scans_by_day} />
              </div>

              {/* Recent Scans Table */}
              <RecentScansTable scans={stats.recent_scans} />
            </>
          ) : null}
        </div>
      </main>
    </div>
  );
}
