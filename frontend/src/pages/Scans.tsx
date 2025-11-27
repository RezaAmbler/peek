import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { scansApi } from '../api/scans';
import { formatDistanceToNow } from 'date-fns';
import { Navigation } from '../components/Navigation';

const statusColors: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-800',
  queued: 'bg-yellow-100 text-yellow-800',
  running: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  cancelled: 'bg-gray-100 text-gray-800',
};

export function Scans() {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<string>('');

  const { data, isLoading } = useQuery({
    queryKey: ['scans', page, statusFilter],
    queryFn: () => scansApi.list(page, 20, statusFilter || undefined),
    refetchInterval: (query) => {
      // Auto-refresh every 3 seconds if there are running/queued scans
      const hasActiveScan = query.state.data?.scans.some(
        (scan) => scan.status === 'running' || scan.status === 'queued'
      );
      return hasActiveScan ? 3000 : false;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: scansApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });

  const startMutation = useMutation({
    mutationFn: scansApi.start,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: scansApi.cancel,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });

  const handleDelete = async (scanId: string, scanName: string) => {
    if (!confirm(`Delete scan "${scanName}"?`)) return;
    deleteMutation.mutate(scanId);
  };

  const handleStart = (scanId: string) => {
    startMutation.mutate(scanId);
  };

  const handleCancel = (scanId: string) => {
    if (!confirm('Cancel this scan?')) return;
    cancelMutation.mutate(scanId);
  };

  return (
    <div className="min-h-screen bg-gray-50" data-component="ScansPage">
      <Navigation />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
      <div className="sm:flex sm:items-center sm:justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Scans</h1>
          <p className="mt-2 text-sm text-gray-700">
            View and manage your network scans
          </p>
        </div>
        <div className="mt-4 sm:mt-0">
          <Link
            to="/scans/new"
            className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
            data-testid="new-scan-button"
          >
            New Scan
          </Link>
        </div>
      </div>

      {/* Filters */}
      <div className="mb-6">
        <label htmlFor="status-filter" className="block text-sm font-medium text-gray-700 mb-2">
          Filter by Status
        </label>
        <select
          id="status-filter"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
          className="block w-full max-w-xs rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
          data-testid="scan-filter-select"
        >
          <option value="">All Scans</option>
          <option value="pending">Pending</option>
          <option value="queued">Queued</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
      </div>

      {/* Scans Table */}
      <div className="bg-white shadow-md rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading scans...</div>
        ) : !data || data.scans.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No scans found. Create your first scan to get started.
          </div>
        ) : (
          <>
            <table className="min-w-full divide-y divide-gray-200" data-component="ScanTable">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Targets
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Open Ports
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Progress
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Created
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {data.scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-gray-50" data-component="ScanTableRow" data-testid={`scan-row-${scan.id}`}>
                    <td className="px-6 py-4">
                      <Link
                        to={`/scans/${scan.id}`}
                        className="text-sm font-medium text-indigo-600 hover:text-indigo-900"
                      >
                        {scan.name}
                      </Link>
                      {scan.description && (
                        <p className="text-sm text-gray-500 mt-1">{scan.description}</p>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex flex-col">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            statusColors[scan.status] || 'bg-gray-100 text-gray-800'
                          }`}
                          data-testid="scan-status-badge"
                        >
                          {scan.status === 'running' && (
                            <span className="w-2 h-2 bg-blue-400 rounded-full mr-1.5 animate-pulse" />
                          )}
                          {scan.status}
                        </span>
                        {(scan.status === 'running' || scan.status === 'queued') && scan.current_phase && (
                          <span className="text-xs text-gray-500 mt-1">
                            {scan.current_phase === 'nmap_discovery' && 'Discovering ports...'}
                            {scan.current_phase === 'nmap' && 'Detecting services...'}
                            {scan.current_phase === 'ssh_audit' && 'Auditing SSH...'}
                            {scan.current_phase === 'nuclei' && 'Scanning vulnerabilities...'}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <div className="flex flex-col">
                        <span>
                          {scan.completed_targets}/{scan.total_targets}
                          {scan.failed_targets > 0 && (
                            <span className="text-red-600 ml-1">({scan.failed_targets} failed)</span>
                          )}
                        </span>
                        {(scan.status === 'running' || scan.status === 'queued') && (
                          <div className="w-20 bg-gray-200 rounded-full h-1.5 mt-1">
                            <div
                              className="bg-green-500 h-1.5 rounded-full transition-all duration-300"
                              style={{ width: `${(scan.completed_targets / scan.total_targets) * 100}%` }}
                            />
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <span className={scan.status === 'running' ? 'font-semibold text-blue-600' : ''}>
                        {scan.total_open_ports}
                      </span>
                      {scan.status === 'running' && scan.total_open_ports > 0 && (
                        <span className="text-xs text-gray-400 ml-1">found</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {(scan.status === 'running' || scan.status === 'queued') && (
                        <div className="flex flex-col">
                          <div className="w-full bg-gray-200 rounded-full h-2">
                            <div
                              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                              style={{ width: `${scan.progress_percent}%` }}
                            />
                          </div>
                          <span className="text-xs text-gray-500 mt-1">
                            {Math.round(scan.progress_percent)}%
                          </span>
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
                      <Link
                        to={`/scans/${scan.id}`}
                        className="text-indigo-600 hover:text-indigo-900"
                        data-testid="scan-view-link"
                      >
                        View
                      </Link>
                      {scan.status === 'pending' && (
                        <button
                          onClick={() => handleStart(scan.id)}
                          className="text-green-600 hover:text-green-900"
                          data-testid="scan-start-button"
                        >
                          Start
                        </button>
                      )}
                      {(scan.status === 'running' || scan.status === 'queued') && (
                        <button
                          onClick={() => handleCancel(scan.id)}
                          className="text-yellow-600 hover:text-yellow-900"
                          data-testid="scan-cancel-button"
                        >
                          Cancel
                        </button>
                      )}
                      {scan.status !== 'running' && (
                        <button
                          onClick={() => handleDelete(scan.id, scan.name)}
                          className="text-red-600 hover:text-red-900"
                          data-testid="scan-delete-button"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            {data.pages > 1 && (
              <div className="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200 sm:px-6">
                <div className="flex-1 flex justify-between sm:hidden">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
                    disabled={page === data.pages}
                    className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
                <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm text-gray-700">
                      Showing page <span className="font-medium">{page}</span> of{' '}
                      <span className="font-medium">{data.pages}</span>
                    </p>
                  </div>
                  <div>
                    <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                      <button
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                        disabled={page === 1}
                        className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                      >
                        Previous
                      </button>
                      <button
                        onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
                        disabled={page === data.pages}
                        className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                      >
                        Next
                      </button>
                    </nav>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  </div>
);
}
