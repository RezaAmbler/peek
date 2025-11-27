import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import { scansApi } from '../api/scans';
import { comparisonsApi } from '../api/comparisons';
import { formatDistanceToNow, format } from 'date-fns';
import { SSHAuditCard } from '../components/SSHAuditCard';
import { VulnerabilityCard } from '../components/VulnerabilityCard';
import { useState, Fragment } from 'react';
import { Menu, Transition } from '@headlessui/react';
import { Navigation } from '../components/Navigation';

const statusColors: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-800',
  queued: 'bg-yellow-100 text-yellow-800',
  running: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  cancelled: 'bg-gray-100 text-gray-800',
  scanning: 'bg-blue-100 text-blue-800',
  timeout: 'bg-orange-100 text-orange-800',
  skipped: 'bg-gray-100 text-gray-800',
};

export function ScanDetail() {
  const { scanId } = useParams({ from: '/scans/$scanId' });
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // State for compare modal
  const [showCompareModal, setShowCompareModal] = useState(false);
  const [selectedBaseline, setSelectedBaseline] = useState<string>('');

  // State for collapsible sections
  const [showTargets, setShowTargets] = useState(false);
  const [showPorts, setShowPorts] = useState(true);
  const [showSSHAudits, setShowSSHAudits] = useState(true);
  const [showVulnerabilities, setShowVulnerabilities] = useState(true);

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId),
    refetchInterval: (query) => {
      // Auto-refresh every 3 seconds if scan is running/queued
      const status = query.state.data?.status;
      return status === 'running' || status === 'queued' ? 3000 : false;
    },
  });

  // Query for user's other scans (potential baselines)
  const { data: userScans } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list(1, 100, 'completed'),
    enabled: scan?.status === 'completed',
  });

  const { data: ports } = useQuery({
    queryKey: ['scan-ports', scanId],
    queryFn: () => scansApi.getPorts(scanId),
    enabled: !!scanId && (scan?.status === 'completed' || scan?.status === 'running'),
    refetchInterval: scan?.status === 'running' ? 5000 : false,
  });

  const { data: sshAudits } = useQuery({
    queryKey: ['scan-ssh-audits', scanId],
    queryFn: () => scansApi.getSSHAudits(scanId),
    enabled: !!scanId && scan?.status === 'completed',
  });

  const { data: vulnerabilities } = useQuery({
    queryKey: ['scan-vulnerabilities', scanId],
    queryFn: () => scansApi.getVulnerabilities(scanId),
    enabled: !!scanId && scan?.status === 'completed',
  });

  const deleteMutation = useMutation({
    mutationFn: scansApi.delete,
    onSuccess: () => {
      navigate({ to: '/scans' });
    },
  });

  const startMutation = useMutation({
    mutationFn: scansApi.start,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: scansApi.cancel,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
    },
  });

  const compareMutation = useMutation({
    mutationFn: (baselineScanId: string) => comparisonsApi.compare(baselineScanId, scanId!),
    onSuccess: (comparison) => {
      setShowCompareModal(false);
      navigate({ to: `/comparisons/${comparison.id}` });
    },
  });

  const restartMutation = useMutation({
    mutationFn: scansApi.restart,
    onSuccess: (newScan) => {
      // Navigate to the new scan
      navigate({ to: `/scans/${newScan.id}` });
    },
  });

  const handleDelete = () => {
    if (!scan) return;
    if (!confirm(`Delete scan "${scan.name}"?`)) return;
    deleteMutation.mutate(scanId);
  };

  const handleStart = () => {
    startMutation.mutate(scanId);
  };

  const handleCancel = () => {
    if (!confirm('Cancel this scan?')) return;
    cancelMutation.mutate(scanId);
  };

  const handleRestart = () => {
    if (!confirm('Restart this scan? A new scan will be created with the same targets and configuration.')) return;
    restartMutation.mutate(scanId);
  };

  const handleExport = (format: string, type: string) => {
    const token = localStorage.getItem('access_token');
    let url = '';

    if (format === 'pdf') {
      if (type === 'executive') {
        url = `http://localhost:8000/api/reports/${scanId}/pdf/executive`;
      } else if (type === 'technical') {
        url = `http://localhost:8000/api/reports/${scanId}/pdf/technical`;
      }
    } else if (format === 'html') {
      url = `http://localhost:8000/api/reports/${scanId}/html`;
    } else if (format === 'csv') {
      if (type === 'vulnerabilities') {
        url = `http://localhost:8000/api/reports/${scanId}/csv/vulnerabilities`;
      } else if (type === 'ports') {
        url = `http://localhost:8000/api/reports/${scanId}/csv/ports`;
      } else if (type === 'summary') {
        url = `http://localhost:8000/api/reports/${scanId}/csv/summary`;
      }
    }

    // Download file
    fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => response.blob())
    .then(blob => {
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `report_${scanId}.${format === 'csv' ? 'csv' : format === 'html' ? 'html' : 'pdf'}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(downloadUrl);
    })
    .catch(error => {
      console.error('Export failed:', error);
      alert('Failed to export report. Please try again.');
    });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navigation />
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-500">Loading scan details...</div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navigation />
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-500">Scan not found</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <Navigation />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex-1">
            <div className="flex items-center space-x-3">
              <h1 className="text-3xl font-bold text-gray-900">{scan.name}</h1>
              <span
                className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                  statusColors[scan.status] || 'bg-gray-100 text-gray-800'
                }`}
              >
                {scan.status}
              </span>
            </div>
            {scan.description && (
              <p className="mt-2 text-sm text-gray-600">{scan.description}</p>
            )}
          </div>
          <div className="flex space-x-2">
            {scan.status === 'completed' && (
              <>
                <button
                  onClick={() => setShowCompareModal(true)}
                  className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
                >
                  Compare with Previous Scan
                </button>

                <Menu as="div" className="relative inline-block text-left">
                  <div>
                    <Menu.Button className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700">
                      Export Report ▼
                    </Menu.Button>
                  </div>

                  <Transition
                    as={Fragment}
                    enter="transition ease-out duration-100"
                    enterFrom="transform opacity-0 scale-95"
                    enterTo="transform opacity-100 scale-100"
                    leave="transition ease-in duration-75"
                    leaveFrom="transform opacity-100 scale-100"
                    leaveTo="transform opacity-0 scale-95"
                  >
                    <Menu.Items className="absolute right-0 mt-2 w-64 origin-top-right divide-y divide-gray-100 rounded-md bg-white shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-10">
                      <div className="px-1 py-1">
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('pdf', 'executive')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              📄 PDF - Executive Summary
                            </button>
                          )}
                        </Menu.Item>
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('pdf', 'technical')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              📄 PDF - Technical Report
                            </button>
                          )}
                        </Menu.Item>
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('html', '')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              🌐 HTML Report
                            </button>
                          )}
                        </Menu.Item>
                      </div>
                      <div className="px-1 py-1">
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('csv', 'vulnerabilities')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              📊 CSV - Vulnerabilities
                            </button>
                          )}
                        </Menu.Item>
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('csv', 'ports')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              📊 CSV - Ports
                            </button>
                          )}
                        </Menu.Item>
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('csv', 'summary')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              📊 CSV - Summary
                            </button>
                          )}
                        </Menu.Item>
                      </div>
                    </Menu.Items>
                  </Transition>
                </Menu>
              </>
            )}
            {scan.status === 'pending' && (
              <>
                <button
                  onClick={() => navigate({ to: `/scans/${scanId}/edit` })}
                  className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
                >
                  Edit
                </button>
                <button
                  onClick={handleStart}
                  className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700"
                >
                  Start Scan
                </button>
              </>
            )}
            {(scan.status === 'running' || scan.status === 'queued') && (
              <button
                onClick={handleCancel}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-yellow-600 hover:bg-yellow-700"
              >
                Cancel
              </button>
            )}
            {(scan.status === 'failed' || scan.status === 'completed' || scan.status === 'cancelled') && (
              <button
                onClick={handleRestart}
                disabled={restartMutation.isPending}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
              >
                {restartMutation.isPending ? 'Restarting...' : 'Restart Scan'}
              </button>
            )}
            {scan.status !== 'running' && (
              <button
                onClick={handleDelete}
                className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              >
                Delete
              </button>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        {(scan.status === 'running' || scan.status === 'queued') && (
          <div className="mb-4">
            <div className="flex justify-between mb-1">
              <span className="text-sm font-medium text-gray-700">
                Progress: {scan.current_phase}
              </span>
              <span className="text-sm font-medium text-gray-700">
                {Math.round(scan.progress_percent)}%
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-3">
              <div
                className="bg-blue-600 h-3 rounded-full transition-all duration-500"
                style={{ width: `${scan.progress_percent}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5 mb-6">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 truncate">Total Targets</dt>
            <dd className="mt-1 text-3xl font-semibold text-gray-900">{scan.total_targets}</dd>
          </div>
        </div>
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 truncate">Completed</dt>
            <dd className="mt-1 text-3xl font-semibold text-green-600">{scan.completed_targets}</dd>
          </div>
        </div>
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 truncate">Failed</dt>
            <dd className="mt-1 text-3xl font-semibold text-red-600">{scan.failed_targets}</dd>
          </div>
        </div>
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 truncate">Open Ports</dt>
            <dd className="mt-1 text-3xl font-semibold text-blue-600">{scan.total_open_ports}</dd>
          </div>
        </div>
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 truncate">Vulnerabilities</dt>
            <dd className="mt-1 text-3xl font-semibold text-orange-600">
              {scan.total_vulnerabilities}
            </dd>
          </div>
        </div>
      </div>

      {/* Info Card */}
      <div className="bg-white shadow rounded-lg mb-6 p-6">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Scan Information</h2>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
          <div>
            <dt className="text-sm font-medium text-gray-500">Created</dt>
            <dd className="mt-1 text-sm text-gray-900">
              {format(new Date(scan.created_at), 'PPpp')} (
              {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })})
            </dd>
          </div>
          {scan.started_at && (
            <div>
              <dt className="text-sm font-medium text-gray-500">Started</dt>
              <dd className="mt-1 text-sm text-gray-900">
                {format(new Date(scan.started_at), 'PPpp')}
              </dd>
            </div>
          )}
          {scan.finished_at && (
            <div>
              <dt className="text-sm font-medium text-gray-500">Finished</dt>
              <dd className="mt-1 text-sm text-gray-900">
                {format(new Date(scan.finished_at), 'PPpp')}
              </dd>
            </div>
          )}
          {scan.started_at && scan.finished_at && (
            <div>
              <dt className="text-sm font-medium text-gray-500">Duration</dt>
              <dd className="mt-1 text-sm text-gray-900">
                {Math.round(
                  (new Date(scan.finished_at).getTime() - new Date(scan.started_at).getTime()) /
                    1000
                )}{' '}
                seconds
              </dd>
            </div>
          )}
        </dl>
      </div>

      {/* Targets Table */}
      <div className="bg-white shadow rounded-lg overflow-hidden">
        <button
          onClick={() => setShowTargets(!showTargets)}
          className="w-full px-6 py-4 border-b border-gray-200 flex items-center justify-between hover:bg-gray-50 transition-colors"
        >
          <h2 className="text-lg font-medium text-gray-900">
            Targets ({scan.targets.length})
          </h2>
          <svg
            className={`w-5 h-5 text-gray-500 transform transition-transform ${showTargets ? 'rotate-180' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {showTargets && (
          <>
            {scan.targets.length === 0 ? (
              <div className="p-8 text-center text-gray-500">No targets found</div>
            ) : (
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Device Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      IP Address
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Duration
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {scan.targets.map((target) => (
                    <tr key={target.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {target.device_name || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                        {target.ip_address}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            statusColors[target.status] || 'bg-gray-100 text-gray-800'
                          }`}
                        >
                          {target.status}
                        </span>
                        {target.error_message && (
                          <p className="text-xs text-red-600 mt-1">{target.error_message}</p>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {target.duration_seconds
                          ? `${target.duration_seconds.toFixed(1)}s`
                          : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>

      {/* Discovered Ports Table */}
      {ports && ports.length > 0 && (
        <div className="mt-6 bg-white shadow rounded-lg overflow-hidden">
          <button
            onClick={() => setShowPorts(!showPorts)}
            className="w-full px-6 py-4 border-b border-gray-200 flex items-center justify-between hover:bg-gray-50 transition-colors"
          >
            <h2 className="text-lg font-medium text-gray-900">
              Discovered Ports ({ports.length})
            </h2>
            <svg
              className={`w-5 h-5 text-gray-500 transform transition-transform ${showPorts ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showPorts && (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      IP Address
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Device
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Port
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Protocol
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Service
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Version
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      State
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Source
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {ports.map((port) => (
                    <tr key={port.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                        {port.ip_address}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {port.device_name || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono font-semibold text-gray-900">
                        {port.port}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {port.protocol}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {port.service_name || <span className="text-gray-400">-</span>}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 max-w-xs truncate" title={port.version || ''}>
                        {port.version || <span className="text-gray-400">-</span>}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                            port.state === 'open'
                              ? 'bg-green-100 text-green-800'
                              : port.state === 'filtered'
                              ? 'bg-yellow-100 text-yellow-800'
                              : 'bg-gray-100 text-gray-800'
                          }`}
                        >
                          {port.state}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                          {port.discovered_by}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* SSH Audits Section */}
      {sshAudits && sshAudits.length > 0 && (
        <div className="mt-6 bg-white shadow rounded-lg overflow-hidden">
          <button
            onClick={() => setShowSSHAudits(!showSSHAudits)}
            className="w-full px-6 py-4 border-b border-gray-200 flex items-center justify-between hover:bg-gray-50 transition-colors"
          >
            <h2 className="text-lg font-medium text-gray-900">
              SSH Security Audits ({sshAudits.length})
            </h2>
            <svg
              className={`w-5 h-5 text-gray-500 transform transition-transform ${showSSHAudits ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showSSHAudits && (
            <div className="p-6 space-y-4">
              {sshAudits.map((audit) => (
                <SSHAuditCard key={audit.id} audit={audit} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Vulnerabilities Section */}
      {scan.status === 'completed' && vulnerabilities && (
        <div className="mt-6 bg-white shadow rounded-lg overflow-hidden">
          <button
            onClick={() => setShowVulnerabilities(!showVulnerabilities)}
            className="w-full px-6 py-4 border-b border-gray-200 flex items-center justify-between hover:bg-gray-50 transition-colors"
          >
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-medium text-gray-900">
                Vulnerabilities ({vulnerabilities.length})
              </h2>
              {vulnerabilities.length === 0 && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                  None found
                </span>
              )}
            </div>
            <svg
              className={`w-5 h-5 text-gray-500 transform transition-transform ${showVulnerabilities ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showVulnerabilities && (
            <div className="p-6">
              {vulnerabilities.length > 0 ? (
                <>
                  {/* Severity counts */}
                  <div className="flex flex-wrap gap-2 mb-4">
                    {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
                      const count = vulnerabilities.filter(
                        (v) => v.severity.toLowerCase() === severity
                      ).length;
                      if (count === 0) return null;

                      const severityColors: Record<string, string> = {
                        critical: 'bg-red-700 text-white',
                        high: 'bg-orange-500 text-white',
                        medium: 'bg-yellow-500 text-white',
                        low: 'bg-blue-500 text-white',
                        info: 'bg-gray-400 text-white',
                      };

                      return (
                        <span
                          key={severity}
                          className={`px-3 py-1 text-sm font-semibold rounded ${severityColors[severity]}`}
                        >
                          {severity.toUpperCase()}: {count}
                        </span>
                      );
                    })}
                  </div>
                  <div className="space-y-4">
                    {vulnerabilities.map((vuln) => (
                      <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
                    ))}
                  </div>
                </>
              ) : (
                <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                  <div className="flex items-center">
                    <svg className="h-5 w-5 text-green-500 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="text-green-800 font-medium">No vulnerabilities detected</span>
                  </div>
                  <p className="text-green-700 text-sm mt-1 ml-7">
                    Nuclei vulnerability scanner completed successfully and found no known vulnerabilities matching its templates.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {scan?.status === 'completed' && (!ports || ports.length === 0) && (
        <div className="mt-6 bg-white shadow rounded-lg p-6">
          <p className="text-gray-500 text-center">No open ports discovered</p>
        </div>
      )}

      {/* Compare Modal */}
      {showCompareModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full">
            <h3 className="text-lg font-semibold mb-4">Select Baseline Scan</h3>
            <select
              value={selectedBaseline}
              onChange={(e) => setSelectedBaseline(e.target.value)}
              className="w-full px-3 py-2 border rounded-md mb-4"
            >
              <option value="">Select a scan to compare with...</option>
              {userScans?.scans
                .filter(s => s.id !== scanId && s.status === 'completed')
                .map(s => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
            </select>
            <div className="flex gap-3">
              <button
                onClick={() => {
                  if (selectedBaseline) {
                    compareMutation.mutate(selectedBaseline);
                  }
                }}
                disabled={!selectedBaseline || compareMutation.isPending}
                className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
              >
                {compareMutation.isPending ? 'Comparing...' : 'Compare'}
              </button>
              <button
                onClick={() => setShowCompareModal(false)}
                className="flex-1 px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  </div>
  );
}
