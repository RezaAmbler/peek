import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import axios from 'axios';
import { scansApi, SSHAudit, Vulnerability } from '../api/scans';
import { comparisonsApi } from '../api/comparisons';
import { API_BASE_URL } from '../api/client';
import { formatDistanceToNow, format } from 'date-fns';
import { SSHAuditCard } from '../components/SSHAuditCard';
import { VulnerabilityCard } from '../components/VulnerabilityCard';
import { ServiceIcon } from '../components/ServiceIcon';
import { SSLScanSection } from '../components/SSLScanSection';
import { NSEFindingsSection } from '../components/NSEFindingsSection';
import { HttpxSection } from '../components/HttpxSection';
import { DiscoveredEndpointsSection } from '../components/DiscoveredEndpointsSection';
import { TestsslResultsSection } from '../components/TestsslResultsSection';
import { useState, Fragment, useMemo } from 'react';
import { Menu, Transition } from '@headlessui/react';
import { Navigation } from '../components/Navigation';
import { parseUTC } from '../utils/date';

// Port type for sorting
interface PortData {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  protocol: string;
  service_name?: string;
  version?: string;
  state: string;
  discovered_by: string;
}

const statusColors: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
  queued: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  running: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  completed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  failed: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  cancelled: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
  scanning: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  timeout: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  skipped: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
};

export function ScanDetail() {
  const { scanId } = useParams({ from: '/scans/$scanId' });
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // State for compare modal
  const [showCompareModal, setShowCompareModal] = useState(false);
  const [selectedBaseline, setSelectedBaseline] = useState<string>('');
  const [compareError, setCompareError] = useState<string>('');

  // State for collapsible sections
  const [showTargets, setShowTargets] = useState(false);
  const [showPorts, setShowPorts] = useState(true);
  const [showSSHAudits, setShowSSHAudits] = useState(true);
  const [showVulnerabilities, setShowVulnerabilities] = useState(true);
  const [showInfoFindings, setShowInfoFindings] = useState(true);

  // State for sorting ports table
  const [sortColumn, setSortColumn] = useState<string>('ip_address');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');

  // State for host filter
  const [hostFilter, setHostFilter] = useState<string | null>(null);

  // State for severity filter (all enabled by default)
  const [activeSeverities, setActiveSeverities] = useState<Set<string>>(
    new Set(['critical', 'high', 'medium', 'low'])
  );

  // Toggle severity filter
  const toggleSeverity = (severity: string) => {
    setActiveSeverities(prev => {
      const next = new Set(prev);
      if (next.has(severity)) {
        next.delete(severity);
      } else {
        next.add(severity);
      }
      return next;
    });
  };

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId),
    refetchInterval: (query) => {
      // Auto-refresh every 3 seconds if scan is running/queued
      const status = query.state.data?.status;
      return status === 'running' || status === 'queued' ? 3000 : false;
    },
  });

  // Query for run history (comparable scans from same config)
  const { data: comparableData } = useQuery({
    queryKey: ['scan-comparable', scanId],
    queryFn: () => scansApi.getComparable(scanId),
    enabled: !!scan?.config_id,
  });

  // Combine current scan with comparable scans for full run history
  const runHistory = useMemo(() => {
    if (!scan || !comparableData) return [];

    // Create entry for current scan
    const currentEntry = {
      id: scan.id,
      name: scan.name,
      run_number: scan.run_number,
      status: scan.status,
      created_at: scan.created_at,
      total_targets: scan.total_targets,
      total_open_ports: scan.total_open_ports,
      total_vulnerabilities: scan.total_vulnerabilities,
    };

    // Combine and sort by run_number descending
    const allRuns = [currentEntry, ...comparableData.comparable_scans];
    return allRuns.sort((a, b) => b.run_number - a.run_number);
  }, [scan, comparableData]);

  // Format date for run history dropdown
  const formatRunDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

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

  const { data: nseFindings } = useQuery({
    queryKey: ['scan-nse-findings', scanId],
    queryFn: () => scansApi.getNSEFindings(scanId),
    enabled: !!scanId && scan?.status === 'completed',
  });

  const { data: sslscanResults } = useQuery({
    queryKey: ['scan-sslscan-results', scanId],
    queryFn: () => scansApi.getSSLScanResults(scanId),
    enabled: !!scanId && scan?.status === 'completed',
  });

  const { data: httpxResults } = useQuery({
    queryKey: ['scan-httpx-results', scanId],
    queryFn: () => scansApi.getHttpxResults(scanId),
    enabled: !!scanId && scan?.status === 'completed',
  });

  // State for discovered endpoints pagination
  const [endpointsPage, setEndpointsPage] = useState(1);

  const { data: discoveredEndpointsData } = useQuery({
    queryKey: ['scan-discovered-endpoints', scanId, endpointsPage],
    queryFn: () => scansApi.getDiscoveredEndpoints(scanId, endpointsPage, 100),
    enabled: !!scanId && scan?.status === 'completed',
  });

  const { data: testsslResults } = useQuery({
    queryKey: ['scan-testssl-results', scanId],
    queryFn: () => scansApi.getTestsslResults(scanId),
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
      setCompareError('');
      setShowCompareModal(false);
      navigate({ to: `/comparisons/${comparison.id}` });
    },
    onError: (error: unknown) => {
      const msg = (axios.isAxiosError(error) ? error.response?.data?.detail : undefined)
        || (error instanceof Error ? error.message : undefined)
        || 'Comparison failed. Please try again.';
      setCompareError(msg);
    },
  });

  const restartMutation = useMutation({
    mutationFn: scansApi.restart,
    onSuccess: (newScan) => {
      // Navigate to the new scan
      navigate({ to: `/scans/${newScan.id}` });
    },
  });

  // Get unique hosts from targets for filter dropdown
  const uniqueHosts = useMemo(() => {
    if (!scan?.targets) return [];
    return scan.targets.map(t => ({
      ip: t.ip_address,
      device: t.device_name
    }));
  }, [scan?.targets]);

  // Sort handler for ports table
  const handleSort = (column: string) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  // Filter and sort ports
  const filteredAndSortedPorts = useMemo(() => {
    if (!ports) return [];

    // Filter by host
    const filtered = hostFilter
      ? ports.filter((p: PortData) => p.ip_address === hostFilter)
      : ports;

    // Sort
    const sorted = [...filtered].sort((a: PortData, b: PortData) => {
      let aVal: string | number = '';
      let bVal: string | number = '';

      switch (sortColumn) {
        case 'ip_address':
          // Sort IPs numerically
          aVal = a.ip_address.split('.').map(n => n.padStart(3, '0')).join('.');
          bVal = b.ip_address.split('.').map(n => n.padStart(3, '0')).join('.');
          break;
        case 'device_name':
          aVal = (a.device_name || '').toLowerCase();
          bVal = (b.device_name || '').toLowerCase();
          break;
        case 'port':
          aVal = a.port;
          bVal = b.port;
          break;
        case 'protocol':
          aVal = a.protocol.toLowerCase();
          bVal = b.protocol.toLowerCase();
          break;
        case 'service_name':
          aVal = (a.service_name || '').toLowerCase();
          bVal = (b.service_name || '').toLowerCase();
          break;
        case 'version':
          aVal = (a.version || '').toLowerCase();
          bVal = (b.version || '').toLowerCase();
          break;
        case 'state':
          aVal = a.state.toLowerCase();
          bVal = b.state.toLowerCase();
          break;
        case 'discovered_by':
          aVal = a.discovered_by.toLowerCase();
          bVal = b.discovered_by.toLowerCase();
          break;
        default:
          aVal = a.ip_address;
          bVal = b.ip_address;
      }

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;

      // Secondary sort by port when primary values are equal
      if (sortColumn !== 'port') {
        if (a.port < b.port) return 1;
        if (a.port > b.port) return -1;
      }
      return 0;
    });

    return sorted;
  }, [ports, hostFilter, sortColumn, sortDirection]);

  // Filter SSH audits by host
  const filteredSSHAudits = useMemo(() => {
    if (!sshAudits) return [];
    if (!hostFilter) return sshAudits;
    return sshAudits.filter((audit: { ip_address?: string }) => audit.ip_address === hostFilter);
  }, [sshAudits, hostFilter]);

  // Separate vulnerabilities from info findings
  const { actualVulnerabilities, infoFindings, vulnCounts } = useMemo(() => {
    const allFindings = vulnerabilities || [];

    const vulns = allFindings.filter((v: { severity?: string }) =>
      ['critical', 'high', 'medium', 'low'].includes(v.severity?.toLowerCase() || '')
    );

    const infos = allFindings.filter((v: { severity?: string }) =>
      v.severity?.toLowerCase() === 'info'
    );

    const counts = {
      critical: vulns.filter((v: { severity?: string }) => v.severity?.toLowerCase() === 'critical').length,
      high: vulns.filter((v: { severity?: string }) => v.severity?.toLowerCase() === 'high').length,
      medium: vulns.filter((v: { severity?: string }) => v.severity?.toLowerCase() === 'medium').length,
      low: vulns.filter((v: { severity?: string }) => v.severity?.toLowerCase() === 'low').length,
    };

    return { actualVulnerabilities: vulns, infoFindings: infos, vulnCounts: counts };
  }, [vulnerabilities]);

  // Filter vulnerabilities by host AND severity
  const filteredVulnerabilities = useMemo(() => {
    let filtered = actualVulnerabilities;

    // Filter by host
    if (hostFilter) {
      filtered = filtered.filter((v: { host?: string; matched_at?: string }) =>
        v.host?.includes(hostFilter) || v.matched_at?.includes(hostFilter)
      );
    }

    // Filter by severity
    filtered = filtered.filter((v: { severity?: string }) =>
      activeSeverities.has(v.severity?.toLowerCase() || 'info')
    );

    return filtered;
  }, [actualVulnerabilities, hostFilter, activeSeverities]);

  const filteredInfoFindings = useMemo(() => {
    if (!hostFilter) return infoFindings;
    return infoFindings.filter((v: { host?: string; matched_at?: string }) =>
      v.host?.includes(hostFilter) || v.matched_at?.includes(hostFilter)
    );
  }, [infoFindings, hostFilter]);

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
        url = `${API_BASE_URL}/api/reports/${scanId}/pdf/executive`;
      } else if (type === 'technical') {
        url = `${API_BASE_URL}/api/reports/${scanId}/pdf/technical`;
      }
    } else if (format === 'html') {
      url = `${API_BASE_URL}/api/reports/${scanId}/html`;
    } else if (format === 'csv') {
      if (type === 'vulnerabilities') {
        url = `${API_BASE_URL}/api/reports/${scanId}/csv/vulnerabilities`;
      } else if (type === 'ports') {
        url = `${API_BASE_URL}/api/reports/${scanId}/csv/ports`;
      } else if (type === 'summary') {
        url = `${API_BASE_URL}/api/reports/${scanId}/csv/summary`;
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
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-500 dark:text-gray-400">Loading scan details...</div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-500 dark:text-gray-400">Scan not found</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900" data-component="ScanDetailPage">
      <Navigation />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-6" data-component="ScanHeader">
        <div className="flex items-center justify-between mb-4">
          <div className="flex-1">
            <div className="flex items-center space-x-3">
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">{scan.name}</h1>
              <span
                className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                  statusColors[scan.status] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
                }`}
              >
                {scan.status}
              </span>
              {scan.config_hash && (
                <span
                  className="inline-flex items-center px-2 py-1 rounded text-xs font-mono bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300"
                  title="Scans with the same config hash use identical scan settings and are comparable."
                  data-testid="config-hash-badge"
                >
                  config: {scan.config_hash.slice(0, 8)}
                </span>
              )}
              {/* Run History Dropdown */}
              {runHistory.length > 1 && (
                <select
                  value={scan.id}
                  onChange={(e) => navigate({ to: `/scans/${e.target.value}` })}
                  className="border border-gray-300 dark:border-gray-600 rounded-md px-3 py-1.5 text-sm bg-white dark:bg-gray-700 dark:text-white focus:ring-indigo-500 focus:border-indigo-500 cursor-pointer"
                  data-testid="run-history-select"
                >
                  {runHistory.map((run) => (
                    <option key={run.id} value={run.id}>
                      {run.id === scan.id ? '● ' : ''}Run #{run.run_number} — {formatRunDate(run.created_at)}
                    </option>
                  ))}
                </select>
              )}
            </div>
            {scan.description && (
              <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">{scan.description}</p>
            )}
          </div>
          <div className="flex space-x-2">
            {scan.status === 'completed' && (
              <>
                <button
                  onClick={() => { setCompareError(''); setShowCompareModal(true); }}
                  className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
                  data-testid="compare-scan-button"
                >
                  Compare with another scan
                </button>

                <Menu as="div" className="relative inline-block text-left">
                  <div>
                    <Menu.Button className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700" data-testid="export-report-button">
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
                    <Menu.Items className="absolute right-0 mt-2 w-64 origin-top-right divide-y divide-gray-100 dark:divide-gray-700 rounded-md bg-white dark:bg-gray-800 shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-10">
                      <div className="px-1 py-1">
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('pdf', 'executive')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900 dark:text-gray-100'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              PDF - Executive Summary
                            </button>
                          )}
                        </Menu.Item>
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('pdf', 'technical')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900 dark:text-gray-100'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              PDF - Technical Report
                            </button>
                          )}
                        </Menu.Item>
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('html', '')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900 dark:text-gray-100'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              HTML Report
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
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900 dark:text-gray-100'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              CSV - Vulnerabilities
                            </button>
                          )}
                        </Menu.Item>
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('csv', 'ports')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900 dark:text-gray-100'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              CSV - Ports
                            </button>
                          )}
                        </Menu.Item>
                        <Menu.Item>
                          {({ active }) => (
                            <button
                              onClick={() => handleExport('csv', 'summary')}
                              className={`${
                                active ? 'bg-indigo-500 text-white' : 'text-gray-900 dark:text-gray-100'
                              } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                            >
                              CSV - Summary
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
                  className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
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
                data-testid="cancel-scan-button"
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
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                data-testid="delete-scan-button"
              >
                Delete
              </button>
            )}
          </div>
        </div>

        {/* Progress Bar and Phase Indicator */}
        {(scan.status === 'running' || scan.status === 'queued') && (
          <div className="mb-4">
            {/* Simplified 3-Phase Stepper */}
            <div className="flex items-center justify-between mb-4">
              {(() => {
                const uiPhases = [
                  { id: 1, label: 'Discovery', backendPhases: ['nmap_discovery'] },
                  { id: 2, label: 'Enumeration', backendPhases: ['nmap'] },
                  { id: 3, label: 'Security Analysis', backendPhases: ['ssh_audit', 'nuclei', 'nse', 'sslscan', 'nikto', 'zap'] },
                ];

                // Map backend phase to UI phase number
                const getCurrentUIPhase = (backendPhase: string): number => {
                  if (['pending'].includes(backendPhase)) return 0;
                  if (['nmap_discovery'].includes(backendPhase)) return 1;
                  if (['nmap'].includes(backendPhase)) return 2;
                  if (['ssh_audit', 'nuclei', 'nse', 'sslscan', 'nikto', 'zap'].includes(backendPhase)) return 3;
                  if (['completed'].includes(backendPhase)) return 4;
                  return 1;
                };

                const currentUIPhase = getCurrentUIPhase(scan.current_phase);

                return uiPhases.map((phase, index, arr) => {
                  const isComplete = phase.id < currentUIPhase;
                  const isCurrent = phase.id === currentUIPhase;

                  return (
                    <div key={phase.id} className="flex items-center flex-1">
                      <div className="flex flex-col items-center">
                        <div
                          className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold ${
                            isComplete
                              ? 'bg-green-500 text-white'
                              : isCurrent
                              ? 'bg-blue-600 text-white animate-pulse'
                              : 'bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400'
                          }`}
                        >
                          {isComplete ? (
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                          ) : (
                            phase.id
                          )}
                        </div>
                        <span
                          className={`mt-1 text-xs font-medium ${
                            isCurrent ? 'text-blue-600 dark:text-blue-400' : isComplete ? 'text-green-600 dark:text-green-400' : 'text-gray-500 dark:text-gray-400'
                          }`}
                        >
                          {phase.label}
                        </span>
                      </div>
                      {index < arr.length - 1 && (
                        <div
                          className={`flex-1 h-1 mx-2 rounded ${
                            phase.id < currentUIPhase ? 'bg-green-500' : 'bg-gray-200 dark:bg-gray-700'
                          }`}
                        />
                      )}
                    </div>
                  );
                });
              })()}
            </div>

            {/* Current Tool Indicator */}
            {scan.status === 'running' && (
              <div className="flex items-center justify-center mb-4 text-sm text-gray-600 dark:text-gray-400">
                <svg className="animate-spin h-4 w-4 mr-2 text-blue-500" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                <span>
                  Running: <strong className="text-gray-800 dark:text-gray-200">
                    {(() => {
                      const toolNames: Record<string, string> = {
                        pending: 'Initializing...',
                        nmap_discovery: 'Port Discovery',
                        nmap: 'Service Enumeration',
                        ssh_audit: 'SSH Audit',
                        nuclei: 'Nuclei Vulnerability Scan',
                        nse: 'NSE Scripts',
                        sslscan: 'SSL/TLS Analysis',
                        nikto: 'Nikto Web Scan',
                        zap: 'OWASP ZAP',
                      };
                      return toolNames[scan.current_phase] || scan.current_phase;
                    })()}
                  </strong>
                </span>
              </div>
            )}

            {/* Progress Bar */}
            <div className="flex justify-between mb-1">
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                {scan.completed_targets} of {scan.total_targets} targets completed
              </span>
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                {Math.round(scan.progress_percent * 100)}%
              </span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
              <div
                className="bg-blue-600 h-3 rounded-full transition-all duration-500"
                style={{ width: `${scan.progress_percent * 100}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5 mb-6" data-component="ScanSummaryCards">
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Total Targets</dt>
            <dd className="mt-1 text-3xl font-semibold text-gray-900 dark:text-white">{scan.total_targets}</dd>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Completed</dt>
            <dd className="mt-1 text-3xl font-semibold text-green-600 dark:text-green-400">{scan.completed_targets}</dd>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Failed</dt>
            <dd className="mt-1 text-3xl font-semibold text-red-600 dark:text-red-400">{scan.failed_targets}</dd>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Open Ports</dt>
            <dd className="mt-1 text-3xl font-semibold text-blue-600 dark:text-blue-400">{scan.total_open_ports}</dd>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Vulnerabilities</dt>
            <dd className="mt-1 text-3xl font-semibold text-orange-600 dark:text-orange-400">
              {scan.total_vulnerabilities}
            </dd>
          </div>
        </div>
      </div>

      {/* Info Card */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg mb-6 p-6">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Scan Information</h2>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Created</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100">
              {format(parseUTC(scan.created_at), 'PPpp')} (
              {formatDistanceToNow(parseUTC(scan.created_at), { addSuffix: true })})
            </dd>
          </div>
          {scan.started_at && (
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Started</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100">
                {format(parseUTC(scan.started_at), 'PPpp')}
              </dd>
            </div>
          )}
          {scan.finished_at && (
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Finished</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100">
                {format(parseUTC(scan.finished_at), 'PPpp')}
              </dd>
            </div>
          )}
          {scan.started_at && scan.finished_at && (
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Duration</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100">
                {Math.round(
                  (parseUTC(scan.finished_at).getTime() - parseUTC(scan.started_at).getTime()) /
                    1000
                )}{' '}
                seconds
              </dd>
            </div>
          )}
        </dl>
      </div>

      {/* Targets Table */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="ScanTargetsSection">
        <button
          onClick={() => setShowTargets(!showTargets)}
          className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
        >
          <h2 className="text-lg font-medium text-gray-900 dark:text-white">
            Targets ({scan.targets.length})
          </h2>
          <svg
            className={`w-5 h-5 text-gray-500 dark:text-gray-400 transform transition-transform ${showTargets ? 'rotate-180' : ''}`}
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
              <div className="p-8 text-center text-gray-500 dark:text-gray-400">No targets found</div>
            ) : (
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Device Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      IP Address
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Duration
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {scan.targets.map((target) => (
                    <tr key={target.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                        {target.device_name || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-gray-100">
                        {target.ip_address}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            statusColors[target.status] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
                          }`}
                        >
                          {target.status}
                        </span>
                        {target.error_message && (
                          <p className="text-xs text-red-600 dark:text-red-400 mt-1">{target.error_message}</p>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
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

      {/* Host Filter */}
      {ports && ports.length > 0 && (
        <div className="mt-6 flex items-center gap-3 flex-wrap" data-component="HostFilter">
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filter by host:</span>
          <select
            value={hostFilter || ''}
            onChange={(e) => setHostFilter(e.target.value || null)}
            className="border border-gray-300 dark:border-gray-600 rounded-md px-3 py-1.5 text-sm focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
            data-testid="host-filter-select"
          >
            <option value="">All Hosts ({uniqueHosts.length})</option>
            {uniqueHosts.map(host => (
              <option key={host.ip} value={host.ip}>
                {host.ip} {host.device ? `(${host.device})` : ''}
              </option>
            ))}
          </select>

          {hostFilter && (
            <button
              onClick={() => setHostFilter(null)}
              className="text-sm text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 flex items-center gap-1"
              data-testid="clear-host-filter"
            >
              <span>x</span> Clear filter
            </button>
          )}

          {hostFilter && (
            <span className="text-sm text-gray-500 dark:text-gray-400">
              Showing {filteredAndSortedPorts.length} of {ports.length} ports
            </span>
          )}
        </div>
      )}

      {/* Discovered Ports Table */}
      {ports && ports.length > 0 && (
        <div className="mt-4 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="ScanPortsSection">
          <button
            onClick={() => setShowPorts(!showPorts)}
            className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <h2 className="text-lg font-medium text-gray-900 dark:text-white">
              Discovered Ports ({hostFilter ? `${filteredAndSortedPorts.length} of ${ports.length}` : ports.length})
            </h2>
            <svg
              className={`w-5 h-5 text-gray-500 dark:text-gray-400 transform transition-transform ${showPorts ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showPorts && (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 select-none"
                      onClick={() => handleSort('ip_address')}
                      data-testid="sort-header-ip_address"
                    >
                      <div className="flex items-center gap-1">
                        IP Address
                        {sortColumn === 'ip_address' && (
                          <span className="text-indigo-600 dark:text-indigo-400">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                    <th
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 select-none"
                      onClick={() => handleSort('device_name')}
                      data-testid="sort-header-device_name"
                    >
                      <div className="flex items-center gap-1">
                        Device
                        {sortColumn === 'device_name' && (
                          <span className="text-indigo-600 dark:text-indigo-400">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                    <th
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 select-none"
                      onClick={() => handleSort('port')}
                      data-testid="sort-header-port"
                    >
                      <div className="flex items-center gap-1">
                        Port
                        {sortColumn === 'port' && (
                          <span className="text-indigo-600 dark:text-indigo-400">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                    <th
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 select-none"
                      onClick={() => handleSort('protocol')}
                      data-testid="sort-header-protocol"
                    >
                      <div className="flex items-center gap-1">
                        Protocol
                        {sortColumn === 'protocol' && (
                          <span className="text-indigo-600 dark:text-indigo-400">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                    <th
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 select-none"
                      onClick={() => handleSort('service_name')}
                      data-testid="sort-header-service_name"
                    >
                      <div className="flex items-center gap-1">
                        Service
                        {sortColumn === 'service_name' && (
                          <span className="text-indigo-600 dark:text-indigo-400">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                    <th className="w-10 px-2 py-3"></th>
                    <th
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 select-none"
                      onClick={() => handleSort('version')}
                      data-testid="sort-header-version"
                    >
                      <div className="flex items-center gap-1">
                        Version
                        {sortColumn === 'version' && (
                          <span className="text-indigo-600 dark:text-indigo-400">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                    <th
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 select-none"
                      onClick={() => handleSort('state')}
                      data-testid="sort-header-state"
                    >
                      <div className="flex items-center gap-1">
                        State
                        {sortColumn === 'state' && (
                          <span className="text-indigo-600 dark:text-indigo-400">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                    <th
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 select-none"
                      onClick={() => handleSort('discovered_by')}
                      data-testid="sort-header-discovered_by"
                    >
                      <div className="flex items-center gap-1">
                        Source
                        {sortColumn === 'discovered_by' && (
                          <span className="text-indigo-600 dark:text-indigo-400">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {filteredAndSortedPorts.map((port: PortData) => (
                    <tr key={port.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-gray-100">
                        {port.ip_address}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {port.device_name || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono font-semibold text-gray-900 dark:text-gray-100">
                        {port.port}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {port.protocol}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                        {port.service_name || <span className="text-gray-400 dark:text-gray-500">-</span>}
                      </td>
                      <td className="px-2 py-4 text-center">
                        {port.service_name && (
                          <ServiceIcon
                            service={port.service_name}
                            version={port.version}
                            size={18}
                          />
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 max-w-xs truncate" title={port.version || ''}>
                        {port.version || <span className="text-gray-400 dark:text-gray-500">-</span>}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                            port.state === 'open'
                              ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                              : port.state === 'filtered'
                              ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                              : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
                          }`}
                        >
                          {port.state}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
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
        <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="ScanSSHAuditSection">
          <button
            onClick={() => setShowSSHAudits(!showSSHAudits)}
            className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <h2 className="text-lg font-medium text-gray-900 dark:text-white">
              SSH Security Audits ({hostFilter ? `${filteredSSHAudits.length} of ${sshAudits.length}` : sshAudits.length})
            </h2>
            <svg
              className={`w-5 h-5 text-gray-500 dark:text-gray-400 transform transition-transform ${showSSHAudits ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showSSHAudits && (
            <div className="p-6 space-y-4">
              {filteredSSHAudits.length > 0 ? (
                filteredSSHAudits.map((audit: SSHAudit) => (
                  <SSHAuditCard key={audit.id} audit={audit} />
                ))
              ) : (
                <p className="text-gray-500 dark:text-gray-400 text-center py-4">No SSH audits for selected host</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* SSL/TLS Analysis Section */}
      {sslscanResults && sslscanResults.length > 0 && (
        <SSLScanSection results={sslscanResults} hostFilter={hostFilter} />
      )}

      {/* HTTP Probe Results Section */}
      {httpxResults && httpxResults.length > 0 && (
        <HttpxSection results={httpxResults} hostFilter={hostFilter} />
      )}

      {/* Deep TLS Analysis (testssl.sh) Section */}
      {testsslResults && testsslResults.length > 0 && (
        <TestsslResultsSection results={testsslResults} hostFilter={hostFilter} />
      )}

      {/* NSE Script Results Section */}
      {nseFindings && nseFindings.length > 0 && (
        <NSEFindingsSection findings={nseFindings} hostFilter={hostFilter} />
      )}

      {/* Discovered Endpoints (Katana) Section */}
      {discoveredEndpointsData && discoveredEndpointsData.total > 0 && (
        <DiscoveredEndpointsSection
          endpoints={discoveredEndpointsData.endpoints}
          hostFilter={hostFilter}
          total={discoveredEndpointsData.total}
          page={discoveredEndpointsData.page}
          pages={discoveredEndpointsData.pages}
          onPageChange={setEndpointsPage}
        />
      )}

      {/* Vulnerabilities Section (non-INFO only) */}
      {scan.status === 'completed' && vulnerabilities && (
        <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="ScanVulnerabilitiesSection" data-testid="vulnerabilities-section">
          <button
            onClick={() => setShowVulnerabilities(!showVulnerabilities)}
            className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-medium text-gray-900 dark:text-white">
                Vulnerabilities ({hostFilter ? `${filteredVulnerabilities.length} of ${actualVulnerabilities.length}` : actualVulnerabilities.length})
              </h2>
              {actualVulnerabilities.length === 0 && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                  None found
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {/* Clickable severity filter badges */}
              {vulnCounts.critical > 0 && (
                <button
                  onClick={(e) => { e.stopPropagation(); toggleSeverity('critical'); }}
                  className={`px-2 py-0.5 text-xs font-semibold rounded transition-all cursor-pointer ${
                    activeSeverities.has('critical')
                      ? 'bg-red-700 text-white'
                      : 'bg-red-100 text-red-700 border border-red-300 dark:bg-red-900/30 dark:text-red-400 dark:border-red-700'
                  }`}
                  title={`${activeSeverities.has('critical') ? 'Hide' : 'Show'} critical vulnerabilities`}
                  data-testid="filter-critical"
                >
                  CRITICAL: {vulnCounts.critical}
                </button>
              )}
              {vulnCounts.high > 0 && (
                <button
                  onClick={(e) => { e.stopPropagation(); toggleSeverity('high'); }}
                  className={`px-2 py-0.5 text-xs font-semibold rounded transition-all cursor-pointer ${
                    activeSeverities.has('high')
                      ? 'bg-orange-500 text-white'
                      : 'bg-orange-100 text-orange-700 border border-orange-300 dark:bg-orange-900/30 dark:text-orange-400 dark:border-orange-700'
                  }`}
                  title={`${activeSeverities.has('high') ? 'Hide' : 'Show'} high vulnerabilities`}
                  data-testid="filter-high"
                >
                  HIGH: {vulnCounts.high}
                </button>
              )}
              {vulnCounts.medium > 0 && (
                <button
                  onClick={(e) => { e.stopPropagation(); toggleSeverity('medium'); }}
                  className={`px-2 py-0.5 text-xs font-semibold rounded transition-all cursor-pointer ${
                    activeSeverities.has('medium')
                      ? 'bg-yellow-500 text-white'
                      : 'bg-yellow-100 text-yellow-700 border border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-700'
                  }`}
                  title={`${activeSeverities.has('medium') ? 'Hide' : 'Show'} medium vulnerabilities`}
                  data-testid="filter-medium"
                >
                  MEDIUM: {vulnCounts.medium}
                </button>
              )}
              {vulnCounts.low > 0 && (
                <button
                  onClick={(e) => { e.stopPropagation(); toggleSeverity('low'); }}
                  className={`px-2 py-0.5 text-xs font-semibold rounded transition-all cursor-pointer ${
                    activeSeverities.has('low')
                      ? 'bg-blue-500 text-white'
                      : 'bg-blue-100 text-blue-700 border border-blue-300 dark:bg-blue-900/30 dark:text-blue-400 dark:border-blue-700'
                  }`}
                  title={`${activeSeverities.has('low') ? 'Hide' : 'Show'} low vulnerabilities`}
                  data-testid="filter-low"
                >
                  LOW: {vulnCounts.low}
                </button>
              )}
              <svg
                className={`w-5 h-5 text-gray-500 dark:text-gray-400 transform transition-transform ${showVulnerabilities ? 'rotate-180' : ''}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </button>
          {showVulnerabilities && (
            <div className="p-6">
              {/* Filter status indicator */}
              {activeSeverities.size < 4 && actualVulnerabilities.length > 0 && (
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                  Showing {filteredVulnerabilities.length} of {actualVulnerabilities.length} vulnerabilities
                  {hostFilter && ' (filtered by host)'}
                </p>
              )}
              {filteredVulnerabilities.length > 0 ? (
                <div className="space-y-4">
                  {filteredVulnerabilities.map((vuln: Vulnerability) => (
                    <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
                  ))}
                </div>
              ) : actualVulnerabilities.length > 0 && (hostFilter || activeSeverities.size < 4) ? (
                <p className="text-gray-500 dark:text-gray-400 text-center py-4">
                  No vulnerabilities match current filters
                  {activeSeverities.size < 4 && ' (click severity badges to adjust)'}
                </p>
              ) : (
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                  <div className="flex items-center">
                    <svg className="h-5 w-5 text-green-500 dark:text-green-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="text-green-800 dark:text-green-200 font-medium">No vulnerabilities found</span>
                  </div>
                  <p className="text-green-700 dark:text-green-300 text-sm mt-1 ml-7">
                    No critical, high, medium, or low severity vulnerabilities were detected.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Informational Findings Section (INFO severity only) */}
      {scan.status === 'completed' && infoFindings.length > 0 && (
        <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700" data-component="ScanInfoFindingsSection" data-testid="info-findings-section">
          <button
            onClick={() => setShowInfoFindings(!showInfoFindings)}
            className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-medium text-gray-600 dark:text-gray-300">
                Informational Findings ({hostFilter ? `${filteredInfoFindings.length} of ${infoFindings.length}` : infoFindings.length})
              </h2>
              <span className="text-sm text-gray-500 dark:text-gray-400">
                Discovery and detection information
              </span>
            </div>
            <svg
              className={`w-5 h-5 text-gray-500 dark:text-gray-400 transform transition-transform ${showInfoFindings ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showInfoFindings && (
            <div className="p-6">
              {filteredInfoFindings.length > 0 ? (
                <div className="space-y-3">
                  {filteredInfoFindings.length > 10 && (
                    <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">
                      Showing {filteredInfoFindings.length} informational findings
                    </p>
                  )}
                  {filteredInfoFindings.map((finding: { id: string; name?: string; template_id?: string; matched_at?: string; host?: string }) => (
                    <div
                      key={finding.id}
                      className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-gray-50 dark:bg-gray-700"
                      data-component="InfoFindingCard"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 text-xs font-medium rounded bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200">
                              INFO
                            </span>
                            <h4 className="font-medium text-gray-800 dark:text-gray-100">{finding.name || finding.template_id}</h4>
                          </div>
                          {finding.matched_at && (
                            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 font-mono">{finding.matched_at}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500 dark:text-gray-400 text-center py-4">No informational findings for selected host</p>
              )}
            </div>
          )}
        </div>
      )}

      {scan?.status === 'completed' && (!ports || ports.length === 0) && (
        <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <p className="text-gray-500 dark:text-gray-400 text-center">No open ports discovered</p>
        </div>
      )}

      {/* Compare Modal */}
      {showCompareModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Select scan to compare against</h3>
            {(!comparableData?.comparable_scans || comparableData.comparable_scans.length === 0) ? (
              <>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                  No comparable scans yet — run this configuration again to enable comparison.
                </p>
                <button
                  onClick={() => setShowCompareModal(false)}
                  className="w-full px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600"
                >
                  Close
                </button>
              </>
            ) : (
              <>
                <select
                  value={selectedBaseline}
                  onChange={(e) => setSelectedBaseline(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md mb-4 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                  <option value="">Select a scan...</option>
                  {comparableData.comparable_scans.map(s => (
                    <option key={s.id} value={s.id}>
                      Run #{s.run_number} — {formatRunDate(s.created_at)}
                    </option>
                  ))}
                </select>
                {compareError && (
                  <div className="mb-4 p-2 bg-red-50 dark:bg-red-900 text-red-700 dark:text-red-200 rounded text-sm">
                    {compareError}
                  </div>
                )}
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
                    className="flex-1 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600"
                  >
                    Cancel
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  </div>
  );
}
