import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  configsApi,
  ScanConfig,
  ScanMode,
  getTimeoutRange,
  isTimeoutValid,
  clampTimeout,
  formatDuration,
} from '../api/configs';
import { Navigation } from '../components/Navigation';
import toast from 'react-hot-toast';

export function Configs() {
  const queryClient = useQueryClient();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingConfig, setEditingConfig] = useState<ScanConfig | null>(null);
  const [editingTargets, setEditingTargets] = useState<string>('');
  // Controlled form state for timeout validation
  const [editingScanMode, setEditingScanMode] = useState<ScanMode>('deep');
  const [editingTimeout, setEditingTimeout] = useState<number>(3600);
  const [timeoutWasAdjusted, setTimeoutWasAdjusted] = useState(false);

  // Initialize controlled state when editingConfig changes
  useEffect(() => {
    if (editingConfig) {
      setEditingScanMode(editingConfig.scan_mode as ScanMode);
      setEditingTimeout(editingConfig.host_timeout_seconds);
      setTimeoutWasAdjusted(false);
    }
  }, [editingConfig]);

  // Clamp timeout when scan mode changes
  const handleScanModeChange = (newMode: ScanMode) => {
    setEditingScanMode(newMode);
    const clamped = clampTimeout(newMode, editingTimeout);
    if (clamped !== editingTimeout) {
      setEditingTimeout(clamped);
      setTimeoutWasAdjusted(true);
      toast(`Timeout adjusted to ${formatDuration(clamped)} for ${newMode} mode`, { icon: 'ℹ️' });
    } else {
      setTimeoutWasAdjusted(false);
    }
  };

  // Reset timeout to center value for current mode
  const handleResetTimeout = () => {
    const { center } = getTimeoutRange(editingScanMode);
    setEditingTimeout(center);
    setTimeoutWasAdjusted(false);
  };

  // Fetch configs
  const { data, isLoading } = useQuery({
    queryKey: ['configs'],
    queryFn: () => configsApi.list(),
  });

  // Set default mutation
  const setDefaultMutation = useMutation({
    mutationFn: (configId: string) => configsApi.setDefault(configId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['configs'] });
      toast.success('Default configuration updated');
    },
    onError: () => {
      toast.error('Failed to set default configuration');
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (configId: string) => configsApi.delete(configId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['configs'] });
      toast.success('Configuration deleted');
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : 'Failed to delete configuration';
      toast.error(message);
    },
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (config: { name: string; description?: string }) =>
      configsApi.create({
        name: config.name,
        description: config.description || '',
        scan_mode: 'deep',
        enable_nuclei: true,
        enable_ssh_audit: true,
        enable_nse: true,
        enable_sslscan: true,
        enable_nikto: true,
        enable_zap: true,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['configs'] });
      setShowCreateForm(false);
      toast.success('Configuration created');
    },
    onError: () => {
      toast.error('Failed to create configuration');
    },
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ScanConfig> }) =>
      configsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['configs'] });
      setEditingConfig(null);
      setEditingTargets('');
      toast.success('Configuration updated');
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : 'Failed to update configuration';
      toast.error(message);
    },
  });

  // Clone mutation (for presets)
  const cloneMutation = useMutation({
    mutationFn: (config: ScanConfig) =>
      configsApi.create({
        name: `${config.name} (Copy)`,
        description: config.description,
        targets: config.targets,
        scan_mode: config.scan_mode,
        enable_nuclei: config.enable_nuclei,
        enable_nuclei_endpoints: config.enable_nuclei_endpoints,
        enable_ssh_audit: config.enable_ssh_audit,
        enable_nse: config.enable_nse,
        enable_sslscan: config.enable_sslscan,
        enable_testssl: config.enable_testssl,
        enable_nikto: config.enable_nikto,
        enable_zap: config.enable_zap,
        enable_httpx: config.enable_httpx,
        enable_katana: config.enable_katana,
        katana_max_depth: config.katana_max_depth,
        nuclei_severity: config.nuclei_severity,
        nuclei_timeout: config.nuclei_timeout,
        zap_timeout: config.zap_timeout,
        nikto_timeout: config.nikto_timeout,
        max_concurrent_hosts: config.max_concurrent_hosts,
        host_timeout_seconds: config.host_timeout_seconds,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['configs'] });
      setEditingConfig(null);
      setEditingTargets('');
      toast.success('Configuration cloned successfully');
    },
    onError: () => {
      toast.error('Failed to clone configuration');
    },
  });

  const handleDelete = (config: ScanConfig) => {
    if (config.is_preset) {
      toast.error('Preset configurations cannot be deleted');
      return;
    }
    if (window.confirm(`Are you sure you want to delete "${config.name}"?`)) {
      deleteMutation.mutate(config.id);
    }
  };

  const handleClone = (config: ScanConfig) => {
    cloneMutation.mutate(config);
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString();
  };

  // Count enabled tools
  const countEnabledTools = (config: ScanConfig) => {
    let count = 0;
    if (config.enable_nuclei) count++;
    if (config.enable_nuclei_endpoints) count++;
    if (config.enable_ssh_audit) count++;
    if (config.enable_nse) count++;
    if (config.enable_sslscan) count++;
    if (config.enable_testssl) count++;
    if (config.enable_nikto) count++;
    if (config.enable_zap) count++;
    if (config.enable_katana) count++;
    return count;
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="flex items-center justify-center min-h-[calc(100vh-4rem)]">
          <div className="text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
            <p className="mt-2 text-gray-600 dark:text-gray-400">Loading configurations...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900" data-component="ConfigsPage">
      <Navigation />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Scan Configurations</h1>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
              Manage scanning parameters and tool settings
            </p>
          </div>
          <button
            onClick={() => setShowCreateForm(true)}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 dark:focus:ring-offset-gray-900"
            data-testid="new-config-button"
          >
            New Configuration
          </button>
        </div>
      </div>

      {/* Create Form */}
      {showCreateForm && (
        <div className="mb-6 bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h3 className="text-lg font-medium mb-4 text-gray-900 dark:text-white">Create New Configuration</h3>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const formData = new FormData(e.currentTarget);
              const name = formData.get('name') as string;
              if (name) createMutation.mutate({ name });
            }}
            className="flex gap-4"
          >
            <input
              type="text"
              name="name"
              placeholder="Configuration name"
              required
              className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700"
              disabled={createMutation.isPending}
            >
              {createMutation.isPending ? 'Creating...' : 'Create'}
            </button>
            <button
              type="button"
              onClick={() => setShowCreateForm(false)}
              className="px-4 py-2 bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200 rounded-md hover:bg-gray-300 dark:hover:bg-gray-500"
            >
              Cancel
            </button>
          </form>
        </div>
      )}

      {/* Configs Grid */}
      {data?.configs.length === 0 ? (
        <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg shadow">
          <p className="text-gray-600 dark:text-gray-400">No configurations found. Create one to get started!</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" data-component="ConfigCardList">
          {data?.configs.map((config) => (
            <div
              key={config.id}
              className={`bg-white dark:bg-gray-800 rounded-lg shadow hover:shadow-lg transition-shadow ${config.is_preset ? 'border-2 border-indigo-200 dark:border-indigo-700' : ''}`}
              data-component="ConfigCard"
              data-testid={`config-card-${config.id}`}
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {config.name}
                    </h3>
                    <div className="flex gap-2 mt-1 flex-wrap">
                      {config.is_preset && (
                        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded bg-indigo-100 dark:bg-indigo-900 text-indigo-800 dark:text-indigo-200">
                          SYSTEM PRESET
                        </span>
                      )}
                      {config.is_default && (
                        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">
                          DEFAULT
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4 line-clamp-2">
                  {config.description || 'No description'}
                </p>

                {/* Config Summary */}
                <div className="text-xs text-gray-500 dark:text-gray-400 space-y-1 mb-4 bg-gray-50 dark:bg-gray-700 p-3 rounded">
                  <div className="flex justify-between">
                    <span>Targets:</span>
                    <span className={`font-medium ${config.targets?.length > 0 ? 'text-green-600 dark:text-green-400' : 'text-gray-400 dark:text-gray-500'}`}>
                      {config.targets?.length || 0} configured
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Scan Mode:</span>
                    <span className={`font-medium ${config.scan_mode === 'deep' ? 'text-indigo-600 dark:text-indigo-400' : 'text-amber-600 dark:text-amber-400'}`}>
                      {config.scan_mode === 'deep' ? 'Deep (All Ports)' : 'Fast (Top 1000)'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Enabled Tools:</span>
                    <span className="font-medium">{countEnabledTools(config)} / 9</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Concurrent Hosts:</span>
                    <span className="font-medium">{config.max_concurrent_hosts}</span>
                  </div>
                </div>

                {/* Tool Status Pills */}
                <div className="flex flex-wrap gap-1 mb-4">
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_nuclei ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'}`}>
                    Nuclei
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_nse ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'}`}>
                    NSE
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_katana ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'}`}>
                    Katana
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_nikto ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'}`}>
                    Nikto
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_zap ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'}`}>
                    ZAP
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_ssh_audit ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'}`}>
                    SSH
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_sslscan ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'}`}>
                    SSL
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_testssl ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'}`}>
                    testssl
                  </span>
                </div>

                <div className="text-xs text-gray-400 dark:text-gray-500 mb-4">
                  Created {formatDate(config.created_at)}
                </div>

                {/* Actions */}
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setEditingConfig(config);
                      setEditingTargets(config.targets?.join('\n') || '');
                    }}
                    className="flex-1 px-3 py-2 text-sm bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-300 rounded hover:bg-indigo-200 dark:hover:bg-indigo-800"
                    data-testid="config-edit-button"
                  >
                    {config.is_preset ? 'View' : 'Edit'}
                  </button>
                  {config.is_preset ? (
                    <button
                      onClick={() => handleClone(config)}
                      className="flex-1 px-3 py-2 text-sm bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded hover:bg-green-200 dark:hover:bg-green-800"
                      disabled={cloneMutation.isPending}
                      data-testid="config-clone-button"
                    >
                      Clone
                    </button>
                  ) : (
                    <>
                      {!config.is_default && (
                        <button
                          onClick={() => setDefaultMutation.mutate(config.id)}
                          className="flex-1 px-3 py-2 text-sm bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded hover:bg-blue-200 dark:hover:bg-blue-800"
                          disabled={setDefaultMutation.isPending}
                          data-testid="config-set-default-button"
                        >
                          Set Default
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(config)}
                        className="px-3 py-2 text-sm bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded hover:bg-red-200 dark:hover:bg-red-800"
                        disabled={deleteMutation.isPending}
                        data-testid="config-delete-button"
                      >
                        Delete
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Edit Modal */}
      {editingConfig && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4" data-component="ConfigEditModal">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                {editingConfig.is_preset ? 'View Preset: ' : 'Edit Configuration: '}
                {editingConfig.name}
              </h3>
              {editingConfig.is_preset && (
                <span className="inline-flex items-center px-3 py-1 text-sm font-medium rounded bg-indigo-100 dark:bg-indigo-900 text-indigo-800 dark:text-indigo-200">
                  SYSTEM PRESET
                </span>
              )}
            </div>

            {editingConfig.is_preset && (
              <div className="mb-4 p-3 bg-amber-50 dark:bg-amber-900/30 border border-amber-200 dark:border-amber-700 rounded-md">
                <p className="text-sm text-amber-800 dark:text-amber-200">
                  This is a system preset and cannot be modified. Clone it to create your own customized version.
                </p>
              </div>
            )}

            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (editingConfig.is_preset) {
                  handleClone(editingConfig);
                  return;
                }
                const formData = new FormData(e.currentTarget);
                const targets = editingTargets
                  .split('\n')
                  .map(t => t.trim())
                  .filter(t => t.length > 0);

                // Validate timeout before submission
                if (!isTimeoutValid(editingScanMode, editingTimeout)) {
                  const { min, max } = getTimeoutRange(editingScanMode);
                  toast.error(`Timeout must be between ${formatDuration(min)} and ${formatDuration(max)} for ${editingScanMode} mode`);
                  return;
                }

                // Warn that editing breaks comparability with prior scans on this config.
                // The backend computes a hash over the comparable subset of these fields
                // at scan-creation time; any change here gives future scans a new hash
                // and removes them from the in-UI compare dropdown for prior scans.
                if (!window.confirm(
                  'Editing this configuration will mean future scans cannot be compared with existing scans on this configuration. Continue?'
                )) {
                  return;
                }

                const data = {
                  name: formData.get('name') as string,
                  description: formData.get('description') as string,
                  targets,
                  scan_mode: editingScanMode,
                  max_concurrent_hosts: parseInt(formData.get('max_concurrent_hosts') as string),
                  host_timeout_seconds: editingTimeout,
                  enable_nuclei: formData.get('enable_nuclei') === 'on',
                  enable_nuclei_endpoints: formData.get('enable_nuclei_endpoints') === 'on',
                  enable_ssh_audit: formData.get('enable_ssh_audit') === 'on',
                  enable_nse: formData.get('enable_nse') === 'on',
                  enable_sslscan: formData.get('enable_sslscan') === 'on',
                  enable_testssl: formData.get('enable_testssl') === 'on',
                  enable_nikto: formData.get('enable_nikto') === 'on',
                  enable_zap: formData.get('enable_zap') === 'on',
                  enable_katana: formData.get('enable_katana') === 'on',
                  httpx_screenshots: formData.get('httpx_screenshots') === 'on',
                  httpx_vhost_discovery: formData.get('httpx_vhost_discovery') === 'on',
                };
                updateMutation.mutate({ id: editingConfig.id, data });
              }}
              className="space-y-6"
            >
              {/* Basic Info */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">Basic Information</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="edit-config-name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                    <input
                      id="edit-config-name"
                      type="text"
                      name="name"
                      defaultValue={editingConfig.name}
                      required
                      disabled={editingConfig.is_preset}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white disabled:bg-gray-100 dark:disabled:bg-gray-600 disabled:text-gray-500 dark:disabled:text-gray-400"
                    />
                  </div>
                  <div>
                    <label htmlFor="edit-config-description" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                    <input
                      id="edit-config-description"
                      type="text"
                      name="description"
                      defaultValue={editingConfig.description || ''}
                      disabled={editingConfig.is_preset}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white disabled:bg-gray-100 dark:disabled:bg-gray-600 disabled:text-gray-500 dark:disabled:text-gray-400"
                    />
                  </div>
                </div>
              </div>

              {/* Targets */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">Scan Targets</h4>
                <div>
                  <label htmlFor="edit-config-targets" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    IP Addresses / Hostnames
                  </label>
                  <textarea
                    id="edit-config-targets"
                    name="targets"
                    value={editingTargets}
                    onChange={(e) => setEditingTargets(e.target.value)}
                    disabled={editingConfig.is_preset}
                    rows={5}
                    placeholder="Enter one target per line, e.g.:&#10;192.168.1.1&#10;10.0.0.0/24&#10;example.com"
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md font-mono text-sm dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 disabled:bg-gray-100 dark:disabled:bg-gray-600 disabled:text-gray-500 dark:disabled:text-gray-400"
                  />
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    One IP address, CIDR range, or hostname per line. Currently: {editingTargets.split('\n').filter(t => t.trim()).length} target(s)
                  </p>
                </div>
              </div>

              {/* Scan Mode */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">Scan Mode</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <label className={`flex items-start p-4 border-2 rounded-lg cursor-pointer transition-colors ${editingScanMode === 'fast' ? 'border-amber-500 bg-amber-50 dark:bg-amber-900/30' : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500'} ${editingConfig.is_preset ? 'cursor-not-allowed' : ''}`}>
                    <input
                      type="radio"
                      name="scan_mode"
                      value="fast"
                      aria-label="Fast Scan"
                      checked={editingScanMode === 'fast'}
                      onChange={() => handleScanModeChange('fast')}
                      disabled={editingConfig.is_preset}
                      className="mt-1 mr-3"
                    />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Fast Scan</div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">Top 1000 ports + common services (~8-38 min). Good for quick assessments.</div>
                    </div>
                  </label>
                  <label className={`flex items-start p-4 border-2 rounded-lg cursor-pointer transition-colors ${editingScanMode === 'deep' ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/30' : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500'} ${editingConfig.is_preset ? 'cursor-not-allowed' : ''}`}>
                    <input
                      type="radio"
                      name="scan_mode"
                      value="deep"
                      aria-label="Deep Scan"
                      checked={editingScanMode === 'deep'}
                      onChange={() => handleScanModeChange('deep')}
                      disabled={editingConfig.is_preset}
                      className="mt-1 mr-3"
                    />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Deep Scan</div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">All 65,535 TCP ports (~24-114 min). Comprehensive coverage.</div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Scanning Tools */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">Scanning Tools</h4>

                {/* Vulnerability Scanners */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Vulnerability Scanners</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_nuclei"
                        aria-label="Nuclei"
                        defaultChecked={editingConfig.enable_nuclei}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">Nuclei</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Template-based vulnerability detection for network services</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_nuclei_endpoints"
                        aria-label="Nuclei Endpoint Scan"
                        defaultChecked={editingConfig.enable_nuclei_endpoints}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">Nuclei Endpoint Scan</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Scan discovered endpoints for vulnerabilities (requires Katana)</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_nse"
                        aria-label="NSE Scripts"
                        defaultChecked={editingConfig.enable_nse}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">NSE Scripts</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Nmap Scripting Engine for service-specific checks</div>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Endpoint Discovery */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Endpoint Discovery</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_katana"
                        aria-label="Katana"
                        defaultChecked={editingConfig.enable_katana}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">Katana</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Web crawler for endpoint and URL discovery</div>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Web Application Scanners */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Web Application Scanners</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_nikto"
                        aria-label="Nikto"
                        defaultChecked={editingConfig.enable_nikto}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">Nikto</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Web server misconfiguration and vulnerability detection</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_zap"
                        aria-label="OWASP ZAP"
                        defaultChecked={editingConfig.enable_zap}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">OWASP ZAP</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Web application security scanner (passive mode)</div>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Security Audits */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Security Audits</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_ssh_audit"
                        aria-label="SSH Audit"
                        defaultChecked={editingConfig.enable_ssh_audit}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">SSH Audit</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">SSH configuration and cryptographic algorithm analysis</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_sslscan"
                        aria-label="SSLScan"
                        defaultChecked={editingConfig.enable_sslscan}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">SSLScan</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">TLS/SSL configuration and certificate analysis</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="enable_testssl"
                        aria-label="testssl.sh"
                        defaultChecked={editingConfig.enable_testssl}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">testssl.sh</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Deep TLS/SSL vulnerability analysis with grading</div>
                      </div>
                    </label>
                  </div>
                </div>

                {/* HTTP Probing */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">HTTP Probing (httpx)</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="httpx_screenshots"
                        aria-label="Screenshots"
                        defaultChecked={editingConfig.httpx_screenshots}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">Screenshots</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Capture webpage screenshots for HTTP ports</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                      <input
                        type="checkbox"
                        name="httpx_vhost_discovery"
                        aria-label="Virtual Host Discovery"
                        defaultChecked={editingConfig.httpx_vhost_discovery !== false}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">Virtual Host Discovery</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Enumerate virtual hosts on web servers</div>
                      </div>
                    </label>
                  </div>
                </div>
              </div>

              {/* Performance Settings */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">Performance Settings</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="edit-config-max-concurrent-hosts" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Max Concurrent Hosts
                    </label>
                    <input
                      id="edit-config-max-concurrent-hosts"
                      type="number"
                      name="max_concurrent_hosts"
                      defaultValue={editingConfig.max_concurrent_hosts}
                      required
                      min="1"
                      max="100"
                      disabled={editingConfig.is_preset}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white disabled:bg-gray-100 dark:disabled:bg-gray-600 disabled:text-gray-500 dark:disabled:text-gray-400"
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Number of hosts to scan in parallel</p>
                  </div>
                  <div>
                    <label htmlFor="edit-config-host-timeout" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Host Timeout (seconds)
                    </label>
                    <div className="flex gap-2">
                      <input
                        id="edit-config-host-timeout"
                        type="number"
                        name="host_timeout_seconds"
                        value={editingTimeout}
                        onChange={(e) => {
                          setEditingTimeout(parseInt(e.target.value) || 0);
                          setTimeoutWasAdjusted(false);
                        }}
                        required
                        min={getTimeoutRange(editingScanMode).min}
                        max={getTimeoutRange(editingScanMode).max}
                        disabled={editingConfig.is_preset}
                        className={`flex-1 px-3 py-2 border rounded-md dark:bg-gray-700 dark:text-white disabled:bg-gray-100 dark:disabled:bg-gray-600 disabled:text-gray-500 dark:disabled:text-gray-400 ${
                          !isTimeoutValid(editingScanMode, editingTimeout)
                            ? 'border-red-500 dark:border-red-500 focus:ring-red-500 focus:border-red-500'
                            : 'border-gray-300 dark:border-gray-600'
                        }`}
                      />
                      {!editingConfig.is_preset && (
                        <button
                          type="button"
                          onClick={handleResetTimeout}
                          className="px-3 py-2 text-sm bg-gray-100 dark:bg-gray-600 text-gray-700 dark:text-gray-200 rounded-md hover:bg-gray-200 dark:hover:bg-gray-500 whitespace-nowrap"
                          title={`Reset to default (${formatDuration(getTimeoutRange(editingScanMode).center)})`}
                        >
                          Reset
                        </button>
                      )}
                    </div>
                    <p className={`text-xs mt-1 ${
                      !isTimeoutValid(editingScanMode, editingTimeout)
                        ? 'text-red-500 dark:text-red-400'
                        : timeoutWasAdjusted
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-gray-500 dark:text-gray-400'
                    }`}>
                      {!isTimeoutValid(editingScanMode, editingTimeout) ? (
                        <>
                          Invalid range. Valid for {editingScanMode}: {formatDuration(getTimeoutRange(editingScanMode).min)} - {formatDuration(getTimeoutRange(editingScanMode).max)}
                        </>
                      ) : timeoutWasAdjusted ? (
                        <>
                          Adjusted from previous value. Valid range: {formatDuration(getTimeoutRange(editingScanMode).min)} - {formatDuration(getTimeoutRange(editingScanMode).max)}
                        </>
                      ) : (
                        <>
                          Valid range for {editingScanMode}: {formatDuration(getTimeoutRange(editingScanMode).min)} - {formatDuration(getTimeoutRange(editingScanMode).max)} (default: {formatDuration(getTimeoutRange(editingScanMode).center)})
                        </>
                      )}
                    </p>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="flex gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                {editingConfig.is_preset ? (
                  <>
                    <button
                      type="submit"
                      className="flex-1 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                      disabled={cloneMutation.isPending}
                      data-testid="config-modal-clone-button"
                    >
                      {cloneMutation.isPending ? 'Cloning...' : 'Clone & Customize'}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setEditingConfig(null);
                        setEditingTargets('');
                      }}
                      className="flex-1 px-4 py-2 bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200 rounded-md hover:bg-gray-300 dark:hover:bg-gray-500"
                      data-testid="config-modal-close-button"
                    >
                      Close
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      type="submit"
                      className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700"
                      disabled={updateMutation.isPending}
                      data-testid="config-modal-save-button"
                    >
                      {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setEditingConfig(null);
                        setEditingTargets('');
                      }}
                      className="flex-1 px-4 py-2 bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200 rounded-md hover:bg-gray-300 dark:hover:bg-gray-500"
                      data-testid="config-modal-cancel-button"
                    >
                      Cancel
                    </button>
                  </>
                )}
              </div>
            </form>
          </div>
        </div>
      )}
      </div>
    </div>
  );
}
