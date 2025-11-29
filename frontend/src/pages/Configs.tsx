import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { configsApi, ScanConfig } from '../api/configs';
import { Navigation } from '../components/Navigation';
import toast from 'react-hot-toast';

export function Configs() {
  const queryClient = useQueryClient();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingConfig, setEditingConfig] = useState<ScanConfig | null>(null);

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
        scan_mode: config.scan_mode,
        enable_nuclei: config.enable_nuclei,
        enable_ssh_audit: config.enable_ssh_audit,
        enable_nse: config.enable_nse,
        enable_sslscan: config.enable_sslscan,
        enable_nikto: config.enable_nikto,
        enable_zap: config.enable_zap,
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
    if (config.enable_ssh_audit) count++;
    if (config.enable_nse) count++;
    if (config.enable_sslscan) count++;
    if (config.enable_nikto) count++;
    if (config.enable_zap) count++;
    return count;
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navigation />
        <div className="flex items-center justify-center min-h-[calc(100vh-4rem)]">
          <div className="text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
            <p className="mt-2 text-gray-600">Loading configurations...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50" data-component="ConfigsPage">
      <Navigation />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Scan Configurations</h1>
            <p className="mt-2 text-sm text-gray-600">
              Manage scanning parameters and tool settings
            </p>
          </div>
          <button
            onClick={() => setShowCreateForm(true)}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            data-testid="new-config-button"
          >
            New Configuration
          </button>
        </div>
      </div>

      {/* Create Form */}
      {showCreateForm && (
        <div className="mb-6 bg-white shadow rounded-lg p-6">
          <h3 className="text-lg font-medium mb-4">Create New Configuration</h3>
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
              className="flex-1 px-3 py-2 border border-gray-300 rounded-md"
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
              className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
            >
              Cancel
            </button>
          </form>
        </div>
      )}

      {/* Configs Grid */}
      {data?.configs.length === 0 ? (
        <div className="text-center py-12 bg-white rounded-lg shadow">
          <p className="text-gray-600">No configurations found. Create one to get started!</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" data-component="ConfigCardList">
          {data?.configs.map((config) => (
            <div
              key={config.id}
              className={`bg-white rounded-lg shadow hover:shadow-lg transition-shadow ${config.is_preset ? 'border-2 border-indigo-200' : ''}`}
              data-component="ConfigCard"
              data-testid={`config-card-${config.id}`}
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-gray-900">
                      {config.name}
                    </h3>
                    <div className="flex gap-2 mt-1 flex-wrap">
                      {config.is_preset && (
                        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded bg-indigo-100 text-indigo-800">
                          SYSTEM PRESET
                        </span>
                      )}
                      {config.is_default && (
                        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded bg-blue-100 text-blue-800">
                          DEFAULT
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <p className="text-sm text-gray-600 mb-4 line-clamp-2">
                  {config.description || 'No description'}
                </p>

                {/* Config Summary */}
                <div className="text-xs text-gray-500 space-y-1 mb-4 bg-gray-50 p-3 rounded">
                  <div className="flex justify-between">
                    <span>Scan Mode:</span>
                    <span className={`font-medium ${config.scan_mode === 'deep' ? 'text-indigo-600' : 'text-amber-600'}`}>
                      {config.scan_mode === 'deep' ? 'Deep (All Ports)' : 'Fast (Top 1000)'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Enabled Tools:</span>
                    <span className="font-medium">{countEnabledTools(config)} / 6</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Concurrent Hosts:</span>
                    <span className="font-medium">{config.max_concurrent_hosts}</span>
                  </div>
                </div>

                {/* Tool Status Pills */}
                <div className="flex flex-wrap gap-1 mb-4">
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_nuclei ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'}`}>
                    Nuclei
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_nse ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'}`}>
                    NSE
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_nikto ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'}`}>
                    Nikto
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_zap ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'}`}>
                    ZAP
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_ssh_audit ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'}`}>
                    SSH
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded ${config.enable_sslscan ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'}`}>
                    SSL
                  </span>
                </div>

                <div className="text-xs text-gray-400 mb-4">
                  Created {formatDate(config.created_at)}
                </div>

                {/* Actions */}
                <div className="flex gap-2">
                  <button
                    onClick={() => setEditingConfig(config)}
                    className="flex-1 px-3 py-2 text-sm bg-indigo-100 text-indigo-700 rounded hover:bg-indigo-200"
                    data-testid="config-edit-button"
                  >
                    {config.is_preset ? 'View' : 'Edit'}
                  </button>
                  {config.is_preset ? (
                    <button
                      onClick={() => handleClone(config)}
                      className="flex-1 px-3 py-2 text-sm bg-green-100 text-green-700 rounded hover:bg-green-200"
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
                          className="flex-1 px-3 py-2 text-sm bg-blue-100 text-blue-700 rounded hover:bg-blue-200"
                          disabled={setDefaultMutation.isPending}
                          data-testid="config-set-default-button"
                        >
                          Set Default
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(config)}
                        className="px-3 py-2 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200"
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
          <div className="bg-white rounded-lg p-6 max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold">
                {editingConfig.is_preset ? 'View Preset: ' : 'Edit Configuration: '}
                {editingConfig.name}
              </h3>
              {editingConfig.is_preset && (
                <span className="inline-flex items-center px-3 py-1 text-sm font-medium rounded bg-indigo-100 text-indigo-800">
                  SYSTEM PRESET
                </span>
              )}
            </div>

            {editingConfig.is_preset && (
              <div className="mb-4 p-3 bg-amber-50 border border-amber-200 rounded-md">
                <p className="text-sm text-amber-800">
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
                const data = {
                  name: formData.get('name') as string,
                  description: formData.get('description') as string,
                  scan_mode: formData.get('scan_mode') as 'fast' | 'deep',
                  max_concurrent_hosts: parseInt(formData.get('max_concurrent_hosts') as string),
                  host_timeout_seconds: parseInt(formData.get('host_timeout_seconds') as string),
                  enable_nuclei: formData.get('enable_nuclei') === 'on',
                  enable_ssh_audit: formData.get('enable_ssh_audit') === 'on',
                  enable_nse: formData.get('enable_nse') === 'on',
                  enable_sslscan: formData.get('enable_sslscan') === 'on',
                  enable_nikto: formData.get('enable_nikto') === 'on',
                  enable_zap: formData.get('enable_zap') === 'on',
                };
                updateMutation.mutate({ id: editingConfig.id, data });
              }}
              className="space-y-6"
            >
              {/* Basic Info */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 border-b pb-2">Basic Information</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                    <input
                      type="text"
                      name="name"
                      defaultValue={editingConfig.name}
                      required
                      disabled={editingConfig.is_preset}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md disabled:bg-gray-100 disabled:text-gray-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                    <input
                      type="text"
                      name="description"
                      defaultValue={editingConfig.description || ''}
                      disabled={editingConfig.is_preset}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md disabled:bg-gray-100 disabled:text-gray-500"
                    />
                  </div>
                </div>
              </div>

              {/* Scan Mode */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 border-b pb-2">Scan Mode</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <label className={`flex items-start p-4 border-2 rounded-lg cursor-pointer transition-colors ${editingConfig.scan_mode === 'fast' ? 'border-amber-500 bg-amber-50' : 'border-gray-200 hover:border-gray-300'} ${editingConfig.is_preset ? 'cursor-not-allowed' : ''}`}>
                    <input
                      type="radio"
                      name="scan_mode"
                      value="fast"
                      defaultChecked={editingConfig.scan_mode === 'fast'}
                      disabled={editingConfig.is_preset}
                      className="mt-1 mr-3"
                    />
                    <div>
                      <div className="font-medium text-gray-900">Fast Scan</div>
                      <div className="text-sm text-gray-500">Top 1000 ports + common services (~2-5 min). Good for quick assessments.</div>
                    </div>
                  </label>
                  <label className={`flex items-start p-4 border-2 rounded-lg cursor-pointer transition-colors ${editingConfig.scan_mode === 'deep' ? 'border-indigo-500 bg-indigo-50' : 'border-gray-200 hover:border-gray-300'} ${editingConfig.is_preset ? 'cursor-not-allowed' : ''}`}>
                    <input
                      type="radio"
                      name="scan_mode"
                      value="deep"
                      defaultChecked={editingConfig.scan_mode === 'deep'}
                      disabled={editingConfig.is_preset}
                      className="mt-1 mr-3"
                    />
                    <div>
                      <div className="font-medium text-gray-900">Deep Scan</div>
                      <div className="text-sm text-gray-500">All 65,535 TCP ports (~15-30 min). Comprehensive coverage.</div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Scanning Tools */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 border-b pb-2">Scanning Tools</h4>

                {/* Vulnerability Scanners */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 mb-2">Vulnerability Scanners</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="flex items-start p-3 border rounded-lg hover:bg-gray-50">
                      <input
                        type="checkbox"
                        name="enable_nuclei"
                        defaultChecked={editingConfig.enable_nuclei}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900">Nuclei</div>
                        <div className="text-xs text-gray-500">Template-based vulnerability detection for network services</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border rounded-lg hover:bg-gray-50">
                      <input
                        type="checkbox"
                        name="enable_nse"
                        defaultChecked={editingConfig.enable_nse}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900">NSE Scripts</div>
                        <div className="text-xs text-gray-500">Nmap Scripting Engine for service-specific checks</div>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Web Application Scanners */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 mb-2">Web Application Scanners</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="flex items-start p-3 border rounded-lg hover:bg-gray-50">
                      <input
                        type="checkbox"
                        name="enable_nikto"
                        defaultChecked={editingConfig.enable_nikto}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900">Nikto</div>
                        <div className="text-xs text-gray-500">Web server misconfiguration and vulnerability detection</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border rounded-lg hover:bg-gray-50">
                      <input
                        type="checkbox"
                        name="enable_zap"
                        defaultChecked={editingConfig.enable_zap}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900">OWASP ZAP</div>
                        <div className="text-xs text-gray-500">Web application security scanner (passive mode)</div>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Security Audits */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 mb-2">Security Audits</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="flex items-start p-3 border rounded-lg hover:bg-gray-50">
                      <input
                        type="checkbox"
                        name="enable_ssh_audit"
                        defaultChecked={editingConfig.enable_ssh_audit}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900">SSH Audit</div>
                        <div className="text-xs text-gray-500">SSH configuration and cryptographic algorithm analysis</div>
                      </div>
                    </label>
                    <label className="flex items-start p-3 border rounded-lg hover:bg-gray-50">
                      <input
                        type="checkbox"
                        name="enable_sslscan"
                        defaultChecked={editingConfig.enable_sslscan}
                        disabled={editingConfig.is_preset}
                        className="mt-1 mr-3"
                      />
                      <div>
                        <div className="font-medium text-gray-900">SSLScan</div>
                        <div className="text-xs text-gray-500">TLS/SSL configuration and certificate analysis</div>
                      </div>
                    </label>
                  </div>
                </div>
              </div>

              {/* Performance Settings */}
              <div className="space-y-4">
                <h4 className="font-medium text-gray-900 border-b pb-2">Performance Settings</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Max Concurrent Hosts
                    </label>
                    <input
                      type="number"
                      name="max_concurrent_hosts"
                      defaultValue={editingConfig.max_concurrent_hosts}
                      required
                      min="1"
                      max="100"
                      disabled={editingConfig.is_preset}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md disabled:bg-gray-100 disabled:text-gray-500"
                    />
                    <p className="text-xs text-gray-500 mt-1">Number of hosts to scan in parallel</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Host Timeout (seconds)
                    </label>
                    <input
                      type="number"
                      name="host_timeout_seconds"
                      defaultValue={editingConfig.host_timeout_seconds}
                      required
                      min="60"
                      max="7200"
                      disabled={editingConfig.is_preset}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md disabled:bg-gray-100 disabled:text-gray-500"
                    />
                    <p className="text-xs text-gray-500 mt-1">Maximum time to spend on each host</p>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="flex gap-3 pt-4 border-t">
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
                      onClick={() => setEditingConfig(null)}
                      className="flex-1 px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
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
                      onClick={() => setEditingConfig(null)}
                      className="flex-1 px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
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
