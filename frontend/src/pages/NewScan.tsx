import { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { scansApi, CreateScanRequest } from '../api/scans';
import { configsApi } from '../api/configs';
import { Navigation } from '../components/Navigation';

// Helper to extract error message from various error formats
function getErrorMessage(err: any): string {
  if (typeof err === 'string') return err;
  if (err?.response?.data?.detail) {
    const detail = err.response.data.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      return detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ');
    }
    if (typeof detail === 'object') return JSON.stringify(detail);
  }
  if (err?.message) return err.message;
  return 'An error occurred';
}

// Helper function to calculate hosts from CIDR
function calculateCidrHosts(cidr: string): { valid: boolean; hosts: number; error?: string } {
  const match = cidr.match(/^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$/);
  if (!match) {
    return { valid: false, hosts: 0, error: 'Invalid CIDR format' };
  }

  const prefix = parseInt(cidr.split('/')[1]);
  if (prefix < 24) {
    return { valid: false, hosts: 0, error: `Prefix /${prefix} too large. Maximum: /24` };
  }
  if (prefix > 32) {
    return { valid: false, hosts: 0, error: 'Invalid prefix (max 32)' };
  }

  const hosts = prefix === 32 ? 1 : Math.pow(2, 32 - prefix) - 2;
  return { valid: true, hosts };
}

// Calculate total hosts from all targets (handling CIDR expansion)
function calculateTotalHosts(targets: string[]): { total: number; errors: string[] } {
  let total = 0;
  const errors: string[] = [];

  for (const target of targets) {
    if (target.includes('/')) {
      const result = calculateCidrHosts(target);
      if (result.valid) {
        total += result.hosts;
      } else if (result.error) {
        errors.push(`${target}: ${result.error}`);
      }
    } else {
      total += 1;
    }
  }

  return { total, errors };
}

export function NewScan() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [configId, setConfigId] = useState('');
  const [targets, setTargets] = useState('');
  const [error, setError] = useState<string | null>(null);

  const { data: configsData, isLoading: configsLoading } = useQuery({
    queryKey: ['configs'],
    queryFn: () => configsApi.list(),
  });

  // Set default config when configs load
  useEffect(() => {
    if (configsData?.configs && configsData.configs.length > 0 && !configId) {
      // Prefer default config, otherwise first one
      const defaultConfig = configsData.configs.find(c => c.is_default);
      setConfigId(defaultConfig?.id || configsData.configs[0].id);
    }
  }, [configsData, configId]);

  const selectedConfig = configsData?.configs.find(c => c.id === configId);

  const createMutation = useMutation({
    mutationFn: scansApi.create,
    onSuccess: (scan) => {
      navigate({ to: `/scans/${scan.id}` });
    },
    onError: (err: any) => {
      setError(getErrorMessage(err));
    },
  });

  const createAndStartMutation = useMutation({
    mutationFn: async (scanData: CreateScanRequest) => {
      const scan = await scansApi.create(scanData);
      return await scansApi.start(scan.id);
    },
    onSuccess: (scan) => {
      navigate({ to: `/scans/${scan.id}` });
    },
    onError: (err: any) => {
      setError(getErrorMessage(err));
    },
  });

  // Parse targets from textarea
  const parsedTargets = targets
    .split('\n')
    .map(t => t.trim())
    .filter(t => t.length > 0);

  // Check if we have targets from either source
  const hasConfigTargets = selectedConfig?.targets && selectedConfig.targets.length > 0;
  const hasOverrideTargets = parsedTargets.length > 0;
  const hasAnyTargets = hasConfigTargets || hasOverrideTargets;

  // Calculate total hosts (considering CIDR expansion)
  const activeTargets = hasOverrideTargets ? parsedTargets : (selectedConfig?.targets || []);
  const { total: totalHosts, errors: cidrErrors } = calculateTotalHosts(activeTargets);

  const handleSubmit = async (startImmediately: boolean) => {
    setError(null);

    if (!configId) {
      setError('Please select a configuration');
      return;
    }

    if (!hasAnyTargets) {
      setError('No targets specified. Either add targets to the configuration or enter them below.');
      return;
    }

    const scanData: CreateScanRequest = {
      config_id: configId,
      name: name.trim() || undefined,  // Let backend auto-generate if empty
      description: description.trim() || undefined,
      targets: hasOverrideTargets ? parsedTargets : undefined,  // Only send if overriding
    };

    if (startImmediately) {
      createAndStartMutation.mutate(scanData);
    } else {
      createMutation.mutate(scanData);
    }
  };

  const isPending = createMutation.isPending || createAndStartMutation.isPending;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900" data-component="NewScanPage">
      <Navigation />
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Create New Scan</h1>
          <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
            Run a scan using a configuration. You can use targets from the configuration or specify your own below.
          </p>
        </div>

        <div className="bg-white dark:bg-gray-800 shadow-md rounded-lg p-6" data-component="NewScanForm">
          {error && (
            <div className="mb-4 p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-700 rounded-md" data-testid="form-error-message">
              <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
            </div>
          )}

          {/* Config Selector */}
          <div className="mb-6">
            <label htmlFor="config" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Configuration *
            </label>
            <select
              id="config"
              value={configId}
              onChange={(e) => setConfigId(e.target.value)}
              disabled={configsLoading}
              className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm disabled:opacity-50 dark:bg-gray-700 dark:text-white"
              data-testid="select-config"
            >
              {configsLoading && <option value="">Loading configurations...</option>}
              {!configsLoading && (!configsData?.configs || configsData.configs.length === 0) && (
                <option value="">No configurations available</option>
              )}
              {!configsLoading && configsData?.configs.map((config) => (
                <option key={config.id} value={config.id}>
                  {config.name} ({config.targets?.length || 0} targets)
                </option>
              ))}
            </select>
          </div>

          {/* Selected Config Info */}
          {selectedConfig && (
            <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-md border border-gray-200 dark:border-gray-600">
              <h3 className="font-medium text-gray-900 dark:text-white mb-2">Configuration Details</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Scan Mode:</span>
                  <span className="ml-2 font-medium text-gray-900 dark:text-white">{selectedConfig.scan_mode}</span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Targets:</span>
                  <span className="ml-2 font-medium text-gray-900 dark:text-white">{selectedConfig.targets?.length || 0}</span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Nuclei:</span>
                  <span className="ml-2 font-medium text-gray-900 dark:text-white">{selectedConfig.enable_nuclei ? 'Enabled' : 'Disabled'}</span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">SSH Audit:</span>
                  <span className="ml-2 font-medium text-gray-900 dark:text-white">{selectedConfig.enable_ssh_audit ? 'Enabled' : 'Disabled'}</span>
                </div>
              </div>
              {selectedConfig.targets && selectedConfig.targets.length > 0 && (
                <div className="mt-3">
                  <span className="text-gray-500 dark:text-gray-400 text-sm">Targets: </span>
                  <span className="text-sm font-mono text-gray-700 dark:text-gray-300">
                    {selectedConfig.targets.slice(0, 5).join(', ')}
                    {selectedConfig.targets.length > 5 && ` ... and ${selectedConfig.targets.length - 5} more`}
                  </span>
                </div>
              )}
              {(!selectedConfig.targets || selectedConfig.targets.length === 0) && !hasOverrideTargets && (
                <div className="mt-3 text-amber-600 dark:text-amber-400 text-sm">
                  This configuration has no targets. Add targets below or update the configuration.
                </div>
              )}
            </div>
          )}

          {/* Targets Override */}
          <div className="mb-6">
            <label htmlFor="targets" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Scan Targets {hasConfigTargets ? '(optional override)' : '(required)'}
            </label>
            <textarea
              id="targets"
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              rows={5}
              className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm font-mono dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder="Enter one target per line, e.g.:&#10;192.168.1.1&#10;10.0.0.0/24&#10;example.com"
              data-testid="input-targets"
            />
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {hasOverrideTargets
                ? `${parsedTargets.length} target(s) entered — will override config targets`
                : hasConfigTargets
                  ? `Leave empty to use ${selectedConfig?.targets?.length} target(s) from configuration`
                  : 'Enter IP addresses, CIDR ranges, or hostnames (one per line)'
              }
            </p>
            {/* CIDR validation errors */}
            {cidrErrors.length > 0 && (
              <div className="mt-2 p-2 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-700 rounded text-sm text-red-700 dark:text-red-300">
                {cidrErrors.map((err, i) => (
                  <div key={i}>{err}</div>
                ))}
              </div>
            )}
            {/* Host count warnings */}
            {totalHosts > 50 && totalHosts <= 254 && cidrErrors.length === 0 && (
              <div className="mt-2 text-yellow-600 dark:text-yellow-400 text-sm">
                This scan will target {totalHosts} hosts and may take a while to complete.
              </div>
            )}
            {totalHosts > 254 && cidrErrors.length === 0 && (
              <div className="mt-2 text-red-600 dark:text-red-400 text-sm">
                Large scan: {totalHosts} hosts will be scanned. This may take considerable time.
              </div>
            )}
          </div>

          {/* Scan Name (optional) */}
          <div className="mb-6">
            <label htmlFor="name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Scan Name (optional)
            </label>
            <input
              type="text"
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder="Leave empty to auto-generate (Run #N — Date)"
              data-testid="input-scan-name"
            />
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              If left empty, the scan will be named "Run #N — {new Date().toLocaleDateString()}"
            </p>
          </div>

          {/* Description (optional) */}
          <div className="mb-6">
            <label htmlFor="description" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Description (optional)
            </label>
            <textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder="Brief description of this scan..."
              data-testid="input-scan-description"
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={() => navigate({ to: '/scans' })}
              className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
              data-testid="new-scan-cancel-button"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => handleSubmit(false)}
              disabled={isPending || !hasAnyTargets || cidrErrors.length > 0}
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50"
              data-testid="create-scan-button"
            >
              Create Scan
            </button>
            <button
              type="button"
              onClick={() => handleSubmit(true)}
              disabled={isPending || !hasAnyTargets || cidrErrors.length > 0}
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 disabled:opacity-50"
              data-testid="create-start-scan-button"
            >
              Create and Start
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
