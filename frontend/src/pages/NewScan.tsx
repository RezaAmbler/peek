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

export function NewScan() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [configId, setConfigId] = useState('');
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

  const handleSubmit = async (startImmediately: boolean) => {
    setError(null);

    if (!configId) {
      setError('Please select a configuration');
      return;
    }

    if (!selectedConfig?.targets || selectedConfig.targets.length === 0) {
      setError('Selected configuration has no targets. Please add targets to the configuration first.');
      return;
    }

    const scanData: CreateScanRequest = {
      config_id: configId,
      name: name.trim() || undefined,  // Let backend auto-generate if empty
      description: description.trim() || undefined,
    };

    if (startImmediately) {
      createAndStartMutation.mutate(scanData);
    } else {
      createMutation.mutate(scanData);
    }
  };

  const isPending = createMutation.isPending || createAndStartMutation.isPending;

  return (
    <div className="min-h-screen bg-gray-50" data-component="NewScanPage">
      <Navigation />
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900">Create New Scan</h1>
          <p className="mt-2 text-sm text-gray-700">
            Run a scan using an existing configuration. Targets are defined in the configuration.
          </p>
        </div>

        <div className="bg-white shadow-md rounded-lg p-6" data-component="NewScanForm">
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md" data-testid="form-error-message">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          )}

          {/* Config Selector */}
          <div className="mb-6">
            <label htmlFor="config" className="block text-sm font-medium text-gray-700 mb-2">
              Configuration *
            </label>
            <select
              id="config"
              value={configId}
              onChange={(e) => setConfigId(e.target.value)}
              disabled={configsLoading}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm disabled:opacity-50"
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
            <div className="mb-6 p-4 bg-gray-50 rounded-md border border-gray-200">
              <h3 className="font-medium text-gray-900 mb-2">Configuration Details</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-500">Scan Mode:</span>
                  <span className="ml-2 font-medium">{selectedConfig.scan_mode}</span>
                </div>
                <div>
                  <span className="text-gray-500">Targets:</span>
                  <span className="ml-2 font-medium">{selectedConfig.targets?.length || 0}</span>
                </div>
                <div>
                  <span className="text-gray-500">Nuclei:</span>
                  <span className="ml-2 font-medium">{selectedConfig.enable_nuclei ? 'Enabled' : 'Disabled'}</span>
                </div>
                <div>
                  <span className="text-gray-500">SSH Audit:</span>
                  <span className="ml-2 font-medium">{selectedConfig.enable_ssh_audit ? 'Enabled' : 'Disabled'}</span>
                </div>
              </div>
              {selectedConfig.targets && selectedConfig.targets.length > 0 && (
                <div className="mt-3">
                  <span className="text-gray-500 text-sm">Targets: </span>
                  <span className="text-sm font-mono text-gray-700">
                    {selectedConfig.targets.slice(0, 5).join(', ')}
                    {selectedConfig.targets.length > 5 && ` ... and ${selectedConfig.targets.length - 5} more`}
                  </span>
                </div>
              )}
              {(!selectedConfig.targets || selectedConfig.targets.length === 0) && (
                <div className="mt-3 text-amber-600 text-sm">
                  ⚠️ This configuration has no targets. Please add targets before running a scan.
                </div>
              )}
            </div>
          )}

          {/* Scan Name (optional) */}
          <div className="mb-6">
            <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-2">
              Scan Name (optional)
            </label>
            <input
              type="text"
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
              placeholder="Leave empty to auto-generate (Run #N — Date)"
              data-testid="input-scan-name"
            />
            <p className="mt-1 text-sm text-gray-500">
              If left empty, the scan will be named "Run #N — {new Date().toLocaleDateString()}"
            </p>
          </div>

          {/* Description (optional) */}
          <div className="mb-6">
            <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-2">
              Description (optional)
            </label>
            <textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
              placeholder="Brief description of this scan..."
              data-testid="input-scan-description"
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={() => navigate({ to: '/scans' })}
              className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              data-testid="new-scan-cancel-button"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => handleSubmit(false)}
              disabled={isPending || !selectedConfig?.targets?.length}
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50"
              data-testid="create-scan-button"
            >
              Create Scan
            </button>
            <button
              type="button"
              onClick={() => handleSubmit(true)}
              disabled={isPending || !selectedConfig?.targets?.length}
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
