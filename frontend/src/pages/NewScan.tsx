import { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { scansApi, TargetInput } from '../api/scans';
import { configsApi } from '../api/configs';
import { Navigation } from '../components/Navigation';

type InputMode = 'manual' | 'csv';

// CIDR expansion utility
function expandCIDR(cidr: string): string[] {
  const match = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!match) return [];

  const [, ip, prefixStr] = match;
  const prefix = parseInt(prefixStr, 10);

  if (prefix < 16 || prefix > 32) return []; // Limit to /16 max for safety

  const parts = ip.split('.').map(Number);
  if (parts.some(p => p < 0 || p > 255)) return [];

  const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const hostBits = 32 - prefix;
  const numHosts = Math.pow(2, hostBits);
  const networkAddr = ipNum & (0xFFFFFFFF << hostBits);

  const ips: string[] = [];
  // Skip network address (first) and broadcast address (last) for /31 and larger
  const start = prefix < 31 ? 1 : 0;
  const end = prefix < 31 ? numHosts - 1 : numHosts;

  for (let i = start; i < end; i++) {
    const addr = networkAddr + i;
    ips.push([
      (addr >>> 24) & 0xFF,
      (addr >>> 16) & 0xFF,
      (addr >>> 8) & 0xFF,
      addr & 0xFF
    ].join('.'));
  }

  return ips;
}

function isValidIP(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const num = parseInt(p, 10);
    return !isNaN(num) && num >= 0 && num <= 255 && p === String(num);
  });
}

function isCIDR(input: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(input);
}

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
  const [inputMode, setInputMode] = useState<InputMode>('manual');
  const [manualInput, setManualInput] = useState('');
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [csvContent, setCsvContent] = useState('');
  const [error, setError] = useState<string | null>(null);

  const { data: configsData, isLoading: configsLoading } = useQuery({
    queryKey: ['configs'],
    queryFn: () => configsApi.list(),
  });

  // Set default config when configs load
  useEffect(() => {
    if (configsData?.configs && configsData.configs.length > 0 && !configId) {
      setConfigId(configsData.configs[0].id);
    }
  }, [configsData, configId]);

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
    mutationFn: async (scanData: any) => {
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

  const parseManualTargets = (): { targets: TargetInput[]; hasCIDR: boolean; expandedCount: number } => {
    const lines = manualInput.split('\n').filter((line) => line.trim());
    const targets: TargetInput[] = [];
    let hasCIDR = false;
    let expandedCount = 0;

    for (const line of lines) {
      const parts = line.trim().split(',').map((p) => p.trim());
      let deviceName: string | undefined;
      let ipOrCidr: string;

      if (parts.length === 1) {
        ipOrCidr = parts[0];
      } else {
        deviceName = parts[0] || undefined;
        ipOrCidr = parts[1];
      }

      // Check if it's CIDR notation
      if (isCIDR(ipOrCidr)) {
        hasCIDR = true;
        const expandedIPs = expandCIDR(ipOrCidr);
        expandedCount += expandedIPs.length;
        for (const ip of expandedIPs) {
          targets.push({
            device_name: deviceName ? `${deviceName}` : undefined,
            ip_address: ip
          });
        }
      } else if (isValidIP(ipOrCidr)) {
        targets.push({
          device_name: deviceName,
          ip_address: ipOrCidr
        });
      }
      // Skip invalid entries silently
    }

    return { targets, hasCIDR, expandedCount };
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setCsvFile(file);
    const text = await file.text();
    setCsvContent(text);
  };

  const handleSubmit = async (startImmediately: boolean) => {
    setError(null);

    if (!name.trim()) {
      setError('Scan name is required');
      return;
    }

    if (!configId) {
      setError('Please select a configuration');
      return;
    }

    try {
      if (inputMode === 'manual') {
        const { targets } = parseManualTargets();
        if (targets.length === 0) {
          setError('Please enter at least one valid target (IP address or CIDR notation)');
          return;
        }

        if (targets.length > 1000) {
          if (!confirm(`This will scan ${targets.length} targets. Are you sure you want to continue?`)) {
            return;
          }
        }

        const scanData = {
          name,
          description: description || undefined,
          config_id: configId,
          targets,
        };

        if (startImmediately) {
          createAndStartMutation.mutate(scanData);
        } else {
          createMutation.mutate(scanData);
        }
      } else {
        // CSV mode
        if (!csvContent) {
          setError('Please upload a CSV file');
          return;
        }

        const scanData = {
          name,
          description: description || undefined,
          config_id: configId,
          targets_csv: csvContent,
        };

        if (startImmediately) {
          const scan = await scansApi.createFromCSV(scanData);
          await scansApi.start(scan.id);
          navigate({ to: `/scans/${scan.id}` });
        } else {
          const scan = await scansApi.createFromCSV(scanData);
          navigate({ to: `/scans/${scan.id}` });
        }
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create scan');
    }
  };

  const parsedResult = inputMode === 'manual' ? parseManualTargets() : { targets: [], hasCIDR: false, expandedCount: 0 };
  const targetCount = parsedResult.targets.length;

  return (
    <div className="min-h-screen bg-gray-50" data-component="NewScanPage">
      <Navigation />
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900">Create New Scan</h1>
        <p className="mt-2 text-sm text-gray-700">
          Configure and launch a network security scan
        </p>
      </div>

      <div className="bg-white shadow-md rounded-lg p-6" data-component="NewScanForm">
        {error && (
          <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md" data-testid="form-error-message">
            <p className="text-sm text-red-800">{error}</p>
          </div>
        )}

        {/* Scan Name */}
        <div className="mb-6">
          <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-2">
            Scan Name *
          </label>
          <input
            type="text"
            id="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
            placeholder="e.g., Production Network Scan"
            data-testid="input-scan-name"
          />
        </div>

        {/* Description */}
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
                {config.name}
              </option>
            ))}
          </select>
          {!configsLoading && configsData?.configs && configsData.configs.length > 0 && (
            <p className="mt-2 text-sm text-gray-500">
              Selected: {configsData.configs.find(c => c.id === configId)?.name || 'None'}
            </p>
          )}
        </div>

        {/* Input Mode Toggle */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">Target Input Mode</label>
          <div className="flex space-x-4">
            <button
              type="button"
              onClick={() => setInputMode('manual')}
              className={`px-4 py-2 rounded-md text-sm font-medium ${
                inputMode === 'manual'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
              data-testid="target-mode-manual"
            >
              Manual Entry
            </button>
            <button
              type="button"
              onClick={() => setInputMode('csv')}
              className={`px-4 py-2 rounded-md text-sm font-medium ${
                inputMode === 'csv'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
              data-testid="target-mode-csv"
            >
              CSV Upload
            </button>
          </div>
        </div>

        {/* Manual Entry Mode */}
        {inputMode === 'manual' && (
          <div className="mb-6">
            <label htmlFor="targets" className="block text-sm font-medium text-gray-700 mb-2">
              Target IP Addresses *
            </label>
            <textarea
              id="targets"
              value={manualInput}
              onChange={(e) => setManualInput(e.target.value)}
              rows={10}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm font-mono"
              placeholder="192.168.1.1&#10;Router,192.168.1.2&#10;Server,192.168.1.3"
              data-testid="textarea-targets"
            />
            <p className="mt-2 text-sm text-gray-500">
              Enter one IP address per line. Supports CIDR notation (e.g., <code>192.168.1.0/24</code>).
              Optionally prefix with device name: <code>DeviceName,192.168.1.1</code>
            </p>
            {targetCount > 0 && (
              <div className="mt-2" data-testid="target-count">
                <p className="text-sm text-green-600">
                  Found {targetCount} valid target{targetCount !== 1 ? 's' : ''}
                  {parsedResult.hasCIDR && (
                    <span className="text-gray-500 ml-1">
                      (includes {parsedResult.expandedCount} from CIDR expansion)
                    </span>
                  )}
                </p>
                {targetCount > 254 && (
                  <p className="text-sm text-amber-600 mt-1">
                    Warning: Large number of targets. Scan may take a long time.
                  </p>
                )}
              </div>
            )}
          </div>
        )}

        {/* CSV Upload Mode */}
        {inputMode === 'csv' && (
          <div className="mb-6">
            <label htmlFor="csv-file" className="block text-sm font-medium text-gray-700 mb-2">
              CSV File *
            </label>
            <input
              type="file"
              id="csv-file"
              accept=".csv"
              onChange={handleFileChange}
              className="block w-full text-sm text-gray-500
                file:mr-4 file:py-2 file:px-4
                file:rounded-md file:border-0
                file:text-sm file:font-semibold
                file:bg-indigo-50 file:text-indigo-700
                hover:file:bg-indigo-100"
              data-testid="input-csv-upload"
            />
            {csvFile && (
              <p className="mt-2 text-sm text-green-600">
                File selected: {csvFile.name}
              </p>
            )}
            <div className="mt-3 p-3 bg-gray-50 rounded-md border border-gray-200">
              <p className="text-sm text-gray-600 mb-2">
                CSV should have columns: <code className="bg-gray-200 px-1 rounded">device_name</code>, <code className="bg-gray-200 px-1 rounded">ip_address</code> (device_name is optional)
              </p>
              <button
                type="button"
                onClick={() => {
                  const template = `device_name,ip_address
Router,192.168.1.1
Firewall,192.168.1.2
Web Server,10.0.0.10
Database Server,10.0.0.20
,172.16.0.1`;
                  const blob = new Blob([template], { type: 'text/csv' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = 'scan_targets_template.csv';
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                  URL.revokeObjectURL(url);
                }}
                className="inline-flex items-center text-sm text-indigo-600 hover:text-indigo-800 font-medium"
              >
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Download template CSV
              </button>
            </div>
          </div>
        )}

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
            disabled={createMutation.isPending || createAndStartMutation.isPending}
            className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50"
            data-testid="create-scan-button"
          >
            Create Scan
          </button>
          <button
            type="button"
            onClick={() => handleSubmit(true)}
            disabled={createMutation.isPending || createAndStartMutation.isPending}
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
