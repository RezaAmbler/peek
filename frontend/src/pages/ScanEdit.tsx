import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import { scansApi, TargetInput } from '../api/scans';
import { configsApi } from '../api/configs';
import { Navigation } from '../components/Navigation';
import toast from 'react-hot-toast';

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

export function ScanEdit() {
  const { scanId } = useParams({ from: '/scans/$scanId/edit' });
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [configId, setConfigId] = useState('');
  const [manualInput, setManualInput] = useState('');
  const [error, setError] = useState<string | null>(null);

  // Fetch scan details
  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId),
  });

  // Fetch configs
  const { data: configsData, isLoading: configsLoading } = useQuery({
    queryKey: ['configs'],
    queryFn: () => configsApi.list(),
  });

  // Populate form when scan loads
  useEffect(() => {
    if (scan) {
      setName(scan.name);
      setDescription(scan.description || '');
      setConfigId(scan.config_id);

      // Format targets for manual input
      if (scan.targets) {
        const targetsText = scan.targets
          .map(t => t.device_name ? `${t.device_name},${t.ip_address}` : t.ip_address)
          .join('\n');
        setManualInput(targetsText);
      }
    }
  }, [scan]);

  const updateMutation = useMutation({
    mutationFn: (data: any) => scansApi.update(scanId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      toast.success('Scan updated successfully');
      navigate({ to: `/scans/${scanId}` });
    },
    onError: (err: any) => {
      const errorMsg = getErrorMessage(err);
      setError(errorMsg);
      toast.error('Failed to update scan');
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
    }

    return { targets, hasCIDR, expandedCount };
  };

  const handleSubmit = async () => {
    setError(null);

    if (!name.trim()) {
      setError('Scan name is required');
      return;
    }

    if (!configId) {
      setError('Please select a configuration');
      return;
    }

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

    const updateData = {
      name,
      description: description || undefined,
      config_id: configId,
      targets,
    };

    updateMutation.mutate(updateData);
  };

  if (scanLoading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navigation />
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-500">Loading scan...</div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navigation />
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-red-500">Scan not found</div>
        </div>
      </div>
    );
  }

  if (scan.status !== 'pending') {
    return (
      <div className="min-h-screen bg-gray-50">
        <Navigation />
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
            <p className="text-sm text-yellow-800">
              Only scans in "pending" status can be edited. This scan is currently "{scan.status}".
            </p>
            <button
              onClick={() => navigate({ to: `/scans/${scanId}` })}
              className="mt-4 px-4 py-2 bg-yellow-600 text-white rounded-md hover:bg-yellow-700"
            >
              Back to Scan Details
            </button>
          </div>
        </div>
      </div>
    );
  }

  const parsedResult = parseManualTargets();
  const targetCount = parsedResult.targets.length;

  return (
    <div className="min-h-screen bg-gray-50" data-component="ScanEditPage">
      <Navigation />
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900">Edit Scan</h1>
          <p className="mt-2 text-sm text-gray-700">
            Modify scan configuration and targets
          </p>
        </div>

        <div className="bg-white shadow-md rounded-lg p-6" data-component="ScanEditForm">
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
              data-testid="edit-scan-name"
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
              data-testid="edit-scan-description"
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
              data-testid="edit-select-config"
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
          </div>

          {/* Target IPs */}
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
              data-testid="edit-textarea-targets"
            />
            <p className="mt-2 text-sm text-gray-500">
              Enter one IP address per line. Supports CIDR notation (e.g., <code>192.168.1.0/24</code>).
              Optionally prefix with device name: <code>DeviceName,192.168.1.1</code>
            </p>
            {targetCount > 0 && (
              <div className="mt-2">
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

          {/* Actions */}
          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={() => navigate({ to: `/scans/${scanId}` })}
              className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              data-testid="edit-scan-cancel-button"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSubmit}
              disabled={updateMutation.isPending}
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50"
              data-testid="edit-scan-save-button"
            >
              {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
