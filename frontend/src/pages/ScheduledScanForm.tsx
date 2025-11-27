import { useState, useEffect } from 'react';
import { useParams, useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scheduledScansApi, CreateScheduledScanRequest } from '../api/scheduled_scans';
import { configsApi } from '../api/configs';
import { Navigation } from '../components/Navigation';
import toast from 'react-hot-toast';

export function ScheduledScanForm() {
  const { scheduledScanId } = useParams({ from: '/scheduled-scans/$scheduledScanId' });
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const isNew = scheduledScanId === 'new';

  const [formData, setFormData] = useState<CreateScheduledScanRequest>({
    name: '',
    description: '',
    cron_expression: '0 2 * * 1',
    timezone: 'UTC',
    config_id: '',
    targets: [],
    auto_compare: true,
    compare_with_previous: true,
    email_on_completion: false,
    email_on_changes_only: true,
    alert_on_critical: true,
    alert_on_new_vulns: true,
    is_active: true,
  });

  const [targetsText, setTargetsText] = useState('');
  const [emailsText, setEmailsText] = useState('');

  // Load configs
  const { data: configs } = useQuery({
    queryKey: ['configs'],
    queryFn: () => configsApi.list(),
  });

  // Load existing schedule if editing
  const { data: existingSchedule } = useQuery({
    queryKey: ['scheduled-scan', scheduledScanId],
    queryFn: () => scheduledScansApi.get(scheduledScanId!),
    enabled: !isNew,
  });

  useEffect(() => {
    if (existingSchedule) {
      setFormData(existingSchedule);
      setTargetsText(existingSchedule.targets.map(t =>
        t.device_name ? `${t.device_name},${t.ip_address}` : t.ip_address
      ).join('\n'));
      setEmailsText(existingSchedule.email_recipients?.join(', ') || '');
    }
  }, [existingSchedule]);

  useEffect(() => {
    if (configs && configs.configs.length > 0 && !formData.config_id) {
      const defaultConfig = configs.configs.find(c => c.is_default) || configs.configs[0];
      setFormData(prev => ({ ...prev, config_id: defaultConfig.id }));
    }
  }, [configs]);

  const createMutation = useMutation({
    mutationFn: (data: CreateScheduledScanRequest) => scheduledScansApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] });
      toast.success('Scheduled scan created');
      navigate({ to: '/scheduled-scans' });
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to create scheduled scan');
    },
  });

  const updateMutation = useMutation({
    mutationFn: (data: CreateScheduledScanRequest) => scheduledScansApi.update(scheduledScanId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] });
      toast.success('Scheduled scan updated');
      navigate({ to: '/scheduled-scans' });
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to update scheduled scan');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    // Parse targets
    const targets = targetsText.split('\n')
      .map(line => line.trim())
      .filter(line => line)
      .map(line => {
        const parts = line.split(',').map(p => p.trim());
        if (parts.length === 2) {
          return { device_name: parts[0], ip_address: parts[1] };
        }
        return { ip_address: parts[0] };
      });

    // Parse emails
    const emails = emailsText
      ? emailsText.split(',').map(e => e.trim()).filter(e => e)
      : undefined;

    const submitData = {
      ...formData,
      targets,
      email_recipients: emails,
    };

    if (isNew) {
      createMutation.mutate(submitData);
    } else {
      updateMutation.mutate(submitData);
    }
  };

  const cronPresets = {
    'Every Monday at 2 AM': '0 2 * * 1',
    'Daily at midnight': '0 0 * * *',
    'Every 6 hours': '0 */6 * * *',
    'Weekdays at 9 AM': '0 9 * * 1-5',
    'First day of month': '0 0 1 * *',
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navigation />

      <main className="max-w-4xl mx-auto py-6 px-4">
        <h1 className="text-2xl font-bold mb-6">
          {isNew ? 'New Scheduled Scan' : 'Edit Scheduled Scan'}
        </h1>

        <form onSubmit={handleSubmit} className="bg-white shadow rounded-lg p-6 space-y-6">
          {/* Basic Info */}
          <div>
            <h2 className="text-lg font-semibold mb-4">Basic Information</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Name *</label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  rows={2}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md"
                />
              </div>
            </div>
          </div>

          {/* Schedule */}
          <div>
            <h2 className="text-lg font-semibold mb-4">Schedule</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Cron Expression *</label>
                <input
                  type="text"
                  required
                  value={formData.cron_expression}
                  onChange={(e) => setFormData({ ...formData, cron_expression: e.target.value })}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md font-mono"
                  placeholder="0 2 * * 1"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Format: minute hour day month weekday (e.g., "0 2 * * 1" = Every Monday at 2 AM)
                </p>

                <div className="mt-2 flex flex-wrap gap-2">
                  {Object.entries(cronPresets).map(([label, cron]) => (
                    <button
                      key={label}
                      type="button"
                      onClick={() => setFormData({ ...formData, cron_expression: cron })}
                      className="px-3 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded"
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Timezone</label>
                <input
                  type="text"
                  value={formData.timezone}
                  onChange={(e) => setFormData({ ...formData, timezone: e.target.value })}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md"
                  placeholder="UTC, America/Los_Angeles, etc."
                />
              </div>
            </div>
          </div>

          {/* Scan Configuration */}
          <div>
            <h2 className="text-lg font-semibold mb-4">Scan Configuration</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Configuration *</label>
                <select
                  required
                  value={formData.config_id}
                  onChange={(e) => setFormData({ ...formData, config_id: e.target.value })}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md"
                >
                  <option value="">Select configuration...</option>
                  {configs?.configs.map(config => (
                    <option key={config.id} value={config.id}>
                      {config.name} {config.is_default && '(Default)'}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Targets *</label>
                <textarea
                  required
                  value={targetsText}
                  onChange={(e) => setTargetsText(e.target.value)}
                  rows={6}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md font-mono text-sm"
                  placeholder="192.168.1.1&#10;Router,192.168.1.254&#10;Server,10.0.0.5"
                />
                <p className="mt-1 text-xs text-gray-500">
                  One target per line. Format: "ip_address" or "device_name,ip_address"
                </p>
              </div>
            </div>
          </div>

          {/* Comparison Settings */}
          <div>
            <h2 className="text-lg font-semibold mb-4">Comparison Settings</h2>
            <div className="space-y-3">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={formData.auto_compare}
                  onChange={(e) => setFormData({ ...formData, auto_compare: e.target.checked })}
                  className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
                />
                <span className="ml-2 text-sm text-gray-900">Auto-compare with previous scans</span>
              </label>

              {formData.auto_compare && (
                <label className="flex items-center ml-6">
                  <input
                    type="checkbox"
                    checked={formData.compare_with_previous}
                    onChange={(e) => setFormData({ ...formData, compare_with_previous: e.target.checked })}
                    className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-900">Compare with most recent run</span>
                </label>
              )}
            </div>
          </div>

          {/* Notifications */}
          <div>
            <h2 className="text-lg font-semibold mb-4">Notifications</h2>
            <div className="space-y-3">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={formData.email_on_completion}
                  onChange={(e) => setFormData({ ...formData, email_on_completion: e.target.checked })}
                  className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
                />
                <span className="ml-2 text-sm text-gray-900">Send email on completion</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={formData.email_on_changes_only}
                  onChange={(e) => setFormData({ ...formData, email_on_changes_only: e.target.checked })}
                  className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
                />
                <span className="ml-2 text-sm text-gray-900">Email only when changes detected</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={formData.alert_on_critical}
                  onChange={(e) => setFormData({ ...formData, alert_on_critical: e.target.checked })}
                  className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
                />
                <span className="ml-2 text-sm text-gray-900">Alert on critical findings</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={formData.alert_on_new_vulns}
                  onChange={(e) => setFormData({ ...formData, alert_on_new_vulns: e.target.checked })}
                  className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
                />
                <span className="ml-2 text-sm text-gray-900">Alert on new vulnerabilities</span>
              </label>

              <div>
                <label className="block text-sm font-medium text-gray-700">Email Recipients</label>
                <input
                  type="text"
                  value={emailsText}
                  onChange={(e) => setEmailsText(e.target.value)}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md"
                  placeholder="email1@example.com, email2@example.com"
                />
                <p className="mt-1 text-xs text-gray-500">Comma-separated email addresses</p>
              </div>
            </div>
          </div>

          {/* Status */}
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={formData.is_active}
                onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-900">Active (scan will run on schedule)</span>
            </label>
          </div>

          {/* Actions */}
          <div className="flex gap-3">
            <button
              type="submit"
              disabled={createMutation.isPending || updateMutation.isPending}
              className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
            >
              {createMutation.isPending || updateMutation.isPending ? 'Saving...' : 'Save'}
            </button>
            <button
              type="button"
              onClick={() => navigate({ to: '/scheduled-scans' })}
              className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
            >
              Cancel
            </button>
          </div>
        </form>
      </main>
    </div>
  );
}
