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
    onError: () => {
      toast.error('Failed to delete configuration');
    },
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (name: string) => configsApi.create({ name, description: '' }),
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
    onError: () => {
      toast.error('Failed to update configuration');
    },
  });

  const handleDelete = (config: ScanConfig) => {
    if (window.confirm(`Are you sure you want to delete "${config.name}"?`)) {
      deleteMutation.mutate(config.id);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString();
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
    <div className="min-h-screen bg-gray-50">
      <Navigation />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Scan Configurations</h1>
            <p className="mt-2 text-sm text-gray-600">
              Manage scanning parameters and settings
            </p>
          </div>
          <button
            onClick={() => setShowCreateForm(true)}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
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
              if (name) createMutation.mutate(name);
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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {data?.configs.map((config) => (
            <div
              key={config.id}
              className="bg-white rounded-lg shadow hover:shadow-lg transition-shadow"
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-gray-900">
                      {config.name}
                    </h3>
                    {config.is_default && (
                      <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded bg-blue-100 text-blue-800 mt-1">
                        DEFAULT
                      </span>
                    )}
                  </div>
                </div>

                <p className="text-sm text-gray-600 mb-4 line-clamp-2">
                  {config.description || 'No description'}
                </p>

                {/* Config Summary */}
                <div className="text-xs text-gray-500 space-y-1 mb-4 bg-gray-50 p-3 rounded">
                  <div className="flex justify-between">
                    <span>Masscan Rate:</span>
                    <span className="font-medium">{config.masscan_rate} PPS</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Concurrent Hosts:</span>
                    <span className="font-medium">{config.max_concurrent_hosts}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>SSH Audit:</span>
                    <span className={config.enable_ssh_audit ? 'text-green-600' : 'text-red-600'}>
                      {config.enable_ssh_audit ? '✓ Enabled' : '✗ Disabled'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Nuclei:</span>
                    <span className={config.enable_nuclei ? 'text-green-600' : 'text-red-600'}>
                      {config.enable_nuclei ? '✓ Enabled' : '✗ Disabled'}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-gray-400 mb-4">
                  Created {formatDate(config.created_at)}
                </div>

                {/* Actions */}
                <div className="flex gap-2">
                  <button
                    onClick={() => setEditingConfig(config)}
                    className="flex-1 px-3 py-2 text-sm bg-indigo-100 text-indigo-700 rounded hover:bg-indigo-200"
                  >
                    Edit
                  </button>
                  {!config.is_default && (
                    <button
                      onClick={() => setDefaultMutation.mutate(config.id)}
                      className="flex-1 px-3 py-2 text-sm bg-blue-100 text-blue-700 rounded hover:bg-blue-200"
                      disabled={setDefaultMutation.isPending}
                    >
                      Set Default
                    </button>
                  )}
                  <button
                    onClick={() => handleDelete(config)}
                    className="px-3 py-2 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200"
                    disabled={deleteMutation.isPending}
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Edit Modal */}
      {editingConfig && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <h3 className="text-xl font-semibold mb-4">Edit Configuration: {editingConfig.name}</h3>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                const data = {
                  name: formData.get('name') as string,
                  description: formData.get('description') as string,
                  masscan_rate: parseInt(formData.get('masscan_rate') as string),
                  max_concurrent_hosts: parseInt(formData.get('max_concurrent_hosts') as string),
                  host_timeout_seconds: parseInt(formData.get('host_timeout_seconds') as string),
                  enable_ssh_audit: formData.get('enable_ssh_audit') === 'on',
                  enable_nuclei: formData.get('enable_nuclei') === 'on',
                };
                updateMutation.mutate({ id: editingConfig.id, data });
              }}
              className="space-y-4"
            >
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                <input
                  type="text"
                  name="name"
                  defaultValue={editingConfig.name}
                  required
                  className="w-full px-3 py-2 border border-gray-300 rounded-md"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                <textarea
                  name="description"
                  defaultValue={editingConfig.description || ''}
                  rows={2}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Masscan Rate (PPS)
                  </label>
                  <input
                    type="number"
                    name="masscan_rate"
                    defaultValue={editingConfig.masscan_rate}
                    required
                    min="100"
                    max="100000"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                  />
                </div>

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
                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                  />
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
                    max="3600"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                  />
                </div>
              </div>

              <div className="flex gap-4">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    name="enable_ssh_audit"
                    defaultChecked={editingConfig.enable_ssh_audit}
                    className="mr-2"
                  />
                  <span className="text-sm">Enable SSH Audit</span>
                </label>

                <label className="flex items-center">
                  <input
                    type="checkbox"
                    name="enable_nuclei"
                    defaultChecked={editingConfig.enable_nuclei}
                    className="mr-2"
                  />
                  <span className="text-sm">Enable Nuclei</span>
                </label>
              </div>

              <div className="flex gap-3 pt-4">
                <button
                  type="submit"
                  className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700"
                  disabled={updateMutation.isPending}
                >
                  {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
                </button>
                <button
                  type="button"
                  onClick={() => setEditingConfig(null)}
                  className="flex-1 px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      </div>
    </div>
  );
}
