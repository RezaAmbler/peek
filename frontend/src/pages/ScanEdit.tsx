import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import axios from 'axios';
import { scansApi, UpdateScanRequest } from '../api/scans';
import { Navigation } from '../components/Navigation';
import toast from 'react-hot-toast';

// Helper to extract error message from various error formats
function getErrorMessage(err: unknown): string {
  if (typeof err === 'string') return err;
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      return detail.map((d) => d.msg || JSON.stringify(d)).join(', ');
    }
    if (detail && typeof detail === 'object') return JSON.stringify(detail);
  }
  if (err instanceof Error) return err.message;
  return 'An error occurred';
}

export function ScanEdit() {
  const { scanId } = useParams({ from: '/scans/$scanId/edit' });
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);

  // Fetch scan details
  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId),
  });

  // Populate form when scan loads
  useEffect(() => {
    if (scan) {
      setName(scan.name || '');
      setDescription(scan.description || '');
    }
  }, [scan]);

  const updateMutation = useMutation({
    mutationFn: (data: UpdateScanRequest) => scansApi.update(scanId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      toast.success('Scan updated successfully');
      navigate({ to: `/scans/${scanId}` });
    },
    onError: (err: unknown) => {
      const errorMsg = getErrorMessage(err);
      setError(errorMsg);
      toast.error('Failed to update scan');
    },
  });

  const handleSubmit = async () => {
    setError(null);

    const updateData: UpdateScanRequest = {
      name: name.trim() || undefined,
      description: description.trim() || undefined,
    };

    updateMutation.mutate(updateData);
  };

  if (scanLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-500 dark:text-gray-400">Loading scan...</div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-red-500 dark:text-red-400">Scan not found</div>
        </div>
      </div>
    );
  }

  if (scan.status !== 'pending') {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-700 rounded-md p-4">
            <p className="text-sm text-yellow-800 dark:text-yellow-200">
              Only scans in &quot;pending&quot; status can be edited. This scan is currently &quot;{scan.status}&quot;.
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

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900" data-component="ScanEditPage">
      <Navigation />
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Edit Scan</h1>
          <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
            Modify scan name and description. Configuration and targets cannot be changed after creation.
          </p>
        </div>

        <div className="bg-white dark:bg-gray-800 shadow-md rounded-lg p-6" data-component="ScanEditForm">
          {error && (
            <div className="mb-4 p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-700 rounded-md" data-testid="form-error-message">
              <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
            </div>
          )}

          {/* Scan Info (read-only) */}
          <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-md border border-gray-200 dark:border-gray-600">
            <h3 className="font-medium text-gray-900 dark:text-white mb-2">Scan Information</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-500 dark:text-gray-400">Config:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{scan.config_name || scan.config_id}</span>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">Run #:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{scan.run_number}</span>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">Targets:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{scan.total_targets}</span>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">Status:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{scan.status}</span>
              </div>
            </div>
          </div>

          {/* Scan Name */}
          <div className="mb-6">
            <label htmlFor="name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Scan Name
            </label>
            <input
              type="text"
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
              placeholder="Leave empty to use auto-generated name"
              data-testid="edit-scan-name"
            />
          </div>

          {/* Description */}
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
              data-testid="edit-scan-description"
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={() => navigate({ to: `/scans/${scanId}` })}
              className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
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
