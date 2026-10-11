import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scheduledScansApi } from '../api/scheduled_scans';
import { Navigation } from '../components/Navigation';
import { useNavigate } from '@tanstack/react-router';
import toast from 'react-hot-toast';
import { formatDistanceToNow } from 'date-fns';
import { formatDateTime, parseUTC } from '../utils/date';

export function ScheduledScans() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['scheduled-scans'],
    queryFn: () => scheduledScansApi.list(),
  });

  const pauseMutation = useMutation({
    mutationFn: (id: string) => scheduledScansApi.pause(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] });
      toast.success('Scheduled scan paused');
    },
  });

  const resumeMutation = useMutation({
    mutationFn: (id: string) => scheduledScansApi.resume(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] });
      toast.success('Scheduled scan resumed');
    },
  });

  const runNowMutation = useMutation({
    mutationFn: (id: string) => scheduledScansApi.runNow(id),
    onSuccess: () => {
      toast.success('Scan queued for execution');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => scheduledScansApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] });
      toast.success('Scheduled scan deleted');
    },
  });

  if (isLoading) {
    return (
      <div className="min-h-page bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="max-w-7xl mx-auto py-6 px-4">
          <p className="text-gray-500 dark:text-gray-400">Loading scheduled scans...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-page bg-gray-50 dark:bg-gray-900" data-component="ScheduledScansPage">
      <Navigation />

      <main className="max-w-7xl mx-auto py-6 px-4">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Scheduled Scans</h1>
          <button
            onClick={() => navigate({ to: '/scheduled-scans/new' })}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700"
            data-testid="new-scheduled-scan-button"
          >
            New Scheduled Scan
          </button>
        </div>

        <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700" data-component="ScheduledScanTable">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Name
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Schedule
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Next Run
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Last Run
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Total Runs
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {data?.scheduled_scans.map((schedule) => (
                <tr key={schedule.id} className="hover:bg-gray-50 dark:hover:bg-gray-700" data-component="ScheduledScanRow" data-testid={`scheduled-scan-row-${schedule.id}`}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900 dark:text-white">{schedule.name}</div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">{schedule.description}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-xs font-mono bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 px-2 py-1 rounded">
                      {schedule.cron_expression}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100" data-testid="scheduled-scan-next-run">
                    {schedule.next_run_at ? (
                      <span title={formatDateTime(schedule.next_run_at)}>
                        {formatDistanceToNow(parseUTC(schedule.next_run_at), { addSuffix: true })}
                      </span>
                    ) : (
                      '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {schedule.last_run_at ? (
                      <span title={formatDateTime(schedule.last_run_at)}>
                        {formatDistanceToNow(parseUTC(schedule.last_run_at), { addSuffix: true })}
                      </span>
                    ) : (
                      'Never'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    {schedule.total_runs}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {schedule.is_active ? (
                      <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" data-testid="scheduled-scan-status">
                        Active
                      </span>
                    ) : (
                      <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200" data-testid="scheduled-scan-status">
                        Paused
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex gap-2">
                      <button
                        onClick={() => runNowMutation.mutate(schedule.id)}
                        className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-900 dark:hover:text-indigo-300"
                        title="Run now"
                        data-testid="scheduled-scan-run-button"
                      >
                        ▶️
                      </button>
                      {schedule.is_active ? (
                        <button
                          onClick={() => pauseMutation.mutate(schedule.id)}
                          className="text-yellow-600 dark:text-yellow-400 hover:text-yellow-900 dark:hover:text-yellow-300"
                          title="Pause"
                          data-testid="scheduled-scan-pause-button"
                        >
                          ⏸️
                        </button>
                      ) : (
                        <button
                          onClick={() => resumeMutation.mutate(schedule.id)}
                          className="text-green-600 dark:text-green-400 hover:text-green-900 dark:hover:text-green-300"
                          title="Resume"
                          data-testid="scheduled-scan-resume-button"
                        >
                          ▶️
                        </button>
                      )}
                      <button
                        onClick={() => navigate({ to: `/scheduled-scans/${schedule.id}` })}
                        className="text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300"
                        title="Edit"
                        data-testid="scheduled-scan-edit-button"
                      >
                        ✏️
                      </button>
                      <button
                        onClick={() => {
                          if (confirm(`Delete "${schedule.name}"?`)) {
                            deleteMutation.mutate(schedule.id);
                          }
                        }}
                        className="text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300"
                        title="Delete"
                        data-testid="scheduled-scan-delete-button"
                      >
                        🗑️
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {(!data?.scheduled_scans || data.scheduled_scans.length === 0) && (
          <div className="text-center py-12">
            <p className="text-gray-500 dark:text-gray-400">No scheduled scans yet. Create one to get started!</p>
          </div>
        )}
      </main>
    </div>
  );
}
