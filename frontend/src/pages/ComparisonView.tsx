import { useParams } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { comparisonsApi } from '../api/comparisons';
import { ChangeCard } from '../components/ChangeCard';
import { Navigation } from '../components/Navigation';

export function ComparisonView() {
  const { comparisonId } = useParams({ from: '/comparisons/$comparisonId' });

  const { data: comparison, isLoading } = useQuery({
    queryKey: ['comparison', comparisonId],
    queryFn: () => comparisonsApi.get(comparisonId!),
  });

  const handleExport = () => {
    const token = localStorage.getItem('access_token');
    const url = `http://localhost:8000/api/reports/comparison/${comparisonId}/pdf`;

    fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => response.blob())
    .then(blob => {
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `comparison_report_${comparisonId}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(downloadUrl);
    })
    .catch(error => {
      console.error('Export failed:', error);
      alert('Failed to export comparison report. Please try again.');
    });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="max-w-7xl mx-auto py-6 px-4">
          <p className="text-gray-500 dark:text-gray-400">Loading comparison...</p>
        </div>
      </div>
    );
  }

  if (!comparison) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Navigation />
        <div className="max-w-7xl mx-auto py-6 px-4">
          <p className="text-gray-500 dark:text-gray-400">Comparison not found</p>
        </div>
      </div>
    );
  }

  // Group changes by category
  const portChanges = comparison.changes.filter(c => c.category === 'port');
  const serviceChanges = comparison.changes.filter(c => c.category === 'service');
  const vulnChanges = comparison.changes.filter(c => c.category === 'vulnerability');
  const sshChanges = comparison.changes.filter(c => c.category === 'ssh');

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900" data-component="ComparisonPage">
      <Navigation />
      <main className="max-w-7xl mx-auto py-6 px-4">
        {/* Header */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 mb-6" data-component="ComparisonSummary">
          <div className="flex items-center justify-between mb-4">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Scan Comparison</h1>
            <button
              onClick={handleExport}
              className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 text-sm font-medium"
              data-testid="comparison-export-button"
            >
              Export PDF Report
            </button>
          </div>

          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4" data-component="ComparisonStats">
            <div className={`p-4 rounded ${comparison.new_ports === 0 ? 'bg-gray-50 dark:bg-gray-700' : 'bg-red-50 dark:bg-red-900/30'}`} data-testid="comparison-stat-new-ports">
              <p className={`text-sm ${comparison.new_ports === 0 ? 'text-gray-400 dark:text-gray-500' : 'text-gray-600 dark:text-gray-300'}`}>New Ports</p>
              <p className={`text-2xl font-bold ${comparison.new_ports === 0 ? 'text-gray-300 dark:text-gray-600' : 'text-red-600 dark:text-red-400'}`}>{comparison.new_ports}</p>
            </div>
            <div className={`p-4 rounded ${comparison.closed_ports === 0 ? 'bg-gray-50 dark:bg-gray-700' : 'bg-green-50 dark:bg-green-900/30'}`} data-testid="comparison-stat-closed-ports">
              <p className={`text-sm ${comparison.closed_ports === 0 ? 'text-gray-400 dark:text-gray-500' : 'text-gray-600 dark:text-gray-300'}`}>Closed Ports</p>
              <p className={`text-2xl font-bold ${comparison.closed_ports === 0 ? 'text-gray-300 dark:text-gray-600' : 'text-green-600 dark:text-green-400'}`}>{comparison.closed_ports}</p>
            </div>
            <div className={`p-4 rounded ${comparison.version_changes === 0 ? 'bg-gray-50 dark:bg-gray-700' : 'bg-yellow-50 dark:bg-yellow-900/30'}`} data-testid="comparison-stat-version-changes">
              <p className={`text-sm ${comparison.version_changes === 0 ? 'text-gray-400 dark:text-gray-500' : 'text-gray-600 dark:text-gray-300'}`}>Version Changes</p>
              <p className={`text-2xl font-bold ${comparison.version_changes === 0 ? 'text-gray-300 dark:text-gray-600' : 'text-yellow-600 dark:text-yellow-400'}`}>{comparison.version_changes}</p>
            </div>
            <div className={`p-4 rounded ${comparison.new_vulnerabilities === 0 ? 'bg-gray-50 dark:bg-gray-700' : 'bg-red-50 dark:bg-red-900/30'}`} data-testid="comparison-stat-new-vulns">
              <p className={`text-sm ${comparison.new_vulnerabilities === 0 ? 'text-gray-400 dark:text-gray-500' : 'text-gray-600 dark:text-gray-300'}`}>New Vulnerabilities</p>
              <p className={`text-2xl font-bold ${comparison.new_vulnerabilities === 0 ? 'text-gray-300 dark:text-gray-600' : 'text-red-600 dark:text-red-400'}`}>{comparison.new_vulnerabilities}</p>
            </div>
            <div className={`p-4 rounded ${comparison.fixed_vulnerabilities === 0 ? 'bg-gray-50 dark:bg-gray-700' : 'bg-green-50 dark:bg-green-900/30'}`} data-testid="comparison-stat-fixed-vulns">
              <p className={`text-sm ${comparison.fixed_vulnerabilities === 0 ? 'text-gray-400 dark:text-gray-500' : 'text-gray-600 dark:text-gray-300'}`}>Fixed Vulnerabilities</p>
              <p className={`text-2xl font-bold ${comparison.fixed_vulnerabilities === 0 ? 'text-gray-300 dark:text-gray-600' : 'text-green-600 dark:text-green-400'}`}>{comparison.fixed_vulnerabilities}</p>
            </div>
          </div>

          {/* Severity Breakdown */}
          <div className="flex gap-2 flex-wrap">
            {comparison.critical_changes > 0 && (
              <span className="px-3 py-1 bg-red-600 text-white text-sm font-bold rounded">
                CRITICAL: {comparison.critical_changes}
              </span>
            )}
            {comparison.high_changes > 0 && (
              <span className="px-3 py-1 bg-orange-600 text-white text-sm font-bold rounded">
                HIGH: {comparison.high_changes}
              </span>
            )}
            {comparison.medium_changes > 0 && (
              <span className="px-3 py-1 bg-yellow-600 text-white text-sm font-bold rounded">
                MEDIUM: {comparison.medium_changes}
              </span>
            )}
            {comparison.positive_changes > 0 && (
              <span className="px-3 py-1 bg-green-600 text-white text-sm font-bold rounded">
                IMPROVEMENTS: {comparison.positive_changes}
              </span>
            )}
          </div>

          {/* Summary Text - parse and display cleanly */}
          <div className="mt-4 bg-gray-50 dark:bg-gray-700 p-4 rounded">
            {comparison.summary.split('\n').map((line, idx) => {
              // First line is the comparison title - make it bold
              if (idx === 0) {
                return (
                  <p key={idx} className="text-sm font-semibold text-gray-800 dark:text-gray-100">
                    {line.replace('Comparison: ', '')}
                  </p>
                );
              }
              // Empty lines
              if (!line.trim()) return null;
              // Lines with emoji stats (duplicates of boxes above) - skip them
              if (line.match(/^[📊🟢🔴🟡]/)) return null;
              // Date lines
              return (
                <p key={idx} className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  {line}
                </p>
              );
            })}
          </div>
        </div>

        {/* Changes by Category */}
        {portChanges.length > 0 && (
          <div className="mb-6" data-component="ComparisonChangesList" data-testid="port-changes-section">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Port Changes ({portChanges.length})</h2>
            <div className="space-y-3">
              {portChanges.map((change, idx) => (
                <ChangeCard key={idx} change={change} />
              ))}
            </div>
          </div>
        )}

        {serviceChanges.length > 0 && (
          <div className="mb-6" data-testid="service-changes-section">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Service Changes ({serviceChanges.length})</h2>
            <div className="space-y-3">
              {serviceChanges.map((change, idx) => (
                <ChangeCard key={idx} change={change} />
              ))}
            </div>
          </div>
        )}

        {vulnChanges.length > 0 && (
          <div className="mb-6" data-testid="vuln-changes-section">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Vulnerability Changes ({vulnChanges.length})</h2>
            <div className="space-y-3">
              {vulnChanges.map((change, idx) => (
                <ChangeCard key={idx} change={change} />
              ))}
            </div>
          </div>
        )}

        {sshChanges.length > 0 && (
          <div className="mb-6" data-testid="ssh-changes-section">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">SSH Security Changes ({sshChanges.length})</h2>
            <div className="space-y-3">
              {sshChanges.map((change, idx) => (
                <ChangeCard key={idx} change={change} />
              ))}
            </div>
          </div>
        )}

        {comparison.total_changes === 0 && (
          <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
            <p className="text-green-600 dark:text-green-400 font-semibold text-center">
              No changes detected between scans
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
