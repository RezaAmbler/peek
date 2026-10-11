import { Fragment } from 'react';
import { Menu, Transition } from '@headlessui/react';
import { comparisonsApi, comparisonExportFilename, ComparisonExportFormat } from '../api/comparisons';

// Same grouping as the scan detail export menu: documents first, then CSVs.
const EXPORT_GROUPS: Array<Array<{ format: ComparisonExportFormat; label: string }>> = [
  [
    { format: 'pdf-executive', label: 'PDF - Executive Summary' },
    { format: 'pdf-detailed', label: 'PDF - Detailed Report' },
    { format: 'html', label: 'HTML Report' },
  ],
  [
    { format: 'csv-changes', label: 'CSV - All Changes' },
    { format: 'csv-vulnerabilities', label: 'CSV - Vulnerability Changes' },
    { format: 'csv-ports', label: 'CSV - Port Changes' },
    { format: 'csv-summary', label: 'CSV - Summary' },
  ],
];

export function ComparisonExportMenu({ comparisonId }: { comparisonId: string }) {
  const handleExport = (format: ComparisonExportFormat) => {
    comparisonsApi.downloadReport(comparisonId, format)
    .then(blob => {
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = comparisonExportFilename(comparisonId, format);
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

  return (
    <Menu as="div" className="relative inline-block text-left">
      <div>
        <Menu.Button className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700" data-testid="comparison-export-button">
          Export Report ▼
        </Menu.Button>
      </div>

      <Transition
        as={Fragment}
        enter="transition ease-out duration-100"
        enterFrom="transform opacity-0 scale-95"
        enterTo="transform opacity-100 scale-100"
        leave="transition ease-in duration-75"
        leaveFrom="transform opacity-100 scale-100"
        leaveTo="transform opacity-0 scale-95"
      >
        <Menu.Items className="absolute right-0 mt-2 w-64 origin-top-right divide-y divide-gray-100 dark:divide-gray-700 rounded-md bg-white dark:bg-gray-800 shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-10">
          {EXPORT_GROUPS.map((group, idx) => (
            <div key={idx} className="px-1 py-1">
              {group.map(({ format, label }) => (
                <Menu.Item key={format}>
                  {({ active }) => (
                    <button
                      onClick={() => handleExport(format)}
                      className={`${
                        active ? 'bg-indigo-500 text-white' : 'text-gray-900 dark:text-gray-100'
                      } group flex w-full items-center rounded-md px-2 py-2 text-sm`}
                      data-testid={`comparison-export-${format}`}
                    >
                      {label}
                    </button>
                  )}
                </Menu.Item>
              ))}
            </div>
          ))}
        </Menu.Items>
      </Transition>
    </Menu>
  );
}
