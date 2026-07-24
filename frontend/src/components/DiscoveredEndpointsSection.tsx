import { useState } from 'react';
import { DiscoveredEndpoint } from '../api/scans';

interface DiscoveredEndpointsSectionProps {
  endpoints: DiscoveredEndpoint[];
  hostFilter?: string | null;
  total: number;
  page: number;
  pages: number;
  onPageChange?: (page: number) => void;
}

// HTTP method colors
const methodColors: Record<string, string> = {
  GET: 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200',
  POST: 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200',
  PUT: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200',
  DELETE: 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200',
  PATCH: 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200',
  OPTIONS: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200',
  HEAD: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200',
};

// Status code colors
function getStatusColor(status?: number): string {
  if (!status) return 'text-gray-400 dark:text-gray-500';
  if (status >= 200 && status < 300) return 'text-green-600 dark:text-green-400';
  if (status >= 300 && status < 400) return 'text-blue-600 dark:text-blue-400';
  if (status >= 400 && status < 500) return 'text-orange-600 dark:text-orange-400';
  if (status >= 500) return 'text-red-600 dark:text-red-400';
  return 'text-gray-600 dark:text-gray-400';
}

function EndpointRow({ endpoint }: { endpoint: DiscoveredEndpoint }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border-b border-gray-100 dark:border-gray-700 last:border-0">
      <div
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        className="flex items-center justify-between p-3 hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setExpanded(!expanded);
          }
        }}
      >
        <div className="flex items-center gap-3 flex-1 min-w-0">
          {/* Method badge */}
          <span className={`px-2 py-0.5 text-xs font-medium rounded ${methodColors[endpoint.method] || methodColors.GET}`}>
            {endpoint.method}
          </span>

          {/* URL */}
          <span className="text-sm font-mono text-gray-800 dark:text-gray-200 truncate" title={endpoint.url}>
            {endpoint.path || '/'}
          </span>

          {/* Query params indicator */}
          {endpoint.query && (
            <span className="text-xs text-gray-400 dark:text-gray-500" title={endpoint.query}>
              ?...
            </span>
          )}
        </div>

        <div className="flex items-center gap-4 flex-shrink-0">
          {/* Status code */}
          <span className={`text-sm font-medium ${getStatusColor(endpoint.status_code)}`}>
            {endpoint.status_code || '-'}
          </span>

          {/* Content type */}
          {endpoint.content_type && (
            <span className="text-xs text-gray-500 dark:text-gray-400 hidden md:block max-w-32 truncate" title={endpoint.content_type}>
              {endpoint.content_type.split(';')[0]}
            </span>
          )}

          {/* Source tool */}
          <span className="px-1.5 py-0.5 text-xs rounded bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400">
            {endpoint.source_tool}
          </span>

          {/* Expand icon */}
          <svg
            className={`w-4 h-4 text-gray-400 transform transition-transform ${expanded ? 'rotate-180' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-3 pb-3 pt-1 bg-gray-50 dark:bg-gray-700/30">
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <dt className="text-gray-500 dark:text-gray-400">Full URL</dt>
              <dd className="text-gray-900 dark:text-white font-mono break-all">{endpoint.url}</dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400">Host</dt>
              <dd className="text-gray-900 dark:text-white">{endpoint.host}:{endpoint.port}</dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400">Depth</dt>
              <dd className="text-gray-900 dark:text-white">{endpoint.depth ?? 'N/A'}</dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400">Content Length</dt>
              <dd className="text-gray-900 dark:text-white">
                {endpoint.content_length ? `${(endpoint.content_length / 1024).toFixed(1)} KB` : 'N/A'}
              </dd>
            </div>
            {endpoint.query && (
              <div className="col-span-2 md:col-span-4">
                <dt className="text-gray-500 dark:text-gray-400">Query Parameters</dt>
                <dd className="text-gray-900 dark:text-white font-mono break-all">{endpoint.query}</dd>
              </div>
            )}
          </dl>
        </div>
      )}
    </div>
  );
}

function HostGroup({ host, endpoints }: { host: string; endpoints: DiscoveredEndpoint[] }) {
  const [expanded, setExpanded] = useState(true);

  // Group by path prefix for organization
  const uniquePaths = new Set(endpoints.map(e => e.path.split('/').slice(0, 3).join('/'))).size;

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-700/50 flex items-center justify-between hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="font-medium text-gray-900 dark:text-white">{host}</span>
          <span className="text-sm text-gray-500 dark:text-gray-400">
            {endpoints.length} endpoints
          </span>
          <span className="text-xs text-gray-400 dark:text-gray-500">
            ({uniquePaths} unique paths)
          </span>
        </div>
        <svg
          className={`w-4 h-4 text-gray-500 transform transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {expanded && (
        <div>
          {endpoints.map(endpoint => (
            <EndpointRow key={endpoint.id} endpoint={endpoint} />
          ))}
        </div>
      )}
    </div>
  );
}

export function DiscoveredEndpointsSection({
  endpoints,
  hostFilter,
  total,
  page,
  pages,
  onPageChange,
}: DiscoveredEndpointsSectionProps) {
  const [show, setShow] = useState(true);

  // Filter by host if specified
  const filteredEndpoints = hostFilter
    ? endpoints.filter(e => e.host === hostFilter)
    : endpoints;

  // Group endpoints by host
  const endpointsByHost = filteredEndpoints.reduce((acc, endpoint) => {
    const key = `${endpoint.host}:${endpoint.port}`;
    if (!acc[key]) acc[key] = [];
    acc[key].push(endpoint);
    return acc;
  }, {} as Record<string, DiscoveredEndpoint[]>);

  if (total === 0) return null;

  return (
    <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="DiscoveredEndpointsSection">
      <button
        onClick={() => setShow(!show)}
        className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white">
            Discovered Endpoints ({hostFilter ? `${filteredEndpoints.length} of ${total}` : total})
          </h2>
          <span className="px-2 py-0.5 text-xs font-medium rounded bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300">
            KATANA
          </span>
        </div>
        <svg
          className={`w-5 h-5 text-gray-500 dark:text-gray-400 transform transition-transform ${show ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {show && (
        <div className="p-6">
          {filteredEndpoints.length > 0 ? (
            <>
              <div className="space-y-4">
                {Object.entries(endpointsByHost).map(([host, eps]) => (
                  <HostGroup key={host} host={host} endpoints={eps} />
                ))}
              </div>

              {/* Pagination */}
              {pages > 1 && onPageChange && (
                <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    Page {page} of {pages} ({total} total)
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => onPageChange(page - 1)}
                      disabled={page <= 1}
                      className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-200 dark:hover:bg-gray-600"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => onPageChange(page + 1)}
                      disabled={page >= pages}
                      className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-200 dark:hover:bg-gray-600"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <p className="text-gray-500 dark:text-gray-400 text-center py-4">
              No discovered endpoints {hostFilter ? 'for selected host' : 'found'}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
