import { useState } from 'react';
import { HttpxResult } from '../api/scans';

interface HttpxSectionProps {
  results: HttpxResult[];
  hostFilter?: string | null;
}

// Status code colors with dark mode
function getStatusCodeColor(code?: number): string {
  if (!code) return 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400';
  if (code >= 200 && code < 300) return 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300';
  if (code >= 300 && code < 400) return 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300';
  if (code >= 400 && code < 500) return 'bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300';
  if (code >= 500) return 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300';
  return 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400';
}

function HttpxCard({ result }: { result: HttpxResult }) {
  const [expanded, setExpanded] = useState(false);

  const hasRedirects = result.redirect_chain && result.redirect_chain.length > 0;
  const hasTech = result.technologies && result.technologies.length > 0;

  return (
    <div
      className="border-l-4 border-indigo-500 bg-white dark:bg-gray-800 rounded-lg shadow p-4"
      data-component="HttpxCard"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className={`px-3 py-1 text-lg font-bold rounded ${getStatusCodeColor(result.status_code)}`}>
            {result.status_code || '?'}
          </span>
          <div>
            <h4 className="font-semibold text-gray-900 dark:text-white">
              {result.ip_address}:{result.port}
            </h4>
            {result.title && (
              <p className="text-sm text-gray-600 dark:text-gray-400 truncate max-w-md" title={result.title}>
                {result.title}
              </p>
            )}
          </div>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300"
        >
          {expanded ? 'Hide Details' : 'Show Details'}
        </button>
      </div>

      {/* Quick Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
        {/* Web Server */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Web Server</p>
          <p className="text-xs text-gray-700 dark:text-gray-300 truncate" title={result.webserver || ''}>
            {result.webserver || 'Unknown'}
          </p>
        </div>

        {/* Technologies */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Technologies</p>
          {hasTech ? (
            <div className="flex flex-wrap gap-1">
              {result.technologies.slice(0, 3).map((tech, idx) => (
                <span key={idx} className="px-1.5 py-0.5 text-xs bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300 rounded">
                  {tech}
                </span>
              ))}
              {result.technologies.length > 3 && (
                <span className="text-xs text-gray-500 dark:text-gray-400">+{result.technologies.length - 3}</span>
              )}
            </div>
          ) : (
            <p className="text-xs text-gray-400 dark:text-gray-500">None detected</p>
          )}
        </div>

        {/* Response Time */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Response Time</p>
          <p className={`text-xs ${result.response_time_ms && result.response_time_ms > 1000 ? 'text-orange-600 dark:text-orange-400' : 'text-gray-700 dark:text-gray-300'}`}>
            {result.response_time_ms ? `${result.response_time_ms}ms` : 'N/A'}
          </p>
        </div>

        {/* Security */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Security</p>
          <div className="flex gap-1.5">
            {result.tls_version && (
              <span className="px-1.5 py-0.5 text-xs bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded">
                {result.tls_version}
              </span>
            )}
            {result.waf && (
              <span className="px-1.5 py-0.5 text-xs bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded" title="WAF Detected">
                WAF
              </span>
            )}
            {result.cdn && (
              <span className="px-1.5 py-0.5 text-xs bg-cyan-100 dark:bg-cyan-900 text-cyan-700 dark:text-cyan-300 rounded" title={result.cdn}>
                CDN
              </span>
            )}
            {!result.tls_version && !result.waf && !result.cdn && (
              <span className="text-xs text-gray-400 dark:text-gray-500">—</span>
            )}
          </div>
        </div>
      </div>

      {/* Connection Failed Warning */}
      {result.connection_failed && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-700 rounded p-2 mb-3">
          <p className="text-xs text-red-700 dark:text-red-300">
            Connection failed: {result.failure_reason || 'Unknown error'}
          </p>
        </div>
      )}

      {/* Expanded Details */}
      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 space-y-4">
          {/* Response Details */}
          <div>
            <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Response Details</h5>
            <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-2 text-xs">
              <div>
                <dt className="text-gray-500 dark:text-gray-400">Status Code</dt>
                <dd className="text-gray-900 dark:text-white">{result.status_code || 'N/A'}</dd>
              </div>
              <div>
                <dt className="text-gray-500 dark:text-gray-400">Content Type</dt>
                <dd className="text-gray-900 dark:text-white truncate" title={result.content_type || ''}>
                  {result.content_type || 'N/A'}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500 dark:text-gray-400">Content Length</dt>
                <dd className="text-gray-900 dark:text-white">
                  {result.content_length ? `${(result.content_length / 1024).toFixed(1)} KB` : 'N/A'}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500 dark:text-gray-400">Response Time</dt>
                <dd className="text-gray-900 dark:text-white">{result.response_time_ms ? `${result.response_time_ms}ms` : 'N/A'}</dd>
              </div>
            </dl>
          </div>

          {/* All Technologies */}
          {hasTech && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                Detected Technologies ({result.technologies.length})
              </h5>
              <div className="flex flex-wrap gap-2">
                {result.technologies.map((tech, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-1 text-xs bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300 rounded border border-purple-200 dark:border-purple-700"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Infrastructure */}
          {(result.cdn || result.waf) && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Infrastructure</h5>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                {result.cdn && (
                  <div>
                    <dt className="text-gray-500 dark:text-gray-400">CDN</dt>
                    <dd className="text-gray-900 dark:text-white">{result.cdn}</dd>
                  </div>
                )}
                {result.waf && (
                  <div>
                    <dt className="text-gray-500 dark:text-gray-400">WAF</dt>
                    <dd className="text-gray-900 dark:text-white">{result.waf}</dd>
                  </div>
                )}
              </dl>
            </div>
          )}

          {/* TLS Information */}
          {(result.tls_version || result.jarm_hash) && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">TLS Information</h5>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                {result.tls_version && (
                  <div>
                    <dt className="text-gray-500 dark:text-gray-400">TLS Version</dt>
                    <dd className="text-gray-900 dark:text-white">{result.tls_version}</dd>
                  </div>
                )}
                {result.jarm_hash && (
                  <div className="col-span-2">
                    <dt className="text-gray-500 dark:text-gray-400">JARM Hash</dt>
                    <dd className="text-gray-900 dark:text-white font-mono text-xs break-all">{result.jarm_hash}</dd>
                  </div>
                )}
              </dl>
            </div>
          )}

          {/* Redirect Chain */}
          {hasRedirects && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                Redirect Chain ({result.redirect_chain.length})
              </h5>
              <div className="space-y-1">
                {result.redirect_chain.map((url, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs">
                    <span className="text-gray-400 dark:text-gray-500">{idx + 1}.</span>
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 truncate"
                      title={url}
                    >
                      {url}
                    </a>
                  </div>
                ))}
                {result.final_url && (
                  <div className="flex items-center gap-2 text-xs mt-2">
                    <span className="text-gray-500 dark:text-gray-400">Final:</span>
                    <a
                      href={result.final_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-green-600 dark:text-green-400 hover:text-green-800 dark:hover:text-green-300 font-medium truncate"
                      title={result.final_url}
                    >
                      {result.final_url}
                    </a>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function HttpxSection({ results, hostFilter }: HttpxSectionProps) {
  const [show, setShow] = useState(true);

  // Filter by host
  const filteredResults = hostFilter
    ? results.filter(r => r.ip_address === hostFilter)
    : results;

  if (results.length === 0) return null;

  // Count technologies across all results
  const techCount = results.reduce((acc, r) => acc + (r.technologies?.length || 0), 0);

  return (
    <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="HttpxSection">
      <button
        onClick={() => setShow(!show)}
        className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white">
            HTTP Probe Results ({hostFilter ? `${filteredResults.length} of ${results.length}` : results.length})
          </h2>
          <span className="px-2 py-0.5 text-xs font-medium rounded bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-300">
            HTTPX
          </span>
          {techCount > 0 && (
            <span className="px-2 py-0.5 text-xs font-medium rounded bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300">
              {techCount} tech detected
            </span>
          )}
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
        <div className="p-6 space-y-4">
          {filteredResults.length > 0 ? (
            filteredResults.map(result => (
              <HttpxCard key={result.id} result={result} />
            ))
          ) : (
            <p className="text-gray-500 dark:text-gray-400 text-center py-4">No HTTP probe results for selected host</p>
          )}
        </div>
      )}
    </div>
  );
}
