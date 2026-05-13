import { useState } from 'react';
import { SSLScanResult } from '../api/scans';

interface SSLScanSectionProps {
  results: SSLScanResult[];
  hostFilter?: string | null;
}

// Grade colors with dark mode
const gradeColors: Record<string, { bg: string; text: string; border: string }> = {
  'A+': { bg: 'bg-green-100 dark:bg-green-900', text: 'text-green-800 dark:text-green-200', border: 'border-green-500' },
  'A': { bg: 'bg-green-100 dark:bg-green-900', text: 'text-green-800 dark:text-green-200', border: 'border-green-500' },
  'B': { bg: 'bg-lime-100 dark:bg-lime-900', text: 'text-lime-800 dark:text-lime-200', border: 'border-lime-500' },
  'C': { bg: 'bg-yellow-100 dark:bg-yellow-900', text: 'text-yellow-800 dark:text-yellow-200', border: 'border-yellow-500' },
  'D': { bg: 'bg-orange-100 dark:bg-orange-900', text: 'text-orange-800 dark:text-orange-200', border: 'border-orange-500' },
  'F': { bg: 'bg-red-100 dark:bg-red-900', text: 'text-red-800 dark:text-red-200', border: 'border-red-500' },
};

// Severity colors for findings with dark mode
const findingSeverityColors: Record<string, string> = {
  critical: 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-200 border-red-300 dark:border-red-700',
  high: 'bg-orange-100 dark:bg-orange-900/50 text-orange-800 dark:text-orange-200 border-orange-300 dark:border-orange-700',
  medium: 'bg-yellow-100 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-200 border-yellow-300 dark:border-yellow-700',
  low: 'bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-200 border-blue-300 dark:border-blue-700',
  info: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 border-gray-300 dark:border-gray-600',
};

function SSLScanCard({ result }: { result: SSLScanResult }) {
  const [expanded, setExpanded] = useState(false);
  const gradeStyle = gradeColors[result.grade || 'F'] || gradeColors['F'];

  // Count protocol issues
  const deprecatedProtocols = [];
  if (result.sslv2_enabled) deprecatedProtocols.push('SSLv2');
  if (result.sslv3_enabled) deprecatedProtocols.push('SSLv3');
  if (result.tlsv10_enabled) deprecatedProtocols.push('TLSv1.0');
  if (result.tlsv11_enabled) deprecatedProtocols.push('TLSv1.1');

  // Enabled protocols
  const enabledProtocols = [];
  if (result.tlsv12_enabled) enabledProtocols.push('TLSv1.2');
  if (result.tlsv13_enabled) enabledProtocols.push('TLSv1.3');

  // Count cipher strengths
  const cipherStats = {
    strong: result.ciphers?.filter(c => c.strength === 'strong').length || 0,
    acceptable: result.ciphers?.filter(c => c.strength === 'acceptable').length || 0,
    weak: result.ciphers?.filter(c => c.strength === 'weak').length || 0,
  };

  return (
    <div
      className={`border-l-4 ${gradeStyle.border} bg-white dark:bg-gray-800 rounded-lg shadow p-4`}
      data-component="SSLScanCard"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className={`px-3 py-1 text-lg font-bold rounded ${gradeStyle.bg} ${gradeStyle.text}`}>
            {result.grade || '?'}
          </span>
          <div>
            <h4 className="font-semibold text-gray-900 dark:text-white">
              {result.ip_address}:{result.port}
            </h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {result.service_name || 'SSL/TLS'}
              {result.device_name && ` - ${result.device_name}`}
            </p>
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
        {/* Protocols */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Protocols</p>
          <div className="flex flex-wrap gap-1">
            {enabledProtocols.map(p => (
              <span key={p} className="px-1.5 py-0.5 text-xs bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded">
                {p}
              </span>
            ))}
            {deprecatedProtocols.map(p => (
              <span key={p} className="px-1.5 py-0.5 text-xs bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded">
                {p}
              </span>
            ))}
          </div>
        </div>

        {/* Ciphers */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Ciphers</p>
          <div className="flex gap-2 text-xs">
            <span className="text-green-600 dark:text-green-400">{cipherStats.strong} strong</span>
            {cipherStats.weak > 0 && (
              <span className="text-red-600 dark:text-red-400">{cipherStats.weak} weak</span>
            )}
          </div>
        </div>

        {/* Certificate */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Certificate</p>
          <p className="text-xs text-gray-700 dark:text-gray-300 truncate" title={result.cert_subject || ''}>
            {result.cert_subject || 'N/A'}
          </p>
          {result.cert_self_signed && (
            <span className="text-xs text-orange-600 dark:text-orange-400">Self-signed</span>
          )}
        </div>

        {/* Issues */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Issues</p>
          <p className="text-xs text-gray-700 dark:text-gray-300">
            {result.findings?.length || 0} findings
            {result.heartbleed_vulnerable && (
              <span className="ml-1 text-red-600 dark:text-red-400 font-semibold">HEARTBLEED!</span>
            )}
          </p>
        </div>
      </div>

      {/* Findings Summary */}
      {result.findings && result.findings.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-2">
          {result.findings.map((finding, idx) => (
            <span
              key={idx}
              className={`px-2 py-1 text-xs rounded border ${findingSeverityColors[finding.severity] || findingSeverityColors.info}`}
              title={finding.detail}
            >
              {finding.finding}
            </span>
          ))}
        </div>
      )}

      {/* Expanded Details */}
      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 space-y-4">
          {/* Protocol Details */}
          <div>
            <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Protocol Support</h5>
            <div className="grid grid-cols-3 md:grid-cols-6 gap-2 text-xs">
              {[
                { name: 'SSLv2', enabled: result.sslv2_enabled, bad: true },
                { name: 'SSLv3', enabled: result.sslv3_enabled, bad: true },
                { name: 'TLSv1.0', enabled: result.tlsv10_enabled, bad: true },
                { name: 'TLSv1.1', enabled: result.tlsv11_enabled, bad: true },
                { name: 'TLSv1.2', enabled: result.tlsv12_enabled, bad: false },
                { name: 'TLSv1.3', enabled: result.tlsv13_enabled, bad: false },
              ].map(p => (
                <div
                  key={p.name}
                  className={`p-2 rounded text-center ${
                    p.enabled
                      ? p.bad
                        ? 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300'
                        : 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300'
                      : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500'
                  }`}
                >
                  {p.name}
                  <br />
                  {p.enabled ? 'Yes' : 'No'}
                </div>
              ))}
            </div>
          </div>

          {/* Certificate Details */}
          {result.cert_subject && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Certificate</h5>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Subject</dt>
                  <dd className="text-gray-900 dark:text-white">{result.cert_subject}</dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Issuer</dt>
                  <dd className="text-gray-900 dark:text-white">{result.cert_issuer}</dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Valid From</dt>
                  <dd className="text-gray-900 dark:text-white">{result.cert_not_before}</dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Valid Until</dt>
                  <dd className={result.cert_expired ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-white'}>
                    {result.cert_not_after}
                    {result.cert_expired && ' (EXPIRED)'}
                  </dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Key</dt>
                  <dd className={`text-gray-900 dark:text-white ${result.cert_key_bits && result.cert_key_bits < 2048 ? 'text-orange-600 dark:text-orange-400' : ''}`}>
                    {result.cert_key_type} {result.cert_key_bits} bits
                  </dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Signature</dt>
                  <dd className="text-gray-900 dark:text-white">{result.cert_signature_algorithm}</dd>
                </div>
              </dl>
            </div>
          )}

          {/* Cipher Suites */}
          {result.ciphers && result.ciphers.length > 0 && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                Cipher Suites ({result.ciphers.length})
              </h5>
              <div className="max-h-48 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="bg-gray-50 dark:bg-gray-700 sticky top-0">
                    <tr>
                      <th className="text-left p-1 text-gray-700 dark:text-gray-300">Cipher</th>
                      <th className="text-left p-1 text-gray-700 dark:text-gray-300">Version</th>
                      <th className="text-left p-1 text-gray-700 dark:text-gray-300">Bits</th>
                      <th className="text-left p-1 text-gray-700 dark:text-gray-300">Strength</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.ciphers.slice(0, 20).map((cipher, idx) => (
                      <tr key={idx} className="border-t border-gray-100 dark:border-gray-700">
                        <td className="p-1 font-mono text-gray-800 dark:text-gray-200">{cipher.cipher}</td>
                        <td className="p-1 text-gray-800 dark:text-gray-200">{cipher.sslversion}</td>
                        <td className="p-1 text-gray-800 dark:text-gray-200">{cipher.bits}</td>
                        <td className="p-1">
                          <span
                            className={`px-1.5 py-0.5 rounded ${
                              cipher.strength === 'strong'
                                ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300'
                                : cipher.strength === 'weak'
                                ? 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300'
                                : 'bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300'
                            }`}
                          >
                            {cipher.strength}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {result.ciphers.length > 20 && (
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    ...and {result.ciphers.length - 20} more
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function SSLScanSection({ results, hostFilter }: SSLScanSectionProps) {
  const [show, setShow] = useState(true);

  // Filter by host
  const filteredResults = hostFilter
    ? results.filter(r => r.ip_address === hostFilter)
    : results;

  if (results.length === 0) return null;

  return (
    <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="SSLScanSection">
      <button
        onClick={() => setShow(!show)}
        className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white">
            SSL/TLS Analysis ({hostFilter ? `${filteredResults.length} of ${results.length}` : results.length})
          </h2>
          <span className="px-2 py-0.5 text-xs font-medium rounded bg-teal-100 dark:bg-teal-900 text-teal-700 dark:text-teal-300">
            SSLSCAN
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
        <div className="p-6 space-y-4">
          {filteredResults.length > 0 ? (
            filteredResults.map(result => (
              <SSLScanCard key={result.id} result={result} />
            ))
          ) : (
            <p className="text-gray-500 dark:text-gray-400 text-center py-4">No SSL/TLS results for selected host</p>
          )}
        </div>
      )}
    </div>
  );
}
