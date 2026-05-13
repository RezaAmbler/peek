import { useState } from 'react';
import { TestsslResult } from '../api/scans';

interface TestsslResultsSectionProps {
  results: TestsslResult[];
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
  'T': { bg: 'bg-red-100 dark:bg-red-900', text: 'text-red-800 dark:text-red-200', border: 'border-red-500' },
};

// Severity colors for vulnerabilities
const vulnSeverityColors: Record<string, string> = {
  critical: 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-200 border-red-300 dark:border-red-700',
  high: 'bg-orange-100 dark:bg-orange-900/50 text-orange-800 dark:text-orange-200 border-orange-300 dark:border-orange-700',
  medium: 'bg-yellow-100 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-200 border-yellow-300 dark:border-yellow-700',
  low: 'bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-200 border-blue-300 dark:border-blue-700',
  info: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 border-gray-300 dark:border-gray-600',
  ok: 'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-200 border-green-300 dark:border-green-700',
};

function TestsslCard({ result }: { result: TestsslResult }) {
  const [expanded, setExpanded] = useState(false);
  const gradeStyle = gradeColors[result.overall_grade || 'F'] || gradeColors['F'];

  // Protocol support summary
  const protocols = result.protocols || {};
  const deprecatedProtocols = [];
  const modernProtocols = [];

  if (protocols.sslv2) deprecatedProtocols.push('SSLv2');
  if (protocols.sslv3) deprecatedProtocols.push('SSLv3');
  if (protocols.tls10) deprecatedProtocols.push('TLSv1.0');
  if (protocols.tls11) deprecatedProtocols.push('TLSv1.1');
  if (protocols.tls12) modernProtocols.push('TLSv1.2');
  if (protocols.tls13) modernProtocols.push('TLSv1.3');

  // Count vulnerability severities
  const vulnCounts = (result.vulnerabilities || []).reduce((acc, v) => {
    const sev = v.severity?.toLowerCase() || 'info';
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Certificate info summary
  const cert = result.certificate_info;
  const certExpired = cert?.validity?.expired;
  const daysRemaining = cert?.validity?.days_remaining;

  return (
    <div
      className={`border-l-4 ${gradeStyle.border} bg-white dark:bg-gray-800 rounded-lg shadow p-4`}
      data-component="TestsslCard"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className={`px-3 py-1 text-lg font-bold rounded ${gradeStyle.bg} ${gradeStyle.text}`}>
            {result.overall_grade || '?'}
          </span>
          <div>
            <h4 className="font-semibold text-gray-900 dark:text-white">
              {result.ip_address}:{result.port}
            </h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {result.service_name || 'TLS'}
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
            {modernProtocols.map(p => (
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
            <span className="text-green-600 dark:text-green-400">
              {result.cipher_findings?.strong?.length || 0} strong
            </span>
            {(result.cipher_findings?.weak?.length || 0) > 0 && (
              <span className="text-orange-600 dark:text-orange-400">
                {result.cipher_findings?.weak?.length} weak
              </span>
            )}
            {(result.cipher_findings?.insecure?.length || 0) > 0 && (
              <span className="text-red-600 dark:text-red-400">
                {result.cipher_findings?.insecure?.length} insecure
              </span>
            )}
          </div>
        </div>

        {/* Certificate */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Certificate</p>
          <p className="text-xs text-gray-700 dark:text-gray-300 truncate" title={cert?.subject || ''}>
            {cert?.subject || 'N/A'}
          </p>
          {certExpired ? (
            <span className="text-xs text-red-600 dark:text-red-400">Expired</span>
          ) : daysRemaining !== undefined && daysRemaining < 30 ? (
            <span className="text-xs text-orange-600 dark:text-orange-400">{daysRemaining}d remaining</span>
          ) : null}
        </div>

        {/* Vulnerabilities */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded p-2">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Vulnerabilities</p>
          <div className="flex gap-2 text-xs">
            {vulnCounts.critical && (
              <span className="text-red-600 dark:text-red-400">{vulnCounts.critical} crit</span>
            )}
            {vulnCounts.high && (
              <span className="text-orange-600 dark:text-orange-400">{vulnCounts.high} high</span>
            )}
            {vulnCounts.medium && (
              <span className="text-yellow-600 dark:text-yellow-400">{vulnCounts.medium} med</span>
            )}
            {!vulnCounts.critical && !vulnCounts.high && !vulnCounts.medium && (
              <span className="text-green-600 dark:text-green-400">No major issues</span>
            )}
          </div>
        </div>
      </div>

      {/* Vulnerability badges */}
      {result.vulnerabilities && result.vulnerabilities.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-2">
          {result.vulnerabilities
            .filter(v => ['critical', 'high', 'medium'].includes(v.severity?.toLowerCase() || ''))
            .slice(0, 8)
            .map((vuln, idx) => (
              <span
                key={idx}
                className={`px-2 py-1 text-xs rounded border ${vulnSeverityColors[vuln.severity?.toLowerCase() || 'info']}`}
                title={vuln.finding}
              >
                {vuln.id}
                {vuln.cve && ` (${vuln.cve})`}
              </span>
            ))}
          {result.vulnerabilities.filter(v => ['critical', 'high', 'medium'].includes(v.severity?.toLowerCase() || '')).length > 8 && (
            <span className="px-2 py-1 text-xs rounded bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400">
              +{result.vulnerabilities.filter(v => ['critical', 'high', 'medium'].includes(v.severity?.toLowerCase() || '')).length - 8} more
            </span>
          )}
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
                { name: 'SSLv2', enabled: protocols.sslv2, bad: true },
                { name: 'SSLv3', enabled: protocols.sslv3, bad: true },
                { name: 'TLSv1.0', enabled: protocols.tls10, bad: true },
                { name: 'TLSv1.1', enabled: protocols.tls11, bad: true },
                { name: 'TLSv1.2', enabled: protocols.tls12, bad: false },
                { name: 'TLSv1.3', enabled: protocols.tls13, bad: false },
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
          {cert && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Certificate</h5>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Subject</dt>
                  <dd className="text-gray-900 dark:text-white">{cert.subject || 'N/A'}</dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Issuer</dt>
                  <dd className="text-gray-900 dark:text-white">{cert.issuer || 'N/A'}</dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Valid From</dt>
                  <dd className="text-gray-900 dark:text-white">{cert.validity?.not_before || 'N/A'}</dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Valid Until</dt>
                  <dd className={certExpired ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-white'}>
                    {cert.validity?.not_after || 'N/A'}
                    {certExpired && ' (EXPIRED)'}
                  </dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Key</dt>
                  <dd className={`text-gray-900 dark:text-white ${cert.key_size && cert.key_size < 2048 ? 'text-orange-600 dark:text-orange-400' : ''}`}>
                    {cert.key_type} {cert.key_size} bits
                  </dd>
                </div>
                <div>
                  <dt className="text-gray-500 dark:text-gray-400">Signature</dt>
                  <dd className="text-gray-900 dark:text-white">{cert.signature_algorithm || 'N/A'}</dd>
                </div>
                {cert.san && cert.san.length > 0 && (
                  <div className="col-span-2">
                    <dt className="text-gray-500 dark:text-gray-400">Subject Alt Names</dt>
                    <dd className="text-gray-900 dark:text-white">{cert.san.join(', ')}</dd>
                  </div>
                )}
              </dl>
            </div>
          )}

          {/* Server Configuration */}
          {result.server_config && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Server Configuration</h5>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                <div className={`p-2 rounded ${result.server_config.forward_secrecy ? 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300' : 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300'}`}>
                  Forward Secrecy: {result.server_config.forward_secrecy ? 'Yes' : 'No'}
                </div>
                <div className={`p-2 rounded ${result.server_config.hsts ? 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300' : 'bg-yellow-100 dark:bg-yellow-900/50 text-yellow-700 dark:text-yellow-300'}`}>
                  HSTS: {result.server_config.hsts ? 'Yes' : 'No'}
                </div>
                <div className={`p-2 rounded ${result.server_config.ocsp_stapling ? 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'}`}>
                  OCSP Stapling: {result.server_config.ocsp_stapling ? 'Yes' : 'No'}
                </div>
              </div>
            </div>
          )}

          {/* All Vulnerabilities */}
          {result.vulnerabilities && result.vulnerabilities.length > 0 && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                All Findings ({result.vulnerabilities.length})
              </h5>
              <div className="max-h-48 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="bg-gray-50 dark:bg-gray-700 sticky top-0">
                    <tr>
                      <th className="text-left p-1 text-gray-700 dark:text-gray-300">Severity</th>
                      <th className="text-left p-1 text-gray-700 dark:text-gray-300">ID</th>
                      <th className="text-left p-1 text-gray-700 dark:text-gray-300">Finding</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.vulnerabilities.map((vuln, idx) => (
                      <tr key={idx} className="border-t border-gray-100 dark:border-gray-700">
                        <td className="p-1">
                          <span className={`px-1.5 py-0.5 rounded ${vulnSeverityColors[vuln.severity?.toLowerCase() || 'info']}`}>
                            {vuln.severity || 'info'}
                          </span>
                        </td>
                        <td className="p-1 font-mono text-gray-800 dark:text-gray-200">{vuln.id}</td>
                        <td className="p-1 text-gray-800 dark:text-gray-200">{vuln.finding}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Cipher Details */}
          {result.cipher_findings && (
            <div>
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Cipher Analysis</h5>
              <div className="space-y-2">
                {result.cipher_findings.strong && result.cipher_findings.strong.length > 0 && (
                  <div>
                    <p className="text-xs text-green-600 dark:text-green-400 mb-1">Strong ({result.cipher_findings.strong.length})</p>
                    <div className="flex flex-wrap gap-1">
                      {result.cipher_findings.strong.slice(0, 5).map((c, i) => (
                        <span key={i} className="px-1.5 py-0.5 text-xs font-mono bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded">
                          {c}
                        </span>
                      ))}
                      {result.cipher_findings.strong.length > 5 && (
                        <span className="text-xs text-gray-500">+{result.cipher_findings.strong.length - 5} more</span>
                      )}
                    </div>
                  </div>
                )}
                {result.cipher_findings.weak && result.cipher_findings.weak.length > 0 && (
                  <div>
                    <p className="text-xs text-orange-600 dark:text-orange-400 mb-1">Weak ({result.cipher_findings.weak.length})</p>
                    <div className="flex flex-wrap gap-1">
                      {result.cipher_findings.weak.map((c, i) => (
                        <span key={i} className="px-1.5 py-0.5 text-xs font-mono bg-orange-50 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 rounded">
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {result.cipher_findings.insecure && result.cipher_findings.insecure.length > 0 && (
                  <div>
                    <p className="text-xs text-red-600 dark:text-red-400 mb-1">Insecure ({result.cipher_findings.insecure.length})</p>
                    <div className="flex flex-wrap gap-1">
                      {result.cipher_findings.insecure.map((c, i) => (
                        <span key={i} className="px-1.5 py-0.5 text-xs font-mono bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded">
                          {c}
                        </span>
                      ))}
                    </div>
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

export function TestsslResultsSection({ results, hostFilter }: TestsslResultsSectionProps) {
  const [show, setShow] = useState(true);

  // Filter by host
  const filteredResults = hostFilter
    ? results.filter(r => r.ip_address === hostFilter)
    : results;

  if (results.length === 0) return null;

  return (
    <div className="mt-6 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden" data-component="TestsslResultsSection">
      <button
        onClick={() => setShow(!show)}
        className="w-full px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white">
            Deep TLS Analysis ({hostFilter ? `${filteredResults.length} of ${results.length}` : results.length})
          </h2>
          <span className="px-2 py-0.5 text-xs font-medium rounded bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300">
            TESTSSL
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
              <TestsslCard key={result.id} result={result} />
            ))
          ) : (
            <p className="text-gray-500 dark:text-gray-400 text-center py-4">No TLS analysis results for selected host</p>
          )}
        </div>
      )}
    </div>
  );
}
