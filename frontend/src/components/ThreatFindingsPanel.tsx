import type { CodeFinding, SecurityReport } from '../types';

interface Props {
  report: SecurityReport | null;
}

function severityClass(severity: string) {
  if (severity === 'CRITICAL') return 'text-red-400 border-red-900/60 bg-red-950/30';
  if (severity === 'HIGH') return 'text-orange-400 border-orange-900/60 bg-orange-950/30';
  if (severity === 'MEDIUM') return 'text-yellow-400 border-yellow-900/60 bg-yellow-950/30';
  return 'text-gray-400 border-gray-800 bg-gray-950/40';
}

function severityRank(severity: string) {
  const rank: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
  };
  return rank[severity] ?? 9;
}

function CodeFindingCard({ finding }: { finding: CodeFinding }) {
  return (
    <div
      className={`rounded-lg border px-4 py-3 ${severityClass(finding.severity)}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
        <span className="font-semibold text-sm text-gray-100">{finding.name}</span>
        <span className="text-[10px] uppercase tracking-wider font-bold">
          {finding.severity}
        </span>
      </div>
      <div className="text-xs text-gray-400 space-y-1 mb-2 font-mono">
        <div>
          {finding.file}:{finding.line} · {finding.language} · {finding.category}
        </div>
        {finding.snippet && (
          <code className="block text-gray-400 bg-black/30 rounded px-2 py-1 truncate not-italic">
            {finding.snippet}
          </code>
        )}
      </div>
      {finding.recommendation && (
        <p className="text-sm text-gray-300">
          <span className="text-green-400 font-medium">Fix: </span>
          {finding.recommendation}
        </p>
      )}
    </div>
  );
}

export default function ThreatFindingsPanel({ report }: Props) {
  if (!report) return null;

  const isGithub = !!report.github_repo;
  const anomalies = [...(report.anomalies ?? [])].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity),
  );
  const codeFindings = [...(report.code_findings ?? [])].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity),
  );
  const headerVulns = (report.vulnerabilities ?? []).filter((v) => v.header);
  const languages = report.repo_languages ?? {};

  const hasContent =
    anomalies.length > 0 ||
    codeFindings.length > 0 ||
    headerVulns.length > 0 ||
    !!report.scan_error ||
    isGithub;

  if (!hasContent) return null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="text-gray-400 text-xs uppercase tracking-widest">
          Detected Threats & Remediation
        </h3>
        {isGithub && (
          <div className="text-right text-sm">
            <a
              href={`https://github.com/${report.github_repo}`}
              target="_blank"
              rel="noreferrer"
              className="text-blue-400 hover:underline"
            >
              {report.github_repo}
            </a>
            <div className="text-gray-500 text-xs mt-0.5">
              {report.primary_language || 'Unknown'} · {report.files_scanned ?? 0} files scanned
            </div>
          </div>
        )}
      </div>

      {report.scan_error && (
        <p className="text-sm text-red-400 bg-red-950/40 border border-red-900 rounded-lg px-3 py-2">
          {report.scan_error}
        </p>
      )}

      {isGithub && Object.keys(languages).length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-widest mb-2">
            Languages Detected
          </h4>
          <div className="flex flex-wrap gap-2">
            {Object.entries(languages).map(([lang, pct]) => (
              <span
                key={lang}
                className="text-xs bg-gray-800 border border-gray-700 rounded-full px-3 py-1 text-gray-300"
              >
                {lang} · {pct}%
              </span>
            ))}
          </div>
        </div>
      )}

      {codeFindings.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-xs text-gray-500 uppercase tracking-widest">
            Code Security Issues ({codeFindings.length})
          </h4>
          {codeFindings.map((f, i) => (
            <CodeFindingCard key={`${f.file}:${f.line}:${f.name}:${i}`} finding={f} />
          ))}
        </div>
      )}

      {isGithub && codeFindings.length === 0 && !report.scan_error && (
        <p className="text-sm text-gray-500">
          No code issues matched scan patterns in {report.files_scanned ?? 0} scanned files.
        </p>
      )}

      {anomalies.length > 0 && (
        <div className="space-y-3">
          {isGithub && codeFindings.length > 0 && (
            <h4 className="text-xs text-gray-500 uppercase tracking-widest">
              Log Threats ({anomalies.length})
            </h4>
          )}
          {anomalies.map((a, i) => {
            const title =
              a.title ?? a.type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
            return (
              <div
                key={`${a.type}-${a.source_ip ?? i}`}
                className={`rounded-lg border px-4 py-3 ${severityClass(a.severity)}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <span className="font-semibold text-sm text-gray-100">{title}</span>
                  <span className="text-[10px] uppercase tracking-wider font-bold">
                    {a.severity}
                  </span>
                </div>
                <div className="text-xs text-gray-400 space-y-1 mb-2">
                  {a.source_ip && a.source_ip !== 'unknown' && (
                    <div>Source IP: {a.source_ip}</div>
                  )}
                  {a.attempt_count != null && (
                    <div>Failed attempts: {a.attempt_count}</div>
                  )}
                  {a.detail && <div>Detail: {a.detail}</div>}
                  {report.cve_matches
                    ?.filter((c) => c.linked_anomaly === a.type)
                    .slice(0, 2)
                    .map((c) => (
                      <div key={c.id}>
                        Related CVE: {c.id} (CVSS {c.cvss_score})
                      </div>
                    ))}
                </div>
                {a.recommendation && (
                  <p className="text-sm text-gray-300">
                    <span className="text-green-400 font-medium">Fix: </span>
                    {a.recommendation}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}

      {headerVulns.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-widest mb-2">
            Missing Security Headers
          </h4>
          <div className="space-y-2">
            {headerVulns.map((v, i) => (
              <div
                key={i}
                className="rounded-lg border border-yellow-900/60 bg-yellow-950/20 px-4 py-3 text-sm"
              >
                <div className="text-yellow-400 font-medium mb-1">{v.header}</div>
                {v.recommendation && (
                  <p className="text-gray-300">
                    <span className="text-green-400 font-medium">Fix: </span>
                    {v.recommendation}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
