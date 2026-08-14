import { groupFindings } from '../lib/severity'
import FindingCard from './FindingCard'

export default function ReportView({ report }) {
  const groups = groupFindings(report.findings)
  return (
    <div>
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8 }}>
          <h2 style={{ fontFamily: 'var(--font-display)', margin: 0, fontSize: 18 }}>
            Report — {report.url}
          </h2>
          <span className="muted mono" style={{ fontSize: 12 }}>
            {report.scan_mode} mode · {report.findings.length} findings
          </span>
        </div>
        {report.screenshots?.length > 0 && (
          <div style={{ display: 'flex', gap: 12, marginTop: 16, flexWrap: 'wrap' }}>
            {report.screenshots.map((s, i) => (
              <a key={i} href={s.file} target="_blank" rel="noreferrer">
                <img
                  src={s.file}
                  alt={`screenshot ${i + 1}`}
                  style={{
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                    height: 120,
                  }}
                />
              </a>
            ))}
          </div>
        )}
        <div style={{ display: 'flex', gap: 16, marginTop: 16, flexWrap: 'wrap' }}>
          {Object.entries(report.summary.by_severity).map(([sev, n]) => (
            <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span
                style={{
                  color: `var(--sev-${sev})`,
                  border: `1px solid var(--sev-${sev})`,
                  borderRadius: 4,
                  padding: '1px 8px',
                  fontSize: 11,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                }}
              >
                {sev}
              </span>
              <span style={{ fontSize: 18, fontFamily: 'var(--font-display)' }}>{n}</span>
            </div>
          ))}
        </div>

        {report.summary.risk_score != null && (
          <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
            <span className="field-label" style={{ margin: 0 }}>Risk score</span>
            <div
              style={{
                width: 220,
                height: 8,
                borderRadius: 4,
                background: 'var(--border)',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  width: `${report.summary.risk_score}%`,
                  height: '100%',
                  background:
                    report.summary.risk_score >= 70
                      ? 'var(--sev-critical)'
                      : report.summary.risk_score >= 35
                      ? 'var(--sev-high)'
                      : 'var(--sev-medium)',
                }}
              />
            </div>
            <span className="mono" style={{ fontSize: 13 }}>{report.summary.risk_score} / 100</span>
          </div>
        )}
      </div>

      {report.executive_summary && (
        <div className="card" style={{ marginBottom: 20 }}>
          <span className="field-label" style={{ marginBottom: 8 }}>Executive summary</span>
          <p style={{ margin: 0, color: 'var(--text-primary)', fontSize: 14.5 }}>{report.executive_summary}</p>
          {report.summary?.warnings?.length > 0 && (
            <div style={{ marginTop: 12, padding: '10px 12px', border: '1px solid var(--sev-high)', borderRadius: 6, background: 'color-mix(in srgb, var(--sev-high) 8%, transparent)' }}>
              <span className="field-label" style={{ marginBottom: 4 }}>Scan warnings</span>
              {report.summary.warnings.map((w, i) => (
                <div key={i} style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{w}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {report.top_risks?.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <span className="field-label" style={{ marginBottom: 12 }}>Top risks to fix first</span>
          {report.top_risks.map((r, i) => (
            <div
              key={i}
              style={{
                display: 'flex',
                gap: 12,
                alignItems: 'baseline',
                padding: '8px 0',
                borderBottom: i < report.top_risks.length - 1 ? '1px solid var(--border)' : 'none',
              }}
            >
              <span
                style={{
                  color: `var(--sev-${r.severity})`,
                  border: `1px solid var(--sev-${r.severity})`,
                  borderRadius: 4,
                  padding: '0 6px',
                  fontSize: 10,
                  textTransform: 'uppercase',
                  flex: 'none',
                }}
              >
                {r.severity}
              </span>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600 }}>{r.title}</div>
                <div className="mono" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{r.location}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {groups.map(({ category, findings }) => (
        <div key={category} style={{ marginBottom: 24 }}>
          <h3
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 13,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: 'var(--text-secondary)',
              margin: '0 0 10px',
            }}
          >
            {category} · {findings.length}
          </h3>
          {findings.map((f) => (
            <FindingCard key={f.finding_id} finding={f} jobId={report.job_id} />
          ))}
        </div>
      ))}
    </div>
  )
}