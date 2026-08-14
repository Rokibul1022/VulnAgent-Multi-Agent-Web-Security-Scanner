import { useState } from 'react'
import { sevColor } from '../lib/severity'

const VERDICTS = [
  { key: 'true_positive', label: 'True positive' },
  { key: 'false_positive', label: 'False positive' },
  { key: 'uncertain', label: 'Uncertain' },
]

export default function FindingCard({ finding, jobId }) {
  const [open, setOpen] = useState(false)
  const [sent, setSent] = useState('')

  async function sendVerdict(verdict) {
    if (sent) return
    setSent(verdict)
    try {
      await fetch('http://localhost:8000/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_id: finding.finding_id,
          job_id: jobId || '',
          url: finding.location,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          verdict,
        }),
      })
    } catch (e) {
      setSent('')
    }
  }

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${sevColor(finding.severity)}`,
        borderRadius: 'var(--radius)',
        background: 'var(--surface)',
        marginBottom: 10,
      }}
    >
      <button
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex',
          width: '100%',
          alignItems: 'center',
          gap: 12,
          background: 'none',
          border: 'none',
          padding: '12px 16px',
          cursor: 'pointer',
          color: 'var(--text-primary)',
          textAlign: 'left',
          fontFamily: 'var(--font-body)',
        }}
      >
        <span
          style={{
            color: sevColor(finding.severity),
            border: `1px solid ${sevColor(finding.severity)}`,
            borderRadius: 4,
            padding: '1px 8px',
            fontSize: 11,
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            whiteSpace: 'nowrap',
          }}
        >
          {finding.severity}
        </span>
        <span style={{ fontWeight: 600, fontSize: 14 }}>{finding.title}</span>
        <span className="muted mono" style={{ marginLeft: 'auto', fontSize: 12 }}>
          {finding.source_tool}
        </span>
      </button>
      {open && (
        <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border)' }}>
          <p style={{ margin: '12px 0', color: 'var(--text-secondary)', fontSize: 14 }}>
            {finding.description}
          </p>
          <div style={{ margin: '8px 0' }}>
            <span className="field-label">Location</span>
            <code className="mono" style={{ color: 'var(--accent)' }}>{finding.location}</code>
            {finding.cwe && (
              <span className="mono" style={{ color: 'var(--text-secondary)', marginLeft: 12 }}>
                {finding.cwe}
              </span>
            )}
          </div>
          {finding.raw_evidence && (
            <div>
              <span className="field-label">Raw evidence</span>
              <pre
                className="mono"
                style={{
                  background: 'var(--bg)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: 10,
                  overflowX: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  color: 'var(--text-secondary)',
                  fontSize: 12,
                }}
              >
                {finding.raw_evidence}
              </pre>
            </div>
          )}
          {finding.hint && (
            <div>
              <span className="field-label">Remediation direction</span>
              <p style={{ margin: '4px 0 0', fontSize: 14 }}>{finding.hint}</p>
            </div>
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            {VERDICTS.map((v) => (
              <button
                key={v.key}
                onClick={() => sendVerdict(v.key)}
                disabled={!!sent}
                style={{
                  border: '1px solid var(--border)',
                  background: sent === v.key ? 'var(--accent)' : 'var(--bg)',
                  color: sent === v.key ? '#fff' : 'var(--text-secondary)',
                  borderRadius: 'var(--radius)',
                  padding: '4px 10px',
                  fontSize: 12,
                  cursor: 'pointer',
                }}
              >
                {sent === v.key ? 'Saved' : v.label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}