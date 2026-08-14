import { useEffect, useRef } from 'react'

export default function ProgressView({ url, mode, stages, active, feed, failed }) {
  const feedRef = useRef(null)

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight
  }, [feed])

  return (
    <div>
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
          <h2 style={{ fontFamily: 'var(--font-display)', margin: 0, fontSize: 18 }}>
            Scan in progress
          </h2>
          <span className="muted mono">{url} · {mode} mode</span>
        </div>
        <div style={{ display: 'flex', gap: 8, marginTop: 20, flexWrap: 'wrap' }}>
          {stages.length === 0 && (
            <span className="muted" style={{ fontSize: 13 }}>Waiting for stage events…</span>
          )}
          {stages.map((s) => {
            const isActive = active === s.name
            return (
              <div
                key={s.name}
                style={{
                  padding: '6px 12px',
                  borderRadius: 'var(--radius)',
                  border: '1px solid var(--border)',
                  fontSize: 13,
                  background:
                    s.status === 'done'
                      ? 'var(--accent-dim)'
                      : isActive
                      ? 'var(--surface-raised)'
                      : 'transparent',
                  color:
                    s.status === 'done'
                      ? '#EDE6DA'
                      : isActive
                      ? 'var(--accent)'
                      : 'var(--text-secondary)',
                }}
              >
                {s.label}
              </div>
            )
          })}
        </div>
        {failed && (
          <p style={{ color: 'var(--sev-critical)', fontSize: 14, marginBottom: 0 }}>
            A stage failed: {failed}
          </p>
        )}
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
          <span className="field-label" style={{ marginBottom: 0 }}>Signal feed</span>
          <span className="muted mono" style={{ fontSize: 12 }}>live</span>
        </div>
        <div
          ref={feedRef}
          style={{
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: 12,
            height: 320,
            overflowY: 'auto',
            fontFamily: 'var(--font-mono)',
            fontSize: 12.5,
            lineHeight: 1.7,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}
        >
          {feed.length === 0 && <span className="muted">Waiting for agents…</span>}
          {feed.map((f) => (
            <div key={f.id}>
              <span style={{ color: 'var(--accent-dim)' }}>[{f.agent}]</span>{' '}
              <span className="muted">{f.line}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
