import { useState } from 'react'
import { startScan } from '../api'

const STAGES = [
  ['surface', 'Attack Surface'],
  ['recon', 'Recon'],
  ['discovery', 'Content Discovery'],
  ['scans', 'Scanning'],
  ['triage', 'Triage'],
  ['report', 'Report'],
]

export default function ScanForm({ onScanStart }) {
  const [url, setUrl] = useState('')
  const [authConfirmed, setAuthConfirmed] = useState(false)
  const [fullConfirmed, setFullConfirmed] = useState(false)
  const [mode, setMode] = useState('light')
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')

  async function submit(e) {
    e.preventDefault()
    setError('')
    setStarting(true)
    try {
      const jobId = await startScan({
        url,
        authorizationConfirmed: authConfirmed,
        scanMode: mode,
      })
      onScanStart({ jobId, url, mode })
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
      setStarting(false)
    }
  }

  return (
    <div className="card">
      <form onSubmit={submit}>
        <label className="field-label" htmlFor="url">
          Target URL
        </label>
        <input
          id="url"
          className="text-input"
          type="url"
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          required
        />

        <div style={{ marginTop: 16 }}>
          <span className="field-label">Scan mode</span>
          <div className="segmented">
            <button
              type="button"
              className={mode === 'light' ? 'active' : ''}
              onClick={() => setMode('light')}
            >
              Light / passive
            </button>
            <button
              type="button"
              className={mode === 'full' ? 'active' : ''}
              onClick={() => setMode('full')}
            >
              Full / active
            </button>
          </div>
          <p className="muted" style={{ fontSize: 13, marginTop: 8, marginBottom: 0 }}>
            Full mode runs intrusive tools (sqlmap, full-range nmap, active ZAP) against the
            target. Use only with explicit permission.
          </p>
        </div>

        <label className="check-row">
          <input
            type="checkbox"
            checked={authConfirmed}
            onChange={(e) => setAuthConfirmed(e.target.checked)}
          />
          <span>
            I confirm I own or have written permission to test this domain.
          </span>
        </label>

        {mode === 'full' && (
          <label className="check-row">
            <input
              type="checkbox"
              checked={fullConfirmed}
              onChange={(e) => setFullConfirmed(e.target.checked)}
            />
            <span>I understand full mode runs active/intrusive tools and confirm again.</span>
          </label>
        )}

        {error && (
          <p style={{ color: 'var(--sev-critical)', fontSize: 14 }}>{error}</p>
        )}

        <div style={{ marginTop: 20 }}>
          <button className="btn" type="submit" disabled={starting || !authConfirmed || (mode === 'full' && !fullConfirmed)}>
            {starting ? 'Starting…' : 'Start Scan'}
          </button>
        </div>
      </form>
    </div>
  )
}