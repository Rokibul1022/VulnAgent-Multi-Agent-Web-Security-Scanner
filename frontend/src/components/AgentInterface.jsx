const CATALOG = [
  {
    stage: 'surface',
    label: 'Attack Surface',
    agents: [
      ['surface_subdomains', 'Subdomains'],
      ['surface_dns', 'DNS'],
      ['surface_ports', 'Ports'],
      ['surface_waf', 'WAF'],
      ['surface_amass', 'Amass'],
    ],
  },
  {
    stage: 'recon',
    label: 'Recon',
    agents: [
      ['recon', 'Crawler'],
    ],
  },
  {
    stage: 'discovery',
    label: 'Content Discovery',
    agents: [
      ['discovery_exposure', 'Exposure'],
      ['discovery_dirs', 'Dir Brute'],
      ['discovery_cms', 'CMS'],
      ['discovery_screenshot', 'Screenshot'],
    ],
  },
  {
    stage: 'scans',
    label: 'Scanning',
    agents: [
      ['scan_headers', 'Headers'],
      ['scan_nuclei', 'Nuclei'],
      ['scan_tls', 'TLS'],
      ['scan_cors', 'CORS'],
      ['scan_jwt', 'JWT'],
      ['scan_open_redirect', 'Open Redirect'],
      ['scan_zap', 'ZAP'],
      ['scan_secrets', 'Secrets'],
      ['scan_sqlmap', 'SQLmap'],
    ],
  },
  {
    stage: 'triage',
    label: 'Triage',
    agents: [['triage', 'LLM']],
  },
  {
    stage: 'report',
    label: 'Report',
    agents: [['report', 'Builder']],
  },
]

const FINDING_RE = /(high|medium|low|info|critical):\s|(\d+)\s+(finding|hit)/

function agentStatus(name, doneStages, active, feed) {
  const stage = CATALOG.find((g) => g.agents.some(([n]) => n === name))
  const stageDone = stage && doneStages.includes(stage.stage)
  const lines = feed.filter((f) => f.agent === name)
  if (lines.some((f) => FINDING_RE.test(f.line))) return 'found'
  if (stageDone && lines.length > 0) return 'done'
  if (lines.length > 0 || active === stage?.stage) return 'active'
  if (stageDone) return 'done'
  return 'idle'
}

const DOT = {
  idle: { background: 'var(--border)' },
  active: { background: 'var(--accent)', animation: 'pulse 1.1s infinite' },
  done: { background: '#4A8A5E' },
  found: { background: 'var(--sev-high)' },
}

export default function AgentInterface({ stages = [], active = '', feed = [] }) {
  const doneStages = stages.filter((s) => s.status === 'done').map((s) => s.name)

  return (
    <section className="card" style={{ marginTop: 40 }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          flexWrap: 'wrap',
          gap: 8,
          marginBottom: 20,
        }}
      >
        <div>
          <span className="field-label" style={{ marginBottom: 4 }}>
            Agent interface
          </span>
          <span className="muted" style={{ fontSize: 13 }}>
            The swarm reports live as each agent works.
          </span>
        </div>
        <div className="mono" style={{ display: 'flex', gap: 14, fontSize: 12, color: 'var(--text-secondary)' }}>
          <span><i style={dot('idle')} /> idle</span>
          <span><i style={dot('active')} /> active</span>
          <span><i style={dot('done')} /> done</span>
          <span><i style={dot('found')} /> finding</span>
        </div>
      </div>

      {CATALOG.map((group) => {
        const isStageDone = doneStages.includes(group.stage)
        const isStageActive = active === group.stage
        return (
          <div key={group.stage} style={{ marginBottom: 18 }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: 8,
                marginBottom: 8,
                fontSize: 12,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                color: isStageActive ? 'var(--accent)' : isStageDone ? '#8a9b8f' : 'var(--text-secondary)',
              }}
            >
              {group.label}
              {isStageActive && <span className="mono" style={{ color: 'var(--accent)' }}>▸ running</span>}
              {isStageDone && <span className="mono">✓</span>}
            </div>
            <div className="agent-grid">
              {group.agents.map(([name, label]) => {
                const status = agentStatus(name, doneStages, active, feed)
                const count = feed.filter((f) => f.agent === name).length
                return (
                  <div key={name} className={`agent-tile ${status}`} title={name}>
                    <i style={DOT[status]} />
                    <span style={{ fontSize: 13, fontWeight: 500 }}>{label}</span>
                    <span className="mono agent-sub">{name}</span>
                    {count > 0 && <span className="mono agent-count">{count} sig</span>}
                  </div>
                )
              })}
            </div>
          </div>
        )
      })}
    </section>
  )
}

function dot(status) {
  return {
    display: 'inline-block',
    width: 8,
    height: 8,
    borderRadius: '50%',
    marginRight: 6,
    ...DOT[status],
  }
}
