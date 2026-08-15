export default function Hero({ onStart }) {
  return (
    <section className="hero">
      <p className="hero-kicker">multi-agent web vulnerability scanner</p>
      <h1 className="hero-title">
        Scan your website.
      </h1>
      <p className="hero-sub">
        VulnAgent deploys a swarm of security agents — subdomain enumeration, port and
        TLS analysis, content discovery, injection and secret detection — and profiles
        your site with an LLM-assisted triage before it ever goes live. Every scan makes
        the agents smarter: past verdicts and your feedback sharpen future results.
      </p>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 28 }}>
        <button className="btn" onClick={onStart}>
          Start a scan
        </button>
        <span className="hero-stats mono">
          19 agents &middot; 6-stage pipeline &middot; ~60s light scan
        </span>
      </div>
      <div className="hero-grid" style={{ marginTop: 32 }}>
        {[
          ['Attack surface', 'subdomains, DNS, ports, WAF'],
          ['Recon', 'crawl, forms, tech fingerprint'],
          ['Discovery', 'dirs, exposure, CMS, screenshots'],
          ['Scanning', 'nuclei, TLS, CORS, JWT, ZAP, secrets, sqlmap'],
        ].map(([t, s]) => (
          <div key={t} className="hero-tile">
            <div style={{ fontWeight: 600, fontSize: 14 }}>{t}</div>
            <div className="muted mono" style={{ fontSize: 12, marginTop: 4 }}>
              {s}
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
