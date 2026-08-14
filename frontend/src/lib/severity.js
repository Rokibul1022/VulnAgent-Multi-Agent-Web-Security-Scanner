const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

export function sevColor(sev) {
  return `var(--sev-${sev in SEV_LABEL ? sev : 'info'})`
}

export function groupFindings(findings) {
  const map = {}
  for (const f of findings) {
    const key = f.category || 'Other'
    if (!map[key]) map[key] = {}
    map[key][f.severity] = [...(map[key][f.severity] || []), f]
  }
  const cats = Object.entries(map)
    .map(([category, bySev]) => ({
      category,
      findings: Object.entries(bySev)
        .sort(([a], [b]) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))
        .flatMap(([, items]) => items),
    }))
    .sort((a, b) => b.findings.length - a.findings.length)
  return cats
}