import { useEffect, useState } from 'react'
import { fetchReport } from '../api'

export default function useScanStream(jobId, onReport) {
  const [stages, setStages] = useState([])
  const [active, setActive] = useState('')
  const [feed, setFeed] = useState([])
  const [failed, setFailed] = useState('')

  useEffect(() => {
    if (!jobId) return
    const es = new EventSource(`http://localhost:8000/scan/${jobId}/stream`)
    const handle = (e) => {
      let data = {}
      try {
        data = JSON.parse(e.data)
      } catch {
        /* ignore malformed frames */
      }
      if (e.type === 'stage_start') {
        setStages((s) => {
          if (s.some((x) => x.name === data.stage)) return s
          return [...s, { name: data.stage, label: data.label }]
        })
        setActive(data.stage)
      } else if (e.type === 'stage_done') {
        setStages((s) =>
          s.map((x) => (x.name === data.stage ? { ...x, status: 'done' } : x)),
        )
        setActive('')
      } else if (e.type === 'stage_failed') {
        setFailed(data.error)
        setActive('')
      } else if (e.type === 'agent_output') {
        setFeed((f) => [...f, { agent: data.agent, line: data.line, id: f.length + 1 }])
      } else if (e.type === 'report_ready') {
        es.close()
        setStages((s) => s.map((x) => ({ ...x, status: 'done' })))
        setActive('')
        setFailed('')
        fetchReport(jobId).then(onReport)
      }
    }
    ;['stage_start', 'stage_done', 'stage_failed', 'agent_output', 'report_ready'].forEach(
      (t) => es.addEventListener(t, handle),
    )
    return () => es.close()
  }, [jobId, onReport])

  return { stages, active, feed, failed }
}
