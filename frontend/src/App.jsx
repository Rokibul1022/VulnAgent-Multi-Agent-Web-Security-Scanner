import { useState } from 'react'
import ScanForm from './components/ScanForm'
import ProgressView from './components/ProgressView'
import ReportView from './components/ReportView'
import AgentInterface from './components/AgentInterface'
import Hero from './components/Hero'
import useScanStream from './hooks/useScanStream'

export default function App() {
  const [scan, setScan] = useState(null)
  const [report, setReport] = useState(null)

  const { stages, active, feed, failed } = useScanStream(scan?.jobId, (r) => setReport(r))

  function handleScanStart(info) {
    setScan(info)
    setReport(null)
  }

  function handleNewScan() {
    setScan(null)
    setReport(null)
  }

  return (
    <div className="app">
      <header className="masthead">
        <h1>VulnAgent</h1>
        <span>multi-agent web vulnerability scanner</span>
      </header>

      {!scan ? (
        <>
          <Hero onStart={() => document.getElementById('scan-form')?.scrollIntoView({ behavior: 'smooth' })} />
          <div id="scan-form" style={{ marginTop: 36 }}>
            <ScanForm onScanStart={handleScanStart} />
          </div>
          <AgentInterface />
        </>
      ) : (
        <>
          <div style={{ marginBottom: 24 }}>
            <AgentInterface stages={stages} active={active} feed={feed} />
          </div>

          {!report ? (
            <ProgressView
              url={scan.url}
              mode={scan.mode}
              stages={stages}
              active={active}
              feed={feed}
              failed={failed}
            />
          ) : (
            <>
              <ReportView report={report} />
              <div style={{ marginTop: 24 }}>
                <button className="btn ghost" onClick={handleNewScan}>
                  New scan
                </button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
