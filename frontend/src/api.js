import axios from 'axios'
import { API_ORIGIN } from './config'

const API = axios.create({ baseURL: API_ORIGIN })

export async function startScan({ url, authorizationConfirmed, scanMode }) {
  const { data } = await API.post('/scan', {
    url,
    authorization_confirmed: authorizationConfirmed,
    scan_mode: scanMode,
  })
  return data.job_id
}

export async function fetchReport(jobId) {
  const { data } = await API.get(`/scan/${jobId}/report`)
  return data
}
