export const API_ORIGIN = (import.meta.env.VITE_API_ORIGIN || 'http://localhost:8000').replace(/\/+$/, '')

export const apiUrl = (path) => `${API_ORIGIN}${path.startsWith('/') ? path : `/${path}`}`
