import { API_URL } from './config'

export const apiClient = {
  get: async (endpoint) => {
    const res = await fetch(`${API_URL}${endpoint}`)
    return res.json()
  },
  post: async (endpoint, data) => {
    const res = await fetch(`${API_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
    return res.json()
  }
}