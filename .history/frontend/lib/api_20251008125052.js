import { API_URL } from './config'
import { getToken } from './auth'

const getHeaders = (includeAuth = true) => {
  const headers = { 'Content-Type': 'application/json' }
  if (includeAuth) {
    const token = getToken()
    if (token) {
      headers.Authorization = `Bearer ${token}`
    }
  }
  return headers
}

export const apiClient = {
  get: async (endpoint, includeAuth = true) => {
    const res = await fetch(`${API_URL}${endpoint}`, {
      headers: getHeaders(includeAuth)
    })
    if (!res.ok) {
      let errorMessage = `API Error: ${res.status} ${res.statusText}`
      try {
        const errorData = await res.json()
        errorMessage = errorData.error || errorMessage
      } catch (e) {
        // Ignore if can't parse JSON
      }
      return { success: false, error: errorMessage }
    }
    const data = await res.json()
    return { success: true, data }
  },
  post: async (endpoint, data, includeAuth = true) => {
    const res = await fetch(`${API_URL}${endpoint}`, {
      method: 'POST',
      headers: getHeaders(includeAuth),
      body: JSON.stringify(data)
    })
    if (!res.ok) {
      let errorMessage = `API Error: ${res.status} ${res.statusText}`
      try {
        const errorData = await res.json()
        errorMessage = errorData.error || errorMessage
      } catch (e) {
        // Ignore if can't parse JSON
      }
      return { success: false, error: errorMessage }
    }
    const responseData = await res.json()
    return { success: true, data: responseData }
  },
  put: async (endpoint, data, includeAuth = true) => {
    const res = await fetch(`${API_URL}${endpoint}`, {
      method: 'PUT',
      headers: getHeaders(includeAuth),
      body: JSON.stringify(data)
    })
    if (!res.ok) {
      let errorMessage = `API Error: ${res.status} ${res.statusText}`
      try {
        const errorData = await res.json()
        errorMessage = errorData.error || errorMessage
      } catch (e) {
        // Ignore if can't parse JSON
      }
      return { success: false, error: errorMessage }
    }
    const responseData = await res.json()
    return { success: true, data: responseData }
  },
  delete: async (endpoint, includeAuth = true) => {
    const res = await fetch(`${API_URL}${endpoint}`, {
      method: 'DELETE',
      headers: getHeaders(includeAuth)
    })
    if (!res.ok) {
      let errorMessage = `API Error: ${res.status} ${res.statusText}`
      try {
        const errorData = await res.json()
        errorMessage = errorData.error || errorMessage
      } catch (e) {
        // Ignore if can't parse JSON
      }
      return { success: false, error: errorMessage }
    }
    const responseData = await res.json()
    return { success: true, data: responseData }
  }
}