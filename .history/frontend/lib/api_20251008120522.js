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

class AuthError extends Error {
  constructor(message) {
    super(message)
    this.name = 'AuthError'
  }
}

export const apiClient = (onAuthError) => ({
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
      throw new Error(errorMessage)
    }
    return res.json()
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
      throw new Error(errorMessage)
    }
    return res.json()
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
      throw new Error(errorMessage)
    }
    return res.json()
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
      if (errorMessage === 'Invalid token' && onAuthError) {
        throw new AuthError(errorMessage)
      }
      throw new Error(errorMessage)
    }
    return res.json()
  }
})