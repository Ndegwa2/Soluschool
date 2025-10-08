import { jwtDecode } from 'jwt-decode'

export const isAuthenticated = () => {
  const token = localStorage.getItem('token')
  if (!token) return false
  try {
    const decoded = jwtDecode(token)
    return decoded.exp * 1000 > Date.now()
  } catch {
    return false
  }
}

export const getToken = () => {
  return localStorage.getItem('token')
}

export const getUserRole = () => {
  const token = getToken()
  if (!token) return null
  try {
    const decoded = jwtDecode(token)
    return decoded.role
  } catch {
    return null
  }
}

export const getUserId = () => {
  const token = getToken()
  if (!token) return null
  try {
    const decoded = jwtDecode(token)
    return decoded.id
  } catch {
    return null
  }
}

export const login = (token) => {
  localStorage.setItem('token', token)
}

export const logout = () => {
  localStorage.removeItem('token')
}