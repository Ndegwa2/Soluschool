import { jwtDecode } from 'jwt-decode'

export const isAuthenticated = () => {
  if (typeof window === 'undefined') return false
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
    return decoded.sub
  } catch {
    return null
  }
}

export const login = (token, user) => {
  localStorage.setItem('token', token)
  localStorage.setItem('user', JSON.stringify(user))
}

export const getUserSchoolId = () => {
  const user = localStorage.getItem('user')
  if (!user) return null
  try {
    const parsed = JSON.parse(user)
    return parsed.school_id
  } catch {
    return null
  }
}

export const logout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
}