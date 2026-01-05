import { jwtDecode } from 'jwt-decode'

export const isAuthenticated = () => {
  if (typeof window === 'undefined') return false
  const token = getToken()
  if (!token) return false
  try {
    const decoded = jwtDecode(token)
    // Check if token is expired
    if (decoded.exp * 1000 < Date.now()) {
      console.log('Token expired')
      logout()
      return false
    }
    return true
  } catch (error) {
    console.error('Token decode error:', error)
    logout()
    return false
  }
}

export const getToken = () => {
  if (typeof window === 'undefined') return null
  return localStorage.getItem('token')
}

export const getUserRole = () => {
  const token = getToken()
  if (!token) return null
  try {
    const decoded = jwtDecode(token)
    // Backend sends role in additional claims
    return decoded.role
  } catch (error) {
    console.error('Role decode error:', error)
    return null
  }
}

export const getUserId = () => {
  const token = getToken()
  if (!token) return null
  try {
    const decoded = jwtDecode(token)
    // Backend sends identity as 'sub' claim
    return decoded.sub ? parseInt(decoded.sub) : null
  } catch (error) {
    console.error('User ID decode error:', error)
    return null
  }
}

export const login = (token, user) => {
  if (typeof window === 'undefined') return
  console.log('Storing auth data:', { token: token?.substring(0, 20) + '...', user })
  localStorage.setItem('token', token)
  localStorage.setItem('user', JSON.stringify(user))
}

export const getUserSchoolId = () => {
  if (typeof window === 'undefined') return null
  const user = localStorage.getItem('user')
  if (!user) return null
  try {
    const parsed = JSON.parse(user)
    return parsed.school_id
  } catch (error) {
    console.error('School ID parse error:', error)
    return null
  }
}

export const getUserData = () => {
  if (typeof window === 'undefined') return null
  const user = localStorage.getItem('user')
  if (!user) return null
  try {
    return JSON.parse(user)
  } catch (error) {
    console.error('User data parse error:', error)
    return null
  }
}

export const logout = () => {
  if (typeof window === 'undefined') return
  localStorage.removeItem('token')
  localStorage.removeItem('user')
}