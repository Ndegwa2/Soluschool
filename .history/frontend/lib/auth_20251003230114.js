// Placeholder auth functions
export const isAuthenticated = () => {
  // Check localStorage or context
  return false
}

export const login = (token) => {
  localStorage.setItem('token', token)
}

export const logout = () => {
  localStorage.removeItem('token')
}