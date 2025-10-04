import { createContext, useContext, useState, useEffect } from 'react'
import { isAuthenticated, getUserRole, logout } from './auth'

const AuthContext = createContext()

export const useAuth = () => useContext(AuthContext)

export const AuthProvider = ({ children }) => {
  const [isAuth, setIsAuth] = useState(false)
  const [role, setRole] = useState(null)

  useEffect(() => {
    setIsAuth(isAuthenticated())
    setRole(getUserRole())
  }, [])

  const handleLogout = () => {
    logout()
    setIsAuth(false)
    setRole(null)
  }

  const refreshAuth = () => {
    setIsAuth(isAuthenticated())
    setRole(getUserRole())
  }

  return (
    <AuthContext.Provider value={{ isAuth, role, logout: handleLogout, refreshAuth }}>
      {children}
    </AuthContext.Provider>
  )
}