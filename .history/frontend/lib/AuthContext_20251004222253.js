it import { createContext, useContext, useState, useEffect } from 'react'
import { useRouter } from 'next/router'
import { isAuthenticated, getUserRole, logout } from './auth'

const AuthContext = createContext()

export const useAuth = () => useContext(AuthContext)

export const AuthProvider = ({ children }) => {
  const [isAuth, setIsAuth] = useState(false)
  const [role, setRole] = useState(null)
  const router = useRouter()

  useEffect(() => {
    setIsAuth(isAuthenticated())
    setRole(getUserRole())
  }, [])

  const handleLogout = () => {
    logout()
    setIsAuth(false)
    setRole(null)
    router.push('/auth/login')
  }

  const refreshAuth = () => {
    console.log('refreshAuth called')
    setIsAuth(isAuthenticated())
    setRole(getUserRole())
    console.log('Auth state updated: isAuth:', isAuthenticated(), 'role:', getUserRole())
  }

  return (
    <AuthContext.Provider value={{ isAuth, role, logout: handleLogout, refreshAuth }}>
      {children}
    </AuthContext.Provider>
  )
}