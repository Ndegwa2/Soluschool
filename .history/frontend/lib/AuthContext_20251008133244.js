import { createContext, useContext, useState, useEffect } from 'react'
import { useRouter } from 'next/router'
import { isAuthenticated, getUserRole, getUserSchoolId, logout } from './auth'

const AuthContext = createContext()

export const useAuth = () => useContext(AuthContext)

export const AuthProvider = ({ children }) => {
  const [isAuth, setIsAuth] = useState(false)
  const [role, setRole] = useState(null)
  const [schoolId, setSchoolId] = useState(null)
  const router = useRouter()

  useEffect(() => {
    setIsAuth(isAuthenticated())
    setRole(getUserRole())
    setSchoolId(getUserSchoolId())
  }, [])

  const handleLogout = () => {
    logout()
    setIsAuth(false)
    setRole(null)
    setSchoolId(null)
    router.push('/auth/login')
  }

  const refreshAuth = () => {
    console.log('refreshAuth called')
    setIsAuth(isAuthenticated())
    setRole(getUserRole())
    setSchoolId(getUserSchoolId())
    console.log('Auth state updated: isAuth:', isAuthenticated(), 'role:', getUserRole(), 'schoolId:', getUserSchoolId())
  }

  return (
    <AuthContext.Provider value={{ isAuth, role, schoolId, logout: handleLogout, refreshAuth }}>
      {children}
    </AuthContext.Provider>
  )
}