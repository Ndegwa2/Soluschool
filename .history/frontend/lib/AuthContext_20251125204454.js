import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/router'
import { isAuthenticated, getUserRole, getUserSchoolId, logout } from './auth'

const AuthContext = createContext()

export const useAuth = () => useContext(AuthContext)

export const AuthProvider = ({ children }) => {
  const [isAuth, setIsAuth] = useState(false)
  const [role, setRole] = useState(null)
  const [schoolId, setSchoolId] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    console.log('[AuthContext] useEffect running - checking auth state')

    // Delay auth check to ensure DOM and localStorage are ready
    const timer = setTimeout(() => {
      const auth = isAuthenticated()
      const userRole = getUserRole()
      const userSchoolId = getUserSchoolId()
      console.log('[AuthContext] Auth state determined after delay:', { auth, userRole, userSchoolId })
      setIsAuth(auth)
      setRole(userRole)
      setSchoolId(userSchoolId)
      setIsLoading(false)
    }, 100) // Small delay to ensure stability

    return () => clearTimeout(timer)
  }, [])

  const handleLogout = () => {
    logout()
    setIsAuth(false)
    setRole(null)
    setSchoolId(null)
    router.push('/auth/login')
  }

  const refreshAuth = () => {
    console.log('[AuthContext] refreshAuth called')
    const auth = isAuthenticated()
    const userRole = getUserRole()
    const userSchoolId = getUserSchoolId()
    console.log('[AuthContext] refreshAuth state:', { auth, userRole, userSchoolId })
    setIsAuth(auth)
    setRole(userRole)
    setSchoolId(userSchoolId)
  }

  return (
    <AuthContext.Provider value={{ isAuth, role, schoolId, isLoading, logout: handleLogout, refreshAuth }}>
      {children}
    </AuthContext.Provider>
  )
}