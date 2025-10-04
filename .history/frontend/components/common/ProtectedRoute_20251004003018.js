import { useRouter } from 'next/router'
import { useEffect } from 'react'
import { useAuth } from '../../lib/AuthContext'

const ProtectedRoute = ({ children, allowedRoles = [] }) => {
  const { isAuth, role } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!isAuth) {
      router.push('/auth/login')
    } else if (allowedRoles.length > 0 && !allowedRoles.includes(role)) {
      // Redirect based on role
      if (role === 'parent') {
        router.push('/dashboard')
      } else if (role === 'guard') {
        router.push('/scan')
      } else if (role === 'admin') {
        router.push('/admin')
      } else {
        router.push('/auth/login')
      }
    }
  }, [isAuth, role, router, allowedRoles])

  if (!isAuth || (allowedRoles.length > 0 && !allowedRoles.includes(role))) {
    return <div>Loading...</div>
  }

  return children
}

export default ProtectedRoute