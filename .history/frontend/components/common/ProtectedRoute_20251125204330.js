'use client'

import { useRouter } from 'next/router'
import { useEffect } from 'react'
import { useAuth } from '../../lib/AuthContext'

const ProtectedRoute = ({ children, allowedRoles = [] }) => {
  const { isAuth, role, isLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    console.log('ProtectedRoute useEffect: isAuth:', isAuth, 'role:', role, 'allowedRoles:', allowedRoles)
    if (!isAuth) {
      console.log('Redirecting to login: not authenticated')
      router.push('/auth/login')
    } else if (allowedRoles.length > 0 && !allowedRoles.includes(role)) {
      console.log('Role not allowed, redirecting based on role:', role)
      // Redirect based on role
      if (role === 'parent') {
        router.push('/dashboard')
      } else if (role === 'guard') {
        router.push('/qr-codes')
      } else if (role === 'admin') {
        router.push('/dashboard')
      } else {
        router.push('/auth/login')
      }
    } else {
      console.log('Access allowed')
    }
  }, [isAuth, role, router, allowedRoles])

  if (isLoading || !isAuth || (allowedRoles.length > 0 && !allowedRoles.includes(role))) {
    return <div>Loading...</div>
  }

  return children
}

export default ProtectedRoute