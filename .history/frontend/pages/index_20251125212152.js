import React, { useEffect } from 'react'
import { useRouter } from 'next/router'
import { isAuthenticated, getUserRole } from '../lib/auth'

export default function Home() {
  const router = useRouter()

  useEffect(() => {
    console.log('Index page: Checking authentication...')
    const authenticated = isAuthenticated()
    console.log('Index page: isAuthenticated result:', authenticated)
    if (authenticated) {
      const role = getUserRole()
      console.log('Index page: User role:', role)
      if (role === 'parent') {
        console.log('Index page: Redirecting to /dashboard')
        router.push('/dashboard')
      } else if (role === 'guard') {
        console.log('Index page: Redirecting to /guard-dashboard')
        router.push('/guard-dashboard')
      } else if (role === 'admin') {
        console.log('Index page: Redirecting to /admin')
        router.push('/admin')
      } else {
        console.log('Index page: Unknown role, redirecting to login')
        router.push('/auth/login')
      }
    } else {
      console.log('Index page: Not authenticated, redirecting to /auth/login')
      router.push('/auth/login')
    }
  }, [router])

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4">Welcome to Qreet Platform</h1>
        <p className="text-gray-600">School pickup management system</p>
        <div className="mt-8">Redirecting...</div>
      </div>
    </div>
  )
}