import React, { useEffect } from 'react'
import { useRouter } from 'next/router'
import { isAuthenticated, getUserRole } from '../lib/auth'

export default function Home() {
  const router = useRouter()

  useEffect(() => {
    if (isAuthenticated()) {
      const role = getUserRole()
      if (role === 'parent') {
        router.push('/dashboard')
      } else if (role === 'guard') {
        router.push('/guard-dashboard')
      } else if (role === 'admin') {
        router.push('/admin')
      }
    } else {
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