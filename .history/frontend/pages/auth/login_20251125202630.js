import React, { useEffect } from 'react'
import { useRouter } from 'next/router'
import Link from 'next/link'
import AuthForm from '../../components/common/AuthForm'
import { isAuthenticated, getUserRole } from '../../lib/auth'
import { useAuth } from '../../lib/AuthContext'

export default function Login() {
  const router = useRouter()
  const { isAuth, role } = useAuth()

  useEffect(() => {
    if (isAuth) {
      if (role === 'parent' || role === 'admin') {
        router.push('/dashboard')
      } else if (role === 'guard') {
        router.push('/guard-dashboard')
      }
    }
  }, [isAuth, role, router])

  return (
    <div className="login-page">
      <div className="form-container">
        <img src="/Qreetlogo.png" alt="Qreet Logo" />
        <h2>Welcome Back</h2>
        <p>Log in to your account</p>

        <AuthForm isLogin={true} />

        <Link href="/auth/register">Don't have an account? Sign up</Link>
      </div>
    </div>
  )
}