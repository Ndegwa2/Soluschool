import React, { useRouter, useEffect } from 'next/router'
import Link from 'next/link'
import AuthForm from '../../components/common/AuthForm'
import { isAuthenticated, getUserRole } from '../../lib/auth'
import { useAuth } from '../../lib/AuthContext'

export default function Login() {
  const router = useRouter()
  const { isAuth, role } = useAuth()

  useEffect(() => {
    console.log('Login useEffect: isAuth:', isAuth, 'role:', role)
    if (isAuth) {
      console.log('Redirecting based on role:', role)
      if (role === 'parent' || role === 'admin') {
        router.push('/dashboard')
      } else if (role === 'guard') {
        router.push('/guard-dashboard')
      }
    }
  }, [isAuth, role, router])

  return (
    <div className="form-container">
      <img src="/qreetlogo.png" alt="Qreet Logo" />
      <h2>Welcome Back</h2>
      <p>Log in to your account</p>

      <AuthForm isLogin={true} />

      <Link href="/auth/register">Don't have an account? Sign up</Link>
    </div>
  )
}