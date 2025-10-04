import { useRouter } from 'next/router'
import { useEffect } from 'react'
import Link from 'next/link'
import AuthForm from '../../components/common/AuthForm'
import { isAuthenticated, getUserRole } from '../../lib/auth'

export default function Register() {
  const router = useRouter()

  useEffect(() => {
    if (isAuthenticated()) {
      const role = getUserRole()
      if (role === 'parent') {
        router.push('/dashboard')
      } else if (role === 'guard') {
        router.push('/qr-codes')
      } else if (role === 'admin') {
        router.push('/dashboard')
      }
    }
  }, [router])

  const handleSuccess = () => {
    router.push('/auth/login') // After register, go to login
  }

  return (
    <div className="form-container">
      <img src="/logo.png" alt="App Logo" />
      <h2>Register</h2>
      <p>Create your account</p>
      <AuthForm isLogin={false} onSuccess={handleSuccess} />
      <a href="/auth/login">Already have an account? Login</a>
    </div>
  )
}