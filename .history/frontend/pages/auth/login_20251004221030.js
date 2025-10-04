import { useRouter } from 'next/router'
import { useEffect } from 'react'
import Link from 'next/link'
import AuthForm from '../../components/common/AuthForm'
import { isAuthenticated, getUserRole } from '../../lib/auth'

export default function Login() {
  const router = useRouter()

  useEffect(() => {
    console.log('Login useEffect: isAuth:', isAuthenticated(), 'role:', getUserRole())
    if (isAuthenticated()) {
      const role = getUserRole()
      console.log('Redirecting based on role:', role)
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
    console.log('handleSuccess called')
    const role = getUserRole()
    console.log('Role for redirect:', role)
    if (role === 'parent') {
      router.push('/dashboard')
    } else if (role === 'guard') {
      router.push('/qr-codes')
    } else if (role === 'admin') {
      router.push('/dashboard')
    }
  }

  return (
    <div className="form-container">
      <img src="/logo.png" alt="App Logo" />
      <h2>Welcome Back</h2>
      <p>Log in to your account</p>

      <AuthForm isLogin={true} onSuccess={handleSuccess} />

      <Link href="/auth/register">Don't have an account? Sign up</Link>
    </div>
  )
}