import { useRouter } from 'next/router'
import { useEffect } from 'react'
import AuthForm from '../../components/common/AuthForm'
import { isAuthenticated, getUserRole } from '../../lib/auth'

export default function Login() {
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
    const role = getUserRole()
    if (role === 'parent') {
      router.push('/dashboard')
    } else if (role === 'guard') {
      router.push('/qr-codes')
    } else if (role === 'admin') {
      router.push('/dashboard')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="text-center">
        <AuthForm isLogin={true} onSuccess={handleSuccess} />
        <p className="mt-4 text-sm text-gray-600">
          Do not have an account?{' '}
          <a href="/auth/register" className="text-blue-500 hover:text-blue-700">
            Register here
          </a>
        </p>
      </div>
    </div>
  )
}