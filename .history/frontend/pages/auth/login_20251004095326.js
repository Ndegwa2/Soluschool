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
      router.push('/scan')
    } else if (role === 'admin') {
      router.push('/admin')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <AuthForm isLogin={true} onSuccess={handleSuccess} />
    </div>
  )
}