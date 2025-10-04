import { useRouter } from 'next/router'
import { useEffect } from 'react'
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
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <AuthForm isLogin={false} onSuccess={handleSuccess} />
    </div>
  )
}