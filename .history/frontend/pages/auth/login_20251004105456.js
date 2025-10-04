import { useRouter } from 'next/router'
import { useEffect } from 'react'
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
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-blue-100">
      <div className="bg-white p-8 rounded-2xl shadow-lg w-full max-w-md">
        {/* Logo / Title */}
        <div className="text-center mb-6">
          <img src="/logo.png" alt="App Logo" className="mx-auto w-16 h-16" />
          <h1 className="text-2xl font-bold text-gray-800">Welcome Back</h1>
          <p className="text-gray-500 text-sm">Log in to your account</p>
        </div>

        <AuthForm isLogin={true} onSuccess={handleSuccess} />

        {/* Links */}
        <div className="mt-4 text-sm text-center text-gray-600">
          <a href="#" className="text-blue-600 hover:underline">Forgot password?</a>
        </div>
        <div className="mt-2 text-sm text-center text-gray-600">
          Don’t have an account?{" "}
          <a href="/auth/register" className="text-blue-600 font-medium hover:underline">Sign up</a>
        </div>
      </div>
    </div>
  )
}