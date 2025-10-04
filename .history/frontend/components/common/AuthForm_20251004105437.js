import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { apiClient } from '../../lib/api'
import { login } from '../../lib/auth'

const AuthForm = ({ isLogin = true, onSuccess }) => {
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { register, handleSubmit, formState: { errors } } = useForm()

  const onSubmit = async (data) => {
    setError('')
    setLoading(true)
    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      const response = await apiClient.post(endpoint, data, false) // no auth for auth endpoints
      console.log('Auth response:', response)
      login(response.token)
      console.log('Token stored')
      onSuccess && onSuccess()
    } catch (err) {
      setError(err.message || 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      {!isLogin && <h2 className="text-2xl font-bold mb-4">Register</h2>}
        {!isLogin && (
          <>
            <div>
              <label className="block text-gray-600 mb-1">Name</label>
              <input
                {...register('name', { required: 'Name is required' })}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-400 focus:outline-none"
                type="text"
              />
              {errors.name && <p className="text-red-500 text-sm">{errors.name.message}</p>}
            </div>
            <div>
              <label className="block text-gray-600 mb-1">Role</label>
              <select
                {...register('role', { required: 'Role is required' })}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-400 focus:outline-none"
              >
                <option value="">Select Role</option>
                <option value="parent">Parent</option>
                <option value="guard">Guard</option>
                <option value="admin">Admin</option>
              </select>
              {errors.role && <p className="text-red-500 text-sm">{errors.role.message}</p>}
            </div>
          </>
        )}
        <div>
          <label className="block text-gray-600 mb-1">Email</label>
          <input
            {...register('email', { required: 'Email is required' })}
            className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-400 focus:outline-none"
            type="email"
          />
          {errors.email && <p className="text-red-500 text-sm">{errors.email.message}</p>}
        </div>
        <div>
          <label className="block text-gray-600 mb-1">Password</label>
          <input
            {...register('password', { required: 'Password is required' })}
            className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-400 focus:outline-none"
            type="password"
          />
          {errors.password && <p className="text-red-500 text-sm">{errors.password.message}</p>}
        </div>
        {error && <p className="text-red-500">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600 disabled:opacity-50"
        >
          {loading ? 'Loading...' : (isLogin ? 'Login' : 'Register')}
        </button>
    </form>
  )
}

export default AuthForm