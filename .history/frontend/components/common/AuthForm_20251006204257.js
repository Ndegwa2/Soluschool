import { useState } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import useSWR from 'swr'
import { apiClient } from '../../lib/api'
import { login } from '../../lib/auth'
import { useAuth } from '../../lib/AuthContext'

const AuthForm = ({ isLogin = true, onSuccess }) => {
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { register, handleSubmit, formState: { errors }, control } = useForm()
  const { refreshAuth } = useAuth()
  const role = useWatch({ control, name: 'role' })
  const { data: schools } = useSWR(isLogin ? null : '/api/schools', (url) => apiClient.get(url, false))

  const onSubmit = async (data) => {
    setError('')
    setLoading(true)
    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      const response = await apiClient.post(endpoint, data, false) // no auth for auth endpoints
      console.log('Auth response:', response)
      login(response.token)
      console.log('Token stored')
      refreshAuth() // Update AuthContext state
      console.log('AuthContext refreshed')
      // Redirect will happen via useEffect in login.js when state updates
    } catch (err) {
      setError(err.message || 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      {!isLogin && (
        <>
          <input
            {...register('name', { required: 'Name is required' })}
            type="text"
            placeholder="Full Name"
          />
          {errors.name && <p className="error">{errors.name.message}</p>}
          <select
            {...register('role', { required: 'Role is required' })}
          >
            <option value="">Select Role</option>
            <option value="parent">Parent</option>
            <option value="teacher">Teacher</option>
            <option value="admin">Admin</option>
          </select>
          {errors.role && <p className="error">{errors.role.message}</p>}
        </>
      )}
      <input
        {...register('email', { required: 'Email is required' })}
        type="email"
        placeholder="Email"
      />
      {errors.email && <p className="error">{errors.email.message}</p>}
      <input
        {...register('password', { required: 'Password is required' })}
        type="password"
        placeholder="Password"
      />
      {errors.password && <p className="error">{errors.password.message}</p>}
      {error && <p className="error">{error}</p>}
      <button
        type="submit"
        disabled={loading}
      >
        {loading ? 'Loading...' : (isLogin ? 'Login' : 'Register')}
      </button>
    </form>
  )
}

export default AuthForm