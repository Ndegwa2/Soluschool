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
    <form onSubmit={handleSubmit(onSubmit)}>
      {!isLogin && <h2>Register</h2>}
        {!isLogin && (
          <>
            <div>
              <label>Name</label>
              <input
                {...register('name', { required: 'Name is required' })}
                type="text"
              />
              {errors.name && <p className="error">{errors.name.message}</p>}
            </div>
            <div>
              <label>Role</label>
              <select
                {...register('role', { required: 'Role is required' })}
              >
                <option value="">Select Role</option>
                <option value="parent">Parent</option>
                <option value="guard">Guard</option>
                <option value="admin">Admin</option>
              </select>
              {errors.role && <p className="error">{errors.role.message}</p>}
            </div>
          </>
        )}
        <div>
          <label>Email</label>
          <input
            {...register('email', { required: 'Email is required' })}
            type="email"
          />
          {errors.email && <p className="error">{errors.email.message}</p>}
        </div>
        <div>
          <label>Password</label>
          <input
            {...register('password', { required: 'Password is required' })}
            type="password"
          />
          {errors.password && <p>{errors.password.message}</p>}
        </div>
        {error && <p>{error}</p>}
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