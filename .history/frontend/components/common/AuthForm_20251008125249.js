import React, { useState } from 'react'
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
  const { data: schools } = useSWR(isLogin ? null : '/api/schools', async (url) => {
    const response = await apiClient.get(url, false)
    if (response.success) {
      return response.data
    } else {
      throw new Error(response.error)
    }
  })

  const onSubmit = async (data) => {
    setError('')
    setLoading(true)
    try {
      if (!isLogin && data.role === 'parent') {
        data.children = [{
          name: data.child_name,
          grade: data.child_grade,
          date_of_birth: data.child_date_of_birth
        }]
        delete data.child_name
        delete data.child_grade
        delete data.child_date_of_birth
      }
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      const response = await apiClient.post(endpoint, data, false) // no auth for auth endpoints
      console.log('Auth response:', response)
      login(response.token, response.user)
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
            <option value="guard">Guard</option>
            <option value="admin">Admin</option>
          </select>
          {errors.role && <p className="error">{errors.role.message}</p>}
          <input
            {...register('phone')}
            type="text"
            placeholder="Phone (optional)"
          />
          {!isLogin && role === 'parent' && (
            <>
              <select {...register('school_id', { required: 'School is required' })}>
                <option value="">Select School</option>
                {schools?.schools?.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
              {errors.school_id && <p className="error">{errors.school_id.message}</p>}
              <input {...register('child_name', { required: 'Child name is required' })} type="text" placeholder="Child Name" />
              {errors.child_name && <p className="error">{errors.child_name.message}</p>}
              <input {...register('child_grade')} type="text" placeholder="Grade" />
              <input {...register('child_date_of_birth')} type="date" placeholder="Date of Birth" />
            </>
          )}
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