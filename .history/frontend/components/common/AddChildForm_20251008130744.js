import React, { useState } from 'react'
import { useForm } from 'react-hook-form'
import { apiClient } from '../../lib/api'

const AddChildForm = ({ onSuccess, onCancel }) => {
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { register, handleSubmit, formState: { errors }, reset } = useForm()

  const onSubmit = async (data) => {
    setError('')
    setLoading(true)
    const response = await apiClient.post('/api/children', data)
    if (response.success) {
      reset()
      onSuccess && onSuccess()
    } else {
      setError(response.error || 'An error occurred')
    }
    setLoading(false)
  }

  return (
    <div className="add-child-form">
      <h3>Add New Child</h3>
      <form onSubmit={handleSubmit(onSubmit)}>
        <div>
          <label>Name</label>
          <input
            {...register('name', { required: 'Name is required' })}
            type="text"
          />
          {errors.name && <p className="text-red-500 text-sm">{errors.name.message}</p>}
        </div>
        <div>
          <label>Grade</label>
          <input
            {...register('grade')}
            type="text"
          />
        </div>
        {error && <p className="text-red-500">{error}</p>}
        <div className="form-buttons">
          <button
            type="submit"
            disabled={loading}
            className="submit-btn"
          >
            {loading ? 'Adding...' : 'Add Child'}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="cancel-btn"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  )
}

export default AddChildForm