import React, { useState } from 'react'
import { useForm } from 'react-hook-form'
import { apiClient } from '../../lib/api'

const AddSchoolForm = ({ isOpen, onSuccess, onCancel }) => {
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { register, handleSubmit, formState: { errors }, reset } = useForm()

  const onSubmit = async (data) => {
    setError('')
    setLoading(true)
    try {
      await apiClient.post('/api/schools', data)
      reset()
      onSuccess && onSuccess()
    } catch (err) {
      setError(err.message || 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white p-6 rounded-lg shadow-lg max-w-md w-full mx-4">
      <h3 className="text-lg font-semibold mb-4">Add New School</h3>
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div>
          <label className="block text-sm font-medium">School Name</label>
          <input
            {...register('name', { required: 'School name is required' })}
            className="w-full p-2 border rounded"
            type="text"
          />
          {errors.name && <p className="text-red-500 text-sm">{errors.name.message}</p>}
        </div>
        <div>
          <label className="block text-sm font-medium">Address</label>
          <textarea
            {...register('address')}
            className="w-full p-2 border rounded"
            rows="3"
            placeholder="School address (optional)"
          />
        </div>
        {error && <p className="text-red-500">{error}</p>}
        <div className="flex space-x-2">
          <button
            type="submit"
            disabled={loading}
            className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
          >
            {loading ? 'Adding...' : 'Add School'}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600"
          >
            Cancel
          </button>
        </div>
      </form>
      </div>
    </div>
  )
}

export default AddSchoolForm