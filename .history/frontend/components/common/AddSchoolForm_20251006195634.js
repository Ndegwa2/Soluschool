import { useState } from 'react'
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

  return (
    <div className="bg-white p-6 rounded-lg shadow border">
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
  )
}

export default AddSchoolForm