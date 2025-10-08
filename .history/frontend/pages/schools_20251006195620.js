import { useState } from 'react'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import AddSchoolForm from '../components/common/AddSchoolForm'
import { apiClient } from '../lib/api'

const fetcher = (url) => apiClient.get(url)

export default function Schools() {
  const { data: schools, error, mutate } = useSWR('/api/schools', fetcher)
  const [showAddForm, setShowAddForm] = useState(false)

  const handleAddSuccess = () => {
    setShowAddForm(false)
    mutate()
  }

  return (
    <ProtectedRoute allowedRoles={['admin']}>
      <div className="min-h-screen bg-gradient-to-br from-teal-100 to-cyan-100">
        <div className="max-w-4xl mx-auto py-6 px-4">
          <div className="flex justify-between items-center mb-6">
            <h1 className="text-3xl font-bold">Schools</h1>
            <button
              onClick={() => setShowAddForm(true)}
              className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
            >
              Add School
            </button>
          </div>

          {showAddForm && (
            <div className="mb-6">
              <AddSchoolForm onSuccess={handleAddSuccess} onCancel={() => setShowAddForm(false)} />
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {schools?.schools?.map((school) => (
              <div key={school.id} className="bg-white p-4 rounded-lg shadow border">
                <h3 className="font-semibold text-lg">{school.name}</h3>
                <p className="text-sm text-gray-600">{school.address || 'No address provided'}</p>
              </div>
            ))}
          </div>

          {schools?.schools?.length === 0 && !error && (
            <p className="text-center text-gray-500 mt-8">No schools found.</p>
          )}

          {error && (
            <p className="text-center text-red-500 mt-8">Error loading schools: {error.message}</p>
          )}
        </div>
      </div>
    </ProtectedRoute>
  )
}