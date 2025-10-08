import { useState } from 'react'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import AddSchoolForm from '../components/common/AddSchoolForm'
import { apiClient } from '../lib/api'
import { getUserId } from '../lib/auth'

const fetcher = (url) => apiClient.get(`${url}?adminId=${getUserId()}`)

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

          <AddSchoolForm isOpen={showAddForm} onSuccess={handleAddSuccess} onCancel={() => setShowAddForm(false)} />

          <div className="bg-white p-6 rounded-lg shadow border mx-auto max-w-4xl">
            <table className="w-full table-auto">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2 px-4 font-semibold">School Name</th>
                  <th className="text-left py-2 px-4 font-semibold">Address</th>
                </tr>
              </thead>
              <tbody>
                {schools?.schools?.map((school) => (
                  <tr key={school.id} className="border-b">
                    <td className="py-2 px-4">{school.name}</td>
                    <td className="py-2 px-4">{school.address || 'No address provided'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
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