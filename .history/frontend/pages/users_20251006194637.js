import { useState } from 'react'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'

const fetcher = (url) => apiClient.get(url)

export default function Users() {
  const [page, setPage] = useState(1)
  const limit = 10
  const { data: usersData, error, mutate } = useSWR(`/api/users?page=${page}&limit=${limit}`, fetcher)
  const users = usersData?.users || []
  const total = usersData?.total || 0
  const totalPages = Math.ceil(total / limit)

  const handlePrevPage = () => {
    if (page > 1) setPage(page - 1)
  }

  const handleNextPage = () => {
    if (page < totalPages) setPage(page + 1)
  }

  return (
    <ProtectedRoute allowedRoles={['admin']}>
      <div className="min-h-screen bg-gray-100">
        <div className="max-w-6xl mx-auto py-6 px-4">
          <div className="flex justify-between items-center mb-6">
            <h1 className="text-3xl font-bold">Users</h1>
          </div>

          <div className="bg-white rounded-lg shadow border overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Phone</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">School ID</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {users.map((user) => (
                  <tr key={user.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{user.name}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.email}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.phone || 'N/A'}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.role}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.school_id || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {users.length === 0 && !error && (
            <p className="text-center text-gray-500 mt-8">No users found.</p>
          )}

          {error && (
            <p className="text-center text-red-500 mt-8">Error loading users: {error.message}</p>
          )}

          {totalPages > 1 && (
            <div className="flex justify-center mt-6">
              <button
                onClick={handlePrevPage}
                disabled={page === 1}
                className="bg-blue-500 text-white px-4 py-2 rounded-l hover:bg-blue-600 disabled:opacity-50"
              >
                Previous
              </button>
              <span className="px-4 py-2 bg-gray-200 text-gray-700">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={handleNextPage}
                disabled={page === totalPages}
                className="bg-blue-500 text-white px-4 py-2 rounded-r hover:bg-blue-600 disabled:opacity-50"
              >
                Next
              </button>
            </div>
          )}
        </div>
      </div>
    </ProtectedRoute>
  )
}