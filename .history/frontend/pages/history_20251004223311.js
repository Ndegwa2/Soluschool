import { useState } from 'react'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'
import { Search } from 'lucide-react'

const fetcher = (url) => apiClient.get(url)

export default function History() {
  const { data: logs, error } = useSWR('/api/logs', fetcher)
  const [filter, setFilter] = useState('')
  const [sortKey, setSortKey] = useState('timestamp')
  const [sortDirection, setSortDirection] = useState('desc')

  const filteredLogs = logs?.filter(log =>
    !filter || log.child_name.toLowerCase().includes(filter.toLowerCase())
  ) || []

  return (
    <ProtectedRoute allowedRoles={['parent', 'admin']}>
      <div className="min-h-screen" style={{ background: 'linear-gradient(135deg, #43cea2, #185a9d)' }}>
        <div className="max-w-6xl mx-auto py-6 px-4">
          <h1 className="text-3xl font-bold mb-6">Pickup History</h1>

          <div className="bg-white p-6 rounded-lg shadow mb-6">
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={20} />
              <input
                type="text"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Search by child name"
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Child
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Gate
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredLogs.map((log) => (
                  <tr key={log.id}>
                    <td className="px-6 py-4 whitespace-nowrap">{log.child_name}</td>
                    <td className="px-6 py-4 whitespace-nowrap">{log.gate_name}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        log.status === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {filteredLogs.length === 0 && !error && (
            <p className="text-center text-gray-500 mt-8">No pickup history found.</p>
          )}
        </div>
      </div>
    </ProtectedRoute>
  )
}