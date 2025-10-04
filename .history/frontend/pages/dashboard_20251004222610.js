import useSWR from 'swr'
import Link from 'next/link'
import { useRouter } from 'next/router'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'
import { logout } from '../lib/auth'

const fetcher = (url) => apiClient.get(url)

export default function Dashboard() {
  const { data: children, error: childrenError } = useSWR('/api/children', fetcher)
  const { data: qrList, error: qrError } = useSWR('/api/qr/list', fetcher)
  const { data: logs, error: logsError } = useSWR('/api/logs', fetcher)

  const activeQRs = qrList?.filter(qr => qr.status === 'active') || []
  const recentLogs = logs?.slice(0, 5) || []

  return (
    <ProtectedRoute allowedRoles={['parent', 'admin']}>
      <div className="min-h-screen bg-gray-100">
        <div className="max-w-7xl mx-auto py-6 px-4">
          <h1 className="text-3xl font-bold mb-6">Parent Dashboard</h1>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold">Children</h3>
              <p className="text-2xl">{children?.length || 0}</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold">Active QR Codes</h3>
              <p className="text-2xl">{activeQRs.length}</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold">Recent Pickups</h3>
              <p className="text-2xl">{recentLogs.length}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold mb-4">Quick Actions</h3>
              <div className="space-y-2">
                <button className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600">
                  Generate QR Code
                </button>
                <button className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600">
                  View Children
                </button>
                <button className="w-full bg-purple-500 text-white p-2 rounded hover:bg-purple-600">
                  View History
                </button>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold mb-4">Recent Activity</h3>
              <ul className="space-y-2">
                {recentLogs.map((log, index) => (
                  <li key={index} className="text-sm">
                    {log.child_name} picked up at {new Date(log.timestamp).toLocaleString()}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </ProtectedRoute>
  )
}