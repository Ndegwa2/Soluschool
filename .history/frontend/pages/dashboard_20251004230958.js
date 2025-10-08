import Link from 'next/link'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'
import { useAuth } from '../lib/AuthContext'

const fetcher = (url) => apiClient.get(url)

export default function Dashboard() {
  const { role } = useAuth()
  const { data: children, error: childrenError } = useSWR(role === 'parent' ? '/api/children' : null, fetcher)
  const { data: qrList, error: qrError } = useSWR('/api/qr/list', fetcher)
  const { data: logs, error: logsError } = useSWR('/api/logs', fetcher)
  const { data: analytics, error: analyticsError } = useSWR(role === 'admin' ? '/api/analytics/summary' : null, fetcher)

  const activeQRs = qrList?.qrs?.filter(qr => qr.is_active) || []
  const recentLogs = logs?.logs?.slice(0, 5) || []

  return (
    <ProtectedRoute allowedRoles={['parent', 'admin']}>
      <div style={{ fontFamily: 'monospace', backgroundColor: '#000', color: '#0f0', minHeight: '100vh', padding: '20px' }}>
        <div style={{ maxWidth: '800px', margin: '0 auto' }}>
          <h1 style={{ fontSize: '24px', marginBottom: '20px' }}>📊 Dashboard</h1>

          <div style={{ border: '1px solid #0f0', marginBottom: '20px' }}>
            <div style={{ borderBottom: '1px solid #0f0', padding: '10px', textAlign: 'center' }}>
              {role === 'parent' ? (
                <>👶 Children | 📷 Active QR Codes | 📦 Recent Pickups</>
              ) : (
                <>🚌 Total Pickups | ⏰ Peak Hour | 👥 Visitors Today</>
              )}
            </div>
            <div style={{ padding: '10px', textAlign: 'center' }}>
              {role === 'parent' ? (
                <>{children?.children?.length || 0} | {activeQRs.length} | {recentLogs.length}</>
              ) : (
                <>{analytics?.total_pickups || 0} | {analytics?.peak_hour ? `${analytics.peak_hour}:00` : 'N/A'} | {analytics?.visitors || 0}</>
              )}
            </div>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <h2 style={{ fontSize: '18px', marginBottom: '10px' }}>⚡ Quick Actions</h2>
            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <Link href="/qr-codes">
                <button style={{ background: 'none', border: '1px solid #0f0', color: '#0f0', padding: '5px 10px', cursor: 'pointer' }}>
                  📷 Generate QR Code
                </button>
              </Link>
              <Link href="/children">
                <button style={{ background: 'none', border: '1px solid #0f0', color: '#0f0', padding: '5px 10px', cursor: 'pointer' }}>
                  👶 View Children
                </button>
              </Link>
              <Link href="/history">
                <button style={{ background: 'none', border: '1px solid #0f0', color: '#0f0', padding: '5px 10px', cursor: 'pointer' }}>
                  📜 View History
                </button>
              </Link>
            </div>
          </div>

          <div>
            <h2 style={{ fontSize: '18px', marginBottom: '10px' }}>📝 Recent Activity</h2>
            <ul style={{ listStyle: 'none', padding: 0 }}>
              {recentLogs.length > 0 ? recentLogs.map((log, index) => (
                <li key={index} style={{ marginBottom: '5px' }}>
                  - {log.child_name} picked up at {new Date(log.timestamp).toLocaleString()}
                </li>
              )) : (
                <li>- No activity yet</li>
              )}
            </ul>
          </div>
        </div>
      </div>
    </ProtectedRoute>
  )
}