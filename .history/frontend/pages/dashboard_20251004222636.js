import useSWR from 'swr'
import Link from 'next/link'
import { useRouter } from 'next/router'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'
import { logout } from '../lib/auth'

const fetcher = (url) => apiClient.get(url)

export default function Dashboard() {
  const router = useRouter()
  const { data: children, error: childrenError } = useSWR('/api/children', fetcher)
  const { data: qrList, error: qrError } = useSWR('/api/qr/list', fetcher)
  const { data: logs, error: logsError } = useSWR('/api/logs', fetcher)

  const activeQRs = qrList?.filter(qr => qr.status === 'active') || []
  const recentLogs = logs?.slice(0, 5) || []

  const handleLogout = () => {
    logout()
    router.push('/')
  }

  return (
    <ProtectedRoute allowedRoles={['parent', 'admin']}>
      <div className="navbar">
        <h1>Qreet Platform</h1>
        <div className="nav-links">
          <Link href="/dashboard">Dashboard</Link>
          <Link href="/children">Schools</Link>
          <Link href="/users">Users</Link>
          <Link href="/history">Logs</Link>
          <a href="#" onClick={handleLogout}>Logout</a>
        </div>
      </div>

      <div className="dashboard">
        <div className="card">
          <h3>Children</h3>
          <p>{children?.length || 0}</p>
        </div>
        <div className="card">
          <h3>Active QR Codes</h3>
          <p>{activeQRs.length}</p>
        </div>
        <div className="card">
          <h3>Recent Pickups</h3>
          <p>{recentLogs.length}</p>
        </div>

        <div className="actions">
          <h3>Quick Actions</h3>
          <Link href="/qr-codes"><button>Generate QR Code</button></Link>
          <Link href="/children"><button>View Children</button></Link>
          <Link href="/history"><button>View History</button></Link>
        </div>
      </div>
    </ProtectedRoute>
  )
}