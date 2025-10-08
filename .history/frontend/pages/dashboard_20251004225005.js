import { useState, useMemo } from 'react'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'

const fetcher = (url) => apiClient.get(url)

export default function Dashboard() {
  const { data: logsData, error: logsError } = useSWR('/api/logs', fetcher)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const logs = logsData?.logs || []

  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      const matchesSearch = log.child_name.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesStatus = !statusFilter || log.status === statusFilter
      return matchesSearch && matchesStatus
    })
  }, [logs, searchTerm, statusFilter])

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'approved': return '✅ Picked'
      case 'denied': return '❌ Denied'
      case 'escalated': return '⚠️ Escalated'
      default: return status
    }
  }

  if (logsError) return <div>Error loading pickup history</div>

  return (
    <ProtectedRoute allowedRoles={['parent', 'admin']}>
      <div className="pickup-history">
        <h2>Pickup History</h2>
        <div className="controls">
          <div className="search">
            <span>🔍</span>
            <input
              type="text"
              placeholder="Search by child name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <div className="filter">
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="">All Statuses</option>
              <option value="approved">Picked</option>
              <option value="denied">Denied</option>
              <option value="escalated">Escalated</option>
            </select>
          </div>
        </div>
        <table className="pickup-table">
          <thead>
            <tr>
              <th>Child</th>
              <th>Gate</th>
              <th>Timestamp</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map(log => (
              <tr key={log.id}>
                <td>{log.child_name}</td>
                <td>{log.gate_name}</td>
                <td>{formatTimestamp(log.timestamp)}</td>
                <td>{getStatusIcon(log.status)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!logsData && <div>Loading...</div>}
        {logsData && filteredLogs.length === 0 && <div>No pickups found</div>}
      </div>
    </ProtectedRoute>
  )
}