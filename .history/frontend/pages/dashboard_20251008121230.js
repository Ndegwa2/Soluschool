import React, { useState, useEffect } from 'react'
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

  const [sortDir, setSortDir] = useState(1)
  const [sortCol, setSortCol] = useState('time')
  const [searchQuery, setSearchQuery] = useState('')
  const [activity, setActivity] = useState([])

  const activeQRs = qrList?.qrs?.filter(qr => qr.is_active) || []
  const allLogs = logs?.logs || []
  const recentLogs = allLogs.slice(0, 5)

  useEffect(() => {
    setActivity(recentLogs.map(log => ({
      text: `${log.child_name} picked up at ${log.gate}`,
      time: new Date(log.timestamp).toLocaleString()
    })))
  }, [logs])

  const pushActivity = (text) => {
    const newActivity = { text, time: 'Just now' }
    setActivity(prev => [newActivity, ...prev])
  }

  const sortTable = (col) => {
    if (sortCol === col) {
      setSortDir(prev => -prev)
    } else {
      setSortCol(col)
      setSortDir(1)
    }
  }

  const filteredLogs = allLogs.filter(log =>
    log.child_name.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const sortedLogs = [...filteredLogs].sort((a, b) => {
    let valA, valB
    switch (sortCol) {
      case 'child':
        valA = a.child_name
        valB = b.child_name
        break
      case 'gate':
        valA = a.gate
        valB = b.gate
        break
      case 'time':
        valA = new Date(a.timestamp)
        valB = new Date(b.timestamp)
        break
      case 'status':
        valA = 'Picked Up' // assuming all are picked up
        valB = 'Picked Up'
        break
      default:
        return 0
    }
    if (sortCol === 'time') {
      return (valA - valB) * sortDir
    }
    return valA.localeCompare(valB) * sortDir
  })

  return (
    <ProtectedRoute allowedRoles={['parent', 'admin']}>
      <main className="container">
        <h1 className="page-title">Dashboard</h1>
        <div className="page-sub">Quick snapshot of todays activity and tools.</div>

        {/* KPI CARDS */}
        <section className="grid kpis">
          <div className="kpi card">
            <div className="icon" aria-hidden="true">🚌</div>
            <div>
              <div className="big" id="kpi-pickups">{analytics?.total_pickups || 0}</div>
              <div className="label">Total Pickups</div>
            </div>
          </div>
          <div className="kpi card">
            <div className="icon" aria-hidden="true">⏰</div>
            <div>
              <div className="big" id="kpi-peak">{analytics?.peak_hour ? `${analytics.peak_hour}:00` : 'N/A'}</div>
              <div className="label">Peak Hour</div>
            </div>
          </div>
          <div className="kpi card">
            <div className="icon" aria-hidden="true">👥</div>
            <div>
              <div className="big" id="kpi-visitors">{analytics?.visitors || 0}</div>
              <div className="label">Visitors Today</div>
            </div>
          </div>
        </section>

        <div className="grid main-grid" style={{ marginTop: '18px' }}>
          {/* LEFT: History + Actions */}
          <section className="grid" style={{ gap: '18px' }}>
            {/* Quick Actions */}
            <article className="card soft">
              <div className="card-header">
                <div className="card-title">Quick Actions</div>
                <div className="card-sub">Frequent tools</div>
              </div>
              <div className="card-body">
                <div className="action-row">
                  <Link href="/qr-codes">
                    <button className="chip-btn" onClick={() => pushActivity('Generated QR code for pickup gate.')}>
                      <span className="chip">▦</span> Generate QR Code
                    </button>
                  </Link>
                  <Link href="/children">
                    <button className="chip-btn">
                      <span className="chip">👶</span> View Children
                    </button>
                  </Link>
                  <Link href="/history">
                    <button className="chip-btn" onClick={() => document.getElementById('history')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}>
                      <span className="chip">🕒</span> View History
                    </button>
                  </Link>
                </div>
              </div>
            </article>

            {/* Pickup History */}
            <article id="history" className="card">
              <div className="card-header">
                <div className="card-title">Pickup History</div>
                <div className="card-sub">Filter and sort</div>
              </div>
              <div className="card-body">
                <div className="searchbar" style={{ marginBottom: '12px' }}>
                  <input
                    id="search"
                    type="text"
                    placeholder="Search by child name…"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
                <div className="table-wrap">
                  <table id="history-table">
                    <thead>
                      <tr>
                        <th data-col="child" onClick={() => sortTable('child')}>Child {sortCol === 'child' ? (sortDir === 1 ? '▾' : '▴') : ''}</th>
                        <th data-col="gate" onClick={() => sortTable('gate')}>Gate {sortCol === 'gate' ? (sortDir === 1 ? '▾' : '▴') : ''}</th>
                        <th data-col="time" onClick={() => sortTable('time')}>Timestamp {sortCol === 'time' ? (sortDir === 1 ? '▾' : '▴') : ''}</th>
                        <th data-col="status" onClick={() => sortTable('status')}>Status {sortCol === 'status' ? (sortDir === 1 ? '▾' : '▴') : ''}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedLogs.length > 0 ? sortedLogs.map((log, index) => (
                        <tr key={index}>
                          <td>{log.child_name}</td>
                          <td>{log.gate}</td>
                          <td>{new Date(log.timestamp).toLocaleString()}</td>
                          <td><span className="status ok">Picked Up</span></td>
                        </tr>
                      )) : (
                        <tr>
                          <td colSpan="4">No logs found</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </article>
          </section>

          {/* RIGHT: Recent Activity */}
          <aside className="card">
            <div className="card-header">
              <div className="card-title">Recent Activity</div>
              <div className="card-sub">Last 24 hours</div>
            </div>
            <div className="card-body">
              <ul id="activity" style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: '10px' }}>
                {activity.length > 0 ? activity.map((item, index) => (
                  <li key={index} className="card" style={{ padding: '12px', border: '1px solid rgba(2,6,23,.06)' }}>
                    <strong>{item.text}</strong><br />
                    <span className="card-sub">{item.time}</span>
                  </li>
                )) : (
                  <li className="card" style={{ padding: '12px', border: '1px solid rgba(2,6,23,.06)' }}>
                    <strong>No activity yet.</strong><br />
                    <span className="card-sub">New events will appear here automatically.</span>
                  </li>
                )}
              </ul>
            </div>
          </aside>
        </div>
      </main>
    </ProtectedRoute>
  )
}