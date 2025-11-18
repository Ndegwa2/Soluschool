import React, { useState, useEffect } from 'react'
import Link from 'next/link'
import { Html5Qrcode } from 'html5-qrcode'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'
import { getUserSchoolId } from '../lib/auth'
import { useAuth } from '../lib/AuthContext'

export default function Scan() {
   const [scanner, setScanner] = useState(null)
   const [scanning, setScanning] = useState(false)
   const [result, setResult] = useState(null)
   const [currentView, setCurrentView] = useState('scanner')
   const [logs, setLogs] = useState([])
   const [analytics, setAnalytics] = useState(null)
   const [toast, setToast] = useState(null)
   const schoolId = getUserSchoolId()
   const { logout } = useAuth()

  useEffect(() => {
    if (currentView === 'logs') {
      loadLogs()
    } else if (currentView === 'analytics') {
      loadAnalytics('24h')
    }
  }, [currentView])

  useEffect(() => {
    return () => {
      if (scanner) {
        scanner.stop().catch(console.error)
      }
    }
  }, [scanner])


  const switchView = (viewId) => {
    setCurrentView(viewId)
  }

  const startScanner = async () => {

    if (scanner) {
      console.log('Scanner already initialized')
      return
    }

    try {
      const qrScanner = new Html5Qrcode("qr-reader")
      setScanner(qrScanner)

      await qrScanner.start(
        { facingMode: "environment" },
        {
          fps: 10,
          qrbox: { width: 250, height: 250 },
          showTorchButtonIfSupported: true,
          showZoomSliderIfSupported: true,
          rememberLastUsedCamera: true,
        },
        onScanSuccess,
        onScanError
      )

      setScanning(true)
      console.log('Scanner started successfully')
    } catch (error) {
      console.error('Scanner error:', error)
      showToast('Failed to start scanner: ' + error.message, 'error')
    }
  }

  const stopScanner = async () => {
    if (scanner) {
      try {
        await scanner.stop()
        setScanner(null)
        setScanning(false)
      } catch (error) {
        console.error('Stop scanner error:', error)
      }
    }
  }

  const onScanSuccess = async (decodedText) => {
    console.log('QR Code scanned:', decodedText)

    const response = await apiClient.post('/api/verify/scan', {
      qr_data: decodedText,
      gate_id: 1 // Default gate ID
    })

    console.log('API response:', response)

    if (response.success) {
      showResult(response.data)
      if (response.data.status === 'approved') {
        await stopScanner()
        showToast('QR code validated successfully', 'success')
      } else {
        showToast('Access denied', 'error')
      }
      loadLogs()
    } else {
      if (response.error === 'Invalid token') {
        logout()
      } else {
        showToast(response.error || 'Validation failed', 'error')
        showResult({
          status: 'denied',
          reason: response.error
        })
      }
    }
  }

  const onScanError = (error) => {
    // Ignore scan errors (they happen frequently)
  }

  const showResult = (data) => {
    // Normalize data for display
    const normalized = {
      status: data.status,
      child: data.child || (data.qr_info ? { name: 'Unknown' } : undefined),
      parent: data.parent || undefined,
      timestamp: data.timestamp || new Date().toISOString(),
      reason: data.error || undefined
    }
    setResult(normalized)
    setTimeout(() => {
      setResult(null)
    }, 7000)
  }

  const showToast = (message, type = 'info') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  const loadLogs = async () => {
    const response = await apiClient.get('/api/logs?limit=20')
    if (response.success) {
      setLogs(response.data.logs)
    } else {
      console.error('Failed to load logs:', response.error)
      if (response.error === 'Invalid token') {
        logout()
      }
    }
  }

  const loadAnalytics = async (timeRange) => {
    const period = timeRange === '24h' ? 'daily' : 'weekly'
    const response = await apiClient.get(`/api/analytics/summary?period=${period}`)
    if (response.success) {
      setAnalytics(response.data)
    } else {
      console.error('Failed to load analytics:', response.error)
      if (response.error === 'Invalid token') {
        logout()
      }
    }
  }

  const handleManualEntry = async (e) => {
    e.preventDefault()
    const parentId = e.target.parentId.value
    const childId = e.target.childId.value

    const response = await apiClient.post('/api/manual-entry', {
      parent_id: parseInt(parentId),
      child_id: parseInt(childId),
      gate_id: 1 // Default gate ID
    })

    if (response.success) {
      showResult(response.data)
      showToast('Manual entry recorded successfully', 'success')
      e.target.reset()
      loadLogs()
    } else {
      if (response.error === 'Invalid token') {
        logout()
      } else {
        showToast(response.error || 'Manual entry failed', 'error')
        showResult({
          status: 'denied',
          reason: response.error
        })
      }
    }
  }

  return (
    <ProtectedRoute allowedRoles={['guard']}>
      {/* Header */}
      <header className="header">
        <div className="logo">
          <div className="logo-circle"></div>
          <span className="logo-text">Qreet Platform</span>
        </div>
        <nav className="nav-links">
          <Link href="/dashboard" className="nav-link active">Dashboard</Link>
          <Link href="/users" className="nav-link">Users</Link>
          <Link href="/history" className="nav-link">History</Link>
        </nav>
        <button className="logout-btn" onClick={logout}>Logout</button>
      </header>

      <div className="container">
        {/* Page Title */}
        <h1 className="page-title">Guard Dashboard</h1>
        <p className="page-subtitle">
          Monitor guard activity, scan visitor QR codes, and review logs in real time.
        </p>

        {/* Navigation Pills */}
        <div className="nav-pills">
          <button
            className={`nav-pill ${currentView === 'scanner' ? 'active' : ''}`}
            onClick={() => switchView('scanner')}
          >
            Scanner
          </button>
          <button
            className={`nav-pill ${currentView === 'logs' ? 'active' : ''}`}
            onClick={() => switchView('logs')}
          >
            Logs
          </button>
          <button
            className={`nav-pill ${currentView === 'analytics' ? 'active' : ''}`}
            onClick={() => switchView('analytics')}
          >
            Analytics
          </button>
          <button
            className={`nav-pill ${currentView === 'manual' ? 'active' : ''}`}
            onClick={() => switchView('manual')}
          >
            Manual Entry
          </button>
        </div>

        {/* Main Card */}
        <div className="card">
          {/* Scanner View */}
          {currentView === 'scanner' && (
            <div className="scanner-section">
              <div className="scanner-content">
                <h2 className="scanner-title">QR Code Scanner</h2>
                <p className="scanner-subtitle">
                  Use your device camera to scan visitor or staff QR codes at the gate.
                </p>

                <div id="qr-reader" className="camera-placeholder">
                  Camera preview will appear here
                </div>

                <button
                  id="start-scan-btn"
                  onClick={startScanner}
                  className="start-scan-btn"
                >
                  Start Scanning
                </button>
              </div>

              <div className="quick-stats">
                <p className="stats-label">Today</p>
                <p className="stats-value">24 check-ins • 3 alerts</p>
              </div>
            </div>
          )}

          {/* Logs View */}
          {currentView === 'logs' && (
            <>
              <h2 className="section-title">Recent Logs</h2>
              <div className="gutter">
                <table className="w-full border-collapse border border-gray-300">
                  <thead>
                    <tr>
                      <th className="border border-gray-300 p-2">Time</th>
                      <th className="border border-gray-300 p-2">Child</th>
                      <th className="border border-gray-300 p-2">Parent</th>
                      <th className="border border-gray-300 p-2">Status</th>
                      <th className="border border-gray-300 p-2">Method</th>
                      <th className="border border-gray-300 p-2">Guard</th>
                    </tr>
                  </thead>
                  <tbody id="logs-tbody">
                    {logs.length > 0 ? logs.map((log, index) => (
                      <tr key={index}>
                        <td className="border border-gray-300 p-2">{new Date(log.timestamp).toLocaleString()}</td>
                        <td className="border border-gray-300 p-2">{log.child_name}</td>
                        <td className="border border-gray-300 p-2">{log.gate_name}</td>
                        <td className="border border-gray-300 p-2">
                          <span className={`px-2 py-1 rounded ${log.status === 'approved' ? 'bg-green-200' : 'bg-red-200'}`}>
                            {log.status}
                          </span>
                        </td>
                        <td className="border border-gray-300 p-2">Scan</td>
                        <td className="border border-gray-300 p-2">Guard</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="6" className="border border-gray-300 p-2 text-center">No logs found</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* Analytics View */}
          {currentView === 'analytics' && (
            <div className="min-h-screen bg-gray-50 p-8">
              {/* Main Analytics Panel */}
              <div className="max-w-6xl mx-auto bg-white rounded-3xl shadow-sm border border-gray-200 p-8">
                {/* Header Section */}
                <div className="flex justify-between items-start mb-8">
                  <div>
                    <h1 className="text-2xl font-bold text-gray-900 mb-2">Analytics</h1>
                    <p className="text-sm text-gray-600">Overview of today's activity and visitor flow.</p>
                  </div>

                  {/* Date Range Chip */}
                  <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-2">
                    <span className="text-sm text-gray-900">Today · 00:00 – Now</span>
                  </div>
                </div>

                {/* Navigation Buttons */}
                <div className="flex gap-4 mb-8">
                  <button className="bg-gray-100 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-50">
                    Scanner
                  </button>
                  <button className="bg-gray-100 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-50">
                    Logs
                  </button>
                  <button className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700">
                    Analytics
                  </button>
                  <button className="bg-gray-100 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-50">
                    Manual Entry
                  </button>
                </div>

                {/* KPI Cards */}
                <div className="grid grid-cols-3 gap-6 mb-8">
                  <div className="bg-gray-50 border border-gray-200 rounded-xl p-6">
                    <div className="text-sm text-gray-600 mb-2">Total Pickups</div>
                    <div className="text-3xl font-bold text-gray-900">{analytics?.total_pickups || 0}</div>
                  </div>

                  <div className="bg-gray-50 border border-gray-200 rounded-xl p-6">
                    <div className="text-sm text-gray-600 mb-2">Peak Hour</div>
                    <div className="text-3xl font-bold text-gray-900">
                      {analytics?.peak_hour ? `${analytics.peak_hour}:00` : 'N/A'}
                    </div>
                  </div>

                  <div className="bg-gray-50 border border-gray-200 rounded-xl p-6">
                    <div className="text-sm text-gray-600 mb-2">Visitors Today</div>
                    <div className="text-3xl font-bold text-gray-900">{analytics?.visitors || 0}</div>
                  </div>
                </div>

                {/* Status Tag */}
                <div className="flex justify-end mb-8">
                  <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-2 flex items-center gap-2">
                    <div className="w-3 h-3 bg-blue-600 rounded-full"></div>
                    <span className="text-sm text-gray-600">Guard Online · Scanner Idle</span>
                  </div>
                </div>

                {/* Chart Area */}
                <div className="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-8">
                  <div className="mb-4">
                    <div className="text-sm font-semibold text-gray-900">Activity Over Time</div>
                    <div className="text-xs text-gray-600">Daily check-ins chart (placeholder)</div>
                  </div>

                  {/* Placeholder Chart */}
                  <div className="space-y-3">
                    <div className="h-px bg-gray-200"></div>
                    <div className="h-px bg-gray-100"></div>
                    <div className="h-px bg-gray-100"></div>
                    <svg className="w-full h-32" viewBox="0 0 1000 128">
                      <polyline
                        points="30,100 160,95 290,98 420,102 550,99 680,101 810,103 940,102"
                        fill="none"
                        stroke="#d1d5db"
                        strokeWidth="2"
                        strokeLinecap="round"
                      />
                    </svg>
                  </div>
                </div>

                {/* Footer Tip */}
                <div className="text-xs text-gray-600">
                  Tip: Keep dashboard in full-screen mode for smoother monitoring.
                </div>
              </div>
            </div>
          )}

          {/* Manual Entry View */}
          {currentView === 'manual' && (
            <>
              <h2 className="section-title">Manual Entry</h2>
              <form id="manual-entry-form" onSubmit={handleManualEntry}>
                <div className="form-grid">
                  <div className="form-item">
                    <label>Parent ID</label>
                    <input
                      type="number"
                      name="parentId"
                      className="input"
                      required
                    />
                  </div>
                  <div className="form-item">
                    <label>Child ID</label>
                    <input
                      type="number"
                      name="childId"
                      className="input"
                      required
                    />
                  </div>
                </div>
                <div className="submit-row">
                  <button
                    type="submit"
                    className="submit-btn"
                  >
                    Record Entry
                  </button>
                </div>
              </form>
            </>
          )}
        </div>

        {/* Scan Result */}
        {result && (
          <div className="card" id="scan-result" style={{
            background: result.status === 'approved' ? 'var(--success)' : 'var(--error)',
            color: 'white',
            border: 'none'
          }}>
            <div id="result-status" className="flex items-center mb-4">
              <span id="result-status-icon" className="text-2xl mr-2">
                {result.status === 'approved' ? '✓' : '✗'}
              </span>
              <span id="result-status-text" className="text-xl font-semibold">
                {result.status === 'approved' ? 'ACCESS GRANTED' : 'ACCESS DENIED'}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <strong>Child:</strong> <span id="result-child-name">{result.child?.name || 'Unknown'}</span>
              </div>
              <div>
                <strong>Parent:</strong> <span id="result-parent-name">{result.parent?.name || 'Unknown'}</span>
              </div>
              <div>
                <strong>Phone:</strong> <span id="result-parent-phone">{result.parent?.phone || 'N/A'}</span>
              </div>
              <div>
                <strong>Time:</strong> <span id="result-time">{new Date(result.timestamp).toLocaleString()}</span>
              </div>
            </div>
            {result.reason && (
              <div className="mt-4">
                <strong>Reason:</strong> <span id="result-reason">{result.reason}</span>
              </div>
            )}
          </div>
        )}

        {/* Footer Note */}
        <p className="footer-note">
          Tip: Keep the guard dashboard open in full-screen mode for smoother scanning and monitoring.
        </p>

        {/* Toast */}
        {toast && (
          <div className={`fixed top-4 right-4 p-4 rounded shadow ${toast.type === 'success' ? 'bg-green-500' : toast.type === 'error' ? 'bg-red-500' : 'bg-blue-500'} text-white z-50`}>
            {toast.message}
          </div>
        )}
      </div>
    </ProtectedRoute>
  )
}