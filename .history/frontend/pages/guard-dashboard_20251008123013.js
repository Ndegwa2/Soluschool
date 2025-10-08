import React, { useState, useEffect } from 'react'
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
        scanner.stop()
        scanner.clear()
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
        scanner.clear()
        setScanner(null)
        setScanning(false)
      } catch (error) {
        console.error('Stop scanner error:', error)
      }
    }
  }

  const onScanSuccess = async (decodedText) => {
    console.log('QR Code scanned:', decodedText)

    await stopScanner()

    try {
      const response = await apiClient.post('/api/verify/scan', {
        qr_data: decodedText,
        gate_id: 1 // Default gate ID
      })

      if (response.success) {
        showResult(response)
        showToast('QR code validated successfully', 'success')
        loadLogs()
      }
    } catch (error) {
      if (error.message === 'Invalid token') {
        logout()
      } else {
        showToast(error.message || 'Validation failed', 'error')
        showResult({
          status: 'denied',
          reason: error.message
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
    try {
      const response = await apiClient.get('/api/logs?limit=20')
      if (response.success) {
        setLogs(response.logs)
      }
    } catch (error) {
      console.error('Failed to load logs:', error)
      if (error.message === 'Invalid token') {
        logout()
      }
    }
  }

  const loadAnalytics = async (timeRange) => {
    try {
      const period = timeRange === '24h' ? 'daily' : 'weekly'
      const response = await apiClient.get(`/api/analytics/summary?period=${period}`)
      if (response.success) {
        setAnalytics(response)
      }
    } catch (error) {
      console.error('Failed to load analytics:', error)
      if (error.message === 'Invalid token') {
        logout()
      }
    }
  }

  const handleManualEntry = async (e) => {
    e.preventDefault()
    const parentId = e.target.parentId.value
    const childId = e.target.childId.value

    try {
      // Assuming manual entry endpoint exists
      const response = await apiClient.post('/api/manual-entry', {
        parent_id: parseInt(parentId),
        child_id: parseInt(childId),
        gate_id: 1 // Default gate ID
      })

      if (response.success) {
        showResult(response)
        showToast('Manual entry recorded successfully', 'success')
        e.target.reset()
        loadLogs()
      }
    } catch (error) {
      if (error.message === 'Invalid token') {
        logout()
      } else {
        showToast(error.message || 'Manual entry failed', 'error')
        showResult({
          status: 'denied',
          reason: error.message
        })
      }
    }
  }

  return (
    <ProtectedRoute allowedRoles={['guard']}>
      <div className="container">
        <h1 className="page-title">Guard Dashboard</h1>

        {/* Navigation */}
        <div className="cta-row">
          <button
            className="ghost-pill"
            onClick={() => switchView('scanner')}
          >
            <span className="emoji">📱</span> Scanner
          </button>
          <button
            className="ghost-pill"
            onClick={() => switchView('logs')}
          >
            <span className="emoji">📋</span> Logs
          </button>
          <button
            className="ghost-pill"
            onClick={() => switchView('analytics')}
          >
            <span className="emoji">📊</span> Analytics
          </button>
          <button
            className="ghost-pill"
            onClick={() => switchView('manual')}
          >
            <span className="emoji">✏️</span> Manual Entry
          </button>
        </div>

        {/* Views */}
        <div className="card">
          {/* Scanner View */}
          {currentView === 'scanner' && (
            <>
              <h2 className="section-title">QR Code Scanner</h2>

              <div className="submit-row">
                {!scanning ? (
                  <button
                    id="start-scan-btn"
                    onClick={startScanner}
                    className="big-btn"
                  >
                    Start Scanning
                  </button>
                ) : (
                  <button
                    id="stop-scan-btn"
                    onClick={stopScanner}
                    className="big-btn"
                    style={{ background: '#dc2626' }}
                  >
                    Stop Scanning
                  </button>
                )}
              </div>
              <div id="qr-reader" className="mt-4"></div>
            </>
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
            <>
              <h2 className="section-title">Analytics</h2>
              <div className="gutter">
                {analytics ? (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 border rounded">
                      <div className="text-2xl font-bold">{analytics.total_pickups || 0}</div>
                      <div>Total Pickups</div>
                    </div>
                    <div className="p-4 border rounded">
                      <div className="text-2xl font-bold">{analytics.peak_hour ? `${analytics.peak_hour}:00` : 'N/A'}</div>
                      <div>Peak Hour</div>
                    </div>
                    <div className="p-4 border rounded">
                      <div className="text-2xl font-bold">{analytics.visitors || 0}</div>
                      <div>Visitors Today</div>
                    </div>
                  </div>
                ) : (
                  <p>Loading analytics...</p>
                )}
              </div>
            </>
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
          <div className="card" id="scan-result" style={{ background: result.status === 'approved' ? '#d1fae5' : '#fee2e2' }}>
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