import { useState, useEffect } from 'react'
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
   const [selectedGate, setSelectedGate] = useState('')
   const [currentView, setCurrentView] = useState('scanner')
   const [logs, setLogs] = useState([])
   const [analytics, setAnalytics] = useState(null)
   const [toast, setToast] = useState(null)
   const schoolId = getUserSchoolId()
   const { logout } = useAuth()
   const { data: gates } = useSWR(schoolId ? `/api/gates/${schoolId}` : null, apiClient.get)

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
    if (!selectedGate) {
      showToast('Please select a gate', 'error')
      return
    }

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
        gate_id: selectedGate
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
        gate_id: selectedGate
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
      <div id="guard-dashboard" className="min-h-screen bg-gray-100">
        <div className="max-w-6xl mx-auto py-6 px-4">
          <h1 className="text-3xl font-bold mb-6">Guard Dashboard</h1>

          {/* Navigation */}
          <div className="bg-white p-4 rounded-lg shadow mb-6">
            <nav className="flex space-x-4">
              <button
                className={`nav-btn px-4 py-2 rounded ${currentView === 'scanner' ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
                data-view="scanner"
                onClick={() => switchView('scanner')}
              >
                Scanner
              </button>
              <button
                className={`nav-btn px-4 py-2 rounded ${currentView === 'logs' ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
                data-view="logs"
                onClick={() => switchView('logs')}
              >
                Logs
              </button>
              <button
                className={`nav-btn px-4 py-2 rounded ${currentView === 'analytics' ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
                data-view="analytics"
                onClick={() => switchView('analytics')}
              >
                Analytics
              </button>
              <button
                className={`nav-btn px-4 py-2 rounded ${currentView === 'manual' ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
                data-view="manual"
                onClick={() => switchView('manual')}
              >
                Manual Entry
              </button>
            </nav>
          </div>

          {/* Views */}
          <div className="views">
            {/* Scanner View */}
            {currentView === 'scanner' && (
              <div className="view scanner-view bg-white p-6 rounded-lg shadow mb-6">
                <h2 className="text-xl font-semibold mb-4">Select Gate</h2>
                <select
                  value={selectedGate}
                  onChange={(e) => setSelectedGate(e.target.value)}
                  className="border p-2 rounded mb-4"
                >
                  <option value="">Select Gate</option>
                  {gates?.gates?.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                </select>

                <div className="flex space-x-4 mb-4">
                  {!scanning ? (
                    <button
                      id="start-scan-btn"
                      onClick={startScanner}
                      className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
                    >
                      Start Scanning
                    </button>
                  ) : (
                    <button
                      id="stop-scan-btn"
                      onClick={stopScanner}
                      className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600"
                    >
                      Stop Scanning
                    </button>
                  )}
                </div>
                <div id="qr-reader" className="mt-4"></div>
              </div>
            )}

            {/* Logs View */}
            {currentView === 'logs' && (
              <div className="view logs-view bg-white p-6 rounded-lg shadow mb-6">
                <h2 className="text-xl font-semibold mb-4">Recent Logs</h2>
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
            )}

            {/* Analytics View */}
            {currentView === 'analytics' && (
              <div className="view analytics-view bg-white p-6 rounded-lg shadow mb-6">
                <h2 className="text-xl font-semibold mb-4">Analytics</h2>
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
            )}

            {/* Manual Entry View */}
            {currentView === 'manual' && (
              <div className="view manual-view bg-white p-6 rounded-lg shadow mb-6">
                <h2 className="text-xl font-semibold mb-4">Manual Entry</h2>
                <form id="manual-entry-form" onSubmit={handleManualEntry}>
                  <div className="mb-4">
                    <label className="block mb-2">Parent ID</label>
                    <input
                      type="number"
                      name="parentId"
                      className="border p-2 rounded w-full"
                      required
                    />
                  </div>
                  <div className="mb-4">
                    <label className="block mb-2">Child ID</label>
                    <input
                      type="number"
                      name="childId"
                      className="border p-2 rounded w-full"
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
                  >
                    Record Entry
                  </button>
                </form>
              </div>
            )}
          </div>

          {/* Scan Result */}
          {result && (
            <div id="scan-result" className={`result-card p-6 rounded-lg shadow mb-6 ${result.status}`}>
              <div id="result-status" className="flex items-center mb-4">
                <span id="result-status-icon" className={`text-2xl mr-2 ${result.status}`}>
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
            <div className={`fixed top-4 right-4 p-4 rounded shadow ${toast.type === 'success' ? 'bg-green-500' : toast.type === 'error' ? 'bg-red-500' : 'bg-blue-500'} text-white`}>
              {toast.message}
            </div>
          )}
        </div>
      </div>
    </ProtectedRoute>
  )
}