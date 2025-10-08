import { useState, useEffect } from 'react'
import { Html5Qrcode } from 'html5-qrcode'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'
import { getUserSchoolId } from '../lib/auth'

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
      showToast(error.message || 'Validation failed', 'error')
      showResult({
        status: 'denied',
        reason: error.message
      })
    }
  }

  const onScanError = (error) => {
    // Ignore scan errors (they happen frequently)
  }

  const showResult = (data) => {
    setResult(data)
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
    }
  }

  const loadAnalytics = async (timeRange) => {
    try {
      const response = await apiClient.get(`/api/analytics/summary?period=${timeRange}`)
      if (response.success) {
        setAnalytics(response)
      }
    } catch (error) {
      console.error('Failed to load analytics:', error)
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
      showToast(error.message || 'Manual entry failed', 'error')
      showResult({
        status: 'denied',
        reason: error.message
      })
    }
  }

  return (
    <ProtectedRoute allowedRoles={['guard']}>
      <div className="min-h-screen bg-gray-100">
        <div className="max-w-4xl mx-auto py-6 px-4">
          <h1 className="text-3xl font-bold mb-6">QR Code Scanner</h1>

          <div className="bg-white p-6 rounded-lg shadow mb-6">
            <h2 className="text-xl font-semibold mb-4">Select Gate</h2>
            <select
              value={selectedGate}
              onChange={(e) => setSelectedGate(e.target.value)}
              className="border p-2 rounded"
            >
              <option value="">Select Gate</option>
              {gates?.gates?.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </div>

          <div className="bg-white p-6 rounded-lg shadow mb-6">
            <h2 className="text-xl font-semibold mb-4">Scanner</h2>
            {!scanning ? (
              <button
                onClick={startScanning}
                className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
              >
                Start Scanning
              </button>
            ) : (
              <button
                onClick={stopScanning}
                className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600"
              >
                Stop Scanning
              </button>
            )}
            <div id="qr-reader" className="mt-4"></div>
          </div>

          {result && (
            <div className="bg-white p-6 rounded-lg shadow">
              <h2 className="text-xl font-semibold mb-4">Result</h2>
              <p>{result}</p>
            </div>
          )}
        </div>
      </div>
    </ProtectedRoute>
  )
}