import { useState, useEffect } from 'react'
import { Html5QrcodeScanner } from 'html5-qrcode'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'
import { getUserSchoolId } from '../lib/auth'

export default function Scan() {
  const [scanner, setScanner] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState('')
  const [selectedGate, setSelectedGate] = useState('')
  const schoolId = getUserSchoolId()
  const { data: gates } = useSWR(schoolId ? `/api/gates/${schoolId}` : null, apiClient.get)

  useEffect(() => {
    if (scanning && selectedGate) {
      const qrScanner = new Html5QrcodeScanner(
        'qr-reader',
        { fps: 10, qrbox: 250 },
        false
      )
      qrScanner.render(onScanSuccess, onScanError)
      setScanner(qrScanner)
    }
    return () => {
      if (scanner) {
        scanner.clear()
      }
    }
  }, [scanning, selectedGate])

  const onScanSuccess = async (decodedText) => {
    setResult('Processing...')
    try {
      const response = await apiClient.post('/api/verify/scan', {
        qr_data: decodedText,
        gate_id: selectedGate
      })
      setResult(`Status: ${response.status}, Info: ${JSON.stringify(response.qr_info)}`)
    } catch (err) {
      setResult(`Error: ${err.message}`)
    }
  }

  const onScanError = (error) => {
    console.log(error)
  }

  const startScanning = () => {
    if (!selectedGate) {
      alert('Please select a gate')
      return
    }
    setScanning(true)
    setResult('')
  }

  const stopScanning = () => {
    setScanning(false)
    if (scanner) {
      scanner.clear()
      setScanner(null)
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