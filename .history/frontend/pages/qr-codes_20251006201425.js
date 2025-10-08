import { useState, useRef } from 'react'
import useSWR from 'swr'
import QRCode from 'qrcode'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'

const fetcher = (url) => apiClient.get(url)

export default function QRCodes() {
  const { data: qrCodes, error, mutate } = useSWR('/api/qr/list', fetcher)
  const [generating, setGenerating] = useState(false)

  const generateQR = async () => {
    setGenerating(true)
    try {
      await apiClient.post('/api/qr/generate', {})
      mutate()
    } catch (err) {
      alert('Error generating QR code')
    } finally {
      setGenerating(false)
    }
  }

  const downloadQR = (qr) => {
    const link = document.createElement('a')
    link.download = `qr-${qr.id}.png`
    link.href = `data:image/png;base64,${qr.qr_data}`
    link.click()
  }

  const emailQR = async (code) => {
    try {
      await apiClient.post('/api/notifications/send', { qr_code: code })
      alert('QR code sent via email')
    } catch (err) {
      alert('Error sending email')
    }
  }

  const revokeQR = async (id) => {
    if (confirm('Are you sure you want to revoke this QR code?')) {
      try {
        await apiClient.put(`/api/qr/${id}/revoke`, {})
        mutate()
      } catch (err) {
        alert('Error revoking QR code')
      }
    }
  }

  return (
    <ProtectedRoute allowedRoles={['parent', 'guard']}>
      <div className="min-h-screen bg-gray-100">
        <div className="max-w-4xl mx-auto py-6 px-4">
          <h1 className="text-3xl font-bold mb-6">QR Codes</h1>

          <div className="bg-white p-6 rounded-lg shadow mb-6">
            <h2 className="text-xl font-semibold mb-4">Generate New QR Code</h2>
            <button
              onClick={generateQR}
              disabled={generating}
              className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
            >
              {generating ? 'Generating...' : 'Generate QR Code'}
            </button>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-semibold mb-4">Active QR Codes</h2>
            <div className="space-y-4">
              {qrCodes?.map((qr) => (
                <div key={qr.id} className="flex items-center justify-between p-4 border rounded">
                  <div className="flex items-center space-x-4">
                    <img src={`data:image/png;base64,${qr.qr_data}`} alt="QR Code" className="w-16 h-16" />
                    <div>
                      <p className="font-medium">ID: {qr.id}</p>
                      <p className="text-sm text-gray-600">Child: {qr.child_id || 'Guest'}</p>
                      <p className="text-sm text-gray-600">Expires: {qr.expires_at ? new Date(qr.expires_at).toLocaleString() : 'Never'}</p>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => downloadQR(qr)}
                      className="bg-green-500 text-white px-3 py-1 rounded text-sm hover:bg-green-600"
                    >
                      Download
                    </button>
                    <button
                      onClick={() => emailQR(qr.id)}
                      className="bg-purple-500 text-white px-3 py-1 rounded text-sm hover:bg-purple-600"
                    >
                      Email
                    </button>
                    <button
                      onClick={() => revokeQR(qr.id)}
                      className="bg-red-500 text-white px-3 py-1 rounded text-sm hover:bg-red-600"
                    >
                      Revoke
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </ProtectedRoute>
  )
}