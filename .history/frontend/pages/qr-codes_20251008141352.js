import React, { useState } from 'react'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import { apiClient } from '../lib/api'

const fetcher = async (url) => {
  const response = await apiClient.get(url)
  if (response.success) {
    return response.data
  } else {
    throw new Error(response.error)
  }
}

export default function QRCodes() {
  const { data: qrCodes, error, mutate } = useSWR('/api/qr/list', fetcher)
  const { data: children } = useSWR('/api/children', fetcher)
  const [generating, setGenerating] = useState(false)
  const [selectedChildId, setSelectedChildId] = useState('')

  const generateQR = async () => {
    setGenerating(true)
    const payload = selectedChildId ? { child_id: parseInt(selectedChildId) } : {}
    const response = await apiClient.post('/api/qr/generate', payload)
    if (response.success) {
      mutate()
      setSelectedChildId('') // Reset selection after successful generation
    } else {
      alert('Error generating QR code: ' + response.error)
    }
    setGenerating(false)
  }

  const downloadQR = (qr) => {
    const link = document.createElement('a')
    link.download = `qr-${qr.id}.png`
    link.href = `data:image/png;base64,${qr.qr_data}`
    link.click()
  }

  const emailQR = async (code) => {
    const response = await apiClient.post('/api/notifications/send', { qr_code: code })
    if (response.success) {
      alert('QR code sent via email')
    } else {
      alert('Error sending email: ' + response.error)
    }
  }

  const revokeQR = async (id) => {
    if (confirm('Are you sure you want to revoke this QR code?')) {
      const response = await apiClient.put(`/api/qr/${id}/revoke`, {})
      if (response.success) {
        mutate()
      } else {
        alert('Error revoking QR code: ' + response.error)
      }
    }
  }

  return (
    <ProtectedRoute allowedRoles={['parent', 'guard']}>
      <div className="container">
        <div className="header-section">
          <h1>QR Codes</h1>
          <button
            onClick={generateQR}
            disabled={generating}
            className="add-child-btn primary"
          >
            {generating ? 'Generating...' : 'Generate QR Code'}
          </button>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Active QR Codes</div>
            <div className="card-sub">Manage your QR codes</div>
          </div>
          <div className="card-body">
            <div className="grid" style={{ gap: '16px' }}>
              {qrCodes?.qrs?.map((qr) => (
                <div key={qr.id} className="card" style={{ padding: '16px', border: '1px solid rgba(2,6,23,.06)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <img src={`data:image/png;base64,${qr.qr_data}`} alt="QR Code" style={{ width: '64px', height: '64px', borderRadius: '8px' }} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: '600', marginBottom: '4px' }}>ID: {qr.id}</div>
                      <div style={{ fontSize: '14px', color: 'var(--muted)', marginBottom: '2px' }}>Child: {qr.child_id || 'Guest'}</div>
                      <div style={{ fontSize: '14px', color: 'var(--muted)' }}>Expires: {qr.expires_at ? new Date(qr.expires_at).toLocaleString() : 'Never'}</div>
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        onClick={() => downloadQR(qr)}
                        style={{ padding: '8px 12px', background: 'var(--brand)', color: '#fff', border: 'none', borderRadius: '8px', fontSize: '14px', cursor: 'pointer' }}
                      >
                        Download
                      </button>
                      <button
                        onClick={() => emailQR(qr.id)}
                        style={{ padding: '8px 12px', background: 'var(--brand-2)', color: '#fff', border: 'none', borderRadius: '8px', fontSize: '14px', cursor: 'pointer' }}
                      >
                        Email
                      </button>
                      <button
                        onClick={() => revokeQR(qr.id)}
                        style={{ padding: '8px 12px', background: 'var(--danger)', color: '#fff', border: 'none', borderRadius: '8px', fontSize: '14px', cursor: 'pointer' }}
                      >
                        Revoke
                      </button>
                    </div>
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