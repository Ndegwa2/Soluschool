import React from 'react'
import { useAuth } from '../../lib/AuthContext'
import AIChatbot from './AIChatbot'

const AdminHeader = ({ activeTab }) => {
  const { user } = useAuth()

  const getTabTitle = (tab) => {
    const titles = {
      'overview': 'Dashboard',
      'schools': 'Schools',
      'visitors': 'Visitors',
      'pre-registered': 'Pre-registered',
      'reports': 'Reports',
      'blacklist': 'Blacklist',
      'settings': 'Settings'
    }
    return titles[tab] || 'Dashboard'
  }

  return (
    <div style={{
      flex: 1,
      padding: '24px 24px 24px 0',
      display: 'flex',
      flexDirection: 'column'
    }}>
      {/* Header */}
      <div style={{
        height: '72px',
        backgroundColor: '#ffffff',
        borderRadius: '12px',
        border: '1px solid #e5e7eb',
        display: 'flex',
        alignItems: 'center',
        padding: '0 24px',
        marginBottom: '24px',
        justifyContent: 'space-between'
      }}>
        <h1 style={{
          fontSize: '20px',
          fontWeight: '600',
          color: '#111827',
          margin: 0
        }}>
          {getTabTitle(activeTab)}
        </h1>

        {/* Search and Profile */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {/* Search Box */}
          <div style={{
            width: '300px',
            height: '36px',
            backgroundColor: '#F9FAFB',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            padding: '0 16px',
            border: '1px solid #e5e7eb'
          }}>
            <input
              type="text"
              placeholder="Search visitors, ID, or host..."
              style={{
                border: 'none',
                background: 'transparent',
                outline: 'none',
                fontSize: '13px',
                color: 'rgba(17, 24, 39, 0.5)',
                width: '100%'
              }}
            />
          </div>

          {/* Profile Avatar */}
          <div style={{
            width: '36px',
            height: '36px',
            backgroundColor: '#1E3A8A',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            fontSize: '12px',
            fontWeight: '600'
          }}>
            {user?.name?.split(' ').map(n => n[0]).join('').toUpperCase() || 'AD'}
          </div>
        </div>
      </div>

      {/* AI Chatbot */}
      <AIChatbot />
    </div>
  )
}

export default AdminHeader