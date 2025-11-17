import React from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'

const AdminSidebar = ({ activeTab, setActiveTab }) => {
  const router = useRouter()

  const navigationItems = [
    { id: 'overview', name: 'Dashboard', icon: '📊' },
    { id: 'visitors', name: 'Visitors', icon: '👥' },
    { id: 'pre-registered', name: 'Pre-registered', icon: '📝' },
    { id: 'reports', name: 'Reports', icon: '📈' },
    { id: 'blacklist', name: 'Blacklist', icon: '🚫' },
    { id: 'settings', name: 'Settings', icon: '⚙️' }
  ]

  return (
    <div style={{
      width: '220px',
      height: '100vh',
      backgroundColor: '#ffffff',
      borderRadius: '12px',
      border: '1px solid #e0e6eb',
      margin: '24px',
      padding: '0',
      display: 'flex',
      flexDirection: 'column'
    }}>
      {/* Logo */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        padding: '40px 0 0 24px',
        gap: '12px'
      }}>
        <div style={{
          width: '60px',
          height: '40px',
          backgroundColor: '#1E3A8A',
          borderRadius: '6px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <span style={{ color: '#fff', fontWeight: 'bold', fontSize: '16px' }}>SQ</span>
        </div>
        <span style={{
          fontSize: '16px',
          fontWeight: '600',
          color: '#111827'
        }}>Soluschool</span>
      </div>

      {/* Navigation */}
      <div style={{ padding: '24px', flex: 1 }}>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {navigationItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                padding: '9px 24px',
                borderRadius: '6px',
                border: 'none',
                backgroundColor: activeTab === item.id ? '#f3f4f6' : 'transparent',
                color: activeTab === item.id ? '#111827' : 'rgba(17, 24, 39, 0.7)',
                fontSize: '14px',
                fontWeight: '500',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.2s ease'
              }}
              onMouseEnter={(e) => {
                if (activeTab !== item.id) {
                  e.target.style.backgroundColor = '#f9fafb'
                }
              }}
              onMouseLeave={(e) => {
                if (activeTab !== item.id) {
                  e.target.style.backgroundColor = 'transparent'
                }
              }}
            >
              <span style={{ marginRight: '16px', fontSize: '16px' }}>{item.icon}</span>
              {item.name}
            </button>
          ))}
        </nav>
      </div>

      {/* Footer */}
      <div style={{
        padding: '0 24px 24px 24px'
      }}>
        <div style={{
          fontSize: '12px',
          color: 'rgba(17, 24, 39, 0.5)',
          fontWeight: '400'
        }}>
          v0.9 • Admin
        </div>
      </div>
    </div>
  )
}

export default AdminSidebar