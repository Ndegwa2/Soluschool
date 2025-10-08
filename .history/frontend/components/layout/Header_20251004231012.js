import React from 'react'
import Link from 'next/link'
import { useAuth } from '../../lib/AuthContext'

const Header = () => {
  const { isAuth, role, logout } = useAuth()

  return (
    <header style={{ fontFamily: 'monospace', backgroundColor: '#000', color: '#0f0', padding: '10px', borderBottom: '1px solid #0f0' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Qreet Platform   Dashboard</span>
        {isAuth && (
          <div style={{ display: 'flex', gap: '10px' }}>
            <Link href="/dashboard" style={{ color: '#0f0', textDecoration: 'none' }}>Dashboard</Link>
            <span>|</span>
            <Link href="/schools" style={{ color: '#0f0', textDecoration: 'none' }}>Schools</Link>
            <span>|</span>
            <Link href="/users" style={{ color: '#0f0', textDecoration: 'none' }}>Users</Link>
            <span>|</span>
            <Link href="/logs" style={{ color: '#0f0', textDecoration: 'none' }}>Logs</Link>
            <span>|</span>
            <a href="#" onClick={logout} style={{ color: '#0f0', textDecoration: 'none' }}>Logout</a>
          </div>
        )}
      </div>
    </header>
  )
}

export default Header