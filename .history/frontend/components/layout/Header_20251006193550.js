import React from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { useAuth } from '../../lib/AuthContext'

const Header = () => {
  const { isAuth, role, logout } = useAuth()
  const router = useRouter()

  if (!isAuth) return null

  return (
    <header style={{
      position: 'sticky',
      top: 0,
      zIndex: 50,
      backdropFilter: 'saturate(140%) blur(10px)',
      background: 'rgba(255,255,255,0.7)',
      borderBottom: '1px solid rgba(0,0,0,0.06)'
    }}>
      <div style={{
        maxWidth: '1200px',
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        gap: '18px',
        padding: '14px 20px'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          fontWeight: 700,
          letterSpacing: '.2px'
        }}>
          <div style={{
            display: 'grid',
            placeItems: 'center',
            width: '34px',
            height: '34px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #10b981, #0ea5e9)',
            color: '#fff',
            fontWeight: 700,
            boxShadow: '0 10px 30px -12px rgba(2, 8, 23, 0.25)'
          }}>Q</div>
          <div>Qreet Platform</div>
        </div>
        <nav style={{
          display: 'flex',
          alignItems: 'center',
          gap: '18px',
          marginLeft: '12px'
        }}>
          <Link href="/dashboard" style={{
            textDecoration: 'none',
            color: router.pathname === '/dashboard' ? '#0ea5e9' : '#0b1220',
            opacity: router.pathname === '/dashboard' ? 1 : 0.85,
            fontWeight: 600,
            textUnderlineOffset: '6px',
            textDecoration: router.pathname === '/dashboard' ? 'underline' : 'none'
          }}>Dashboard</Link>
          <Link href="/schools" style={{
            textDecoration: 'none',
            color: router.pathname === '/schools' ? '#0ea5e9' : '#0b1220',
            opacity: router.pathname === '/schools' ? 1 : 0.85,
            fontWeight: 600,
            textUnderlineOffset: '6px',
            textDecoration: router.pathname === '/schools' ? 'underline' : 'none'
          }}>Schools</Link>
          <Link href="/users" style={{
            textDecoration: 'none',
            color: router.pathname === '/users' ? '#0ea5e9' : '#0b1220',
            opacity: router.pathname === '/users' ? 1 : 0.85,
            fontWeight: 600,
            textUnderlineOffset: '6px',
            textDecoration: router.pathname === '/users' ? 'underline' : 'none'
          }}>Users</Link>
          <Link href="/logs" style={{
            textDecoration: 'none',
            color: router.pathname === '/logs' ? '#0ea5e9' : '#0b1220',
            opacity: router.pathname === '/logs' ? 1 : 0.85,
            fontWeight: 600,
            textUnderlineOffset: '6px',
            textDecoration: router.pathname === '/logs' ? 'underline' : 'none'
          }}>Logs</Link>
        </nav>
        <div style={{ flex: '1 1 auto' }}></div>
        <button
          onClick={() => {
            logout()
            router.push('/auth/login')
          }}
          style={{
            border: 0,
            cursor: 'pointer',
            fontWeight: 600,
            borderRadius: '999px',
            padding: '10px 16px',
            boxShadow: '0 6px 18px -8px rgba(0,0,0,.3)',
            transition: 'transform .06s ease, box-shadow .2s ease, opacity .2s ease',
            background: '#ef4444',
            color: '#fff'
          }}
          onMouseOver={(e) => {
            e.target.style.transform = 'translateY(-1px)'
            e.target.style.boxShadow = '0 10px 22px -10px rgba(0,0,0,.35)'
          }}
          onMouseOut={(e) => {
            e.target.style.transform = 'translateY(0)'
            e.target.style.boxShadow = '0 6px 18px -8px rgba(0,0,0,.3)'
          }}
        >
          Logout
        </button>
      </div>
    </header>
  )
}

export default Header