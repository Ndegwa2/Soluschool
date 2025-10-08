import React from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { useAuth } from '../../lib/AuthContext'
import { Home, Building, Users, FileText, LogOut } from 'lucide-react'

const Header = () => {
  const { isAuth, role, logout } = useAuth()
  const router = useRouter()

  return (
    <header className="navbar">
      <div className="flex justify-between items-center">
        <h1>
          Qreet Platform
        </h1>
        {isAuth && (
          <div className="nav-links">
              {role === 'parent' && (
                <>
                  <Link href="/dashboard" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/dashboard' ? 'font-bold' : ''}`}>
                    <Home size={16} />
                    <span>Dashboard</span>
                  </Link>
                  <Link href="/children" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/children' ? 'font-bold' : ''}`}>
                    <Users size={16} />
                    <span>Children</span>
                  </Link>
                  <Link href="/qr-codes" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/qr-codes' ? 'font-bold' : ''}`}>
                    <FileText size={16} />
                    <span>QR Codes</span>
                  </Link>
                  <Link href="/history" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/history' ? 'font-bold' : ''}`}>
                    <FileText size={16} />
                    <span>History</span>
                  </Link>
                </>
              )}
              {role === 'admin' && (
                <>
                  <Link href="/dashboard" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/dashboard' ? 'font-bold' : ''}`}>
                    <Home size={16} />
                    <span>Dashboard</span>
                  </Link>
                  <Link href="/schools" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/schools' ? 'font-bold' : ''}`}>
                    <Building size={16} />
                    <span>Schools</span>
                  </Link>
                  <Link href="/users" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/users' ? 'font-bold' : ''}`}>
                    <Users size={16} />
                    <span>Users</span>
                  </Link>
                  <Link href="/logs" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/logs' ? 'font-bold' : ''}`}>
                    <FileText size={16} />
                    <span>Logs</span>
                  </Link>
                </>
              )}
              {role === 'guard' && (
                <>
                  <Link href="/scan" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/scan' ? 'font-bold' : ''}`}>
                    <FileText size={16} />
                    <span>Scan QR</span>
                  </Link>
                  <Link href="/logs" className={`flex items-center space-x-1 hover:underline ${router.pathname === '/logs' ? 'font-bold' : ''}`}>
                    <FileText size={16} />
                    <span>Logs</span>
                  </Link>
                </>
              )}
              <a href="#" onClick={logout}>Logout</a>
            </div>
          )}
        </div>
    </header>
  )
}

export default Header