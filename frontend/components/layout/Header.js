import React from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { useAuth } from '../../lib/AuthContext'
import { Home, Building, Users, FileText, LogOut } from 'lucide-react'

const Header = () => {
  const { isAuth, role, logout } = useAuth()
  const router = useRouter()

  return (
    <header className="bg-blue-600 text-white shadow">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex justify-between items-center py-4">
          <Link href="/" className="text-xl font-bold">
            Qreet Platform
          </Link>
          {isAuth && (
            <nav className="flex space-x-6">
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
              <button onClick={logout} className="flex items-center space-x-1 hover:underline bg-transparent border border-white px-3 py-1 rounded text-white hover:bg-white hover:text-blue-600 transition">
                <LogOut size={16} />
                <span>Logout</span>
              </button>
            </nav>
          )}
        </div>
      </div>
    </header>
  )
}

export default Header