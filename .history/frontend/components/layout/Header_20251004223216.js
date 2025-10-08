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
            <nav className="flex space-x-4">
              {role === 'parent' && (
                <>
                  <Link href="/dashboard" className="hover:text-blue-200">Dashboard</Link>
                  <Link href="/children" className="hover:text-blue-200">Children</Link>
                  <Link href="/qr-codes" className="hover:text-blue-200">QR Codes</Link>
                  <Link href="/history" className="hover:text-blue-200">History</Link>
                </>
              )}
              {role === 'admin' && (
                <>
                  <Link href="/dashboard" className="hover:text-blue-200">Dashboard</Link>
                  <Link href="/schools" className="hover:text-blue-200">Schools</Link>
                  <Link href="/users" className="hover:text-blue-200">Users</Link>
                  <Link href="/logs" className="hover:text-blue-200">Logs</Link>
                </>
              )}
              {role === 'guard' && (
                <>
                  <Link href="/scan" className="hover:text-blue-200">Scan QR</Link>
                  <Link href="/logs" className="hover:text-blue-200">Logs</Link>
                </>
              )}
              <button onClick={logout} className="hover:text-blue-200">Logout</button>
            </nav>
          )}
        </div>
      </div>
    </header>
  )
}

export default Header