import React from 'react'
import Link from 'next/link'
import { useAuth } from '../../lib/AuthContext'

const Header = () => {
  const { isAuth, role, logout } = useAuth()

  return (
    <header className="bg-blue-600 text-white shadow">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex justify-between items-center py-4">
          <Link href="/" className="text-xl font-bold">
            Qreet Platform
          </Link>
          {isAuth && role === 'parent' && (
            <nav className="flex space-x-4">
              <Link href="/dashboard" className="hover:text-blue-200">Dashboard</Link>
              <Link href="/children" className="hover:text-blue-200">Children</Link>
              <Link href="/qr-codes" className="hover:text-blue-200">QR Codes</Link>
              <Link href="/history" className="hover:text-blue-200">History</Link>
              <button onClick={logout} className="hover:text-blue-200">Logout</button>
            </nav>
          )}
        </div>
      </div>
    </header>
  )
}

export default Header