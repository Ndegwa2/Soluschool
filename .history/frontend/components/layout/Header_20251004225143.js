import React from 'react'
import Link from 'next/link'
import { useAuth } from '../../lib/AuthContext'

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
            <Link href="/dashboard">Dashboard</Link>
            <Link href="/schools">Schools</Link>
            <Link href="/users">Users</Link>
            <Link href="/logs">Logs</Link>
            <a href="#" onClick={logout}>Logout</a>
          </div>
        )}
        </div>
    </header>
  )
}

export default Header