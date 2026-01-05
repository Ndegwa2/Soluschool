'use client'

import React, { useState } from 'react'
import React, { useState } from 'react'
import ProtectedRoute from '../components/common/ProtectedRoute'
import AdminSidebar from '../components/admin/AdminSidebar'
import AdminHeader from '../components/admin/AdminHeader'
import AdminDashboardOverview from '../components/admin/AdminDashboardOverview'
import UserManagement from '../components/admin/UserManagement'
import VisitorManagement from '../components/admin/VisitorManagement'
import BlacklistManagement from '../components/admin/BlacklistManagement'
import BulkOperations from '../components/admin/BulkOperations'
import SystemConfig from '../components/admin/SystemConfig'
import AdvancedAnalytics from '../components/admin/AdvancedAnalytics'
import AuditManagement from '../components/admin/AuditManagement'
import SchoolsManagement from '../components/admin/SchoolsManagement'
import AIChatbot from '../components/admin/AIChatbot'

export default function AdminDashboard() {
  const [activeTab, setActiveTab] = useState('overview')

  const renderTabContent = () => {
    switch (activeTab) {
      case 'schools':
        return <SchoolsManagement />
      case 'visitors':
        return <VisitorManagement />
      case 'user-management':
        return <UserManagement />
      case 'pre-registered':
        return <BulkOperations />
      case 'reports':
        return <AdvancedAnalytics />
      case 'blacklist':
        return <BlacklistManagement />
      case 'audit':
        return <AuditManagement />
      case 'settings':
        return <SystemConfig />
      default:
        return <AdminDashboardOverview />
    }
  }

  return (
    <ProtectedRoute allowedRoles={['admin']}>
      <div style={{
        minHeight: '100vh',
        backgroundColor: '#f4f6f8',
        display: 'flex'
      }}>
        <AdminSidebar activeTab={activeTab} setActiveTab={setActiveTab} />
        <AdminHeader activeTab={activeTab} />
        <div style={{
          padding: '0 24px 24px 0',
          flex: 1,
          overflowY: 'auto'
        }}>
          {renderTabContent()}
        </div>
        <AIChatbot />
      </div>
    </ProtectedRoute>
  )
}