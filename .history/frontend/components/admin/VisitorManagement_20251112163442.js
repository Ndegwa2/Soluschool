import React, { useState } from 'react'
import useSWR from 'swr'
import { apiClient } from '../../lib/api'

const fetcher = async (url) => {
  const response = await apiClient.get(url)
  if (response.success) {
    return response.data
  } else {
    throw new Error(response.error)
  }
}

const getStatusColor = (status) => {
  switch (status) {
    case 'approved': return 'bg-green-100 text-green-800'
    case 'denied': return 'bg-red-100 text-red-800'
    case 'checked_in': return 'bg-blue-100 text-blue-800'
    case 'checked_out': return 'bg-gray-100 text-gray-800'
    default: return 'bg-yellow-100 text-yellow-800'
  }
}

const getStatusIcon = (status) => {
  switch (status) {
    case 'approved': return '✅'
    case 'denied': return '❌'
    case 'checked_in': return '🚪'
    case 'checked_out': return '🏠'
    default: return '⏳'
  }
}

export default function VisitorManagement() {
  const [activeTab, setActiveTab] = useState('list')
  const [showModal, setShowModal] = useState(false)
  const [selectedVisitor, setSelectedVisitor] = useState(null)
  const [filters, setFilters] = useState({
    status: '',
    date_from: '',
    date_to: ''
  })
  const [page, setPage] = useState(1)
  const limit = 20

  const queryParams = new URLSearchParams({
    page: page.toString(),
    limit: limit.toString(),
    ...(filters.status && { status: filters.status }),
    ...(filters.date_from && { date_from: filters.date_from }),
    ...(filters.date_to && { date_to: filters.date_to })
  })

  const { data: visitorsData, error, mutate } = useSWR(`/api/visitors?${queryParams}`, fetcher)
  const visitors = visitorsData?.visitors || []
  const total = visitorsData?.total || 0
  const totalPages = Math.ceil(total / limit)

  const handleVisitorAction = (action, visitor) => {
    setSelectedVisitor(visitor)
    setActiveTab(action)
    setShowModal(true)
  }

  const handleApprove = async (visitorId) => {
    try {
      const response = await apiClient.post(`/api/visitors/${visitorId}/approve`)
      if (response.success) {
        alert('Visitor approved successfully!')
        mutate()
        setShowModal(false)
      } else {
        alert('Error: ' + response.error)
      }
    } catch (error) {
      alert('Error approving visitor: ' + error.message)
    }
  }

  const handleBlacklist = async (visitorId, reason) => {
    try {
      const response = await apiClient.post('/api/visitors/blacklist', {
        visitor_id: visitorId,
        reason: reason,
        severity: 'medium'
      })
      if (response.success) {
        alert('Visitor blacklisted successfully!')
        mutate()
        setShowModal(false)
      } else {
        alert('Error: ' + response.error)
      }
    } catch (error) {
      alert('Error blacklisting visitor: ' + error.message)
    }
  }

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }))
    setPage(1)
  }

  const clearFilters = () => {
    setFilters({ status: '', date_from: '', date_to: '' })
    setPage(1)
  }

  return (
    <div className="space-y-6">
      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <div className="sm:flex sm:items-center sm:justify-between">
            <div>
              <h3 className="text-lg leading-6 font-medium text-gray-900">Visitor Management</h3>
              <p className="mt-1 text-sm text-gray-500">
                Manage visitor registrations, approvals, and access control
              </p>
            </div>
            <div className="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
              <button
                onClick={() => {
                  setSelectedVisitor(null)
                  setActiveTab('register')
                  setShowModal(true)
                }}
                className="inline-flex items-center justify-center rounded-md border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                + Register Visitor
              </button>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="border-t border-gray-200 p-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Status Filter
              </label>
              <select
                value={filters.status}
                onChange={(e) => handleFilterChange('status', e.target.value)}
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              >
                <option value="">All Statuses</option>
                <option value="pending">Pending</option>
                <option value="approved">Approved</option>
                <option value="denied">Denied</option>
                <option value="checked_in">Checked In</option>
                <option value="checked_out">Checked Out</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Date From
              </label>
              <input
                type="date"
                value={filters.date_from}
                onChange={(e) => handleFilterChange('date_from', e.target.value)}
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Date To
              </label>
              <input
                type="date"
                value={filters.date_to}
                onChange={(e) => handleFilterChange('date_to', e.target.value)}
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              />
            </div>

            <div className="flex items-end">
              <button
                onClick={clearFilters}
                className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
              >
                Clear Filters
              </button>
            </div>
          </div>
        </div>

        {/* Visitors Table */}
        <div className="overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Visitor</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Contact</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Purpose</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Host</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Arrival</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {visitors.map((visitor) => (
                <tr key={visitor.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="flex-shrink-0 h-10 w-10">
                        <div className="h-10 w-10 rounded-full bg-gray-300 flex items-center justify-center">
                          <span className="text-sm font-medium text-gray-700">
                            {visitor.name.charAt(0).toUpperCase()}
                          </span>
                        </div>
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-gray-900">{visitor.name}</div>
                        {visitor.company && (
                          <div className="text-sm text-gray-500">{visitor.company}</div>
                        )}
                        {visitor.id_number && (
                          <div className="text-sm text-gray-500">ID: {visitor.id_number}</div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">{visitor.phone}</div>
                    {visitor.email && (
                      <div className="text-sm text-gray-500">{visitor.email}</div>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-gray-900 max-w-xs truncate" title={visitor.purpose}>
                      {visitor.purpose}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">{visitor.host_name}</div>
                    {visitor.host_contact && (
                      <div className="text-sm text-gray-500">{visitor.host_contact}</div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">
                      {new Date(visitor.expected_arrival).toLocaleDateString()}
                    </div>
                    <div className="text-sm text-gray-500">
                      {new Date(visitor.expected_arrival).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <span className="mr-2">{getStatusIcon(visitor.status)}</span>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(visitor.status)}`}>
                        {visitor.status.replace('_', ' ')}
                      </span>
                    </div>
                    {visitor.is_blacklisted && (
                      <div className="text-xs text-red-600 mt-1">🚫 Blacklisted</div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      {visitor.status === 'pending' && (
                        <>
                          <button
                            onClick={() => handleApprove(visitor.id)}
                            className="text-green-600 hover:text-green-900"
                          >
                            Approve
                          </button>
                          <button
                            onClick={() => handleVisitorAction('deny', visitor)}
                            className="text-red-600 hover:text-red-900"
                          >
                            Deny
                          </button>
                        </>
                      )}
                      {visitor.status === 'approved' && (
                        <button
                          onClick={() => handleVisitorAction('view-pass', visitor)}
                          className="text-blue-600 hover:text-blue-900"
                        >
                          View Pass
                        </button>
                      )}
                      {!visitor.is_blacklisted && (
                        <button
                          onClick={() => handleVisitorAction('blacklist', visitor)}
                          className="text-red-600 hover:text-red-900"
                        >
                          Blacklist
                        </button>
                      )}
                      <button
                        onClick={() => handleVisitorAction('edit', visitor)}
                        className="text-gray-600 hover:text-gray-900"
                      >
                        Edit
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200 sm:px-6">
            <div className="flex-1 flex justify-between sm:hidden">
              <button
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page === 1}
                className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
              >
                Previous
              </button>
              <button
                onClick={() => setPage(Math.min(totalPages, page + 1))}
                disabled={page === totalPages}
                className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
              >
                Next
              </button>
            </div>
            <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
              <div>
                <p className="text-sm text-gray-700">
                  Showing{' '}
                  <span className="font-medium">{(page - 1) * limit + 1}</span>
                  {' '}to{' '}
                  <span className="font-medium">{Math.min(page * limit, total)}</span>
                  {' '}of{' '}
                  <span className="font-medium">{total}</span>
                  {' '}results
                </p>
              </div>
              <div>
                <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                  <button
                    onClick={() => setPage(Math.max(1, page - 1))}
                    disabled={page === 1}
                    className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                  >
                    Previous
                  </button>
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    const pageNum = Math.max(1, Math.min(page - 2 + i, totalPages - 4 + i))
                    if (pageNum > totalPages) return null
                    return (
                      <button
                        key={pageNum}
                        onClick={() => setPage(pageNum)}
                        className={`relative inline-flex items-center px-4 py-2 border text-sm font-medium ${
                          page === pageNum
                            ? 'z-10 bg-blue-50 border-blue-500 text-blue-600'
                            : 'bg-white border-gray-300 text-gray-500 hover:bg-gray-50'
                        }`}
                      >
                        {pageNum}
                      </button>
                    )
                  })}
                  <button
                    onClick={() => setPage(Math.min(totalPages, page + 1))}
                    disabled={page === totalPages}
                    className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                  >
                    Next
                  </button>
                </nav>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Modal */}
      {showModal && (
        <VisitorModal
          visitor={selectedVisitor}
          activeTab={activeTab}
          onClose={() => {
            setShowModal(false)
            setSelectedVisitor(null)
          }}
          onSuccess={() => {
            setShowModal(false)
            setSelectedVisitor(null)
            mutate()
          }}
          onApprove={handleApprove}
          onBlacklist={handleBlacklist}
        />
      )}
    </div>
  )
}

function VisitorModal({ visitor, activeTab, onClose, onSuccess, onApprove, onBlacklist }) {
  const [loading, setLoading] = useState(false)
  const [formData, setFormData] = useState({
    name: visitor?.name || '',
    email: visitor?.email || '',
    phone: visitor?.phone || '',
    id_number: visitor?.id_number || '',
    company: visitor?.company || '',
    purpose: visitor?.purpose || '',
    expected_arrival: visitor?.expected_arrival ? visitor.expected_arrival.split('T')[0] : '',
    expected_departure: visitor?.expected_departure ? visitor.expected_departure.split('T')[0] : '',
    host_name: visitor?.host_name || '',
    host_contact: visitor?.host_contact || ''
  })
  const [blacklistReason, setBlacklistReason] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)

    try {
      const url = visitor ? `/api/visitors/${visitor.id}` : '/api/visitors'
      const method = visitor ? 'PUT' : 'POST'
      
      // Convert dates to ISO format
      const submitData = {
        ...formData,
        expected_arrival: formData.expected_arrival ? new Date(formData.expected_arrival).toISOString() : null,
        expected_departure: formData.expected_departure ? new Date(formData.expected_departure).toISOString() : null
      }

      const response = await apiClient[method.toLowerCase()](url, submitData)
      
      if (response.success) {
        onSuccess()
      } else {
        alert('Error: ' + response.error)
      }
    } catch (error) {
      alert('Error saving visitor: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  const handleBlacklistSubmit = async (e) => {
    e.preventDefault()
    if (!blacklistReason.trim()) {
      alert('Please provide a reason for blacklisting')
      return
    }
    setLoading(true)
    
    try {
      await onBlacklist(visitor.id, blacklistReason)
    } catch (error) {
      alert('Error blacklisting visitor: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  const renderModalContent = () => {
    switch (activeTab) {
      case 'register':
      case 'edit':
        return (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">
              {visitor ? 'Edit Visitor' : 'Register New Visitor'}
            </h3>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Full Name *</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    required
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Phone Number *</label>
                  <input
                    type="tel"
                    value={formData.phone}
                    onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                    required
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Email</label>
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">ID Number</label>
                  <input
                    type="text"
                    value={formData.id_number}
                    onChange={(e) => setFormData({ ...formData, id_number: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Company/Organization</label>
                  <input
                    type="text"
                    value={formData.company}
                    onChange={(e) => setFormData({ ...formData, company: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Purpose of Visit *</label>
                  <input
                    type="text"
                    value={formData.purpose}
                    onChange={(e) => setFormData({ ...formData, purpose: e.target.value })}
                    required
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Expected Arrival *</label>
                  <input
                    type="datetime-local"
                    value={formData.expected_arrival}
                    onChange={(e) => setFormData({ ...formData, expected_arrival: e.target.value })}
                    required
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Expected Departure</label>
                  <input
                    type="datetime-local"
                    value={formData.expected_departure}
                    onChange={(e) => setFormData({ ...formData, expected_departure: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Host Name *</label>
                  <input
                    type="text"
                    value={formData.host_name}
                    onChange={(e) => setFormData({ ...formData, host_name: e.target.value })}
                    required
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">Host Contact</label>
                  <input
                    type="text"
                    value={formData.host_contact}
                    onChange={(e) => setFormData({ ...formData, host_contact: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 disabled:opacity-50"
                >
                  {loading ? 'Saving...' : (visitor ? 'Update' : 'Register')}
                </button>
              </div>
            </form>
          </div>
        )

      case 'approve':
        return (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Approve Visitor</h3>
            <div className="mb-4">
              <div className="text-sm text-gray-600">
                <strong>Visitor:</strong> {visitor.name}<br/>
                <strong>Purpose:</strong> {visitor.purpose}<br/>
                <strong>Host:</strong> {visitor.host_name}<br/>
                <strong>Expected Arrival:</strong> {new Date(visitor.expected_arrival).toLocaleString()}
              </div>
            </div>
            <div className="flex justify-end space-x-3">
              <button
                onClick={onClose}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={() => onApprove(visitor.id)}
                className="px-4 py-2 text-sm font-medium text-white bg-green-600 border border-transparent rounded-md hover:bg-green-700"
              >
                Approve & Generate Pass
              </button>
            </div>
          </div>
        )

      case 'deny':
        return (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Deny Visitor</h3>
            <div className="mb-4">
              <div className="text-sm text-gray-600">
                <strong>Visitor:</strong> {visitor.name}<br/>
                <strong>Purpose:</strong> {visitor.purpose}<br/>
                <strong>Host:</strong> {visitor.host_name}
              </div>
            </div>
            <div className="flex justify-end space-x-3">
              <button
                onClick={onClose}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  // Update visitor status to denied
                  apiClient.put(`/api/visitors/${visitor.id}`, { status: 'denied' })
                    .then(() => {
                      onSuccess()
                    })
                    .catch(error => alert('Error: ' + error.message))
                }}
                className="px-4 py-2 text-sm font-medium text-white bg-red-600 border border-transparent rounded-md hover:bg-red-700"
              >
                Deny Visitor
              </button>
            </div>
          </div>
        )

      case 'blacklist':
        return (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Blacklist Visitor</h3>
            <form onSubmit={handleBlacklistSubmit}>
              <div className="mb-4">
                <div className="text-sm text-gray-600 mb-4">
                  <strong>Visitor:</strong> {visitor.name}<br/>
                  <strong>Phone:</strong> {visitor.phone}<br/>
                  <strong>Company:</strong> {visitor.company || 'N/A'}
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Reason for Blacklisting *
                  </label>
                  <textarea
                    value={blacklistReason}
                    onChange={(e) => setBlacklistReason(e.target.value)}
                    required
                    rows={3}
                    className="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 sm:text-sm"
                    placeholder="Provide a detailed reason for blacklisting this visitor..."
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 border border-transparent rounded-md hover:bg-red-700 disabled:opacity-50"
                >
                  {loading ? 'Blacklisting...' : 'Blacklist Visitor'}
                </button>
              </div>
            </form>
          </div>
        )

      case 'view-pass':
        return (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Visitor Pass</h3>
            <VisitorPassDisplay visitor={visitor} />
            <div className="flex justify-end space-x-3 mt-4">
              <button
                onClick={onClose}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
              >
                Close
              </button>
            </div>
          </div>
        )

      default:
        return null
    }
  }

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-20 mx-auto p-5 border w-full max-w-4xl shadow-lg rounded-md bg-white">
        {renderModalContent()}
      </div>
    </div>
  )
}

function VisitorPassDisplay({ visitor }) {
  const { data: passData } = useSWR(
    visitor ? `/api/visitors/${visitor.id}/pass` : null,
    fetcher
  )

  if (!passData) {
    return <div className="text-center text-gray-500">Loading visitor pass...</div>
  }

  return (
    <div className="text-center">
      <div className="bg-gray-100 p-4 rounded-lg mb-4">
        <h4 className="text-lg font-semibold mb-2">Visitor Pass QR Code</h4>
        <img 
          src={passData.pass.qr_code} 
          alt="Visitor QR Code" 
          className="mx-auto mb-2 max-w-xs"
        />
        <p className="text-sm text-gray-600">
          Valid until: {new Date(passData.pass.expires_at).toLocaleString()}
        </p>
      </div>
      
      <div className="text-left bg-gray-50 p-4 rounded">
        <h5 className="font-medium mb-2">Visitor Details:</h5>
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div><strong>Name:</strong> {visitor.name}</div>
          <div><strong>Purpose:</strong> {visitor.purpose}</div>
          <div><strong>Host:</strong> {visitor.host_name}</div>
          <div><strong>Company:</strong> {visitor.company || 'N/A'}</div>
        </div>
      </div>
    </div>
  )
}