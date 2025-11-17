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

const getSeverityColor = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'bg-red-100 text-red-800'
    case 'high': return 'bg-orange-100 text-orange-800'
    case 'medium': return 'bg-yellow-100 text-yellow-800'
    case 'low': return 'bg-green-100 text-green-800'
    default: return 'bg-gray-100 text-gray-800'
  }
}

const getSeverityIcon = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical': return '🚨'
    case 'high': return '⚠️'
    case 'medium': return '⚠️'
    case 'low': return 'ℹ️'
    default: return '📋'
  }
}

export default function BlacklistManagement() {
  const [activeTab, setActiveTab] = useState('list')
  const [showModal, setShowModal] = useState(false)
  const [selectedVisitor, setSelectedVisitor] = useState(null)
  const [filters, setFilters] = useState({
    search_term: '',
    date_from: '',
    date_to: ''
  })
  const [page, setPage] = useState(1)
  const limit = 20

  const queryParams = new URLSearchParams({
    page: page.toString(),
    limit: limit.toString(),
    ...(filters.date_from && { date_from: filters.date_from }),
    ...(filters.date_to && { date_to: filters.date_to })
  })

  const { data: blacklistData, error, mutate } = useSWR(
    `/api/visitors/blacklist?${queryParams}`,
    fetcher
  )
  const blacklistedVisitors = blacklistData?.blacklisted_visitors || []
  const total = blacklistData?.total || 0
  const totalPages = Math.ceil(total / limit)

  const handleSearch = async () => {
    if (!filters.search_term.trim()) {
      return
    }
    
    try {
      const response = await apiClient.post('/api/visitors/blacklist/search', {
        search_term: filters.search_term
      })
      
      if (response.success) {
        // Update the list with search results
        mutate()
      } else {
        alert('Search error: ' + response.error)
      }
    } catch (error) {
      alert('Search failed: ' + error.message)
    }
  }

  const handleUnblacklist = async (visitorId) => {
    if (confirm('Are you sure you want to unblacklist this visitor?')) {
      try {
        const response = await apiClient.post(`/api/visitors/${visitorId}/unblacklist`)
        if (response.success) {
          alert('Visitor unblacklisted successfully!')
          mutate()
        } else {
          alert('Error: ' + response.error)
        }
      } catch (error) {
        alert('Error unblacklisting visitor: ' + error.message)
      }
    }
  }

  const handleBulkAction = async (action, visitorIds) => {
    try {
      let response
      if (action === 'unblacklist') {
        // Individual unblacklist for each visitor
        for (const visitorId of visitorIds) {
          await apiClient.post(`/api/visitors/${visitorId}/unblacklist`)
        }
      } else if (action === 'bulk-blacklist') {
        response = await apiClient.post('/api/visitors/blacklist/bulk', {
          visitor_ids: visitorIds,
          reason: 'Bulk blacklist action',
          severity: 'medium'
        })
      }

      if (response?.success !== false || action === 'unblacklist') {
        alert(`Bulk ${action} completed successfully!`)
        mutate()
        setSelectedVisitor(null)
      } else {
        alert('Error: ' + (response?.error || 'Unknown error'))
      }
    } catch (error) {
      alert(`Error during bulk action: ${error.message}`)
    }
  }

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }))
    setPage(1)
  }

  const clearFilters = () => {
    setFilters({ search_term: '', date_from: '', date_to: '' })
    setPage(1)
  }

  return (
    <div className="space-y-6">
      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <div className="sm:flex sm:items-center sm:justify-between">
            <div>
              <h3 className="text-lg leading-6 font-medium text-gray-900">Blacklist Management</h3>
              <p className="mt-1 text-sm text-gray-500">
                Manage blacklisted visitors and access control restrictions
              </p>
            </div>
            <div className="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
              <button
                onClick={() => {
                  setSelectedVisitor(null)
                  setActiveTab('add-blacklist')
                  setShowModal(true)
                }}
                className="inline-flex items-center justify-center rounded-md border border-transparent bg-red-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
              >
                + Add to Blacklist
              </button>
            </div>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="border-t border-gray-200 p-6">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Search Blacklist
              </label>
              <div className="flex">
                <input
                  type="text"
                  value={filters.search_term}
                  onChange={(e) => handleFilterChange('search_term', e.target.value)}
                  placeholder="Name, phone, email, ID, or company"
                  className="flex-1 rounded-l-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 text-sm"
                />
                <button
                  onClick={handleSearch}
                  className="inline-flex items-center px-4 py-2 border border-l-0 border-gray-300 rounded-r-md bg-gray-50 text-sm font-medium text-gray-700 hover:bg-gray-100"
                >
                  Search
                </button>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Date From
              </label>
              <input
                type="date"
                value={filters.date_from}
                onChange={(e) => handleFilterChange('date_from', e.target.value)}
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 text-sm"
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
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 text-sm"
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

        {/* Blacklisted Visitors Table */}
        <div className="overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Visitor</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Contact Info</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reason</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date Blacklisted</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {blacklistedVisitors.map((visitor) => (
                <tr key={visitor.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="flex-shrink-0 h-10 w-10">
                        <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                          <span className="text-sm font-medium text-red-700">
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
                    <div className="text-sm text-gray-900 max-w-xs truncate" title={visitor.blacklist_reason}>
                      {visitor.blacklist_reason}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <span className="mr-2">{getSeverityIcon(visitor.severity)}</span>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(visitor.severity)}`}>
                        {visitor.severity || 'medium'}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">
                      {new Date(visitor.updated_at).toLocaleDateString()}
                    </div>
                    <div className="text-sm text-gray-500">
                      {new Date(visitor.updated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => {
                          setSelectedVisitor(visitor)
                          setActiveTab('view-details')
                          setShowModal(true)
                        }}
                        className="text-blue-600 hover:text-blue-900"
                      >
                        View Details
                      </button>
                      <button
                        onClick={() => handleUnblacklist(visitor.id)}
                        className="text-green-600 hover:text-green-900"
                      >
                        Unblacklist
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
                            ? 'z-10 bg-red-50 border-red-500 text-red-600'
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

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-red-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">🚫</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Total Blacklisted</dt>
                  <dd className="text-lg font-medium text-gray-900">{total}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-orange-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">⚠️</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">High Severity</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {blacklistedVisitors.filter(v => (v.severity || '').toLowerCase() === 'high').length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-yellow-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">⚠️</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Medium Severity</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {blacklistedVisitors.filter(v => (v.severity || '').toLowerCase() === 'medium').length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">ℹ️</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Low Severity</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {blacklistedVisitors.filter(v => (v.severity || '').toLowerCase() === 'low').length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Modal */}
      {showModal && (
        <BlacklistModal
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
          onUnblacklist={handleUnblacklist}
        />
      )}
    </div>
  )
}

function BlacklistModal({ visitor, activeTab, onClose, onSuccess, onUnblacklist }) {
  const [loading, setLoading] = useState(false)
  const [blacklistData, setBlacklistData] = useState({
    visitor_id: visitor?.id || '',
    reason: '',
    severity: 'medium',
    expires_at: ''
  })

  const handleBlacklistSubmit = async (e) => {
    e.preventDefault()
    if (!blacklistData.reason.trim()) {
      alert('Please provide a reason for blacklisting')
      return
    }
    setLoading(true)
    
    try {
      const response = await apiClient.post('/api/visitors/blacklist', blacklistData)
      if (response.success) {
        onSuccess()
      } else {
        alert('Error: ' + response.error)
      }
    } catch (error) {
      alert('Error blacklisting visitor: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  const renderModalContent = () => {
    switch (activeTab) {
      case 'add-blacklist':
        return (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Add to Blacklist</h3>
            <form onSubmit={handleBlacklistSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Visitor ID *
                </label>
                <input
                  type="number"
                  value={blacklistData.visitor_id}
                  onChange={(e) => setBlacklistData({ ...blacklistData, visitor_id: e.target.value })}
                  required
                  className="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 sm:text-sm"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Reason for Blacklisting *
                </label>
                <textarea
                  value={blacklistData.reason}
                  onChange={(e) => setBlacklistData({ ...blacklistData, reason: e.target.value })}
                  required
                  rows={3}
                  className="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 sm:text-sm"
                  placeholder="Provide a detailed reason for blacklisting this visitor..."
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Severity Level
                </label>
                <select
                  value={blacklistData.severity}
                  onChange={(e) => setBlacklistData({ ...blacklistData, severity: e.target.value })}
                  className="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 sm:text-sm"
                >
                  <option value="low">Low - Minor issues</option>
                  <option value="medium">Medium - Standard restrictions</option>
                  <option value="high">High - Serious concerns</option>
                  <option value="critical">Critical - Severe security threat</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Expiration Date (Optional)
                </label>
                <input
                  type="datetime-local"
                  value={blacklistData.expires_at}
                  onChange={(e) => setBlacklistData({ ...blacklistData, expires_at: e.target.value })}
                  className="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 sm:text-sm"
                />
                <p className="mt-1 text-sm text-gray-500">Leave empty for permanent blacklist</p>
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
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 border border-transparent rounded-md hover:bg-red-700 disabled:opacity-50"
                >
                  {loading ? 'Blacklisting...' : 'Add to Blacklist'}
                </button>
              </div>
            </form>
          </div>
        )

      case 'view-details':
        return (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Blacklist Details</h3>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Name</label>
                  <div className="text-sm text-gray-900">{visitor.name}</div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Phone</label>
                  <div className="text-sm text-gray-900">{visitor.phone}</div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Email</label>
                  <div className="text-sm text-gray-900">{visitor.email || 'N/A'}</div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Company</label>
                  <div className="text-sm text-gray-900">{visitor.company || 'N/A'}</div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Severity</label>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(visitor.severity)}`}>
                    {visitor.severity || 'medium'}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Date Blacklisted</label>
                  <div className="text-sm text-gray-900">
                    {new Date(visitor.updated_at).toLocaleString()}
                  </div>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Reason</label>
                <div className="text-sm text-gray-900 bg-gray-50 p-3 rounded-md">
                  {visitor.blacklist_reason}
                </div>
              </div>
            </div>

            <div className="flex justify-end space-x-3 pt-4 mt-6">
              <button
                onClick={onClose}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
              >
                Close
              </button>
              <button
                onClick={() => {
                  onUnblacklist(visitor.id)
                  onClose()
                }}
                className="px-4 py-2 text-sm font-medium text-white bg-green-600 border border-transparent rounded-md hover:bg-green-700"
              >
                Unblacklist Visitor
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
      <div className="relative top-20 mx-auto p-5 border w-full max-w-2xl shadow-lg rounded-md bg-white">
        {renderModalContent()}
      </div>
    </div>
  )
}