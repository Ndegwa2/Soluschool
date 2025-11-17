import React, { useState } from 'react'
import { apiClient } from '../../lib/api'

export default function BulkOperations() {
  const [activeTab, setActiveTab] = useState('import')
  const [importData, setImportData] = useState('')
  const [importResults, setImportResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [exportFilters, setExportFilters] = useState({
    role: '',
    school_id: '',
    format: 'json'
  })

  const handleImport = async () => {
    if (!importData.trim()) {
      alert('Please provide user data to import')
      return
    }

    setLoading(true)
    try {
      // Parse the JSON data
      const usersData = JSON.parse(importData)
      
      if (!usersData.users || !Array.isArray(usersData.users)) {
        alert('Invalid format. Expected JSON with "users" array')
        setLoading(false)
        return
      }

      const response = await apiClient.post('/api/admin/users/bulk-create', usersData)
      
      if (response.success) {
        setImportResults(response.data.results)
      } else {
        alert('Error: ' + response.error)
      }
    } catch (error) {
      alert('Error parsing data or importing users: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  const handleExport = async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (exportFilters.role) params.append('role', exportFilters.role)
      if (exportFilters.school_id) params.append('school_id', exportFilters.school_id)
      if (exportFilters.format) params.append('format', exportFilters.format)

      const response = await apiClient.get(`/api/admin/users/export?${params}`)
      
      if (response.success) {
        if (exportFilters.format === 'csv') {
          // Handle CSV download
          const blob = new Blob([response.data], { type: 'text/csv' })
          const url = window.URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = 'users_export.csv'
          a.click()
          window.URL.revokeObjectURL(url)
        } else {
          // Display JSON data
          const dataStr = JSON.stringify(response.data, null, 2)
          setImportData(dataStr)
          setActiveTab('import') // Switch to import tab to show results
        }
      } else {
        alert('Error exporting users: ' + response.error)
      }
    } catch (error) {
      alert('Error exporting users: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  const sampleData = `{
  "users": [
    {
      "name": "John Doe",
      "email": "john.doe@example.com",
      "phone": "+1234567890",
      "password": "password123",
      "role": "parent",
      "school_id": 1,
      "children": [
        {
          "name": "Jane Doe",
          "grade": "5th Grade",
          "date_of_birth": "2015-05-15"
        }
      ]
    },
    {
      "name": "Alice Smith",
      "email": "alice.smith@example.com",
      "phone": "+1987654321",
      "password": "password456",
      "role": "guard",
      "school_id": 1
    }
  ]
}`

  return (
    <div className="space-y-6">
      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900">Bulk Operations</h3>
          <p className="mt-1 text-sm text-gray-500">
            Import and export users in bulk, manage large-scale operations
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex">
            <button
              onClick={() => setActiveTab('import')}
              className={`py-2 px-4 text-sm font-medium border-b-2 ${
                activeTab === 'import'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Import Users
            </button>
            <button
              onClick={() => setActiveTab('export')}
              className={`py-2 px-4 text-sm font-medium border-b-2 ${
                activeTab === 'export'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Export Users
            </button>
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'import' && (
            <div className="space-y-4">
              <div>
                <h4 className="text-lg font-medium text-gray-900 mb-2">Import Users</h4>
                <p className="text-sm text-gray-500 mb-4">
                  Paste JSON data with user information. All users will be created with the provided details.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  User Data (JSON Format)
                </label>
                <textarea
                  value={importData}
                  onChange={(e) => setImportData(e.target.value)}
                  rows={15}
                  className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 font-mono text-sm"
                  placeholder="Paste JSON data here..."
                />
              </div>

              <div className="flex justify-between">
                <button
                  onClick={() => setImportData(sampleData)}
                  className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Load Sample Data
                </button>
                
                <button
                  onClick={handleImport}
                  disabled={loading || !importData.trim()}
                  className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                >
                  {loading ? 'Importing...' : 'Import Users'}
                </button>
              </div>

              {/* Import Results */}
              {importResults && (
                <div className="mt-6 p-4 border rounded-md">
                  <h5 className="text-lg font-medium text-gray-900 mb-4">Import Results</h5>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div className="bg-green-50 p-3 rounded-md">
                      <div className="text-sm font-medium text-green-800">
                        Successful: {importResults.successful?.length || 0}
                      </div>
                      {importResults.successful?.length > 0 && (
                        <div className="text-xs text-green-600 mt-1">
                          {importResults.successful.map(s => s.email).join(', ')}
                        </div>
                      )}
                    </div>
                    
                    <div className="bg-red-50 p-3 rounded-md">
                      <div className="text-sm font-medium text-red-800">
                        Failed: {importResults.failed?.length || 0}
                      </div>
                      {importResults.failed?.length > 0 && (
                        <div className="text-xs text-red-600 mt-1">
                          {importResults.failed.map(f => `${f.email}: ${f.error}`).join(', ')}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'export' && (
            <div className="space-y-4">
              <div>
                <h4 className="text-lg font-medium text-gray-900 mb-2">Export Users</h4>
                <p className="text-sm text-gray-500 mb-4">
                  Export user data with optional filters and in various formats.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Role Filter
                  </label>
                  <select
                    value={exportFilters.role}
                    onChange={(e) => setExportFilters({ ...exportFilters, role: e.target.value })}
                    className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
                  >
                    <option value="">All Roles</option>
                    <option value="parent">Parent</option>
                    <option value="guard">Guard</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    School ID Filter
                  </label>
                  <input
                    type="number"
                    value={exportFilters.school_id}
                    onChange={(e) => setExportFilters({ ...exportFilters, school_id: e.target.value })}
                    placeholder="Enter school ID"
                    className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Export Format
                  </label>
                  <select
                    value={exportFilters.format}
                    onChange={(e) => setExportFilters({ ...exportFilters, format: e.target.value })}
                    className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
                  >
                    <option value="json">JSON</option>
                    <option value="csv">CSV</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={handleExport}
                  disabled={loading}
                  className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                >
                  {loading ? 'Exporting...' : 'Export Users'}
                </button>
              </div>

              <div className="mt-6 p-4 bg-blue-50 rounded-md">
                <h6 className="text-sm font-medium text-blue-800 mb-2">Export Information</h6>
                <ul className="text-sm text-blue-600 space-y-1">
                  <li>• JSON format includes full user details and children information</li>
                  <li>• CSV format includes basic user information in spreadsheet format</li>
                  <li>• Filters will be applied before export</li>
                  <li>• Large exports may take some time to process</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}