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

export default function SystemConfig() {
  const { data: configs, error, mutate } = useSWR('/api/admin/system-config', fetcher)
  const [editingConfig, setEditingConfig] = useState(null)
  const [formData, setFormData] = useState({
    key: '',
    value: '',
    description: ''
  })
  const [loading, setLoading] = useState(false)

  const handleEdit = (config) => {
    setEditingConfig(config)
    setFormData({
      key: config.key,
      value: config.value.toString(),
      description: config.description
    })
  }

  const handleSave = async () => {
    if (!formData.key || !formData.value) {
      alert('Key and value are required')
      return
    }

    setLoading(true)
    try {
      const response = await apiClient.post('/api/admin/system-config', {
        key: formData.key,
        value: formData.value,
        description: formData.description
      })
      
      if (response.success) {
        setEditingConfig(null)
        setFormData({ key: '', value: '', description: '' })
        mutate()
        alert('Configuration updated successfully')
      } else {
        alert('Error: ' + response.error)
      }
    } catch (error) {
      alert('Error saving configuration: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCancel = () => {
    setEditingConfig(null)
    setFormData({ key: '', value: '', description: '' })
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-md p-4">
        <div className="text-sm text-red-600">
          Error loading system configuration: {error.message}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <div className="sm:flex sm:items-center sm:justify-between">
            <div>
              <h3 className="text-lg leading-6 font-medium text-gray-900">System Configuration</h3>
              <p className="mt-1 text-sm text-gray-500">
                Manage system-wide settings and parameters
              </p>
            </div>
          </div>
        </div>

        <div className="border-t border-gray-200">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Configuration Key
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Value
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Description
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {configs?.configs?.map((config) => (
                <tr key={config.key}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-mono text-gray-900">{config.key}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {editingConfig?.key === config.key ? (
                      <input
                        type="text"
                        value={formData.value}
                        onChange={(e) => setFormData({ ...formData, value: e.target.value })}
                        className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                      />
                    ) : (
                      <div className="text-sm text-gray-900">
                        {typeof config.value === 'boolean' ? (
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            config.value ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}>
                            {config.value ? 'Enabled' : 'Disabled'}
                          </span>
                        ) : (
                          config.value.toString()
                        )}
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    {editingConfig?.key === config.key ? (
                      <input
                        type="text"
                        value={formData.description}
                        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                        className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                      />
                    ) : (
                      <div className="text-sm text-gray-500">{config.description}</div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    {editingConfig?.key === config.key ? (
                      <div className="flex space-x-2">
                        <button
                          onClick={handleSave}
                          disabled={loading}
                          className="text-blue-600 hover:text-blue-900 disabled:opacity-50"
                        >
                          Save
                        </button>
                        <button
                          onClick={handleCancel}
                          className="text-gray-600 hover:text-gray-900"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => handleEdit(config)}
                        className="text-blue-600 hover:text-blue-900"
                      >
                        Edit
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Configuration Categories */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">🔐</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Security Settings</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {configs?.configs?.find(c => c.key === 'session_timeout_minutes')?.value || 'N/A'} min
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
                  <span className="text-white text-sm font-medium">📱</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Photo Verification</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {configs?.configs?.find(c => c.key === 'require_photo_verification')?.value ? 'Required' : 'Optional'}
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
                <div className="w-8 h-8 bg-purple-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">👶</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Max Children/Parent</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {configs?.configs?.find(c => c.key === 'max_children_per_parent')?.value || 'N/A'}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* System Status */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">System Status</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Database Connection</span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  Healthy
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Backup System</span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  Active
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Email Service</span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  Connected
                </span>
              </div>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">SMS Service</span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  Active
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Cache System</span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  Limited
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Storage Usage</span>
                <span className="text-sm font-medium text-gray-900">65%</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration Notes */}
      <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
        <div className="flex">
          <div className="ml-3">
            <h3 className="text-sm font-medium text-blue-800">
              Configuration Guidelines
            </h3>
            <div className="mt-2 text-sm text-blue-700">
              <ul className="list-disc list-inside space-y-1">
                <li>Changes to system configuration may require a restart to take effect</li>
                <li>Security settings should be reviewed regularly</li>
                <li>Backup frequency should be set based on your data recovery requirements</li>
                <li>Photo verification is recommended for enhanced security</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}