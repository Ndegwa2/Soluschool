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

export default function AdvancedAnalytics() {
  const [selectedMetric, setSelectedMetric] = useState('daily_activity')
  const [selectedPeriod, setSelectedPeriod] = useState('weekly')
  const [schoolId, setSchoolId] = useState('')
  const [reportType, setReportType] = useState('activity_summary')

  const queryParams = new URLSearchParams({
    metric: selectedMetric,
    period: selectedPeriod,
    ...(schoolId && { school_id: schoolId })
  })

  const { data: analyticsData, error: analyticsError } = useSWR(
    `/api/admin/analytics/advanced?${queryParams}`,
    fetcher
  )

  const { data: reportData, error: reportError } = useSWR(
    `/api/admin/reports/export?type=${reportType}&${schoolId ? `school_id=${schoolId}` : ''}`,
    fetcher
  )

  const { data: basicAnalytics } = useSWR('/api/analytics/summary', fetcher)

  const metrics = [
    { id: 'daily_activity', name: 'Daily Activity', icon: '📅' },
    { id: 'user_engagement', name: 'User Engagement', icon: '👥' },
    { id: 'pickup_patterns', name: 'Pickup Patterns', icon: '⏰' }
  ]

  const renderChart = () => {
    if (!analyticsData?.data) return null

    switch (selectedMetric) {
      case 'daily_activity':
        return renderActivityChart(analyticsData.data)
      case 'user_engagement':
        return renderEngagementChart(analyticsData.data)
      case 'pickup_patterns':
        return renderPickupPatternsChart(analyticsData.data)
      default:
        return <div className="text-gray-500">No data available</div>
    }
  }

  const renderActivityChart = (data) => {
    const maxValue = Math.max(...data.map(d => d.total_logs || 0))
    
    return (
      <div className="space-y-4">
        {data.map((item, index) => (
          <div key={index} className="flex items-center space-x-4">
            <div className="w-20 text-sm text-gray-600">
              {new Date(item.date).toLocaleDateString()}
            </div>
            <div className="flex-1">
              <div className="flex items-center space-x-2">
                <div className="w-full bg-gray-200 rounded-full h-4">
                  <div
                    className="bg-blue-500 h-4 rounded-full transition-all duration-300"
                    style={{ width: `${(item.total_logs / maxValue) * 100}%` }}
                  />
                </div>
                <div className="text-sm font-medium text-gray-900 w-16">
                  {item.total_logs || 0}
                </div>
              </div>
              <div className="flex items-center space-x-4 text-xs text-gray-500 mt-1">
                <span>✅ {item.approved || 0} Approved</span>
                <span>❌ {item.denied || 0} Denied</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    )
  }

  const renderEngagementChart = (data) => {
    const colors = ['bg-blue-500', 'bg-green-500', 'bg-purple-500', 'bg-yellow-500', 'bg-red-500']
    
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <h4 className="text-sm font-medium text-gray-900 mb-4">User Role Distribution</h4>
          {data.map((item, index) => (
            <div key={index} className="flex items-center justify-between py-2">
              <div className="flex items-center space-x-2">
                <div className={`w-4 h-4 rounded ${colors[index % colors.length]}`} />
                <span className="text-sm text-gray-600 capitalize">{item.role}</span>
              </div>
              <span className="text-sm font-medium text-gray-900">{item.count}</span>
            </div>
          ))}
        </div>
        <div className="flex items-center justify-center">
          <div className="w-32 h-32 relative">
            {/* Simple pie chart representation */}
            <div className="w-full h-full rounded-full border-4 border-gray-200 relative overflow-hidden">
              {data.reduce((acc, item, index) => {
                const percentage = (item.count / data.reduce((sum, i) => sum + i.count, 0)) * 100
                const rotation = acc.reduce((sum, p) => sum + p, 0) * 3.6
                return [...acc, percentage]
              }, []).map((percentage, index) => (
                <div
                  key={index}
                  className={`absolute w-full h-full ${colors[index % colors.length]}`}
                  style={{
                    clipPath: `polygon(50% 50%, 50% 0%, ${50 + percentage * 0.5}% 0%, ${50 + percentage * 0.5}% 100%, 50% 100%)`,
                    transform: `rotate(${data.slice(0, index).reduce((sum, p) => sum + p.count, 0) * 3.6}deg)`
                  }}
                />
              ))}
            </div>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-xs font-medium text-gray-700">
                {data.reduce((sum, item) => sum + item.count, 0)}
              </span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  const renderPickupPatternsChart = (data) => {
    const maxPickups = Math.max(...data.map(d => d.pickups || 0))
    
    return (
      <div className="space-y-2">
        <div className="grid grid-cols-12 gap-1 mb-4">
          {Array.from({ length: 24 }, (_, hour) => {
            const hourData = data.find(d => d.hour === hour)
            const pickups = hourData?.pickups || 0
            const intensity = maxPickups > 0 ? pickups / maxPickups : 0
            
            return (
              <div key={hour} className="text-center">
                <div
                  className={`h-16 rounded ${
                    intensity > 0.8 ? 'bg-red-500' :
                    intensity > 0.6 ? 'bg-orange-500' :
                    intensity > 0.4 ? 'bg-yellow-500' :
                    intensity > 0.2 ? 'bg-green-500' :
                    'bg-gray-200'
                  }`}
                  style={{ opacity: 0.3 + intensity * 0.7 }}
                  title={`${hour}:00 - ${pickups} pickups`}
                />
                <div className="text-xs text-gray-600 mt-1">{hour}</div>
              </div>
            )
          })}
        </div>
        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>Low Activity</span>
          <div className="flex space-x-1">
            <div className="w-4 h-3 bg-gray-200" />
            <div className="w-4 h-3 bg-green-500" />
            <div className="w-4 h-3 bg-yellow-500" />
            <div className="w-4 h-3 bg-orange-500" />
            <div className="w-4 h-3 bg-red-500" />
          </div>
          <span>High Activity</span>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Analytics Controls */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900">Advanced Analytics</h3>
          <p className="mt-1 text-sm text-gray-500">
            Deep insights into system usage and user behavior
          </p>
        </div>

        <div className="border-t border-gray-200 p-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Analytics Metric
              </label>
              <select
                value={selectedMetric}
                onChange={(e) => setSelectedMetric(e.target.value)}
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              >
                {metrics.map(metric => (
                  <option key={metric.id} value={metric.id}>
                    {metric.icon} {metric.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Time Period
              </label>
              <select
                value={selectedPeriod}
                onChange={(e) => setSelectedPeriod(e.target.value)}
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                School ID (Optional)
              </label>
              <input
                type="number"
                value={schoolId}
                onChange={(e) => setSchoolId(e.target.value)}
                placeholder="Filter by school"
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              />
            </div>

            <div className="flex items-end">
              <button
                onClick={() => {
                  setSchoolId('')
                  setSelectedMetric('daily_activity')
                  setSelectedPeriod('weekly')
                }}
                className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
              >
                Reset Filters
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">📊</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Total Pickups</dt>
                  <dd className="text-lg font-medium text-gray-900">{basicAnalytics?.total_pickups || 0}</dd>
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
                  <span className="text-white text-sm font-medium">👥</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Unique Visitors</dt>
                  <dd className="text-lg font-medium text-gray-900">{basicAnalytics?.visitors || 0}</dd>
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
                  <span className="text-white text-sm font-medium">⏰</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Peak Hour</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {basicAnalytics?.peak_hour ? `${basicAnalytics.peak_hour}:00` : 'N/A'}
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
                  <span className="text-white text-sm font-medium">📈</span>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Data Points</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {analyticsData?.data?.length || 0}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Analytics Chart */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
            {metrics.find(m => m.id === selectedMetric)?.name || 'Analytics'} Chart
          </h3>
          
          {analyticsError ? (
            <div className="text-red-500 text-sm">Error loading analytics data</div>
          ) : analyticsData?.data ? (
            <div className="min-h-[400px]">
              {renderChart()}
            </div>
          ) : (
            <div className="text-gray-500 text-center py-8">Loading analytics data...</div>
          )}
        </div>
      </div>

      {/* Reports Section */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <div className="sm:flex sm:items-center sm:justify-between mb-4">
            <div>
              <h3 className="text-lg leading-6 font-medium text-gray-900">Generate Reports</h3>
              <p className="mt-1 text-sm text-gray-500">
                Export detailed reports for further analysis
              </p>
            </div>
            <div className="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
              <button
                onClick={() => {
                  const params = new URLSearchParams({
                    type: reportType,
                    ...(schoolId && { school_id: schoolId })
                  })
                  window.open(`/api/admin/reports/export?${params}`, '_blank')
                }}
                className="inline-flex items-center justify-center rounded-md border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700"
              >
                Export Report
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Report Type
              </label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              >
                <option value="activity_summary">Activity Summary</option>
                <option value="user_engagement">User Engagement</option>
                <option value="system_performance">System Performance</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                School ID (Optional)
              </label>
              <input
                type="number"
                value={schoolId}
                onChange={(e) => setSchoolId(e.target.value)}
                placeholder="Filter by school"
                className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              />
            </div>
          </div>

          {reportData && (
            <div className="mt-6 p-4 bg-gray-50 rounded-md">
              <h4 className="text-sm font-medium text-gray-900 mb-2">Report Preview</h4>
              <div className="text-sm text-gray-600 space-y-1">
                <div>Total Pickups: {reportData.data?.total_pickups || 0}</div>
                <div>Total Denied: {reportData.data?.total_denied || 0}</div>
                <div>Total Escalated: {reportData.data?.total_escalated || 0}</div>
                <div>Date Range: {reportData.data?.date_range}</div>
                <div>Generated At: {reportData.data?.generated_at}</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}