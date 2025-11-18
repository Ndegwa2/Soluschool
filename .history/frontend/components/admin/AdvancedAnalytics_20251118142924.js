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
  const { data: basicAnalytics } = useSWR('/api/analytics/summary', fetcher)


  return (
    <div className="min-h-screen bg-gray-50 p-8">
      {/* Main Analytics Panel */}
      <div className="max-w-6xl mx-auto bg-white rounded-3xl shadow-sm border border-gray-200 p-8">
        {/* Header Section */}
        <div className="flex justify-between items-start mb-8">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Analytics</h1>
            <p className="text-sm text-gray-600">Overview of today's activity and visitor flow.</p>
          </div>

          {/* Date Range Chip */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-2">
            <span className="text-sm text-gray-900">Today · 00:00 – Now</span>
          </div>
        </div>

        {/* Navigation Buttons */}
        <div className="flex gap-4 mb-8">
          <button className="bg-gray-100 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-50">
            Scanner
          </button>
          <button className="bg-gray-100 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-50">
            Logs
          </button>
          <button className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700">
            Analytics
          </button>
          <button className="bg-gray-100 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-50">
            Manual Entry
          </button>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-3 gap-6 mb-8">
          <div className="bg-gray-50 border border-gray-200 rounded-xl p-6">
            <div className="text-sm text-gray-600 mb-2">Total Pickups</div>
            <div className="text-3xl font-bold text-gray-900">{basicAnalytics?.total_pickups || 0}</div>
          </div>

          <div className="bg-gray-50 border border-gray-200 rounded-xl p-6">
            <div className="text-sm text-gray-600 mb-2">Peak Hour</div>
            <div className="text-3xl font-bold text-gray-900">
              {basicAnalytics?.peak_hour ? `${basicAnalytics.peak_hour}:00` : 'N/A'}
            </div>
          </div>

          <div className="bg-gray-50 border border-gray-200 rounded-xl p-6">
            <div className="text-sm text-gray-600 mb-2">Visitors Today</div>
            <div className="text-3xl font-bold text-gray-900">{basicAnalytics?.visitors || 0}</div>
          </div>
        </div>

        {/* Status Tag */}
        <div className="flex justify-end mb-8">
          <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-2 flex items-center gap-2">
            <div className="w-3 h-3 bg-blue-600 rounded-full"></div>
            <span className="text-sm text-gray-600">Guard Online · Scanner Idle</span>
          </div>
        </div>

        {/* Chart Area */}
        <div className="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-8">
          <div className="mb-4">
            <div className="text-sm font-semibold text-gray-900">Activity Over Time</div>
            <div className="text-xs text-gray-600">Daily check-ins chart (placeholder)</div>
          </div>

          {/* Placeholder Chart */}
          <div className="space-y-3">
            <div className="h-px bg-gray-200"></div>
            <div className="h-px bg-gray-100"></div>
            <div className="h-px bg-gray-100"></div>
            <svg className="w-full h-32" viewBox="0 0 1000 128">
              <polyline
                points="30,100 160,95 290,98 420,102 550,99 680,101 810,103 940,102"
                fill="none"
                stroke="#d1d5db"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          </div>
        </div>

        {/* Footer Tip */}
        <div className="text-xs text-gray-600">
          Tip: Keep dashboard in full-screen mode for smoother monitoring.
        </div>
      </div>
    </div>
  )
}