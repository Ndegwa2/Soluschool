import React from 'react'
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

const StatCard = ({ title, value, color, icon }) => {
  return (
    <div style={{
      width: '220px',
      height: '92px',
      backgroundColor: '#ffffff',
      borderRadius: '10px',
      border: '1px solid #e5e7eb',
      padding: '16px 20px',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between'
    }}>
      <div style={{
        fontSize: '13px',
        color: 'rgba(17, 24, 39, 0.6)',
        fontWeight: '500'
      }}>
        {title}
      </div>
      <div style={{
        fontSize: '26px',
        fontWeight: '600',
        color: color,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <span>{value}</span>
        <span style={{ fontSize: '20px' }}>{icon}</span>
      </div>
    </div>
  )
}

const VisitorChart = () => {
  // Simple trend data for the wireframe
  const trendData = [
    { day: 'Mon', value: 85 },
    { day: 'Tue', value: 120 },
    { day: 'Wed', value: 95 },
    { day: 'Thu', value: 140 },
    { day: 'Fri', value: 110 },
    { day: 'Sat', value: 75 },
    { day: 'Sun', value: 90 }
  ]

  const maxValue = Math.max(...trendData.map(d => d.value))
  const chartHeight = 160

  return (
    <div style={{
      width: '600px',
      height: '240px',
      backgroundColor: '#ffffff',
      borderRadius: '12px',
      border: '1px solid #e5e7eb',
      padding: '20px'
    }}>
      <h3 style={{
        fontSize: '14px',
        fontWeight: '600',
        color: '#111827',
        margin: '0 0 20px 0'
      }}>
        Visitor Trends (7 days)
      </h3>
      
      <div style={{ position: 'relative', height: '160px' }}>
        <svg width="100%" height="100%" viewBox="0 0 560 160" style={{ overflow: 'visible' }}>
          {/* Grid lines */}
          {[0, 1, 2, 3, 4].map(i => (
            <line
              key={i}
              x1="0"
              y1={i * 32}
              x2="560"
              y2={i * 32}
              stroke="#f1f5f9"
              strokeWidth="1"
            />
          ))}
          
          {/* Line chart */}
          <polyline
            points={trendData.map((d, i) => {
              const x = (i / (trendData.length - 1)) * 520 + 20
              const y = chartHeight - (d.value / maxValue) * chartHeight + 20
              return `${x},${y}`
            }).join(' ')}
            fill="none"
            stroke="#1E3A8A"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{ opacity: 0.95 }}
          />
          
          {/* Data points */}
          {trendData.map((d, i) => {
            const x = (i / (trendData.length - 1)) * 520 + 20
            const y = chartHeight - (d.value / maxValue) * chartHeight + 20
            return (
              <circle
                key={i}
                cx={x}
                cy={y}
                r="4"
                fill="#1E3A8A"
              />
            )
          })}
        </svg>
        
        {/* X-axis labels */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          marginTop: '8px',
          padding: '0 20px'
        }}>
          {trendData.map((d, i) => (
            <div key={i} style={{
              fontSize: '11px',
              color: 'rgba(17, 24, 39, 0.6)',
              fontWeight: '500'
            }}>
              {d.day}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

const QuickActions = () => {
  return (
    <div style={{
      width: '296px',
      height: '240px',
      backgroundColor: '#ffffff',
      borderRadius: '12px',
      border: '1px solid #e5e7eb',
      padding: '20px'
    }}>
      <h3 style={{
        fontSize: '14px',
        fontWeight: '600',
        color: '#111827',
        margin: '0 0 20px 0'
      }}>
        Quick Actions
      </h3>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <button style={{
          width: '136px',
          height: '36px',
          backgroundColor: '#1E3A8A',
          color: '#ffffff',
          border: 'none',
          borderRadius: '8px',
          fontSize: '13px',
          fontWeight: '500',
          cursor: 'pointer',
          textAlign: 'center',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px'
        }}>
          <span>+</span>
          <span>Register Visitor</span>
        </button>
        
        <button style={{
          width: '128px',
          height: '36px',
          backgroundColor: '#f3f4f6',
          color: '#111827',
          border: 'none',
          borderRadius: '8px',
          fontSize: '13px',
          fontWeight: '500',
          cursor: 'pointer'
        }}>
          Generate Report
        </button>
      </div>
      
      <div style={{ marginTop: '32px' }}>
        <div style={{
          fontSize: '12px',
          color: 'rgba(17, 24, 39, 0.6)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          marginBottom: '8px'
        }}>
          <span style={{ color: '#FACC15' }}>•</span>
          <span>Visitor ID missing (3)</span>
        </div>
        <div style={{
          fontSize: '12px',
          color: 'rgba(17, 24, 39, 0.6)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          marginBottom: '8px'
        }}>
          <span style={{ color: '#ef4444' }}>•</span>
          <span>Blacklist alert: 1 recent arrival</span>
        </div>
        <div style={{
          fontSize: '12px',
          color: 'rgba(17, 24, 39, 0.6)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <span style={{ color: '#1E3A8A' }}>•</span>
          <span>Evacuation drill scheduled</span>
        </div>
      </div>
    </div>
  )
}

const RecentActivityTable = () => {
  const activities = [
    { time: '08:12', visitor: 'John Mwangi', host: 'Mrs. Kamau', purpose: 'Parent meeting', status: 'checked-in', statusColor: '#17a673' },
    { time: '09:03', visitor: 'Supply Co.', host: 'Stores Dept.', purpose: 'Delivery', status: 'pending', statusColor: '#f6b23a' },
    { time: '10:20', visitor: 'Alice N.', host: 'Mr. Otieno', purpose: 'Interview', status: 'blacklisted', statusColor: '#d64545' }
  ]

  return (
    <div style={{
      width: '916px',
      height: '208px',
      backgroundColor: '#ffffff',
      borderRadius: '12px',
      border: '1px solid #e5e7eb',
      padding: '20px'
    }}>
      <h3 style={{
        fontSize: '14px',
        fontWeight: '600',
        color: '#111827',
        margin: '0 0 20px 0'
      }}>
        Recent Activity
      </h3>
      
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {/* Table Header */}
        <div style={{
          height: '36px',
          backgroundColor: '#f9fafb',
          borderRadius: '6px',
          border: '1px solid #e5e7eb',
          display: 'flex',
          alignItems: 'center',
          padding: '0 16px',
          marginBottom: '12px'
        }}>
          <div style={{ width: '80px', fontSize: '12px', color: 'rgba(17, 24, 39, 0.7)', fontWeight: '500' }}>Time</div>
          <div style={{ width: '160px', fontSize: '12px', color: 'rgba(17, 24, 39, 0.7)', fontWeight: '500' }}>Visitor</div>
          <div style={{ width: '160px', fontSize: '12px', color: 'rgba(17, 24, 39, 0.7)', fontWeight: '500' }}>Host</div>
          <div style={{ width: '220px', fontSize: '12px', color: 'rgba(17, 24, 39, 0.7)', fontWeight: '500' }}>Purpose</div>
          <div style={{ width: '80px', fontSize: '12px', color: 'rgba(17, 24, 39, 0.7)', fontWeight: '500' }}>Status</div>
        </div>
        
        {/* Table Rows */}
        {activities.map((activity, index) => (
          <div key={index} style={{
            height: '40px',
            display: 'flex',
            alignItems: 'center',
            padding: '0 16px',
            borderBottom: index < activities.length - 1 ? '1px solid #f3f4f6' : 'none'
          }}>
            <div style={{ width: '80px', fontSize: '13px', color: '#111827', fontWeight: '400' }}>{activity.time}</div>
            <div style={{ width: '160px', fontSize: '13px', color: '#111827', fontWeight: '400' }}>{activity.visitor}</div>
            <div style={{ width: '160px', fontSize: '13px', color: '#111827', fontWeight: '400' }}>{activity.host}</div>
            <div style={{ width: '220px', fontSize: '13px', color: '#111827', fontWeight: '400' }}>{activity.purpose}</div>
            <div style={{
              width: '80px',
              height: '24px',
              backgroundColor: activity.statusColor,
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '12px',
              fontWeight: '500',
              color: activity.status === 'checked-in' || activity.status === 'blacklisted' ? '#ffffff' : '#111827'
            }}>
              {activity.status.replace('-', ' ')}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

const AdminDashboardOverview = () => {
  const { data: analytics } = useSWR('/api/analytics/summary', fetcher)

  const stats = [
    { title: 'Visitors Today', value: analytics?.visitors_today || 128, color: '#111827', icon: '👥' },
    { title: 'Currently Inside', value: analytics?.currently_inside || 27, color: '#e56a00', icon: '🚪' },
    { title: 'Pending Approvals', value: analytics?.pending_approvals || 8, color: '#17a673', icon: '⏳' },
    { title: 'Blacklisted', value: analytics?.blacklisted || 3, color: '#d64545', icon: '🚫' }
  ]

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      gap: '24px'
    }}>
      {/* Stat Cards */}
      <div style={{ display: 'flex', gap: '16px' }}>
        {stats.map((stat, index) => (
          <StatCard key={index} {...stat} />
        ))}
      </div>
      
      {/* Charts and Quick Actions */}
      <div style={{ display: 'flex', gap: '24px' }}>
        <VisitorChart />
        <QuickActions />
      </div>
      
      {/* Recent Activity Table */}
      <RecentActivityTable />
      
      {/* Footer */}
      <div style={{
        fontSize: '11px',
        color: 'rgba(17, 24, 39, 0.5)',
        textAlign: 'center',
        padding: '20px 0'
      }}>
        © Soluschool — Visitor Management • Prototype
      </div>
    </div>
  )
}

export default AdminDashboardOverview