import React, { useState } from 'react'
import useSWR from 'swr'
import { apiClient } from '../../lib/api'
import { getUserId } from '../../lib/auth'

const fetcher = async (url) => {
  const response = await apiClient.get(url)
  if (response.success) {
    return response.data
  } else {
    throw new Error(response.error)
  }
}

export default function SchoolsManagement() {
  const { data: schoolsData, error, mutate } = useSWR('/api/schools', fetcher)
  const [selectedSchools, setSelectedSchools] = useState([])
  const [activeFilter, setActiveFilter] = useState('All')
  const [selectedSchool, setSelectedSchool] = useState(null)
  const [showSlidePanel, setShowSlidePanel] = useState(false)

  const schools = schoolsData?.schools || []

  // Mock stats - in real implementation, calculate from actual data
  const stats = {
    total: schools.length,
    active: schools.filter(s => s.status === 'active').length,
    pending: schools.filter(s => s.status === 'pending').length
  }

  const filteredSchools = schools.filter(school => {
    if (activeFilter === 'All') return true
    return school.status === activeFilter.toLowerCase()
  })

  const handleSelectSchool = (schoolId) => {
    setSelectedSchools(prev =>
      prev.includes(schoolId)
        ? prev.filter(id => id !== schoolId)
        : [...prev, schoolId]
    )
  }

  const handleSelectAll = () => {
    if (selectedSchools.length === filteredSchools.length) {
      setSelectedSchools([])
    } else {
      setSelectedSchools(filteredSchools.map(s => s.id))
    }
  }

  const handleRowClick = (school) => {
    setSelectedSchool(school)
    setShowSlidePanel(true)
  }

  const getStatusBadge = (status) => {
    const styles = {
      active: { bg: '#ecfdf5', stroke: '#bbf7d0', text: '#065f46' },
      pending: { bg: '#fffbeb', stroke: '#fde68a', text: '#92400e' },
      blocked: { bg: '#fff1f2', stroke: '#fca5a5', text: '#be123c' }
    }
    const style = styles[status] || styles.pending
    return { backgroundColor: style.bg, border: `1px solid ${style.stroke}`, color: style.text }
  }

  return (
    <div style={{ padding: '24px', backgroundColor: '#f3f4f6', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h1 style={{ fontSize: '22px', fontWeight: '700', color: '#111827', margin: 0, fontFamily: 'Inter, Arial, sans-serif' }}>Schools</h1>
        <button style={{
          backgroundColor: '#0f62fe',
          color: '#ffffff',
          border: 'none',
          borderRadius: '10px',
          padding: '12px 20px',
          fontSize: '13px',
          fontWeight: '600',
          cursor: 'pointer',
          fontFamily: 'Inter, Arial, sans-serif'
        }}>
          + Add School
        </button>
      </div>

      {/* Search */}
      <div style={{
        backgroundColor: '#ffffff',
        borderRadius: '12px',
        border: '1px solid #e6e7ea',
        padding: '16px',
        marginBottom: '24px'
      }}>
        <input
          type="text"
          placeholder="Search school name, address, or ID..."
          style={{
            width: '100%',
            border: 'none',
            outline: 'none',
            fontSize: '13px',
            color: '#6b7280',
            fontFamily: 'Inter, Arial, sans-serif'
          }}
        />
      </div>

      {/* Filter Chips and Bulk Upload */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px', alignItems: 'center' }}>
        {['All', 'Active', 'Pending', 'Blocked'].map(filter => (
          <button
            key={filter}
            onClick={() => setActiveFilter(filter)}
            style={{
              backgroundColor: activeFilter === filter ? '#e6f4ff' : '#ffffff',
              border: activeFilter === filter ? '1px solid #c8e1ff' : '1px solid #e6e7ea',
              borderRadius: '999px',
              padding: '8px 16px',
              fontSize: '12px',
              fontWeight: activeFilter === filter ? '700' : '500',
              color: activeFilter === filter ? '#0456d6' : '#374151',
              cursor: 'pointer',
              fontFamily: 'Inter, Arial, sans-serif'
            }}
          >
            {filter}
          </button>
        ))}

        {/* Bulk Upload */}
        <div style={{
          backgroundColor: '#f3f4f6',
          borderRadius: '8px',
          border: '1px solid #e6e7ea',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          marginLeft: 'auto'
        }}>
          <span>📁</span>
          <span style={{ fontSize: '13px', color: '#374151', fontFamily: 'Inter, Arial, sans-serif' }}>Bulk upload (CSV, XLSX)</span>
        </div>
      </div>

      {/* Stats Cards */}
      <div style={{ display: 'flex', gap: '20px', marginBottom: '24px' }}>
        <div style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          border: '1px solid #e6e7ea',
          padding: '20px',
          flex: 1
        }}>
          <div style={{ fontSize: '13px', color: '#6b7280', marginBottom: '8px', fontFamily: 'Inter, Arial, sans-serif' }}>Total Schools</div>
          <div style={{ fontSize: '20px', fontWeight: '700', color: '#111827', fontFamily: 'Inter, Arial, sans-serif' }}>{stats.total}</div>
        </div>
        <div style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          border: '1px solid #e6e7ea',
          padding: '20px',
          flex: 1
        }}>
          <div style={{ fontSize: '13px', color: '#6b7280', marginBottom: '8px', fontFamily: 'Inter, Arial, sans-serif' }}>Active</div>
          <div style={{ fontSize: '20px', fontWeight: '700', color: '#111827', fontFamily: 'Inter, Arial, sans-serif' }}>{stats.active}</div>
        </div>
        <div style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          border: '1px solid #e6e7ea',
          padding: '20px',
          flex: 1
        }}>
          <div style={{ fontSize: '13px', color: '#6b7280', marginBottom: '8px', fontFamily: 'Inter, Arial, sans-serif' }}>Pending</div>
          <div style={{ fontSize: '20px', fontWeight: '700', color: '#111827', fontFamily: 'Inter, Arial, sans-serif' }}>{stats.pending}</div>
        </div>
      </div>

      {/* Table */}
      <div style={{
        backgroundColor: '#ffffff',
        borderRadius: '12px',
        border: '1px solid #e6e7ea',
        overflow: 'hidden'
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #eef2f7' }}>
              <th style={{ padding: '16px', textAlign: 'left', fontWeight: '600', fontSize: '13px', fontFamily: 'Inter, Arial, sans-serif' }}>
                <input
                  type="checkbox"
                  checked={selectedSchools.length === filteredSchools.length && filteredSchools.length > 0}
                  onChange={handleSelectAll}
                  style={{ width: '20px', height: '20px' }}
                />
              </th>
              <th style={{ padding: '16px', textAlign: 'left', fontWeight: '600', fontSize: '13px', fontFamily: 'Inter, Arial, sans-serif' }}>School</th>
              <th style={{ padding: '16px', textAlign: 'left', fontWeight: '600', fontSize: '13px', fontFamily: 'Inter, Arial, sans-serif' }}>Location</th>
              <th style={{ padding: '16px', textAlign: 'left', fontWeight: '600', fontSize: '13px', fontFamily: 'Inter, Arial, sans-serif' }}>Status</th>
              <th style={{ padding: '16px', textAlign: 'left', fontWeight: '600', fontSize: '13px', fontFamily: 'Inter, Arial, sans-serif' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredSchools.map((school, index) => (
              <tr
                key={school.id}
                onClick={() => handleRowClick(school)}
                style={{
                  borderBottom: '1px solid #eef2f7',
                  cursor: 'pointer',
                  backgroundColor: index % 2 === 0 ? '#ffffff' : '#f9fafb'
                }}
              >
                <td style={{ padding: '16px' }}>
                  <input
                    type="checkbox"
                    checked={selectedSchools.includes(school.id)}
                    onChange={(e) => {
                      e.stopPropagation()
                      handleSelectSchool(school.id)
                    }}
                    style={{ width: '20px', height: '20px' }}
                  />
                </td>
                <td style={{ padding: '16px', fontSize: '13px', color: '#374151', fontFamily: 'Inter, Arial, sans-serif' }}>{school.name}</td>
                <td style={{ padding: '16px', fontSize: '12px', color: '#9ca3af', fontFamily: 'Inter, Arial, sans-serif' }}>{school.address || 'No address'}</td>
                <td style={{ padding: '16px' }}>
                  <span style={{
                    padding: '4px 12px',
                    borderRadius: '999px',
                    fontSize: '12px',
                    fontWeight: '700',
                    ...getStatusBadge(school.status || 'pending')
                  }}>
                    {school.status || 'Pending'}
                  </span>
                </td>
                <td style={{ padding: '16px', fontSize: '12px', color: '#6b7280', fontFamily: 'Inter, Arial, sans-serif' }}>
                  Edit • Delete
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        marginTop: '24px',
        padding: '16px',
        backgroundColor: '#ffffff',
        borderRadius: '8px',
        border: '1px solid #e6e7ea'
      }}>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button style={{
            backgroundColor: '#ffffff',
            border: '1px solid #e6e7ea',
            borderRadius: '8px',
            padding: '8px 16px',
            fontSize: '13px',
            cursor: 'pointer',
            fontFamily: 'Inter, Arial, sans-serif',
            color: '#6b7280'
          }}>Prev</button>
          <button style={{
            backgroundColor: '#0f62fe',
            color: '#ffffff',
            border: 'none',
            borderRadius: '8px',
            padding: '8px 12px',
            fontSize: '13px',
            fontFamily: 'Inter, Arial, sans-serif'
          }}>1</button>
          <button style={{
            backgroundColor: '#ffffff',
            border: '1px solid #e6e7ea',
            borderRadius: '8px',
            padding: '8px 12px',
            fontSize: '13px',
            cursor: 'pointer',
            fontFamily: 'Inter, Arial, sans-serif',
            color: '#6b7280'
          }}>2</button>
          <button style={{
            backgroundColor: '#ffffff',
            border: '1px solid #e6e7ea',
            borderRadius: '8px',
            padding: '8px 16px',
            fontSize: '13px',
            cursor: 'pointer',
            fontFamily: 'Inter, Arial, sans-serif',
            color: '#6b7280'
          }}>Next</button>
        </div>
      </div>

      {/* Slide-out Panel */}
      {showSlidePanel && selectedSchool && (
        <div style={{
          position: 'fixed',
          top: 0,
          right: 0,
          width: '400px',
          height: '100vh',
          backgroundColor: '#ffffff',
          borderLeft: '1px solid #e6e7ea',
          boxShadow: '-4px 0 12px rgba(0,0,0,0.1)',
          zIndex: 1000,
          padding: '24px'
        }}>
          <h2 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '24px' }}>School Details</h2>

          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '4px' }}>Name</div>
            <div style={{ fontSize: '14px', color: '#374151' }}>{selectedSchool.name}</div>
          </div>

          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '4px' }}>Address</div>
            <div style={{ fontSize: '14px', color: '#374151' }}>{selectedSchool.address || 'No address provided'}</div>
          </div>

          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '4px' }}>Contact</div>
            <div style={{ fontSize: '14px', color: '#374151' }}>{selectedSchool.contact || '+254 712 345678'}</div>
          </div>

          <div style={{ marginBottom: '24px' }}>
            <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '8px' }}>Status</div>
            <span style={{
              padding: '4px 12px',
              borderRadius: '999px',
              fontSize: '12px',
              fontWeight: '700',
              ...getStatusBadge(selectedSchool.status || 'pending')
            }}>
              {selectedSchool.status || 'Pending'}
            </span>
          </div>

          <div style={{ marginBottom: '24px' }}>
            <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '8px' }}>Actions</div>
            <button style={{
              backgroundColor: '#0f62fe',
              color: '#ffffff',
              border: 'none',
              borderRadius: '10px',
              padding: '12px 20px',
              fontSize: '14px',
              fontWeight: '600',
              cursor: 'pointer',
              width: '100%'
            }}>
              Edit School
            </button>
          </div>

          <div>
            <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '8px' }}>Bulk Actions</div>
            <button style={{
              backgroundColor: '#f3f4f6',
              color: '#374151',
              border: '1px solid #e6e7ea',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '14px',
              cursor: 'pointer',
              width: '100%',
              marginBottom: '8px'
            }}>
              Export Selected
            </button>
            <button style={{
              backgroundColor: '#f3f4f6',
              color: '#374151',
              border: '1px solid #e6e7ea',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '14px',
              cursor: 'pointer',
              width: '100%'
            }}>
              Delete Selected
            </button>
          </div>

          <button
            onClick={() => setShowSlidePanel(false)}
            style={{
              position: 'absolute',
              top: '24px',
              right: '24px',
              background: 'none',
              border: 'none',
              fontSize: '20px',
              cursor: 'pointer'
            }}
          >
            ×
          </button>
        </div>
      )}

      {error && (
        <div style={{
          backgroundColor: '#fef2f2',
          border: '1px solid #fca5a5',
          borderRadius: '8px',
          padding: '16px',
          marginTop: '24px',
          color: '#dc2626'
        }}>
          Error loading schools: {error.message}
        </div>
      )}
    </div>
  )
}