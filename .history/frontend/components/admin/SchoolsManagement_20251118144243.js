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

export default function SchoolsManagement() {
  const { data: schoolsData, error, mutate } = useSWR('/api/schools?adminId=12', fetcher)
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
    return {
      backgroundColor: style.bg,
      border: `1px solid ${style.stroke}`,
      color: style.text,
      fontFamily: 'Inter, Arial, sans-serif',
      fontSize: '12px',
      fontWeight: '700'
    }
  }

  if (error) {
    return (
      <div style={{
        position: 'absolute',
        left: '240px',
        top: '24px',
        right: '24px',
        backgroundColor: '#f3f4f6',
        minHeight: '100vh',
        padding: '24px'
      }}>
        <div style={{
          backgroundColor: '#fef2f2',
          border: '1px solid #fca5a5',
          borderRadius: '8px',
          padding: '16px',
          color: '#dc2626'
        }}>
          Error loading schools: {error.message}
        </div>
      </div>
    )
  }

  if (!schoolsData) {
    return (
      <div style={{
        position: 'absolute',
        left: '240px',
        top: '24px',
        right: '24px',
        backgroundColor: '#f3f4f6',
        minHeight: '100vh',
        padding: '24px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '200px' }}>
          <div>Loading schools...</div>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      position: 'absolute',
      left: '240px',
      top: '24px',
      right: '24px',
      backgroundColor: '#f3f4f6',
      minHeight: '100vh'
    }}>
      {/* Header */}
      <div style={{ marginBottom: '24px' }}>
        <text style={{
          fontSize: '22px',
          fontWeight: '700',
          fill: '#111827',
          fontFamily: 'Inter, Arial, sans-serif'
        }}>Schools</text>
        <button style={{
          position: 'absolute',
          left: '800px',
          top: '-6px',
          backgroundColor: '#0f62fe',
          color: '#ffffff',
          border: 'none',
          borderRadius: '10px',
          width: '120px',
          height: '36px',
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
        width: '640px',
        height: '44px',
        marginBottom: '24px',
        display: 'flex',
        alignItems: 'center',
        padding: '0 16px'
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

      {/* Filters and bulk upload */}
      <div style={{ marginBottom: '24px' }}>
        {/* Filter chips */}
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          {[
            { key: 'All', width: '110px' },
            { key: 'Active', width: '120px' },
            { key: 'Pending', width: '120px' },
            { key: 'Blocked', width: '120px' }
          ].map((filter, index) => (
            <button
              key={filter.key}
              onClick={() => setActiveFilter(filter.key)}
              style={{
                backgroundColor: activeFilter === filter.key ? '#e6f4ff' : '#ffffff',
                border: activeFilter === filter.key ? '1px solid #c8e1ff' : '1px solid #e6e7ea',
                borderRadius: '999px',
                width: filter.width,
                height: '32px',
                fontSize: '12px',
                fontWeight: activeFilter === filter.key ? '700' : '500',
                color: activeFilter === filter.key ? '#0456d6' : '#374151',
                cursor: 'pointer',
                fontFamily: 'Inter, Arial, sans-serif',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}
            >
              {filter.key}
            </button>
          ))}
        </div>

        {/* Bulk upload */}
        <div style={{
          position: 'absolute',
          left: '800px',
          top: '104px',
          backgroundColor: '#f3f4f6',
          borderRadius: '8px',
          border: '1px solid #e6e7ea',
          width: '180px',
          height: '36px',
          display: 'flex',
          alignItems: 'center',
          padding: '0 16px',
          gap: '12px'
        }}>
          <span>📁</span>
          <span style={{ fontSize: '13px', color: '#374151', fontFamily: 'Inter, Arial, sans-serif' }}>Bulk upload (CSV, XLSX)</span>
        </div>
      </div>

      {/* Stats cards */}
      <div style={{ marginBottom: '24px', display: 'flex', gap: '20px' }}>
        <div style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          border: '1px solid #e6e7ea',
          width: '240px',
          height: '84px',
          padding: '16px 16px'
        }}>
          <div style={{
            fontSize: '13px',
            color: '#6b7280',
            marginBottom: '8px',
            fontFamily: 'Inter, Arial, sans-serif'
          }}>Total Schools</div>
          <div style={{
            fontSize: '20px',
            fontWeight: '700',
            color: '#111827',
            fontFamily: 'Inter, Arial, sans-serif'
          }}>{stats.total}</div>
        </div>
        <div style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          border: '1px solid #e6e7ea',
          width: '240px',
          height: '84px',
          padding: '16px 16px'
        }}>
          <div style={{
            fontSize: '13px',
            color: '#6b7280',
            marginBottom: '8px',
            fontFamily: 'Inter, Arial, sans-serif'
          }}>Active</div>
          <div style={{
            fontSize: '20px',
            fontWeight: '700',
            color: '#111827',
            fontFamily: 'Inter, Arial, sans-serif'
          }}>{stats.active}</div>
        </div>
        <div style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          border: '1px solid #e6e7ea',
          width: '240px',
          height: '84px',
          padding: '16px 16px'
        }}>
          <div style={{
            fontSize: '13px',
            color: '#6b7280',
            marginBottom: '8px',
            fontFamily: 'Inter, Arial, sans-serif'
          }}>Pending</div>
          <div style={{
            fontSize: '20px',
            fontWeight: '700',
            color: '#111827',
            fontFamily: 'Inter, Arial, sans-serif'
          }}>{stats.pending}</div>
        </div>
      </div>

      {/* Table container */}
      <div style={{
        backgroundColor: '#ffffff',
        borderRadius: '12px',
        border: '1px solid #e6e7ea',
        width: '760px',
        height: '320px',
        overflow: 'hidden',
        position: 'relative'
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #eef2f7' }}>
              <th style={{
                padding: '16px',
                textAlign: 'left',
                fontWeight: '600',
                fontSize: '13px',
                fontFamily: 'Inter, Arial, sans-serif',
                color: '#111827'
              }}>
                <input
                  type="checkbox"
                  checked={selectedSchools.length === filteredSchools.length && filteredSchools.length > 0}
                  onChange={handleSelectAll}
                  style={{ width: '20px', height: '20px' }}
                />
              </th>
              <th style={{
                padding: '16px',
                textAlign: 'left',
                fontWeight: '600',
                fontSize: '13px',
                fontFamily: 'Inter, Arial, sans-serif',
                color: '#111827'
              }}>School</th>
              <th style={{
                padding: '16px',
                textAlign: 'left',
                fontWeight: '600',
                fontSize: '13px',
                fontFamily: 'Inter, Arial, sans-serif',
                color: '#111827'
              }}>Location</th>
              <th style={{
                padding: '16px',
                textAlign: 'left',
                fontWeight: '600',
                fontSize: '13px',
                fontFamily: 'Inter, Arial, sans-serif',
                color: '#111827'
              }}>Status</th>
              <th style={{
                padding: '16px',
                textAlign: 'left',
                fontWeight: '600',
                fontSize: '13px',
                fontFamily: 'Inter, Arial, sans-serif',
                color: '#111827'
              }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredSchools.slice(0, 4).map((school, index) => (
              <tr
                key={school.id}
                onClick={() => handleRowClick(school)}
                style={{
                  cursor: 'pointer',
                  height: '56px'
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
                <td style={{
                  padding: '16px',
                  fontSize: '13px',
                  color: '#374151',
                  fontFamily: 'Inter, Arial, sans-serif'
                }}>{school.name}</td>
                <td style={{
                  padding: '16px',
                  fontSize: '12px',
                  color: '#9ca3af',
                  fontFamily: 'Inter, Arial, sans-serif'
                }}>{school.address || 'No address'}</td>
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
                <td style={{
                  padding: '16px',
                  fontSize: '12px',
                  color: '#6b7280',
                  fontFamily: 'Inter, Arial, sans-serif'
                }}>
                  Edit • Delete
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        <div style={{
          position: 'absolute',
          bottom: '16px',
          right: '20px',
          display: 'flex',
          gap: '8px',
          alignItems: 'center'
        }}>
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

      {/* Slide-out panel */}
      {showSlidePanel && selectedSchool && (
        <div style={{
          position: 'fixed',
          top: '36px',
          right: '36px',
          width: '168px',
          height: '648px',
          backgroundColor: '#ffffff',
          border: '1px solid #e6e7ea',
          borderRadius: '12px',
          padding: '16px',
          zIndex: 1000
        }}>
          <h2 style={{
            fontSize: '16px',
            fontWeight: '600',
            marginBottom: '24px',
            fontFamily: 'Inter, Arial, sans-serif',
            color: '#111827'
          }}>School details</h2>

          <div style={{ marginBottom: '16px' }}>
            <div style={{
              fontSize: '12px',
              color: '#6b7280',
              marginBottom: '4px',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>Name</div>
            <div style={{
              fontSize: '13px',
              color: '#374151',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>{selectedSchool.name}</div>
          </div>

          <div style={{ marginBottom: '16px' }}>
            <div style={{
              fontSize: '12px',
              color: '#6b7280',
              marginBottom: '4px',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>Address</div>
            <div style={{
              fontSize: '13px',
              color: '#374151',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>{selectedSchool.address || 'No address provided'}</div>
          </div>

          <div style={{ marginBottom: '16px' }}>
            <div style={{
              fontSize: '12px',
              color: '#6b7280',
              marginBottom: '4px',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>Contact</div>
            <div style={{
              fontSize: '13px',
              color: '#374151',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>{selectedSchool.contact || '+254 712 345678'}</div>
          </div>

          <div style={{ marginBottom: '24px' }}>
            <div style={{
              fontSize: '12px',
              color: '#6b7280',
              marginBottom: '8px',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>Status</div>
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
            <div style={{
              fontSize: '12px',
              color: '#6b7280',
              marginBottom: '8px',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>Actions</div>
            <button style={{
              backgroundColor: '#0f62fe',
              color: '#ffffff',
              border: 'none',
              borderRadius: '10px',
              padding: '12px 20px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
              width: '100%',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>
              Edit school
            </button>
          </div>

          <div>
            <div style={{
              fontSize: '12px',
              color: '#6b7280',
              marginBottom: '8px',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>Bulk actions</div>
            <button style={{
              backgroundColor: '#f3f4f6',
              color: '#374151',
              border: '1px solid #e6e7ea',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '12px',
              cursor: 'pointer',
              width: '100%',
              marginBottom: '8px',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>
              Export selected
            </button>
            <button style={{
              backgroundColor: '#f3f4f6',
              color: '#374151',
              border: '1px solid #e6e7ea',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '12px',
              cursor: 'pointer',
              width: '100%',
              fontFamily: 'Inter, Arial, sans-serif'
            }}>
              Delete selected
            </button>
          </div>

          <button
            onClick={() => setShowSlidePanel(false)}
            style={{
              position: 'absolute',
              top: '16px',
              right: '16px',
              background: 'none',
              border: 'none',
              fontSize: '20px',
              cursor: 'pointer',
              color: '#6b7280'
            }}
          >
            ×
          </button>
        </div>
      )}
    </div>
  )
}