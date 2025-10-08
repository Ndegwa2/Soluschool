import React, { useState } from 'react'
import useSWR from 'swr'
import ProtectedRoute from '../components/common/ProtectedRoute'
import ChildCard from '../components/common/ChildCard'
import AddChildForm from '../components/common/AddChildForm'
import { apiClient } from '../lib/api'

const fetcher = async (url) => {
  const response = await apiClient.get(url)
  if (response.success) {
    return response.data
  } else {
    throw new Error(response.error)
  }
}

export default function Children() {
  const { data, error, mutate } = useSWR('/api/children', fetcher)
  const [showAddForm, setShowAddForm] = useState(false)
  const [editingChild, setEditingChild] = useState(null)

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this child? This action cannot be undone.')) {
      const response = await apiClient.delete(`/api/children/${id}`)
      if (response.success) {
        mutate()
      } else {
        alert('Error deleting child: ' + response.error)
      }
    }
  }

  const handleEdit = (child) => {
    setEditingChild(child)
    // For now, just log; implement edit form later if needed
    console.log('Edit child:', child)
  }

  const handleAddSuccess = () => {
    setShowAddForm(false)
    mutate()
  }

  return (
    <ProtectedRoute allowedRoles={['parent']}>
      <div className="children-container">
        <div className="header-section">
          <h1>My Children</h1>
          <button
            onClick={() => setShowAddForm(true)}
            className="add-child-btn primary"
          >
            Add Child
          </button>
        </div>

        {showAddForm && (
          <div className="mb-6">
            <AddChildForm onSuccess={handleAddSuccess} onCancel={() => setShowAddForm(false)} />
          </div>
        )}

        {!data && !error && (
          <div className="loading-state">
            <div className="skeleton-grid">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="skeleton-card">
                  <div className="skeleton-line"></div>
                  <div className="skeleton-line short"></div>
                  <div className="skeleton-actions">
                    <div className="skeleton-btn"></div>
                    <div className="skeleton-btn"></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {data?.children && data.children.length > 0 && (
          <div className="children-grid">
            {data.children.map((child) => (
              <ChildCard
                key={child.id}
                child={child}
                onEdit={handleEdit}
                onDelete={handleDelete}
              />
            ))}
          </div>
        )}

        {data?.children?.length === 0 && !error && (
          <div className="empty-state">
            <div className="empty-illustration">
              <svg width="120" height="120" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2C13.1 2 14 2.9 14 4C14 5.1 13.1 6 12 6C10.9 6 10 5.1 10 4C10 2.9 10.9 2 12 2ZM21 9V7L15 1H5C3.89 1 3 1.89 3 3V21C3 22.11 3.89 23 5 23H19C20.11 23 21 22.11 21 21V9M19 9H14V4H19V9Z" fill="currentColor"/>
              </svg>
            </div>
            <h3>No children added yet</h3>
            <p>Start by adding your first child to manage their school activities.</p>
            <button
              onClick={() => setShowAddForm(true)}
              className="add-child-btn primary large"
            >
              Add Your First Child
            </button>
          </div>
        )}
      </div>
    </ProtectedRoute>
  )
}