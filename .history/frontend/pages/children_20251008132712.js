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
    if (confirm('Are you sure you want to delete this child?')) {
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
      <div className="children-page">
        <div className="max-w-4xl mx-auto py-6 px-4">
          <div className="flex justify-between items-center mb-6">
            <h1>My Children</h1>
            <button
              onClick={() => setShowAddForm(true)}
              className="add-child-btn"
            >
              Add Child
            </button>
          </div>

          {showAddForm && (
            <div className="mb-6">
              <AddChildForm onSuccess={handleAddSuccess} onCancel={() => setShowAddForm(false)} />
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {data?.children?.map((child) => (
              <ChildCard
                key={child.id}
                child={child}
                onEdit={handleEdit}
                onDelete={handleDelete}
              />
            ))}
          </div>

          {data?.children?.length === 0 && !error && (
            <p className="text-center text-gray-500 mt-8">No children added yet.</p>
          )}
        </div>
      </div>
    </ProtectedRoute>
  )
}