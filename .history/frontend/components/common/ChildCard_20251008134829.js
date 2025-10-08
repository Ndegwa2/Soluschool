import React from 'react'

const ChildCard = ({ child, onEdit, onDelete }) => {
  return (
    <div className="child-card">
      <h2>{child.name}</h2>
      <p>Grade: {child.grade}</p>
      <div className="card-actions">
        <button
          onClick={() => onEdit(child)}
          className="edit-btn"
        >
          Edit
        </button>
        <button
          onClick={() => onDelete(child.id)}
          className="delete-btn"
        >
          Delete
        </button>
      </div>
    </div>
  )
}

export default ChildCard