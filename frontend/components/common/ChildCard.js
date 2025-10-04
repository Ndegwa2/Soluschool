const ChildCard = ({ child, onEdit, onDelete }) => {
  return (
    <div className="bg-white p-4 rounded-lg shadow border">
      <div className="flex items-center space-x-4">
        <div className="w-12 h-12 bg-gray-300 rounded-full flex items-center justify-center">
          {child.photo ? (
            <img src={child.photo} alt={child.name} className="w-12 h-12 rounded-full" />
          ) : (
            <span className="text-gray-600">{child.name.charAt(0)}</span>
          )}
        </div>
        <div className="flex-1">
          <h3 className="font-semibold">{child.name}</h3>
          <p className="text-sm text-gray-600">Class: {child.class}</p>
          <p className="text-sm text-gray-600">Status: {child.status}</p>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={() => onEdit(child)}
            className="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600"
          >
            Edit
          </button>
          <button
            onClick={() => onDelete(child.id)}
            className="bg-red-500 text-white px-3 py-1 rounded text-sm hover:bg-red-600"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  )
}

export default ChildCard