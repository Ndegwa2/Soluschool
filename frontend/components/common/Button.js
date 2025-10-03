import React from 'react'

const Button = ({ children, onClick }) => (
  <button onClick={onClick} style={{ padding: '0.5rem 1rem' }}>
    {children}
  </button>
)

export default Button