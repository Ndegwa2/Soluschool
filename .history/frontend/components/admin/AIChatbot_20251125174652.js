'use client'

import React, { useState } from 'react'
import React, { useState } from 'react'

const AIChatbot = () => {
  const [isOpen, setIsOpen] = useState(false)
  const [messages, setMessages] = useState([
    { text: "Hello! I'm your AI assistant for admin tasks. How can I help you today?", sender: 'bot' }
  ])
  const [input, setInput] = useState('')

  const handleSend = () => {
    if (!input.trim()) return

    const newMessages = [...messages, { text: input, sender: 'user' }]
    setMessages(newMessages)
    setInput('')

    // Simulate AI response (replace with actual AI integration)
    setTimeout(() => {
      const responses = [
        "I can help you with user management, visitor tracking, or system analytics.",
        "Try asking me about recent visitor logs or user statistics.",
        "I can assist with bulk operations or generating reports.",
        "Need help with school management or blacklist updates?"
      ]
      const randomResponse = responses[Math.floor(Math.random() * responses.length)]
      setMessages(prev => [...prev, { text: randomResponse, sender: 'bot' }])
    }, 1000)
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSend()
    }
  }

  return (
    <>
      {/* Floating Button */}
      <button
        onClick={() => setIsOpen(true)}
        style={{
          position: 'fixed',
          bottom: '20px',
          right: '20px',
          width: '56px',
          height: '56px',
          borderRadius: '50%',
          backgroundColor: '#1E3A8A',
          color: '#fff',
          border: 'none',
          cursor: 'pointer',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '24px',
          zIndex: 1000
        }}
        title="AI Assistant"
      >
        🤖
      </button>

      {/* Chat Modal */}
      {isOpen && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1001
        }} onClick={() => setIsOpen(false)}>
          <div
            style={{
              width: '400px',
              maxHeight: '600px',
              backgroundColor: '#ffffff',
              borderRadius: '12px',
              boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)',
              overflow: 'hidden',
              position: 'relative'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Chat Header */}
            <div style={{
              padding: '16px 20px',
              backgroundColor: '#1E3A8A',
              color: '#fff',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <span style={{ fontSize: '16px', fontWeight: '600' }}>AI Assistant</span>
              <button
                onClick={() => setIsOpen(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#fff',
                  fontSize: '20px',
                  cursor: 'pointer',
                  padding: '0'
                }}
              >
                ×
              </button>
            </div>

            {/* Chat Body */}
            <div style={{
              height: '400px',
              overflowY: 'auto',
              padding: '16px 20px',
              backgroundColor: '#f9fafb'
            }}>
              {messages.map((msg, index) => (
                <div
                  key={index}
                  style={{
                    marginBottom: '12px',
                    textAlign: msg.sender === 'user' ? 'right' : 'left'
                  }}
                >
                  <div style={{
                    display: 'inline-block',
                    maxWidth: '80%',
                    padding: '10px 14px',
                    borderRadius: '12px',
                    backgroundColor: msg.sender === 'user' ? '#1E3A8A' : '#e5e7eb',
                    color: msg.sender === 'user' ? '#fff' : '#111827',
                    fontSize: '14px',
                    lineHeight: '1.4'
                  }}>
                    {msg.text}
                  </div>
                </div>
              ))}
            </div>

            {/* Chat Input */}
            <div style={{
              padding: '16px 20px',
              borderTop: '1px solid #e5e7eb',
              display: 'flex',
              gap: '12px',
              backgroundColor: '#fff'
            }}>
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Ask me anything..."
                style={{
                  flex: 1,
                  padding: '10px 14px',
                  border: '1px solid #d1d5db',
                  borderRadius: '8px',
                  fontSize: '14px',
                  outline: 'none'
                }}
              />
              <button
                onClick={handleSend}
                style={{
                  padding: '10px 16px',
                  backgroundColor: '#1E3A8A',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '8px',
                  fontSize: '14px',
                  cursor: 'pointer',
                  fontWeight: '500'
                }}
              >
                Send
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

export default AIChatbot