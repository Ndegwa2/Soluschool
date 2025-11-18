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
    <div style={{
      width: '300px',
      marginTop: '12px',
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      border: '1px solid #e5e7eb',
      boxShadow: '0 1px 3px rgba(0, 0, 0, 0.1)',
      overflow: 'hidden'
    }}>
      {/* Chat Header */}
      <div
        style={{
          padding: '12px 16px',
          backgroundColor: '#1E3A8A',
          color: '#fff',
          cursor: 'pointer',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
        onClick={() => setIsOpen(!isOpen)}
      >
        <span style={{ fontSize: '14px', fontWeight: '600' }}>AI Assistant</span>
        <span style={{ fontSize: '12px' }}>{isOpen ? '▼' : '▶'}</span>
      </div>

      {/* Chat Body */}
      {isOpen && (
        <>
          <div style={{
            height: '200px',
            overflowY: 'auto',
            padding: '12px 16px',
            backgroundColor: '#f9fafb'
          }}>
            {messages.map((msg, index) => (
              <div
                key={index}
                style={{
                  marginBottom: '8px',
                  textAlign: msg.sender === 'user' ? 'right' : 'left'
                }}
              >
                <div style={{
                  display: 'inline-block',
                  maxWidth: '80%',
                  padding: '8px 12px',
                  borderRadius: '8px',
                  backgroundColor: msg.sender === 'user' ? '#1E3A8A' : '#e5e7eb',
                  color: msg.sender === 'user' ? '#fff' : '#111827',
                  fontSize: '13px'
                }}>
                  {msg.text}
                </div>
              </div>
            ))}
          </div>

          {/* Chat Input */}
          <div style={{
            padding: '12px 16px',
            borderTop: '1px solid #e5e7eb',
            display: 'flex',
            gap: '8px'
          }}>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Ask me anything..."
              style={{
                flex: 1,
                padding: '8px 12px',
                border: '1px solid #d1d5db',
                borderRadius: '4px',
                fontSize: '13px',
                outline: 'none'
              }}
            />
            <button
              onClick={handleSend}
              style={{
                padding: '8px 12px',
                backgroundColor: '#1E3A8A',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                fontSize: '13px',
                cursor: 'pointer'
              }}
            >
              Send
            </button>
          </div>
        </>
      )}
    </div>
  )
}

export default AIChatbot