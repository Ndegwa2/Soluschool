import React, { createContext, useContext, useEffect, useState } from 'react';
import io from 'socket.io-client';
import { useAuth } from './auth';

const SocketContext = createContext();

export const useSocket = () => {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
};

export const SocketProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const { user, token } = useAuth();

  useEffect(() => {
    if (!token || !user) {
      // Disconnect if no authentication
      if (socket) {
        socket.disconnect();
        setSocket(null);
        setConnected(false);
      }
      return;
    }

    // Connect to Socket.IO server
    const newSocket = io(process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5000', {
      auth: {
        token: token
      },
      transports: ['websocket', 'polling']
    });

    newSocket.on('connect', () => {
      console.log('Connected to Socket.IO server');
      setConnected(true);
      
      // Join user-specific room
      newSocket.emit('join_room', `user_${user.id}`);
      
      // Join role-based rooms for real-time updates
      if (user.role === 'admin') {
        newSocket.emit('join_room', 'admins');
      } else if (user.role === 'guard') {
        newSocket.emit('join_room', `school_${user.school_id}_guards`);
      }
    });

    newSocket.on('disconnect', () => {
      console.log('Disconnected from Socket.IO server');
      setConnected(false);
    });

    newSocket.on('connect_error', (error) => {
      console.error('Socket.IO connection error:', error);
      setConnected(false);
    });

    // Handle visitor notifications
    newSocket.on('visitor_created', (data) => {
      console.log('New visitor created:', data);
      const notification = {
        id: Date.now(),
        type: 'visitor_created',
        title: 'New Visitor Registration',
        message: `${data.name} has registered for ${data.purpose}`,
        data: data,
        timestamp: new Date().toISOString(),
        read: false
      };
      setNotifications(prev => [notification, ...prev]);
    });

    newSocket.on('visitor_approved', (data) => {
      console.log('Visitor approved:', data);
      const notification = {
        id: Date.now(),
        type: 'visitor_approved',
        title: 'Visitor Approved',
        message: `${data.name} has been approved for ${data.purpose}`,
        data: data,
        timestamp: new Date().toISOString(),
        read: false
      };
      setNotifications(prev => [notification, ...prev]);
    });

    newSocket.on('visitor_denied', (data) => {
      console.log('Visitor denied:', data);
      const notification = {
        id: Date.now(),
        type: 'visitor_denied',
        title: 'Visitor Denied',
        message: `${data.name} has been denied for ${data.purpose}`,
        data: data,
        timestamp: new Date().toISOString(),
        read: false
      };
      setNotifications(prev => [notification, ...prev]);
    });

    // Handle security alerts
    newSocket.on('security_alert', (data) => {
      console.log('Security alert:', data);
      const notification = {
        id: Date.now(),
        type: 'security_alert',
        title: 'Security Alert',
        message: data.message,
        data: data,
        timestamp: new Date().toISOString(),
        read: false,
        priority: data.severity || 'medium'
      };
      setNotifications(prev => [notification, ...prev]);
    });

    // Handle blacklist alerts
    newSocket.on('blacklist_alert', (data) => {
      console.log('Blacklist alert:', data);
      const notification = {
        id: Date.now(),
        type: 'blacklist_alert',
        title: 'Blacklist Alert',
        message: `${data.name} is in the blacklist`,
        data: data,
        timestamp: new Date().toISOString(),
        read: false,
        priority: 'high'
      };
      setNotifications(prev => [notification, ...prev]);
    });

    // Handle general notifications
    newSocket.on('notification', (data) => {
      console.log('General notification:', data);
      const notification = {
        id: Date.now(),
        type: 'general',
        title: data.title || 'Notification',
        message: data.message,
        data: data,
        timestamp: new Date().toISOString(),
        read: false
      };
      setNotifications(prev => [notification, ...prev]);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
      setSocket(null);
      setConnected(false);
    };
  }, [token, user]);

  const markAsRead = (notificationId) => {
    setNotifications(prev =>
      prev.map(notification =>
        notification.id === notificationId
          ? { ...notification, read: true }
          : notification
      )
    );
  };

  const markAllAsRead = () => {
    setNotifications(prev =>
      prev.map(notification => ({ ...notification, read: true }))
    );
  };

  const removeNotification = (notificationId) => {
    setNotifications(prev =>
      prev.filter(notification => notification.id !== notificationId)
    );
  };

  const clearAllNotifications = () => {
    setNotifications([]);
  };

  const value = {
    socket,
    connected,
    notifications,
    markAsRead,
    markAllAsRead,
    removeNotification,
    clearAllNotifications
  };

  return (
    <SocketContext.Provider value={value}>
      {children}
    </SocketContext.Provider>
  );
};