import logging
from flask import Flask
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from models import User, Notification, AuditLog
from sqlalchemy.orm import joinedload
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self, socketio):
        self.socketio = socketio
        # Track connected users and their rooms
        self.connected_users = {}  # user_id -> [session_ids]
        self.user_sessions = {}    # session_id -> user_id
        
    def connect_user(self, user_id, session_id):
        """Track user connection"""
        if user_id not in self.connected_users:
            self.connected_users[user_id] = []
        self.connected_users[user_id].append(session_id)
        self.user_sessions[session_id] = user_id
        logger.info(f"User {user_id} connected with session {session_id}")
        
    def disconnect_user(self, session_id):
        """Handle user disconnection"""
        user_id = self.user_sessions.get(session_id)
        if user_id:
            if user_id in self.connected_users:
                self.connected_users[user_id] = [
                    sid for sid in self.connected_users[user_id] 
                    if sid != session_id
                ]
                if not self.connected_users[user_id]:
                    del self.connected_users[user_id]
            del self.user_sessions[session_id]
            logger.info(f"User {user_id} disconnected session {session_id}")
    
    def send_to_user(self, user_id, event, data):
        """Send notification to specific user"""
        if user_id in self.connected_users:
            for session_id in self.connected_users[user_id]:
                self.socketio.emit(event, data, room=session_id)
                logger.info(f"Sent {event} to user {user_id} (session {session_id})")
        else:
            # Store notification for later delivery
            logger.info(f"User {user_id} not connected, notification will be delivered on next login")
    
    def send_to_role(self, role, event, data):
        """Send notification to all users with specific role"""
        users = User.query.filter_by(role=role).all()
        for user in users:
            self.send_to_user(user.id, event, data)
    
    def send_to_school(self, school_id, event, data):
        """Send notification to all users in a school"""
        users = User.query.filter_by(school_id=school_id).all()
        for user in users:
            self.send_to_user(user.id, event, data)
    
    def broadcast_system_alert(self, event, data, target_roles=None):
        """Send system-wide alerts"""
        if target_roles:
            for role in target_roles:
                self.send_to_role(role, event, data)
        else:
            # Broadcast to all connected users
            for user_id in self.connected_users.keys():
                self.send_to_user(user_id, event, data)

# Global notification manager instance
notification_manager = None

def setup_socketio_handlers(socketio, db):
    """Setup all Socket.IO event handlers"""
    global notification_manager
    
    # Initialize notification manager
    notification_manager = NotificationManager(socketio)
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        try:
            # Verify JWT token
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            session_id = request.sid
            
            if user_id:
                notification_manager.connect_user(int(user_id), session_id)
                
                # Join user to their personal room
                join_room(f"user_{user_id}")
                
                # Join user to role-based room
                user = User.query.get(user_id)
                if user:
                    join_room(f"role_{user.role}")
                    
                    # Join school-specific room if user has a school
                    if user.school_id:
                        join_room(f"school_{user.school_id}")
                
                emit('connected', {
                    'success': True,
                    'message': 'Connected to real-time notifications',
                    'user_id': user_id
                })
                
                logger.info(f"User {user_id} successfully connected to WebSocket")
            else:
                emit('error', {'message': 'Authentication required'})
                return False
                
        except Exception as e:
            logger.error(f"Connection error: {e}")
            emit('error', {'message': 'Connection failed'})
            return False
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        session_id = request.sid
        notification_manager.disconnect_user(session_id)
        logger.info(f"Session {session_id} disconnected")
    
    @socketio.on('join_room')
    def handle_join_room(data):
        """Allow clients to join specific rooms"""
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            room = data.get('room')
            
            if room:
                join_room(room)
                emit('room_joined', {'room': room})
                logger.info(f"User {user_id} joined room {room}")
                
        except Exception as e:
            logger.error(f"Join room error: {e}")
            emit('error', {'message': 'Failed to join room'})
    
    @socketio.on('leave_room')
    def handle_leave_room(data):
        """Allow clients to leave specific rooms"""
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            room = data.get('room')
            
            if room:
                leave_room(room)
                emit('room_left', {'room': room})
                logger.info(f"User {user_id} left room {room}")
                
        except Exception as e:
            logger.error(f"Leave room error: {e}")
            emit('error', {'message': 'Failed to leave room'})
    
    @socketio.on('get_notifications')
    def handle_get_notifications():
        """Get user's recent notifications"""
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            
            # Get recent notifications
            notifications = Notification.query.filter_by(
                user_id=int(user_id)
            ).order_by(Notification.sent_at.desc()).limit(10).all()
            
            notification_data = [{
                'id': n.id,
                'type': n.type,
                'message': n.message,
                'sent_at': n.sent_at.isoformat(),
                'status': n.status
            } for n in notifications]
            
            emit('notifications', {
                'success': True,
                'notifications': notification_data
            })
            
        except Exception as e:
            logger.error(f"Get notifications error: {e}")
            emit('error', {'message': 'Failed to get notifications'})
    
    @socketio.on('mark_notification_read')
    def handle_mark_notification_read(data):
        """Mark a notification as read"""
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            notification_id = data.get('notification_id')
            
            notification = Notification.query.filter_by(
                id=notification_id,
                user_id=int(user_id)
            ).first()
            
            if notification:
                notification.status = 'read'
                db.session.commit()
                emit('notification_marked_read', {
                    'success': True,
                    'notification_id': notification_id
                })
            else:
                emit('error', {'message': 'Notification not found'})
                
        except Exception as e:
            logger.error(f"Mark notification read error: {e}")
            emit('error', {'message': 'Failed to mark notification as read'})
    
    return notification_manager

def create_notification(user_id, notification_type, message, db):
    """Create a notification and send via WebSocket if user is connected"""
    try:
        # Create notification in database
        notification = Notification(
            user_id=user_id,
            type=notification_type,
            message=message
        )
        db.session.add(notification)
        db.session.commit()
        
        # Send via WebSocket if user is connected
        if notification_manager:
            notification_data = {
                'id': notification.id,
                'type': notification.type,
                'message': notification.message,
                'sent_at': notification.sent_at.isoformat(),
                'status': notification.status
            }
            notification_manager.send_to_user(
                user_id, 
                'new_notification', 
                notification_data
            )
        
        logger.info(f"Notification created for user {user_id}: {message}")
        return notification
        
    except Exception as e:
        logger.error(f"Create notification error: {e}")
        raise

def send_visitor_alert(visitor_data, action, db):
    """Send real-time alerts for visitor management"""
    try:
        alert_data = {
            'visitor_id': visitor_data.get('id'),
            'name': visitor_data.get('name'),
            'action': action,  # created, approved, denied, blacklisted
            'timestamp': datetime.utcnow().isoformat(),
            'message': f"Visitor {visitor_data.get('name')} was {action}"
        }
        
        # Send to all admins and guards
        if notification_manager:
            notification_manager.send_to_role('admin', 'visitor_alert', alert_data)
            notification_manager.send_to_role('guard', 'visitor_alert', alert_data)
        
        logger.info(f"Visitor alert sent: {action} for {visitor_data.get('name')}")
        
    except Exception as e:
        logger.error(f"Send visitor alert error: {e}")

def send_security_alert(alert_type, details, db, target_roles=None):
    """Send security alerts to relevant personnel"""
    try:
        alert_data = {
            'type': alert_type,  # blacklist_attempt, unauthorized_access, etc.
            'details': details,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': 'high',
            'message': f"Security Alert: {alert_type} - {details}"
        }
        
        # Send to admins and guards
        if notification_manager:
            target_roles = target_roles or ['admin', 'guard']
            notification_manager.broadcast_system_alert(
                'security_alert', 
                alert_data, 
                target_roles
            )
        
        logger.warning(f"Security alert sent: {alert_type}")
        
    except Exception as e:
        logger.error(f"Send security alert error: {e}")