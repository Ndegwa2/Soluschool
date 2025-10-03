from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Date, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy import event

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    role = Column(String(50), nullable=False)  # parent, admin, guard
    name = Column(String(100), nullable=False)
    phone = Column(String(20), unique=True, nullable=False)
    email = Column(String(100), unique=True)
    password_hash = Column(Text, nullable=False)
    school_id = Column(Integer, ForeignKey('schools.id'))  # for guards/admins
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    children = relationship('Child', back_populates='parent')
    qr_codes = relationship('QRCode', back_populates='user')
    school = relationship('School', back_populates='users')
    logs_scanned = relationship('Log', back_populates='scanned_by_user')
    notifications = relationship('Notification', back_populates='user')

class Child(db.Model):
    __tablename__ = 'children'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    parent_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    school_id = Column(Integer, ForeignKey('schools.id'), nullable=False)
    grade = Column(String(50))
    date_of_birth = Column(Date)
    created_at = Column(DateTime, default=func.now())

    # Relationships
    parent = relationship('User', back_populates='children')
    school = relationship('School', back_populates='children')
    qr_codes = relationship('QRCode', back_populates='child')

class School(db.Model):
    __tablename__ = 'schools'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    address = Column(Text)
    admin_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=func.now())

    # Relationships
    admin = relationship('User', back_populates='school')
    children = relationship('Child', back_populates='school')
    gates = relationship('Gate', back_populates='school')
    users = relationship('User', back_populates='school')

class QRCode(db.Model):
    __tablename__ = 'qr_codes'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    child_id = Column(Integer, ForeignKey('children.id'))
    qr_data = Column(Text, unique=True, nullable=False)  # base64 encoded QR
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime)  # NULL for permanent
    is_guest = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())

    # Relationships
    user = relationship('User', back_populates='qr_codes')
    child = relationship('Child', back_populates='qr_codes')
    logs = relationship('Log', back_populates='qr_code')

class Gate(db.Model):
    __tablename__ = 'gates'
    id = Column(Integer, primary_key=True, autoincrement=True)
    school_id = Column(Integer, ForeignKey('schools.id'), nullable=False)
    name = Column(String(100), nullable=False)  # e.g., "Main Gate"
    location = Column(Text)
    created_at = Column(DateTime, default=func.now())

    # Relationships
    school = relationship('School', back_populates='gates')
    logs = relationship('Log', back_populates='gate')

class Log(db.Model):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    qr_id = Column(Integer, ForeignKey('qr_codes.id'))
    gate_id = Column(Integer, ForeignKey('gates.id'), nullable=False)
    scanned_by = Column(Integer, ForeignKey('users.id'))  # guard
    status = Column(String(50), nullable=False)  # approved, denied, escalated
    timestamp = Column(DateTime, default=func.now())
    notes = Column(Text)

    # Relationships
    qr_code = relationship('QRCode', back_populates='logs')
    gate = relationship('Gate', back_populates='logs')
    scanned_by_user = relationship('User', back_populates='logs_scanned')

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    type = Column(String(50), nullable=False)  # pickup_confirmed, alert, etc.
    message = Column(Text, nullable=False)
    sent_at = Column(DateTime, default=func.now())
    status = Column(String(20), default='sent')  # sent, delivered, read

    # Relationships
    user = relationship('User', back_populates='notifications')

# Indexes as per schema.md
Index('idx_users_phone', User.phone)
Index('idx_users_email', User.email)
Index('idx_qr_codes_user_child', QRCode.user_id, QRCode.child_id)
Index('idx_logs_timestamp', Log.timestamp)
Index('idx_logs_qr', Log.qr_id)