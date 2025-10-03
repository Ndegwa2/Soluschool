from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
import africastalking
from marshmallow import Schema, fields, ValidationError
import qrcode
import base64
from io import BytesIO
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from sqlalchemy import event
from models import User, Child, School, QRCode, Gate, Log, Notification

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///qreet.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail config
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

from models import db
db.init_app(app)

# Run migrations on startup
with app.app_context():
    from alembic.config import Config
    from alembic import command
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)
limiter = Limiter(get_remote_address, app=app)
mail = Mail(app)

# Africa's Talking
africas_talking_username = os.getenv('AFRICAS_TALKING_USERNAME')
africas_talking_api_key = os.getenv('AFRICAS_TALKING_API_KEY')
at = africastalking.initialize(africas_talking_username, africas_talking_api_key)
sms = at.sms

# Encryption key for QR
encryption_key = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
cipher = Fernet(encryption_key)

# Schemas
class RegisterSchema(Schema):
    name = fields.Str(required=True)
    phone = fields.Str(required=True)
    email = fields.Email()
    password = fields.Str(required=True, validate=lambda p: len(p) >= 6)
    role = fields.Str(required=True, validate=lambda r: r in ['parent', 'admin', 'guard'])
    school_id = fields.Int()

class LoginSchema(Schema):
    phone_or_email = fields.Str(required=True)
    password = fields.Str(required=True)

class GenerateQRSchema(Schema):
    child_id = fields.Int()
    is_guest = fields.Bool()
    expires_at = fields.DateTime()

class ScanSchema(Schema):
    qr_data = fields.Str(required=True)
    gate_id = fields.Int(required=True)

class LogSchema(Schema):
    qr_id = fields.Int()
    gate_id = fields.Int(required=True)
    status = fields.Str(required=True, validate=lambda s: s in ['approved', 'denied', 'escalated'])
    notes = fields.Str()

class NotificationSendSchema(Schema):
    user_id = fields.Int(required=True)
    type = fields.Str(required=True)
    message = fields.Str(required=True)

# Auth routes
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    schema = RegisterSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 400

    # Check if user exists
    existing = User.query.filter((User.phone == data['phone']) | (User.email == data.get('email'))).first()
    if existing:
        return jsonify({'success': False, 'error': 'User already exists'}), 400

    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(
        name=data['name'],
        phone=data['phone'],
        email=data.get('email'),
        password_hash=hashed,
        role=data['role'],
        school_id=data.get('school_id')
    )
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=user.id)
    return jsonify({'success': True, 'token': token, 'user': {'id': user.id, 'name': user.name, 'role': user.role}})

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    schema = LoginSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 400

    user = User.query.filter((User.phone == data['phone_or_email']) | (User.email == data['phone_or_email'])).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, data['password']):
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    token = create_access_token(identity=user.id)
    return jsonify({'success': True, 'token': token, 'user': {'id': user.id, 'name': user.name, 'role': user.role}})

# QR routes
@app.route('/api/qr/generate', methods=['POST'])
@jwt_required()
def generate_qr():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    schema = GenerateQRSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 400

    # Check permissions
    if user.role == 'parent':
        if data.get('child_id'):
            child = Child.query.filter_by(id=data['child_id'], parent_id=user_id).first()
            if not child:
                return jsonify({'success': False, 'error': 'Child not found or not yours'}), 403
    elif user.role in ['admin', 'guard']:
        if data.get('child_id'):
            child = Child.query.get(data['child_id'])
            if not child or child.school_id != user.school_id:
                return jsonify({'success': False, 'error': 'Child not in your school'}), 403
    else:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    # Generate nonce
    import secrets
    nonce = secrets.token_hex(16)
    timestamp = datetime.utcnow().isoformat()
    qr_data_dict = {
        'child_id': data.get('child_id'),
        'is_guest': data.get('is_guest', False),
        'nonce': nonce,
        'timestamp': timestamp,
        'expires_at': data.get('expires_at').isoformat() if data.get('expires_at') else None
    }

    # Encrypt
    import json
    encrypted_data = cipher.encrypt(json.dumps(qr_data_dict).encode())
    qr_string = base64.b64encode(encrypted_data).decode('utf-8')

    # Generate QR
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_string)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    # Save to DB
    qr_code = QRCode(
        user_id=user_id,
        child_id=data.get('child_id'),
        qr_data=qr_base64,
        is_active=True,
        expires_at=data.get('expires_at'),
        is_guest=data.get('is_guest', False)
    )
    db.session.add(qr_code)
    db.session.commit()

    return jsonify({'success': True, 'qr_id': qr_code.id, 'qr_data': qr_base64})

@app.route('/api/qr/list', methods=['GET'])
@jwt_required()
def list_qr():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    query = QRCode.query
    if user.role == 'parent':
        query = query.filter_by(user_id=user_id)
    elif user.role in ['admin', 'guard']:
        filter_user_id = request.args.get('user_id', type=int)
        if filter_user_id:
            query = query.filter_by(user_id=filter_user_id)
        else:
            query = query.filter_by(user_id=user_id)
    qrs = query.filter_by(is_active=True).all()
    result = [{'id': qr.id, 'child_id': qr.child_id, 'is_guest': qr.is_guest, 'expires_at': qr.expires_at.isoformat() if qr.expires_at else None} for qr in qrs]
    return jsonify({'success': True, 'qrs': result})

@app.route('/api/qr/<int:qr_id>/revoke', methods=['PUT'])
@jwt_required()
def revoke_qr(qr_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    qr = QRCode.query.get(qr_id)
    if not qr:
        return jsonify({'success': False, 'error': 'QR not found'}), 404
    if qr.user_id != user_id and user.role not in ['admin']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    qr.is_active = False
    db.session.commit()
    return jsonify({'success': True})

# Verification
@app.route('/api/verify/scan', methods=['POST'])
@jwt_required()
@limiter.limit("100 per minute")
def verify_scan():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role not in ['guard', 'admin']:
        return jsonify({'success': False, 'error': 'Only guards can scan'}), 403

    schema = ScanSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 400

    # Decrypt QR data
    try:
        encrypted_data = base64.b64decode(data['qr_data'])
        decrypted_data = cipher.decrypt(encrypted_data)
        qr_info = json.loads(decrypted_data.decode())
    except Exception as e:
        return jsonify({'success': False, 'status': 'denied', 'error': 'Invalid QR'}), 400

    # Validate
    now = datetime.utcnow()
    if qr_info.get('expires_at'):
        expires = datetime.fromisoformat(qr_info['expires_at'])
        if now > expires:
            status = 'denied'
            notes = 'Expired'
        else:
            status = 'approved'
            notes = None
    else:
        status = 'approved'
        notes = None

    # Check if QR is active in DB
    qr = QRCode.query.filter_by(qr_data=base64.b64encode(encrypted_data).decode(), is_active=True).first()
    if not qr:
        status = 'denied'
        notes = 'Inactive QR'

    # Log the scan
    log = Log(
        qr_id=qr.id if qr else None,
        gate_id=data['gate_id'],
        scanned_by=user_id,
        status=status,
        notes=notes
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({'success': True, 'status': status, 'qr_info': qr_info})

# Logging
@app.route('/api/logs', methods=['GET'])
@jwt_required()
def get_logs():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role != 'admin':
        return jsonify({'success': False, 'error': 'Admin only'}), 403

    school_id = request.args.get('school_id', type=int)
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    status_filter = request.args.get('status')

    query = Log.query.join(Gate)
    if school_id:
        query = query.filter(Gate.school_id == school_id)
    if date_from:
        query = query.filter(Log.timestamp >= datetime.fromisoformat(date_from))
    if date_to:
        query = query.filter(Log.timestamp <= datetime.fromisoformat(date_to))
    if status_filter:
        query = query.filter(Log.status == status_filter)

    logs = query.all()
    result = [{
        'id': log.id,
        'qr_id': log.qr_id,
        'gate_id': log.gate_id,
        'scanned_by': log.scanned_by,
        'status': log.status,
        'timestamp': log.timestamp.isoformat(),
        'notes': log.notes
    } for log in logs]
    return jsonify({'success': True, 'logs': result})

@app.route('/api/logs', methods=['POST'])
@jwt_required()
def add_log():
    user_id = get_jwt_identity()
    schema = LogSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 400

    log = Log(
        qr_id=data.get('qr_id'),
        gate_id=data['gate_id'],
        scanned_by=user_id,
        status=data['status'],
        notes=data.get('notes')
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({'success': True, 'log_id': log.id})

# Notifications
@app.route('/api/notifications/send', methods=['POST'])
@jwt_required()
def send_notification():
    schema = NotificationSendSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 400

    user = User.query.get(data['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    # Save to DB
    notification = Notification(
        user_id=data['user_id'],
        type=data['type'],
        message=data['message']
    )
    db.session.add(notification)
    db.session.commit()

    # Send SMS if phone
    if user.phone:
        try:
            sms_response = sms.send(data['message'], [user.phone])
        except Exception as e:
            pass  # Log error

    # Send email if email
    if user.email:
        try:
            msg = Message(data['type'], recipients=[user.email])
            msg.body = data['message']
            mail.send(msg)
        except Exception as e:
            pass

    return jsonify({'success': True, 'notification_id': notification.id})

@app.route('/api/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.sent_at.desc()).all()
    result = [{
        'id': n.id,
        'type': n.type,
        'message': n.message,
        'sent_at': n.sent_at.isoformat(),
        'status': n.status
    } for n in notifications]
    return jsonify({'success': True, 'notifications': result})

# Analytics
@app.route('/api/analytics/summary', methods=['GET'])
@jwt_required()
def analytics_summary():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role != 'admin':
        return jsonify({'success': False, 'error': 'Admin only'}), 403

    school_id = request.args.get('school_id', type=int)
    period = request.args.get('period', 'daily')

    now = datetime.utcnow()
    if period == 'daily':
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == 'weekly':
        start = now - timedelta(days=now.weekday())
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)

    query = Log.query.join(Gate).filter(Log.status == 'approved', Log.timestamp >= start)
    if school_id:
        query = query.filter(Gate.school_id == school_id)

    total_pickups = query.count()

    from sqlalchemy import func
    peak_times = db.session.query(func.extract('hour', Log.timestamp).label('hour'), func.count(Log.id).label('count')).join(Gate).filter(Log.status == 'approved', Log.timestamp >= start)
    if school_id:
        peak_times = peak_times.filter(Gate.school_id == school_id)
    peak_times = peak_times.group_by(func.extract('hour', Log.timestamp)).order_by(func.count(Log.id).desc()).first()
    peak_hour = int(peak_times.hour) if peak_times else None

    visitors = query.distinct(Log.qr_id).count()

    return jsonify({'success': True, 'total_pickups': total_pickups, 'peak_hour': peak_hour, 'visitors': visitors})

@app.route('/api/analytics/chart-data', methods=['GET'])
@jwt_required()
def analytics_chart_data():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role != 'admin':
        return jsonify({'success': False, 'error': 'Admin only'}), 403

    metric = request.args.get('metric')
    school_id = request.args.get('school_id', type=int)

    from sqlalchemy import func
    if metric == 'pickups_by_hour':
        query = db.session.query(func.extract('hour', Log.timestamp).label('hour'), func.count(Log.id).label('count')).join(Gate).filter(Log.status == 'approved')
        if school_id:
            query = query.filter(Gate.school_id == school_id)
        data = query.group_by(func.extract('hour', Log.timestamp)).order_by('hour').all()
        result = [{'hour': int(row.hour), 'count': row.count} for row in data]
    else:
        result = []

    return jsonify({'success': True, 'data': result})


@app.route('/')
def hello():
    return {'message': 'Hello, Qreet!'}

if __name__ == '__main__':
    app.run(debug=True)