import logging
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
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
from flask_jwt_extended import JWTManager
from sqlalchemy import event
from models import User, Child, School, QRCode, Gate, Log, Notification
from sqlalchemy.orm import joinedload

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///qreet.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-prod')
print(f'JWT_SECRET_KEY: {app.config["JWT_SECRET_KEY"]}')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

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

# JWT error handlers
@jwt.invalid_token_loader
def invalid_token_callback(error):
    app.logger.info(f'Invalid token: {error}')
    return jsonify({'success': False, 'error': 'Invalid token'}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'success': False, 'error': 'Token expired'}), 401

@jwt.unauthorized_loader
def unauthorized_callback(error):
    return jsonify({'success': False, 'error': 'Missing token'}), 401

CORS(app)
limiter = Limiter(get_remote_address, app=app)
mail = Mail(app)

@app.before_request
def log_request_info():
    if request.method != 'OPTIONS':
        auth_header = request.headers.get('Authorization')
        app.logger.info(f'Request: {request.method} {request.path}, Auth: {auth_header[:20] if auth_header else None}')

# Africa's Talking
africas_talking_username = os.getenv('AFRICAS_TALKING_USERNAME')
africas_talking_api_key = os.getenv('AFRICAS_TALKING_API_KEY')
if africas_talking_username and africas_talking_api_key:
    at = africastalking.initialize(africas_talking_username, africas_talking_api_key)
    sms = at.sms
else:
    sms = None

# Encryption key for QR
encryption_key = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
cipher = Fernet(encryption_key)

# Schemas
class ChildSchema(Schema):
    name = fields.Str(required=True)
    school_id = fields.Int(allow_none=True)
    grade = fields.Str(allow_none=True)
    date_of_birth = fields.Date(allow_none=True)

class RegisterSchema(Schema):
    name = fields.Str(required=True)
    phone = fields.Str(allow_none=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=lambda p: len(p) >= 6)
    role = fields.Str(required=True, validate=lambda r: r in ['parent', 'admin', 'guard'])
    school_id = fields.Int(allow_none=True)
    children = fields.List(fields.Nested(ChildSchema), allow_none=True)

class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)

class GenerateQRSchema(Schema):
    child_id = fields.Int(allow_none=True)
    is_guest = fields.Bool()
    expires_at = fields.DateTime(allow_none=True)

class ScanSchema(Schema):
    qr_data = fields.Str(required=True)
    gate_id = fields.Int(required=True)

class ManualEntrySchema(Schema):
    parent_id = fields.Int(required=True)
    child_id = fields.Int(required=True)
    gate_id = fields.Int(required=True)

class LogSchema(Schema):
    qr_id = fields.Int(allow_none=True)
    gate_id = fields.Int(required=True)
    status = fields.Str(required=True, validate=lambda s: s in ['approved', 'denied', 'escalated'])
    notes = fields.Str(allow_none=True)

class NotificationSendSchema(Schema):
    user_id = fields.Int(required=True)
    type = fields.Str(required=True)
    message = fields.Str(required=True)

class SchoolSchema(Schema):
    name = fields.Str(required=True)
    address = fields.Str(allow_none=True)

class GateSchema(Schema):
    school_id = fields.Int(required=True)
    name = fields.Str(required=True)
    location = fields.Str(allow_none=True)

# Auth routes
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    schema = RegisterSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 422

    # Check if user exists
    existing = User.query.filter_by(email=data['email']).first()
    if existing:
        return jsonify({'success': False, 'error': 'User already exists'}), 400

    # For parents, require school_id
    if data['role'] == 'parent' and not data.get('school_id'):
        return jsonify({'success': False, 'error': 'School required for parents'}), 422

    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(
        name=data['name'],
        phone=data.get('phone'),
        email=data['email'],
        password_hash=hashed,
        role=data['role'],
        school_id=data.get('school_id')
    )
    db.session.add(user)

    # Create children if provided
    if data.get('children'):
        for child_data in data['children']:
            child = Child(
                parent_id=user.id,
                name=child_data['name'],
                school_id=data['school_id'],
                grade=child_data.get('grade'),
                date_of_birth=child_data.get('date_of_birth')
            )
            db.session.add(child)

    db.session.commit()

    app.logger.info(f'User registered: {user.email} with role {user.role}')
    token = create_access_token(identity=user.id)
    return jsonify({'success': True, 'token': token, 'user': {'id': user.id, 'name': user.name, 'role': user.role}})

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    schema = LoginSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 422

    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, data['password']):
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    app.logger.info(f'User logged in: {user.email}')
    token = create_access_token(identity=str(user.id), additional_claims={'role': user.role})
    return jsonify({'success': True, 'token': token, 'user': {'id': user.id, 'name': user.name, 'role': user.role, 'school_id': user.school_id}})

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
        return jsonify({'success': False, 'error': err.messages}), 422

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
    result = [{'id': qr.id, 'child_id': qr.child_id, 'is_guest': qr.is_guest, 'expires_at': qr.expires_at.isoformat() if qr.expires_at else None, 'qr_data': qr.qr_data} for qr in qrs]
    return jsonify({'success': True, 'qrs': result})

@app.route('/api/qr/<int:qr_id>/revoke', methods=['PUT'])
@jwt_required()
def revoke_qr(qr_id):
    user_id = int(get_jwt_identity())
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
        return jsonify({'success': False, 'error': err.messages}), 422

    qr_data = data['qr_data']

    # Check if qr_data is a plain child_id (numeric string)
    if qr_data.isdigit():
        child_id = int(qr_data)
        child = Child.query.get(child_id)
        if not child:
            return jsonify({'success': False, 'status': 'denied', 'error': 'Child not found'}), 400
        # Check if child is in guard's school
        if child.school_id != user.school_id:
            return jsonify({'success': False, 'status': 'denied', 'error': 'Child not in your school'}), 403
        # For plain child_id, always approve (no expiration)
        status = 'approved'
        notes = 'Scanned child ID'
        qr_info = {'child_id': child_id, 'is_guest': False}
        qr = None  # No QR record for plain child_id
    else:
        # Decrypt QR data
        try:
            encrypted_data = base64.b64decode(qr_data)
            decrypted_data = cipher.decrypt(encrypted_data)
            qr_info = json.loads(decrypted_data.decode())
        except Exception as e:
            app.logger.warning(f'Invalid QR data received: {e}')
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

    app.logger.info(f'QR scan logged: status {status} at gate {data["gate_id"]} by user {user_id}')
    return jsonify({'success': True, 'status': status, 'qr_info': qr_info})

@app.route('/api/manual-entry', methods=['POST'])
@jwt_required()
def manual_entry():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role not in ['guard', 'admin']:
        return jsonify({'success': False, 'error': 'Only guards can do manual entry'}), 403

    schema = ManualEntrySchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': str(err.messages)}), 422

    # Check if parent and child exist
    parent = User.query.get(data['parent_id'])
    child = Child.query.get(data['child_id'])
    if not parent or not child or child.parent_id != parent.id:
        return jsonify({'success': False, 'error': 'Invalid parent or child'}), 400

    # Log the manual entry
    log = Log(
        gate_id=data['gate_id'],
        scanned_by=user_id,
        status='approved',
        notes='Manual entry'
    )
    db.session.add(log)
    db.session.commit()

    app.logger.info(f'Manual entry logged: child {data["child_id"]} at gate {data["gate_id"]} by user {user_id}')
    return jsonify({'success': True, 'status': 'approved', 'child': {'name': child.name}, 'parent': {'name': parent.name, 'phone': parent.phone}, 'timestamp': log.timestamp.isoformat()})

# Logging
@app.route('/api/logs', methods=['GET'])
@jwt_required()
def get_logs():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role not in ['admin', 'parent', 'guard']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    school_id = request.args.get('school_id', type=int)
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    status_filter = request.args.get('status')
    limit = request.args.get('limit', type=int)

    query = Log.query.join(Gate).outerjoin(QRCode).outerjoin(Child).options(joinedload(Log.qr_code).joinedload(QRCode.child), joinedload(Log.gate))
    if user.role == 'parent':
        query = query.filter(Child.parent_id == user_id)
    elif user.role in ['admin', 'guard']:
        if school_id:
            query = query.filter(Gate.school_id == school_id)
        else:
            query = query.filter(Gate.school_id == user.school_id)

    if date_from:
        query = query.filter(Log.timestamp >= datetime.fromisoformat(date_from))
    if date_to:
        query = query.filter(Log.timestamp <= datetime.fromisoformat(date_to))
    if status_filter:
        query = query.filter(Log.status == status_filter)

    if limit:
        logs = query.order_by(Log.timestamp.desc()).limit(limit).all()
    else:
        logs = query.all()
    result = [{
        'id': log.id,
        'child_name': log.qr_code.child.name if log.qr_code and log.qr_code.child else 'Guest',
        'gate_name': log.gate.name,
        'status': log.status,
        'timestamp': log.timestamp.isoformat(),
        'notes': log.notes
    } for log in logs]
    return jsonify({'success': True, 'logs': result})

@app.route('/api/logs', methods=['POST'])
@jwt_required()
def add_log():
    user_id = int(get_jwt_identity())
    schema = LogSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 422

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
        return jsonify({'success': False, 'error': err.messages}), 422

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
    if user.phone and sms:
        try:
            sms_response = sms.send(data['message'], [user.phone])
        except Exception as e:
            app.logger.error(f'Failed to send SMS to {user.phone}: {e}')

    # Send email if email
    if user.email:
        try:
            msg = Message(data['type'], recipients=[user.email])
            msg.body = data['message']
            mail.send(msg)
        except Exception as e:
            app.logger.error(f'Failed to send email to {user.email}: {e}')

    return jsonify({'success': True, 'notification_id': notification.id})

@app.route('/api/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = int(get_jwt_identity())
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
    if user.role not in ['admin', 'guard']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

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
    elif user.role == 'guard':
        query = query.filter(Gate.school_id == user.school_id)

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

# Schools & Gates
@app.route('/api/schools', methods=['GET'])
def get_schools():
    admin_id = request.args.get('adminId', type=int)
    if admin_id:
        # Require auth for filtered schools
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user or user.role != 'admin':
                return jsonify({'success': False, 'error': 'Admin only'}), 403
        except:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        schools = School.query.filter_by(admin_id=admin_id).all()
    else:
        # Public access for all schools
        schools = School.query.all()
    result = [{'id': s.id, 'name': s.name, 'address': s.address} for s in schools]
    return jsonify({'success': True, 'schools': result})

@app.route('/api/schools', methods=['POST'])
@jwt_required()
def create_school():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role != 'admin':
        return jsonify({'success': False, 'error': 'Admin only'}), 403

    schema = SchoolSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 422

    school = School(
        name=data['name'],
        address=data.get('address'),
        admin_id=user_id
    )
    db.session.add(school)
    db.session.commit()
    return jsonify({'success': True, 'school_id': school.id})

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role != 'admin':
        return jsonify({'success': False, 'error': 'Admin only'}), 403

    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    role_filter = request.args.get('role')
    school_id_filter = request.args.get('school_id', type=int)

    query = User.query
    if role_filter:
        query = query.filter_by(role=role_filter)
    if school_id_filter:
        query = query.filter_by(school_id=school_id_filter)

    total = query.count()
    users = query.offset((page - 1) * limit).limit(limit).all()
    result = [{
        'id': u.id,
        'name': u.name,
        'email': u.email,
        'phone': u.phone,
        'role': u.role,
        'school_id': u.school_id
    } for u in users]
    return jsonify({'success': True, 'users': result, 'total': total, 'page': page, 'limit': limit})

@app.route('/api/gates', methods=['POST'])
@jwt_required()
def create_gate():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role != 'admin':
        return jsonify({'success': False, 'error': 'Admin only'}), 403

    schema = GateSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'success': False, 'error': err.messages}), 422

    gate = Gate(
        school_id=data['school_id'],
        name=data['name'],
        location=data.get('location')
    )
    db.session.add(gate)
    db.session.commit()
    return jsonify({'success': True, 'gate_id': gate.id})

@app.route('/api/gates/<int:school_id>', methods=['GET'])
@jwt_required()
def get_gates(school_id):
    gates = Gate.query.filter_by(school_id=school_id).all()
    result = [{'id': g.id, 'name': g.name, 'location': g.location} for g in gates]
    return jsonify({'success': True, 'gates': result})

# Children
@app.route('/api/children', methods=['POST'])
@jwt_required()
def create_child():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if user.role != 'parent':
        return jsonify({'success': False, 'error': 'Parent only'}), 403

    app.logger.info(f'Creating child for user {user_id}, user.school_id: {user.school_id}')
    request_data = request.get_json()
    app.logger.info(f'Request data: {request_data}')

    # If school_id not provided or null, set to default school 1 (assuming single school system)
    if not request_data.get('school_id') or request_data.get('school_id') is None:
        request_data['school_id'] = 1

    schema = ChildSchema()
    try:
        data = schema.load(request_data)
    except ValidationError as err:
        app.logger.error(f'Validation error: {err.messages}')
        return jsonify({'success': False, 'error': err.messages}), 422

    child = Child(
        parent_id=user_id,
        name=data['name'],
        school_id=data['school_id'],
        grade=data.get('grade'),
        date_of_birth=data.get('date_of_birth')
    )
    db.session.add(child)
    db.session.commit()
    return jsonify({'success': True, 'child_id': child.id})

@app.route('/api/children', methods=['GET'])
@jwt_required()
def get_children():
    user_id = int(get_jwt_identity())
    claims = get_jwt()
    app.logger.info(f'get_children called by user_id: {user_id}, claims: {claims}')
    user = User.query.get(user_id)
    if not user:
        app.logger.error(f'User not found: {user_id}')
        return jsonify({'success': False, 'error': 'User not found'}), 404
    app.logger.info(f'User role: {user.role}')
    if user.role == 'parent':
        children = Child.query.filter_by(parent_id=user_id).all()
    elif user.role in ['admin', 'guard']:
        # For admins, perhaps all, but for simplicity, none or filter
        children = []
    else:
        children = []

    result = [{'id': c.id, 'name': c.name, 'school_id': c.school_id, 'grade': c.grade, 'date_of_birth': c.date_of_birth.isoformat() if c.date_of_birth else None} for c in children]
    return jsonify({'success': True, 'children': result})

@app.route('/api/children/<int:child_id>', methods=['DELETE'])
@jwt_required()
def delete_child(child_id):
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if user.role != 'parent':
        return jsonify({'success': False, 'error': 'Parent only'}), 403

    child = Child.query.filter_by(id=child_id, parent_id=user_id).first()
    if not child:
        return jsonify({'success': False, 'error': 'Child not found'}), 404

    db.session.delete(child)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/health')
def health():
    return {'status': 'ok'}

@app.route('/')
def hello():
    return {'message': 'Hello, Qreet!'}

if __name__ == '__main__':
    app.run(debug=True)