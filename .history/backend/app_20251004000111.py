from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
import africastalking
from marshmallow import Schema, fields, ValidationError
import qrcode
import base64
from io import BytesIO
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
from sqlalchemy import event
from models import User, Child, School, QRCode, Gate, Log, Notification

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///qreet.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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


@app.route('/')
def hello():
    return {'message': 'Hello, Qreet!'}

if __name__ == '__main__':
    app.run(debug=True)