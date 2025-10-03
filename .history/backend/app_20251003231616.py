from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
from sqlalchemy import event

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

# Set SQLCipher key
database_key = os.getenv('DATABASE_KEY', 'default-key')
@event.listens_for(db.engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if 'sqlcipher' in app.config['SQLALCHEMY_DATABASE_URI']:
        cursor = dbapi_connection.cursor()
        cursor.execute(f"PRAGMA key = '{database_key}'")
        cursor.close()

@app.route('/')
def hello():
    return {'message': 'Hello, Qreet!'}

if __name__ == '__main__':
    app.run(debug=True)