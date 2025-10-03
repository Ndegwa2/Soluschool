from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///qreet.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key')

db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

@app.route('/')
def hello():
    return {'message': 'Hello, Qreet!'}

if __name__ == '__main__':
    app.run(debug=True)