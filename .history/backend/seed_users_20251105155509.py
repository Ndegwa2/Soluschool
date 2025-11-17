#!/usr/bin/env python3

import sys
import os
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, User
from werkzeug.security import generate_password_hash

def create_test_users():
    """Create test users for authentication testing"""
    
    with app.app_context():
        print("Creating test users...")
        
        # Check existing users
        users = User.query.all()
        print(f'Existing users: {len(users)}')
        for user in users:
            print(f'  - {user.email} ({user.role})')
        
        # Create admin user if not exists
        admin = User.query.filter_by(email='admin@qreet.com').first()
        if not admin:
            admin = User(
                name='Admin User',
                email='admin@qreet.com',
                phone='+254700000000',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                created_at=datetime.utcnow()
            )
            db.session.add(admin)
            print('✓ Created admin user: admin@qreet.com / admin123')
        else:
            print('✓ Admin user already exists')
        
        # Create parent user
        parent = User.query.filter_by(email='parent@qreet.com').first()
        if not parent:
            parent = User(
                name='Parent User',
                email='parent@qreet.com',
                phone='+254700000001',
                password_hash=generate_password_hash('parent123'),
                role='parent',
                school_id=1,
                created_at=datetime.utcnow()
            )
            db.session.add(parent)
            print('✓ Created parent user: parent@qreet.com / parent123')
        else:
            print('✓ Parent user already exists')
        
        # Create guard user
        guard = User.query.filter_by(email='guard@qreet.com').first()
        if not guard:
            guard = User(
                name='Guard User',
                email='guard@qreet.com',
                phone='+254700000002',
                password_hash=generate_password_hash('guard123'),
                role='guard',
                school_id=1,
                created_at=datetime.utcnow()
            )
            db.session.add(guard)
            print('✓ Created guard user: guard@qreet.com / guard123')
        else:
            print('✓ Guard user already exists')
        
        # Create test school if not exists
        from models import School
        school = School.query.filter_by(id=1).first()
        if not school:
            school = School(
                name='Test School',
                address='123 Test Street',
                admin_id=admin.id if 'admin' in locals() else 1
            )
            db.session.add(school)
            print('✓ Created test school')
        else:
            print('✓ Test school already exists')
        
        try:
            db.session.commit()
            print("\n🎉 All test users created successfully!")
            print("\nTest credentials:")
            print("  Admin: admin@qreet.com / admin123")
            print("  Parent: parent@qreet.com / parent123")
            print("  Guard: guard@qreet.com / guard123")
        except Exception as e:
            print(f"❌ Error creating users: {e}")
            db.session.rollback()

if __name__ == '__main__':
    create_test_users()