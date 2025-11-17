#!/usr/bin/env python3

import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, User
from werkzeug.security import generate_password_hash

def fix_admin_auth():
    """Fix admin user authentication"""
    
    with app.app_context():
        print("Fixing admin user authentication...")
        
        # Get the admin user
        admin = User.query.filter_by(email='admin@qreet.com').first()
        if admin:
            print(f"Found admin user: {admin.email}")
            # Update password with proper hash
            admin.password_hash = generate_password_hash('admin123')
            admin.updated_at = datetime.utcnow()
            print("✓ Updated admin password hash")
        else:
            print("Admin user not found!")
            return
        
        # Get the parent user
        parent = User.query.filter_by(email='parent@qreet.com').first()
        if parent:
            print(f"Found parent user: {parent.email}")
            parent.password_hash = generate_password_hash('parent123')
            parent.updated_at = datetime.utcnow()
            print("✓ Updated parent password hash")
        
        # Get the guard user
        guard = User.query.filter_by(email='guard@qreet.com').first()
        if guard:
            print(f"Found guard user: {guard.email}")
            guard.password_hash = generate_password_hash('guard123')
            guard.updated_at = datetime.utcnow()
            print("✓ Updated guard password hash")
        
        try:
            db.session.commit()
            print("\n🎉 Authentication fixed!")
            print("\nTest credentials:")
            print("  Admin: admin@qreet.com / admin123")
            print("  Parent: parent@qreet.com / parent123") 
            print("  Guard: guard@qreet.com / guard123")
        except Exception as e:
            print(f"❌ Error fixing auth: {e}")
            db.session.rollback()

if __name__ == '__main__':
    from datetime import datetime
    fix_admin_auth()