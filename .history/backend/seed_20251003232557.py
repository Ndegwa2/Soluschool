from app import app, db, bcrypt
from models import User, School, Child, QRCode, Gate
import os

def seed_data():
    with app.app_context():
        # Create tables
        db.create_all()
        # Create sample school
        school = School(name="Sample School", address="123 Main St")
        db.session.add(school)
        db.session.commit()

        # Create admin user
        admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(
            role='admin',
            name='Admin User',
            phone='+1234567890',
            email='admin@sample.com',
            password_hash=admin_password,
            school_id=school.id
        )
        db.session.add(admin)
        db.session.commit()

        # Update school admin_id
        school.admin_id = admin.id
        db.session.commit()

        # Create parent user
        parent_password = bcrypt.generate_password_hash('parent123').decode('utf-8')
        parent = User(
            role='parent',
            name='Parent User',
            phone='+0987654321',
            email='parent@sample.com',
            password_hash=parent_password
        )
        db.session.add(parent)
        db.session.commit()

        # Create guard user
        guard_password = bcrypt.generate_password_hash('guard123').decode('utf-8')
        guard = User(
            role='guard',
            name='Guard User',
            phone='+1122334455',
            email='guard@sample.com',
            password_hash=guard_password,
            school_id=school.id
        )
        db.session.add(guard)
        db.session.commit()

        # Create child
        child = Child(
            name='Child One',
            parent_id=parent.id,
            school_id=school.id,
            grade='Grade 1'
        )
        db.session.add(child)
        db.session.commit()

        # Create QR code
        qr_code = QRCode(
            user_id=parent.id,
            child_id=child.id,
            qr_data='sample-qr-data-base64-encoded',
            is_active=True
        )
        db.session.add(qr_code)
        db.session.commit()

        # Create gate
        gate = Gate(
            school_id=school.id,
            name='Main Gate',
            location='Front entrance'
        )
        db.session.add(gate)
        db.session.commit()

        print("Seed data inserted successfully!")

if __name__ == '__main__':
    seed_data()