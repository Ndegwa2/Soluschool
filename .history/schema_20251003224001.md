# Qreet Platform - Database Schema (SQLite)

## Tables

### users
- id: INTEGER PRIMARY KEY AUTOINCREMENT
- role: TEXT NOT NULL (parent, admin, guard)
- name: TEXT NOT NULL
- phone: TEXT UNIQUE NOT NULL
- email: TEXT UNIQUE
- password_hash: TEXT NOT NULL
- school_id: INTEGER (for guards/admins)
- created_at: DATETIME DEFAULT CURRENT_TIMESTAMP
- updated_at: DATETIME DEFAULT CURRENT_TIMESTAMP

### children
- id: INTEGER PRIMARY KEY AUTOINCREMENT
- name: TEXT NOT NULL
- parent_id: INTEGER NOT NULL (FK to users)
- school_id: INTEGER NOT NULL (FK to schools)
- grade: TEXT
- date_of_birth: DATE
- created_at: DATETIME DEFAULT CURRENT_TIMESTAMP

### schools
- id: INTEGER PRIMARY KEY AUTOINCREMENT
- name: TEXT NOT NULL
- address: TEXT
- admin_id: INTEGER (FK to users)
- created_at: DATETIME DEFAULT CURRENT_TIMESTAMP

### qr_codes
- id: INTEGER PRIMARY KEY AUTOINCREMENT
- user_id: INTEGER NOT NULL (FK to users)
- child_id: INTEGER (FK to children)
- qr_data: TEXT UNIQUE NOT NULL (base64 encoded QR)
- is_active: BOOLEAN DEFAULT 1
- expires_at: DATETIME (NULL for permanent)
- is_guest: BOOLEAN DEFAULT 0
- created_at: DATETIME DEFAULT CURRENT_TIMESTAMP

### gates
- id: INTEGER PRIMARY KEY AUTOINCREMENT
- school_id: INTEGER NOT NULL (FK to schools)
- name: TEXT NOT NULL (e.g., "Main Gate")
- location: TEXT
- created_at: DATETIME DEFAULT CURRENT_TIMESTAMP

### logs
- id: INTEGER PRIMARY KEY AUTOINCREMENT
- qr_id: INTEGER (FK to qr_codes)
- gate_id: INTEGER NOT NULL (FK to gates)
- scanned_by: INTEGER (FK to users - guard)
- status: TEXT NOT NULL (approved, denied, escalated)
- timestamp: DATETIME DEFAULT CURRENT_TIMESTAMP
- notes: TEXT

### notifications
- id: INTEGER PRIMARY KEY AUTOINCREMENT
- user_id: INTEGER NOT NULL (FK to users)
- type: TEXT NOT NULL (pickup_confirmed, alert, etc.)
- message: TEXT NOT NULL
- sent_at: DATETIME DEFAULT CURRENT_TIMESTAMP
- status: TEXT DEFAULT 'sent' (sent, delivered, read)

## Indexes
- CREATE INDEX idx_users_phone ON users(phone);
- CREATE INDEX idx_users_email ON users(email);
- CREATE INDEX idx_qr_codes_user_child ON qr_codes(user_id, child_id);
- CREATE INDEX idx_logs_timestamp ON logs(timestamp);
- CREATE INDEX idx_logs_qr ON logs(qr_id);

## Foreign Key Constraints
- children.parent_id REFERENCES users(id)
- children.school_id REFERENCES schools(id)
- qr_codes.user_id REFERENCES users(id)
- qr_codes.child_id REFERENCES children(id)
- schools.admin_id REFERENCES users(id)
- gates.school_id REFERENCES schools(id)
- logs.qr_id REFERENCES qr_codes(id)
- logs.gate_id REFERENCES gates(id)
- logs.scanned_by REFERENCES users(id)
- notifications.user_id REFERENCES users(id)