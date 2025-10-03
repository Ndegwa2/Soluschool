# Qreet Platform - System Requirements

## Overview
Qreet is a school pickup management system using QR codes for secure and efficient parent/guardian verification at school gates. The platform consists of a web-based parent portal, a guard-facing mobile app (PWA), and an admin dashboard.

## User Roles
- **Parents**: Register children, generate/manage QR codes, receive notifications, view pickup history
- **Guards**: Scan QR codes at gates, verify access, operate in offline mode
- **Admins**: Manage school setup, view analytics, monitor logs, handle escalations

## Core Features

### 1. User Onboarding & Identity Management
- Simple parent registration (name, phone, child details)
- Unique QR code generation per parent
- QR distribution via email/SMS or portal download
- Guest/delegate access with temporary QR codes
- School admin onboarding with role-based access

### 2. Gate Verification (Guard Application)
- PWA with one-click QR scanner
- Traffic-light verification results (Green=Valid, Red=Invalid, Yellow=Escalation)
- Photo confirmation display (parent + child info)
- Offline mode with cached QR validation
- Sync when connection resumes

### 3. Notifications & Real-Time Updates
- Parent alerts: Pickup confirmations via SMS/push
- Admin alerts: Unrecognized QR attempts
- Child safety timeline: Pickup/drop-off history
- Customizable notification preferences

### 4. Secure Logging System
- Immutable event logs (timestamp, actor, gate, status)
- Encrypted storage for compliance (GDPR/local rules)
- Easy search and audit trail

### 5. Analytics Dashboard
- Visitor volumes (daily/weekly)
- Peak pickup times
- Frequent visitor metrics
- Simple bar/line charts

### 6. Optional Offline SMS Fallback
- Parents send SMS commands (e.g., "PICKUP <childID>")
- Guards verify via SMS response when internet unavailable

## Technical Constraints
- Frontend: React + Next.js
- Backend: Python Flask
- Database: SQLite
- Deployment: Docker containers

## MVP Scope
- QR generation and distribution
- Gate scanning and verification
- Real-time alerts (SMS + in-app)
- Secure log system
- Basic analytics dashboard
- Offline SMS fallback (optional)

## Non-Functional Requirements
- Security: Encrypted data, role-based access control
- Performance: Fast QR scanning and verification
- Reliability: Offline operation capability
- Usability: Simple, WhatsApp-like onboarding
- Compliance: Secure storage for privacy regulations