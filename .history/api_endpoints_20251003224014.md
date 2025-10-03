# Qreet Platform - Flask API Endpoints

## Authentication
- POST /api/auth/register
  - Body: {name, phone, email, password, role, school_id?}
  - Creates user account, returns JWT token

- POST /api/auth/login
  - Body: {phone_or_email, password}
  - Returns JWT token and user info

## QR Code Management
- POST /api/qr/generate
  - Headers: Authorization (JWT)
  - Body: {child_id, is_guest?, expires_at?}
  - Generates and returns QR code data

- GET /api/qr/list
  - Headers: Authorization (JWT)
  - Query: user_id (for admins)
  - Returns list of active QR codes

- PUT /api/qr/{qr_id}/revoke
  - Headers: Authorization (JWT)
  - Deactivates QR code

## Verification
- POST /api/verify/scan
  - Headers: Authorization (JWT - guard)
  - Body: {qr_data, gate_id}
  - Validates QR, logs event, returns status (approved/denied/escalated)

## Logging
- GET /api/logs
  - Headers: Authorization (JWT - admin)
  - Query: school_id, date_from, date_to, status
  - Returns filtered logs

- POST /api/logs
  - Headers: Authorization (JWT)
  - Body: {qr_id, gate_id, status, notes}
  - Adds log entry (used by verification endpoint)

## Notifications
- POST /api/notifications/send
  - Headers: Authorization (JWT)
  - Body: {user_id, type, message}
  - Sends notification (SMS/email/push)

- GET /api/notifications
  - Headers: Authorization (JWT)
  - Returns user's notifications

## Analytics
- GET /api/analytics/summary
  - Headers: Authorization (JWT - admin)
  - Query: school_id, period (daily/weekly)
  - Returns: pickup counts, peak times, visitor metrics

- GET /api/analytics/chart-data
  - Headers: Authorization (JWT - admin)
  - Query: metric (pickups_by_hour, etc.)
  - Returns data for charts

## Schools & Gates
- GET /api/schools
  - Headers: Authorization (JWT)
  - Returns schools (for admin setup)

- POST /api/gates
  - Headers: Authorization (JWT - admin)
  - Body: {school_id, name, location}
  - Creates gate

- GET /api/gates/{school_id}
  - Headers: Authorization (JWT)
  - Returns gates for school

## Children
- POST /api/children
  - Headers: Authorization (JWT - parent)
  - Body: {name, school_id, grade, date_of_birth}
  - Adds child to parent account

- GET /api/children
  - Headers: Authorization (JWT)
  - Returns parent's children

## Error Handling
All endpoints return JSON with:
- Success: {success: true, data: ...}
- Error: {success: false, error: "message", code: 400}

## Security
- All endpoints require JWT in Authorization header
- Role-based access control enforced
- Input validation and sanitization
- Rate limiting on verification endpoints