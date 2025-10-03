# Qreet Platform - System Architecture

## High-Level Architecture Diagram

```mermaid
graph TD
    A[Parent Portal<br/>Next.js] --> B[Flask API<br/>Backend]
    C[Guard PWA<br/>Next.js] --> B
    D[Admin Dashboard<br/>Next.js] --> B
    B --> E[SQLite Database]
    B --> F[SMS Gateway<br/>Twilio/Africa's Talking]
    B --> G[Email Service<br/>Flask-Mail]

    C --> H[Offline Cache<br/>IndexedDB]
    H -.-> B

    I[QR Scanner<br/>Camera API] --> C
    J[Charts<br/>Recharts] --> D

    subgraph "User Roles"
        A
        C
        D
    end

    subgraph "Core Services"
        B
        E
        F
        G
    end

    subgraph "External Integrations"
        F
        G
    end
```

## Component Descriptions

### Frontend Layer
- **Parent Portal**: Web interface for registration, QR management, notifications
- **Guard PWA**: Mobile-optimized app for QR scanning with offline capabilities
- **Admin Dashboard**: Analytics, logs, and system management

### Backend Layer
- **Flask API**: RESTful endpoints for all business logic
  - Authentication & authorization
  - QR generation & verification
  - Logging & notifications
  - Analytics queries

### Data Layer
- **SQLite Database**: Lightweight relational storage
  - User accounts and roles
  - Children and QR codes
  - Event logs and analytics data

### External Services
- **SMS Gateway**: For real-time notifications and offline fallback
- **Email Service**: For QR distribution and admin alerts

### Offline Capabilities
- Guard PWA caches valid QR codes in IndexedDB
- Syncs with backend when connection resumes
- SMS fallback for critical communications

## Data Flow
1. Parent registers → QR generated → Stored in DB → Distributed via email/SMS
2. Guard scans QR → API validates → Logs event → Sends notifications
3. Admin views analytics → Queries DB → Displays charts

## Security Layers
- JWT authentication for API access
- Role-based access control
- Encrypted data storage
- HTTPS for all communications