# Qreet Platform - Next.js Frontend Structure

## Project Structure
```
qreet-frontend/
├── pages/
│   ├── _app.js (global layout, auth provider)
│   ├── index.js (landing page)
│   ├── auth/
│   │   ├── login.js
│   │   └── register.js
│   ├── parent/
│   │   ├── dashboard.js
│   │   ├── children.js
│   │   ├── qr-codes.js
│   │   └── history.js
│   ├── guard/
│   │   └── scan.js (PWA entry)
│   └── admin/
│       ├── dashboard.js
│       ├── logs.js
│       ├── analytics.js
│       └── schools.js
├── components/
│   ├── layout/
│   │   ├── Header.js
│   │   ├── Sidebar.js
│   │   └── Footer.js
│   ├── auth/
│   │   ├── LoginForm.js
│   │   └── RegisterForm.js
│   ├── parent/
│   │   ├── ChildCard.js
│   │   ├── QRCodeDisplay.js
│   │   └── NotificationList.js
│   ├── guard/
│   │   ├── QRScanner.js
│   │   ├── VerificationResult.js
│   │   └── OfflineIndicator.js
│   ├── admin/
│   │   ├── LogTable.js
│   │   ├── AnalyticsChart.js
│   │   └── SchoolForm.js
│   └── common/
│       ├── Button.js
│       ├── Modal.js
│       ├── LoadingSpinner.js
│       └── ErrorMessage.js
├── lib/
│   ├── api.js (API client functions)
│   ├── auth.js (JWT handling, role checks)
│   ├── utils.js (helpers)
│   └── config.js (environment variables)
├── styles/
│   ├── globals.css
│   ├── theme.js (CSS variables)
│   └── components/
│       ├── Button.module.css
│       └── ...
├── public/
│   ├── manifest.json (PWA)
│   ├── icons/
│   └── ...
├── next.config.js
├── package.json
└── README.md
```

## Key Features by Section

### Parent Portal (/parent/*)
- Dashboard: Overview of children, recent pickups, notifications
- Children: Add/manage children, link to schools
- QR Codes: View active QRs, generate guest codes, download
- History: Timeline of pickups/drop-offs

### Guard App (/guard/scan)
- PWA optimized for mobile/tablet
- Camera access for QR scanning
- Traffic-light UI (green/red/yellow)
- Offline mode with local cache
- Photo confirmation display

### Admin Dashboard (/admin/*)
- Dashboard: Key metrics, alerts
- Logs: Searchable event logs
- Analytics: Charts for pickups, visitors, peaks
- Schools: Manage schools, gates, users

## PWA Configuration
- Service worker for offline caching
- Install prompt for guard devices
- Camera permissions for scanning
- Local storage for offline QR validation

## State Management
- React Context for auth state
- Local state for forms/components
- SWR for API data fetching/caching

## Styling
- CSS Modules for component styles
- Global theme variables
- Responsive design (mobile-first)
- Traffic-light color scheme for guard app

## Authentication Flow
- JWT stored in localStorage
- Automatic redirects based on role
- Protected routes with HOC
- Logout clears tokens and redirects to login