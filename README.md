# iOS App Distribution Platform

A web application for distributing iOS apps with UDID registration and admin management.

## Features

- User UDID registration via mobileconfig profile
- Admin panel for app management and user association
- App signing with user certificates
- App Store style interface
- Secure app distribution

## Setup

1. Install dependencies:
```
pip install -r requirements.txt
```

2. Initialize the database:
```
python init_db.py
```

3. Run the application:
```
python app.py
```

4. Access the application at http://localhost:5000

## Admin Access

Default admin credentials:
- Username: admin
- Password: admin

Change these credentials after first login for security.

## Requirements

- Python 3.8+
- iOS Developer Certificates (p12 and mobileprovision)
- iOS App Signing tools
