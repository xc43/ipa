import os
import sqlite3
from werkzeug.security import generate_password_hash

# Create database directory if it doesn't exist
os.makedirs('instance', exist_ok=True)

# Initialize database
conn = sqlite3.connect('instance/app.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create devices table
cursor.execute('''
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    udid TEXT UNIQUE NOT NULL,
    name TEXT,
    user_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
''')

# Create certificates table
cursor.execute('''
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    p12_path TEXT NOT NULL,
    p12_password TEXT NOT NULL,
    mobileprovision_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
''')

# Create apps table
cursor.execute('''
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT,
    icon_path TEXT,
    original_ipa_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create signed_apps table
cursor.execute('''
CREATE TABLE IF NOT EXISTS signed_apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    signed_ipa_path TEXT NOT NULL,
    download_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_id) REFERENCES apps (id),
    FOREIGN KEY (device_id) REFERENCES devices (id)
)
''')

# Create app_device_access table to control which devices can access which apps
cursor.execute('''
CREATE TABLE IF NOT EXISTS app_device_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_id) REFERENCES apps (id),
    FOREIGN KEY (device_id) REFERENCES devices (id),
    UNIQUE(app_id, device_id)
)
''')

# Insert default admin user
admin_password = generate_password_hash('admin')
cursor.execute('''
INSERT OR IGNORE INTO users (username, password, is_admin)
VALUES (?, ?, ?)
''', ('admin', admin_password, True))

# Commit changes and close connection
conn.commit()
conn.close()

print("Database initialized successfully with default admin user (username: admin, password: admin)")
