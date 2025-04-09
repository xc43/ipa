import os
import uuid
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_in_production')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance/app.db')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max upload size

# Add current datetime to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Ensure upload directories exist
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'ipas'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'signed'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'certs'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'icons'), exist_ok=True)

# Database helper functions
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

# Authentication helpers
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        
        user = query_db('SELECT * FROM users WHERE id = ?', [session['user_id']], one=True)
        if not user or not user['is_admin']:
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# UDID Registration and Profile Generation
def generate_mobileconfig(device_name="iOS Device"):
    """Generate a mobileconfig file for UDID collection"""
    profile_id = str(uuid.uuid4())
    profile_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDescription</key>
            <string>Configures device UDID registration</string>
            <key>PayloadDisplayName</key>
            <string>UDID Registration</string>
            <key>PayloadIdentifier</key>
            <string>com.appstore.profile.udid</string>
            <key>PayloadType</key>
            <string>Profile Service</string>
            <key>PayloadUUID</key>
            <string>{profile_id}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadOrganization</key>
            <string>App Store Distribution</string>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>This profile helps collect your device UDID for app installation</string>
    <key>PayloadDisplayName</key>
    <string>UDID Registration Profile</string>
    <key>PayloadIdentifier</key>
    <string>com.appstore.config.udid.{profile_id}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{str(uuid.uuid4())}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>'''
    
    profile_path = os.path.join(app.config['UPLOAD_FOLDER'], f'udid_{profile_id}.mobileconfig')
    with open(profile_path, 'w') as f:
        f.write(profile_content)
    
    return profile_path

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        user = query_db('SELECT * FROM users WHERE id = ?', [session['user_id']], one=True)
        if user and user['is_admin']:
            return redirect(url_for('admin_dashboard'))
    
    # Get all available apps for the device if UDID is registered
    apps = []
    if 'device_id' in session:
        device_id = session['device_id']
        apps = query_db('''
            SELECT a.*, sa.id as signed_app_id, sa.signed_ipa_path
            FROM apps a
            JOIN app_device_access ada ON a.id = ada.app_id
            LEFT JOIN signed_apps sa ON a.id = sa.app_id AND sa.device_id = ?
            WHERE ada.device_id = ?
        ''', [device_id, device_id])
    
    return render_template('index.html', apps=apps, has_device='device_id' in session)

@app.route('/register-device')
def register_device():
    profile_path = generate_mobileconfig()
    return send_file(profile_path, as_attachment=True, 
                     download_name='udid_registration.mobileconfig',
                     mimetype='application/x-apple-aspen-config')

@app.route('/udid-callback', methods=['POST'])
def udid_callback():
    data = request.form
    udid = data.get('UDID')
    device_name = data.get('DEVICE_NAME', 'iOS Device')
    
    if not udid:
        return jsonify({'error': 'No UDID provided'}), 400
    
    # Check if device already exists
    existing_device = query_db('SELECT * FROM devices WHERE udid = ?', [udid], one=True)
    
    if existing_device:
        device_id = existing_device['id']
    else:
        # Create new device
        user_id = session.get('user_id')
        query_db('INSERT INTO devices (udid, name, user_id) VALUES (?, ?, ?)', 
                [udid, device_name, user_id])
        device_id = query_db('SELECT last_insert_rowid()', one=True)[0]
    
    # Store device ID in session
    session['device_id'] = device_id
    
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('Login successful', 'success')
            
            if user['is_admin']:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        existing_user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password)
        query_db('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed_password])
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Admin routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    apps = query_db('SELECT * FROM apps ORDER BY created_at DESC')
    devices = query_db('SELECT * FROM devices ORDER BY created_at DESC')
    return render_template('admin/dashboard.html', apps=apps, devices=devices)

@app.route('/admin/upload-app', methods=['GET', 'POST'])
@admin_required
def upload_app():
    if request.method == 'POST':
        if 'ipa_file' not in request.files:
            flash('No IPA file selected', 'error')
            return redirect(request.url)
        
        ipa_file = request.files['ipa_file']
        if ipa_file.filename == '':
            flash('No IPA file selected', 'error')
            return redirect(request.url)
        
        if ipa_file:
            # Save IPA file
            filename = secure_filename(ipa_file.filename)
            ipa_path = os.path.join(app.config['UPLOAD_FOLDER'], 'ipas', filename)
            ipa_file.save(ipa_path)
            
            # Save app icon if provided
            icon_path = None
            if 'app_icon' in request.files and request.files['app_icon'].filename != '':
                icon_file = request.files['app_icon']
                icon_filename = secure_filename(icon_file.filename)
                icon_path = os.path.join(app.config['UPLOAD_FOLDER'], 'icons', icon_filename)
                icon_file.save(icon_path)
            
            # Insert app into database
            name = request.form.get('name')
            bundle_id = request.form.get('bundle_id')
            version = request.form.get('version')
            description = request.form.get('description')
            
            query_db('''
                INSERT INTO apps (name, bundle_id, version, description, icon_path, original_ipa_path)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', [name, bundle_id, version, description, icon_path, ipa_path])
            
            flash('App uploaded successfully', 'success')
            return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/upload_app.html')

@app.route('/admin/manage-app/<int:app_id>', methods=['GET', 'POST'])
@admin_required
def manage_app(app_id):
    app = query_db('SELECT * FROM apps WHERE id = ?', [app_id], one=True)
    if not app:
        flash('App not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    devices = query_db('SELECT * FROM devices ORDER BY created_at DESC')
    
    # Get devices that have access to this app
    app_devices = query_db('''
        SELECT d.* FROM devices d
        JOIN app_device_access ada ON d.id = ada.device_id
        WHERE ada.app_id = ?
    ''', [app_id])
    
    app_device_ids = [d['id'] for d in app_devices]
    
    if request.method == 'POST':
        # Update app access
        selected_devices = request.form.getlist('devices')
        selected_devices = [int(d) for d in selected_devices]
        
        # Remove access for devices not in the selection
        for device in app_devices:
            if device['id'] not in selected_devices:
                query_db('DELETE FROM app_device_access WHERE app_id = ? AND device_id = ?', 
                        [app_id, device['id']])
        
        # Add access for newly selected devices
        for device_id in selected_devices:
            if device_id not in app_device_ids:
                query_db('INSERT INTO app_device_access (app_id, device_id) VALUES (?, ?)', 
                        [app_id, device_id])
        
        flash('App access updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/manage_app.html', app=app, devices=devices, app_device_ids=app_device_ids)

@app.route('/admin/sign-app/<int:app_id>/<int:device_id>')
@admin_required
def sign_app(app_id, device_id):
    app = query_db('SELECT * FROM apps WHERE id = ?', [app_id], one=True)
    device = query_db('SELECT * FROM devices WHERE id = ?', [device_id], one=True)
    
    if not app or not device:
        flash('App or device not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Check if app is already signed for this device
    signed_app = query_db('''
        SELECT * FROM signed_apps 
        WHERE app_id = ? AND device_id = ?
    ''', [app_id, device_id], one=True)
    
    if signed_app:
        flash('App is already signed for this device', 'info')
        return redirect(url_for('admin_dashboard'))
    
    # In a real implementation, this would call the signing script
    # For now, we'll simulate signing by copying the original IPA
    import shutil
    signed_filename = f"{app['name']}_{device['udid']}.ipa"
    signed_path = os.path.join(app.config['UPLOAD_FOLDER'], 'signed', signed_filename)
    shutil.copy2(app['original_ipa_path'], signed_path)
    
    # Record the signed app in the database
    query_db('''
        INSERT INTO signed_apps (app_id, device_id, signed_ipa_path)
        VALUES (?, ?, ?)
    ''', [app_id, device_id, signed_path])
    
    flash('App signed successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/download/<int:signed_app_id>')
def download_app(signed_app_id):
    signed_app = query_db('SELECT * FROM signed_apps WHERE id = ?', [signed_app_id], one=True)
    
    if not signed_app:
        flash('App not found', 'error')
        return redirect(url_for('index'))
    
    # Update download count
    query_db('UPDATE signed_apps SET download_count = download_count + 1 WHERE id = ?', [signed_app_id])
    
    app = query_db('SELECT * FROM apps WHERE id = ?', [signed_app['app_id']], one=True)
    filename = f"{app['name']}.ipa"
    
    return send_file(signed_app['signed_ipa_path'], as_attachment=True, download_name=filename)

@app.route('/admin/certificates', methods=['GET', 'POST'])
@admin_required
def manage_certificates():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        p12_password = request.form.get('p12_password')
        
        if 'p12_file' not in request.files or 'mobileprovision_file' not in request.files:
            flash('Missing certificate files', 'error')
            return redirect(request.url)
        
        p12_file = request.files['p12_file']
        mobileprovision_file = request.files['mobileprovision_file']
        
        if p12_file.filename == '' or mobileprovision_file.filename == '':
            flash('No certificate files selected', 'error')
            return redirect(request.url)
        
        # Save certificate files
        p12_filename = secure_filename(p12_file.filename)
        p12_path = os.path.join(app.config['UPLOAD_FOLDER'], 'certs', p12_filename)
        p12_file.save(p12_path)
        
        mobileprovision_filename = secure_filename(mobileprovision_file.filename)
        mobileprovision_path = os.path.join(app.config['UPLOAD_FOLDER'], 'certs', mobileprovision_filename)
        mobileprovision_file.save(mobileprovision_path)
        
        # Insert certificate into database
        query_db('''
            INSERT INTO certificates (user_id, p12_path, p12_password, mobileprovision_path)
            VALUES (?, ?, ?, ?)
        ''', [user_id, p12_path, p12_password, mobileprovision_path])
        
        flash('Certificate uploaded successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    users = query_db('SELECT * FROM users ORDER BY username')
    certificates = query_db('''
        SELECT c.*, u.username FROM certificates c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
    ''')
    
    return render_template('admin/certificates.html', users=users, certificates=certificates)

if __name__ == '__main__':
    app.run(debug=True)
