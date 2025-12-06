"""
Complete Flask app with Supabase integration
Includes all routes from both versions with proper Supabase implementation
"""

import os
import sys
import json
import logging
import random
import smtplib
import string
import base64
import uuid
import mimetypes
from io import BytesIO
from functools import wraps
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from email.mime.text import MIMEText
from decimal import Decimal
import re
from PIL import Image
import io
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    make_response,
    send_file,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional imports
try:
    from dotenv import load_dotenv
except Exception:
    def load_dotenv(*args, **kwargs):
        return None

try:
    from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
except Exception:
    URLSafeTimedSerializer = None
    BadSignature = Exception
    SignatureExpired = Exception

try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except Exception:
    create_client = None
    Client = None
    SUPABASE_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

# -----------------------
# App setup
# -----------------------
load_dotenv()
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key_change_in_production')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app.permanent_session_lifetime = timedelta(days=30)

# File upload configuration
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', os.path.join(os.getcwd(), 'uploads'))
RECEIPT_SUBDIR = 'receipts'
RECEIPT_FOLDER = os.path.join(UPLOAD_FOLDER, RECEIPT_SUBDIR)
os.makedirs(RECEIPT_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_CONTENT_LENGTH = int(os.getenv('MAX_UPLOAD_BYTES', 5 * 1024 * 1024))
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Supabase configuration
SUPABASE_URL = os.getenv('SUPABASE_URL', '').strip()
SUPABASE_KEY = os.getenv('SUPABASE_KEY', '').strip()
SUPABASE_RECEIPT_BUCKET = os.getenv('SUPABASE_RECEIPT_BUCKET', 'receipts')

# SMTP / email config
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDGRID_FROM = os.getenv('SENDGRID_FROM')
SMTP_EMAIL = os.getenv('SMTP_EMAIL')
SMTP_PASS = os.getenv('SMTP_PASS')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587)) if os.getenv('SMTP_PORT') else 587

# 2FA / rate limit config
SEND_LIMIT_WINDOW = int(os.getenv('SEND_LIMIT_WINDOW', 3600))
SEND_LIMIT_COUNT = int(os.getenv('SEND_LIMIT_COUNT', 5))
CODE_TTL = int(os.getenv('CODE_TTL', 300))
REQUIRE_2FA_BEFORE_CREATE = os.getenv('REQUIRE_2FA_BEFORE_CREATE', '0') in ('1', 'true', 'True')

# Global supabase client singleton
_supabase_client = None

# -----------------------
# Supabase helpers
# -----------------------

def get_supabase():
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client
    if not SUPABASE_AVAILABLE or not create_client:
        raise RuntimeError('Supabase library not available')
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError('Supabase URL/KEY not configured')
    _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _supabase_client


def safe_execute(query, operation_name='database operation'):
    try:
        response = query.execute()
        if hasattr(response, 'error') and response.error:
            logger.error(f"{operation_name} failed: {response.error}")
            return False, None, str(response.error)
        data = getattr(response, 'data', None)
        return True, data, None
    except Exception as e:
        logger.exception(f"{operation_name} exception: {e}")
        return False, None, str(e)


def fetch_one(table_name: str, **filters):
    try:
        sb = get_supabase()
        query = sb.table(table_name).select('*')
        for k, v in filters.items():
            query = query.eq(k, v)
        success, data, error = safe_execute(query.limit(1), f'fetch_one({table_name})')
        if not success:
            return None
        if data and len(data) > 0:
            return data[0]
        return None
    except Exception:
        return None

# -----------------------
# helpers
# -----------------------

def json_response(success, message=None, code=200, **kwargs):
    payload = {'success': success}
    if message:
        payload['message'] = message
    payload.update(kwargs)
    return jsonify(payload), code


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return json_response(False, 'Login required', 401)
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap


def role_required(*allowed_roles):
    allowed_norm = [r.lower() for r in allowed_roles]
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                if request.path.startswith('/api/'):
                    return json_response(False, 'Login required', 401)
                return redirect(url_for('login'))
            role = (session.get('role') or '').lower()
            if role not in allowed_norm:
                if request.path.startswith('/api/'):
                    return json_response(False, 'Forbidden', 403)
                return redirect(url_for('interface'))
            return f(*args, **kwargs)
        return wrapped
    return decorator


def admin_required(f):
    return role_required('admin', 'administrator', 'superuser')(f)


def user_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return json_response(False, 'Login required', 401)
            return redirect(url_for('login'))
        role = (session.get('role') or '').lower()
        if role != 'user':
            if role in ('admin', 'administrator', 'superuser'):
                return redirect(url_for('admin_interface'))
            if request.path.startswith('/api/'):
                return json_response(False, 'Forbidden', 403)
            flash('Access forbidden for your account role.', 'error')
            return redirect(url_for('interface'))
        return f(*args, **kwargs)
    return wrap


def is_allowed_email_for_signup(email):
    if not email:
        return False
    e = email.strip().lower()
    if e == 'admin@admin.com':
        return True
    return e.endswith('@gmail.com')


def generate_csrf_token():
    token = str(uuid4())
    session['csrf_token'] = token
    return token


def allowed_file(filename):
    if not filename:
        return False
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXTENSIONS


def save_uploaded_file(file_storage):
    """Save file to Supabase storage and return filename"""
    if not file_storage or file_storage.filename == '':
        raise ValueError("No file provided")
    filename = secure_filename(file_storage.filename)
    if not allowed_file(filename):
        raise ValueError("File type not allowed")
    
    unique = f"{uuid.uuid4().hex}_{filename}"
    
    try:
        sb = get_supabase()
        file_content = file_storage.read()
        sb.storage.from_(SUPABASE_RECEIPT_BUCKET).upload(unique, file_content)
        return unique
    except Exception as e:
        logger.exception(f"Failed to upload file to Supabase: {e}")
        raise


def get_receipt_url(filename, expires_seconds=3600):
    """Get signed URL for receipt from Supabase storage"""
    if not filename:
        return None
    try:
        sb = get_supabase()
        response = sb.storage.from_(SUPABASE_RECEIPT_BUCKET).create_signed_url(filename, expires_seconds)
        return response.get('signedURL')
    except Exception as e:
        logger.warning(f"Failed to get signed URL for {filename}: {e}")
        return url_for('serve_receipt', filename=filename)


def serialize_meeting(row):
    m = {
        "id": row.get("id"),
        "title": row.get("title"),
        "type": row.get("type"),
        "purpose": row.get("purpose") or "",
        "datetime": row.get("datetime"),
        "location": row.get("location") or "",
        "meetLink": row.get("meet_link") or "",
        "status": row.get("status") or "Not Started",
        "attendees": []
    }
    try:
        attendees_str = row.get("attendees")
        if attendees_str:
            if isinstance(attendees_str, str):
                m["attendees"] = json.loads(attendees_str)
            elif isinstance(attendees_str, list):
                m["attendees"] = attendees_str
    except Exception:
        m["attendees"] = []
    return m


def serialize_task(row):
    return {
        "id": row.get("id"),
        "title": row.get("title"),
        "due": row.get("due") or "",
        "priority": row.get("priority") or "medium",
        "notes": row.get("notes") or "",
        "status": row.get("status") or "pending",
        "progress": int(row.get("progress") or 0),
        "type": row.get("type") or "assignment",
        "completed": bool(row.get("completed")),
        "created_at": row.get("created_at")
    }

# -----------------------
# Email functions
# -----------------------

def _write_email_to_local_file(recipient_email, subject, html):
    try:
        out_dir = os.getenv('EMAIL_DUMP_DIR', os.path.join(UPLOAD_FOLDER, 'email_dumps'))
        os.makedirs(out_dir, exist_ok=True)
        fname = f"email_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}_{secure_filename(recipient_email)}.html"
        path = os.path.join(out_dir, fname)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(f"To: {recipient_email}\nSubject: {subject}\n\n{html}")
        logger.info(f"Email written to local file: {path}")
        return True
    except Exception:
        logger.exception('Failed to write email to file')
        return False


def send_via_smtp(recipient_email, subject, html, timeout=15):
    from_addr = SMTP_EMAIL or 'no-reply@example.com'
    msg = MIMEText(html, _subtype='html')
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = recipient_email

    try_methods = []
    if SENDGRID_API_KEY:
        try_methods.append(('sendgrid-smtp', 'apikey', SENDGRID_API_KEY))
    if SMTP_EMAIL and SMTP_PASS:
        try_methods.append(('smtp-login', SMTP_EMAIL, SMTP_PASS))
    if not try_methods:
        logger.warning('No SMTP credentials configured. Using local file fallback.')
        return _write_email_to_local_file(recipient_email, subject, html)

    for method, user, pwd in try_methods:
        server = None
        try:
            logger.info(f'Attempting SMTP send via {method} to {recipient_email}')
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=timeout)
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception:
                pass
            if user and pwd:
                server.login(user, pwd)
            server.sendmail(from_addr, [recipient_email], msg.as_string())
            server.quit()
            logger.info(f'Email sent successfully via {method}')
            return True
        except Exception:
            logger.exception(f'SMTP method {method} failed')
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
    logger.error('All SMTP methods failed. Using file fallback.')
    return _write_email_to_local_file(recipient_email, subject, html)


def send_otp_email(recipient_email, code):
    subject = 'Your Likhayag Verification Code'
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #059669, #064e3b); padding: 30px; border-radius: 10px; text-align: center;">
            <h2 style="color: white; margin: 0;">Likhayag Verification</h2>
        </div>
        <div style="padding: 30px; background: #f9fafb; border-radius: 10px; margin-top: 20px;">
            <p style="font-size: 16px; color: #374151;">Your verification code is:</p>
            <div style="background: white; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                <h1 style="color: #059669; font-family: monospace; letter-spacing: 3px; margin: 0;">{code}</h1>
            </div>
            <p style="font-size: 14px; color: #6b7280;">This code will expire in {int(CODE_TTL/60)} minutes.</p>
            <p style="font-size: 14px; color: #6b7280;">If you didn't request this code, please ignore this email.</p>
        </div>
        <div style="text-align: center; margin-top: 20px; color: #9ca3af; font-size: 12px;">
            <p>© 2024 Likhayag Organization. All rights reserved.</p>
        </div>
    </body>
    </html>
    """
    return send_via_smtp(recipient_email, subject, html)

# -----------------------
# 2FA code storage (Supabase)
# -----------------------

def store_code(email, code, user_id=None):
    try:
        email = email.strip().lower()
        sb = get_supabase()
        expires = datetime.now(timezone.utc) + timedelta(seconds=CODE_TTL)
        payload = {
            'user_id': user_id,
            'email': email,
            'code': code.upper(),
            'expires_at': expires.isoformat(),
        }
        success, data, error = safe_execute(sb.table('user_2fa_codes').insert(payload), 'store_code')
        return bool(success)
    except Exception:
        logger.exception('store_code exception')
        return False


def get_stored_code(email):
    try:
        email = email.strip().lower()
        sb = get_supabase()
        query = sb.table('user_2fa_codes').select('*').eq('email', email).order('id', desc=True).limit(1)
        success, data, error = safe_execute(query, 'get_stored_code')
        if not success or not data:
            return None
        row = data[0]
        expires_at = row.get('expires_at')
        expires_dt = None
        if isinstance(expires_at, str):
            try:
                expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            except Exception:
                return None
        elif isinstance(expires_at, datetime):
            expires_dt = expires_at
        if not expires_dt:
            return None
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_dt:
            return None
        return (row.get('code') or '').strip().upper() or None
    except Exception:
        logger.exception('get_stored_code exception')
        return None


def delete_stored_code(email):
    try:
        email = email.strip().lower()
        sb = get_supabase()
        success, data, error = safe_execute(sb.table('user_2fa_codes').delete().eq('email', email), 'delete_stored_code')
        return bool(success)
    except Exception:
        logger.exception('delete_stored_code exception')
        return False

# -----------------------
# Rate limiting for 2FA
# -----------------------

def can_send_code(email):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if not hasattr(app, '_send_hist'):
        app._send_hist = {}
    history = app._send_hist.get(email, [])
    history = [t for t in history if now_ts - t < SEND_LIMIT_WINDOW]
    if len(history) >= SEND_LIMIT_COUNT:
        app._send_hist[email] = history
        return False
    history.append(now_ts)
    app._send_hist[email] = history
    return True

# -----------------------
# Authentication routes
# -----------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('interface'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('login'))
        
        try:
            sb = get_supabase()
            query = sb.table('users').select('*').eq('email', email).limit(1)
            success, data, error = safe_execute(query, 'login_query')
            
            if not success or not data or len(data) == 0:
                flash('Invalid email or password', 'error')
                return redirect(url_for('login'))
            
            user = data[0]
            
            if not check_password_hash(user.get('password_hash', ''), password):
                flash('Invalid email or password', 'error')
                return redirect(url_for('login'))
            
            role = (user.get('role') or 'user').strip().lower()
            session.update({
                'user_id': user['id'],
                'display_name': user.get('display_name') or user.get('first_name') or '',
                'first_name': user.get('first_name') or '',
                'last_name': user.get('last_name') or '',
                'role': role,
                'user_email': user.get('email'),
            })
            session.permanent = True
            
            token = generate_csrf_token()
            redirect_to = url_for('admin_interface') if role in ('admin', 'administrator', 'superuser') else url_for('user_interface')
            
            resp = make_response(redirect(redirect_to))
            resp.set_cookie('csrf_token', token, samesite='Lax')
            
            flash('Login successful!', 'success')
            return resp
            
        except Exception:
            logger.exception('Login error')
            flash('Server error. Please try again.', 'error')
            return redirect(url_for('login'))
    
    return render_template('auth/login.html')


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    if not data:
        data = request.form.to_dict() or {}

    email = (data.get('email') or '').strip().lower()
    pw = data.get('password') or ''

    if not email or not pw:
        return json_response(False, "Email and password required", 400)

    try:
        sb = get_supabase()
        query = sb.table('users').select('*').eq('email', email).limit(1)
        success, user_data, error = safe_execute(query, 'api_login_query')
        
        if not success or not user_data or len(user_data) == 0:
            return json_response(False, "Invalid credentials", 401)
        
        u = user_data[0]
        
        if not check_password_hash(u.get("password_hash", ""), pw):
            return json_response(False, "Invalid credentials", 401)

        role_val = (u.get("role") or "user").strip().lower()

        session.update({
            "user_id": u["id"],
            "display_name": u.get("display_name") or f"{u.get('first_name','')}",
            "first_name": u.get("first_name") or "",
            "last_name": u.get("last_name") or "",
            "role": role_val,
            "user_email": u.get("email"),
        })
        session.permanent = True

        token = generate_csrf_token()
        redirect_url = url_for('admin_interface') if role_val in ('admin', 'administrator', 'superuser') else url_for('user_interface')

        resp = make_response(
            json_response(
                True, "Login successful", 200,
                user={
                    "id": u["id"],
                    "name": u.get("display_name"),
                    "email": u.get("email")
                },
                redirect_url=redirect_url
            )
        )

        resp.set_cookie('csrf_token', token, samesite='Lax')
        return resp
        
    except Exception:
        logger.exception('API login error')
        return json_response(False, "Server error", 500)


@app.route('/signup', methods=['GET'])
def signup():
    return render_template('auth/signup.html')


@app.route('/api/signup', methods=['POST'])
def api_signup():
    """Creates user account in Supabase with 2FA verification"""
    data = request.get_json(silent=True) or request.form.to_dict()
    
    first = (data.get('first_name') or '').strip()
    middle = (data.get('middle_name') or '').strip()
    last = (data.get('last_name') or '').strip()
    suffix = (data.get('suffix') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    confirm_password = data.get('confirmPassword') or ''
    code = (data.get('code') or data.get('two_fa_code') or '').strip().upper()
    role = (data.get('role') or 'user').strip().lower()
    
    if not all([email, password, first, last]):
        return json_response(False, 'Missing required fields (first name, last name, email, password)', 400)
    
    if not is_allowed_email_for_signup(email):
        return json_response(False, 'Email must be Gmail (@gmail.com) or admin@admin.com', 400)
    
    if len(password) < 8:
        return json_response(False, 'Password must be at least 8 characters', 400)
    
    if password != confirm_password:
        return json_response(False, 'Passwords do not match', 400)
    
    import re
    if not re.search(r'\d', password):
        return json_response(False, 'Password must contain at least one number', 400)
    if not re.search(r'[!@#$%^&*()_\-+={[\]}\|\\:;"\'<>,.?/]', password):
        return json_response(False, 'Password must contain at least one special character', 400)
    
    try:
        sb = get_supabase()
        
        # If code provided, verify it first
        if code:
            stored = get_stored_code(email)
            if not stored:
                return json_response(False, "No verification code found or code expired", 400)
            if stored != code:
                return json_response(False, "Invalid verification code", 400)
            
            delete_stored_code(email)
            
            # Check if email exists
            existing_query = sb.table('users').select('id').eq('email', email).limit(1)
            success, existing_data, _ = safe_execute(existing_query, 'check_existing_user')
            
            if success and existing_data and len(existing_data) > 0:
                return json_response(False, 'Email already registered', 409)
            
            # Build display name
            display_name = first
            if middle:
                display_name += f" {middle}"
            display_name += f" {last}"
            if suffix:
                display_name += f", {suffix}"
            
            # Create user verified
            user_payload = {
                'first_name': first,
                'middle_name': middle if middle else None,
                'last_name': last,
                'suffix': suffix if suffix else None,
                'display_name': display_name.strip(),
                'email': email,
                'password_hash': generate_password_hash(password),
                'two_fa_verified': True,
                'role': role,
            }
            
            insert_query = sb.table('users').insert(user_payload)
            success, created_data, error = safe_execute(insert_query, 'create_user')
            
            if not success or not created_data:
                return json_response(False, 'Failed to create account', 500)
            
            created_user = created_data[0]
            
            # Sign user in
            session.update({
                "user_id": created_user["id"],
                "display_name": created_user.get("display_name"),
                "first_name": created_user.get("first_name", ""),
                "last_name": created_user.get("last_name", ""),
                "role": (created_user.get("role") or role).strip().lower(),
                "user_email": created_user.get("email"),
            })
            session.permanent = True
            token = generate_csrf_token()
            
            resp = make_response(json_response(True, "Account created and verified", 201, redirect_url=url_for('user_interface')))
            resp.set_cookie('csrf_token', token, samesite='Lax')
            return resp
        
        # No code - check if 2FA required before creating
        if REQUIRE_2FA_BEFORE_CREATE:
            return json_response(False, "Verification required. Request a 2FA code first.", 400)
        
        # Check if email exists
        existing_query = sb.table('users').select('id').eq('email', email).limit(1)
        success, existing_data, _ = safe_execute(existing_query, 'check_existing_user')
        
        if success and existing_data and len(existing_data) > 0:
            return json_response(False, 'Email already registered', 409)
        
        # Build display name
        display_name = first
        if middle:
            display_name += f" {middle}"
        display_name += f" {last}"
        if suffix:
            display_name += f", {suffix}"
        
        # Create user unverified
        user_payload = {
            'first_name': first,
            'middle_name': middle if middle else None,
            'last_name': last,
            'suffix': suffix if suffix else None,
            'display_name': display_name.strip(),
            'email': email,
            'password_hash': generate_password_hash(password),
            'two_fa_verified': False,
            'role': role,
        }
        
        insert_query = sb.table('users').insert(user_payload)
        success, created_data, error = safe_execute(insert_query, 'create_user')
        
        if not success or not created_data:
            return json_response(False, f'Failed to create account: {error}', 500)
        
        created_user = created_data[0]
        user_id = created_user.get('id')
        
        return json_response(
            True,
            'Account created (unverified). Please verify your email.',
            201,
            user_id=user_id,
            redirect_url=url_for('interface')
        )
        
    except Exception:
        logger.exception('Signup error')
        return json_response(False, 'Server error during signup', 500)


@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('csrf_token')
    flash('Logged out successfully', 'success')
    return resp


@app.route('/api/logout', methods=['GET'])
@login_required
def api_logout():
    session.clear()
    resp = make_response(json_response(True, "Logged out"))
    resp.delete_cookie('csrf_token')
    return resp

# -----------------------
# 2FA endpoints
# -----------------------
@app.route('/api/2fa/send', methods=['POST'])
def api_2fa_send():
    data = request.get_json(silent=True) or request.form.to_dict()
    email = (data.get('email') or '').strip().lower()
    user_id = data.get('user_id')
    
    if not email:
        return json_response(False, "Missing email", 400)
    
    if not is_allowed_email_for_signup(email):
        return json_response(False, "Email must be Gmail or admin@admin.com", 400)
    
    if not can_send_code(email):
        return json_response(False, "Too many requests. Try again later.", 429)
    
    alphabet = string.ascii_uppercase + string.digits
    code = ''.join(random.choices(alphabet, k=16))
    
    stored = store_code(email, code, user_id)
    if not stored:
        return json_response(False, 'Server error storing code', 500)
    
    sent = send_otp_email(email, code)
    if not sent:
        delete_stored_code(email)
        return json_response(False, 'Failed to send email', 500)
    
    logger.info(f'2FA code sent to {email}')
    return json_response(True, 'Verification code sent to your email', 200)


@app.route('/api/2fa/resend', methods=['POST'])
def api_2fa_resend():
    return api_2fa_send()


@app.route('/api/2fa/verify', methods=['POST'])
def api_2fa_verify():
    """Verifies 2FA code and marks user as verified"""
    data = request.get_json(silent=True) or request.form.to_dict()
    code = str(data.get('code') or '').strip().upper()
    email = (data.get('email') or '').strip().lower()
    
    if not code or not email:
        return json_response(False, 'Missing email or code', 400)
    
    stored = get_stored_code(email)
    if not stored:
        return json_response(False, 'Code expired or not found. Please request a new code.', 400)
    
    if stored != code:
        return json_response(False, 'Invalid verification code', 400)
    
    delete_stored_code(email)
    
    try:
        sb = get_supabase()
        query = sb.table('users').select('*').eq('email', email).limit(1)
        success, user_data, error = safe_execute(query, 'get_user_for_verification')
        
        if not success or not user_data or len(user_data) == 0:
            logger.error(f"User not found for email: {email}")
            return json_response(False, 'User account not found', 404)
        
        user = user_data[0]
        
        update_query = sb.table('users').update({'two_fa_verified': True}).eq('id', user['id'])
        success, _, error = safe_execute(update_query, 'update_2fa_verified')
        
        if not success:
            logger.error(f"Failed to update verification status: {error}")
            return json_response(False, 'Failed to verify account', 500)
        
        logger.info(f"User verified successfully: {email}")
        
        role = (user.get('role') or 'user').strip().lower()
        session.update({
            'user_id': user['id'],
            'display_name': user.get('display_name') or user.get('first_name', ''),
            'first_name': user.get('first_name', ''),
            'last_name': user.get('last_name', ''),
            'role': role,
            'user_email': user.get('email'),
        })
        session.permanent = True
        
        token = generate_csrf_token()
        redirect_url = url_for('login')
        resp = make_response(
            json_response(
                True, 
                'Email verified successfully! Please login with your credentials.', 
                200,
                redirect_url=redirect_url
            )
        )
        resp.set_cookie('csrf_token', token, samesite='Lax')
        
        return resp
        
    except Exception:
        logger.exception('2FA verify error')
        return json_response(False, 'Server error during verification', 500)

# -----------------------
# Interface routes
# -----------------------
@app.route('/interface')
@login_required
def interface():
    role = (session.get('role') or '').strip().lower()
    if role in ('admin', 'administrator', 'superuser'):
        return redirect(url_for('admin_interface'))
    return redirect(url_for('user_interface'))


@app.route('/user_interface')
@login_required
@user_required
def user_interface():
    return render_template('user/home.html', 
                         display_name=session.get('display_name'), 
                         first_name=session.get('first_name', ''), 
                         last_name=session.get('last_name', ''))


@app.route('/admin_interface')
@login_required
@admin_required
def admin_interface():
    return render_template('admin/home.html', 
                         display_name=session.get('display_name'), 
                         first_name=session.get('first_name', ''), 
                         last_name=session.get('last_name', ''))


# User-facing page routes
def render_user_template(template_name):
    return render_template(
        template_name,
        display_name=session.get('display_name'),
        first_name=session.get('first_name', ''),
        last_name=session.get('last_name', '')
    )


@app.route('/user/home', endpoint='user_home')
@login_required
@user_required
def user_home():
    return render_user_template('user/home.html')


@app.route('/user/calendar_view', endpoint='user_calendar_view')
@login_required
@user_required
def user_calendar_view():
    return render_user_template('user/calendar.html')


@app.route('/user/planner_view', endpoint='user_planner_view')
@login_required
@user_required
def user_planner_view():
    return render_user_template('user/planner.html')


@app.route('/user/budget_view', endpoint='user_budget_view')
@login_required
@user_required
def user_budget_view():
    return render_user_template('user/budget.html')


@app.route('/user/meetings_page', endpoint='user_meetings_page')
@login_required
@user_required
def user_meetings_page():
    return render_user_template('user/meeting.html')


@app.route('/user/profile_view', endpoint='user_profile_view')
@login_required
@user_required
def user_profile_view():
    return render_user_template('user/profile.html')


# Admin page routes
@app.route('/home')
@login_required
@admin_required
def home():
    return render_template('admin/home.html',
                         display_name=session.get('display_name'),
                         first_name=session.get('first_name', ''),
                         last_name=session.get('last_name', ''))


@app.route('/calendar_view')
@login_required
@admin_required
def calendar_view():
    return render_template('admin/calendar.html',
                         display_name=session.get('display_name'),
                         first_name=session.get('first_name', ''),
                         last_name=session.get('last_name', ''))


@app.route('/planner_view')
@login_required
@admin_required
def planner_view():
    return render_template('admin/planner.html',
                         display_name=session.get('display_name'),
                         first_name=session.get('first_name', ''),
                         last_name=session.get('last_name', ''))


@app.route('/budget_view')
@login_required
@admin_required
def budget_view():
    return render_template('admin/budget.html',
                         display_name=session.get('display_name'),
                         first_name=session.get('first_name', ''),
                         last_name=session.get('last_name', ''))


@app.route('/meetings_page')
@login_required
@admin_required
def meetings_page():
    return render_template('admin/meeting.html',
                         display_name=session.get('display_name'),
                         first_name=session.get('first_name', ''),
                         last_name=session.get('last_name', ''))


@app.route('/profile_view')
@login_required
def profile_view():
    return render_template('admin/profile.html',
                         display_name=session.get('display_name'),
                         first_name=session.get('first_name', ''),
                         last_name=session.get('last_name', ''))

# -----------------------
# Students API
# -----------------------
@app.route('/api/students', methods=['GET'])
@login_required
def api_get_students():
    try:
        sb = get_supabase()
        success, data, error = safe_execute(sb.table('students').select('id,name,email').order('name'), 'get_students')
        if not success:
            return json_response(False, 'Failed to fetch students', 500)
        students = [{'id': r['id'], 'name': r['name'], 'email': r.get('email')} for r in (data or [])]
        return jsonify(students)
    except Exception:
        logger.exception('Get students error')
        return json_response(False, 'Server error', 500)

# -----------------------
# Meetings API
# -----------------------
@app.route('/api/meetings', methods=['GET', 'POST'])
@login_required
def api_meetings():
    sb = get_supabase()
    if request.method == 'GET':
        try:
            success, data, error = safe_execute(sb.table('meetings').select('*').order('datetime', desc=False), 'get_meetings')
            if not success:
                return json_response(False, 'Failed to fetch meetings', 500)
            meetings = [serialize_meeting(r) for r in (data or [])]
            return jsonify(meetings)
        except Exception:
            logger.exception('Get meetings error')
            return json_response(False, 'Server error', 500)
    
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    meeting_type = data.get('type', '').strip()
    purpose = data.get('purpose', '').strip()
    datetime_str = data.get('datetime')
    location = data.get('location', '').strip()
    attendees = data.get('attendees', [])
    meet_link = data.get('meetLink') or data.get('meet_link') or ''
    
    if not title or not datetime_str:
        return json_response(False, 'Title and datetime required', 400)
    
    try:
        try:
            dt = datetime.fromisoformat(datetime_str)
        except Exception:
            try:
                dt = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M')
            except Exception:
                return json_response(False, 'Invalid datetime format', 400)
        
        payload = {
            'title': title,
            'type': meeting_type,
            'purpose': purpose,
            'datetime': dt.isoformat(),
            'location': location,
            'meet_link': meet_link,
            'status': 'Not Started',
            'attendees': json.dumps(attendees),
        }
        success, data, error = safe_execute(sb.table('meetings').insert(payload), 'create_meeting')
        if not success:
            return json_response(False, f'Failed to create meeting: {error}', 500)
        created = data[0] if data else None
        if not created:
            return json_response(False, 'Meeting created but data not returned', 500)
        return json_response(True, 'Meeting created', 201, meeting=serialize_meeting(created))
    except Exception:
        logger.exception('Create meeting error')
        return json_response(False, 'Server error', 500)


@app.route('/api/meetings/<int:meeting_id>', methods=['GET', 'PATCH', 'DELETE'])
@login_required
def api_meeting_item(meeting_id):
    sb = get_supabase()
    if request.method == 'GET':
        meeting = fetch_one('meetings', id=meeting_id)
        if not meeting:
            return json_response(False, 'Not found', 404)
        return jsonify(serialize_meeting(meeting))
    
    if request.method == 'DELETE':
        try:
            success, _, error = safe_execute(sb.table('meetings').delete().eq('id', meeting_id), 'delete_meeting')
            if not success:
                return json_response(False, 'Failed to delete', 500)
            return json_response(True, 'Meeting deleted')
        except Exception:
            logger.exception('Delete meeting error')
            return json_response(False, 'Server error', 500)
    
    # PATCH
    data = request.get_json() or {}
    allowed = {}
    if 'status' in data:
        allowed['status'] = data['status']
    if 'title' in data:
        allowed['title'] = data['title']
    if 'type' in data:
        allowed['type'] = data['type']
    if 'purpose' in data:
        allowed['purpose'] = data['purpose']
    if 'datetime' in data:
        try:
            allowed['datetime'] = datetime.fromisoformat(data['datetime']).isoformat()
        except Exception:
            return json_response(False, 'Invalid datetime', 400)
    if 'location' in data:
        allowed['location'] = data['location']
    if 'meetLink' in data or 'meet_link' in data:
        allowed['meet_link'] = data.get('meetLink') or data.get('meet_link')
    if 'attendees' in data:
        try:
            allowed['attendees'] = json.dumps(data['attendees'])
        except Exception:
            return json_response(False, 'Invalid attendees format', 400)
    
    if not allowed:
        return json_response(False, 'No valid fields to update', 400)
    
    try:
        success, _, error = safe_execute(sb.table('meetings').update(allowed).eq('id', meeting_id), 'update_meeting')
        if not success:
            return json_response(False, f'Failed to update: {error}', 500)
        return json_response(True, 'Meeting updated')
    except Exception:
        logger.exception('Update meeting error')
        return json_response(False, 'Server error', 500)

# -----------------------
# Tasks API
# -----------------------
@app.route('/api/tasks', methods=['GET', 'POST'])
@login_required
def api_tasks():
    sb = get_supabase()
    if request.method == 'GET':
        try:
            search = (request.args.get('search') or '').strip()
            filter_by = (request.args.get('filter') or 'all').strip()
            sort_by = (request.args.get('sort') or 'due').strip()
            
            query = sb.table('tasks').select('*')
            success, data, error = safe_execute(query, 'get_tasks')
            if not success:
                return json_response(False, 'Failed to fetch tasks', 500)
            
            tasks = data or []
            
            if search:
                tasks = [t for t in tasks if (search.lower() in (t.get('title') or '').lower() or search.lower() in (t.get('notes') or '').lower())]
            
            if filter_by == 'pending':
                tasks = [t for t in tasks if not t.get('completed')]
            elif filter_by == 'completed':
                tasks = [t for t in tasks if t.get('completed')]
            elif filter_by == 'high':
                tasks = [t for t in tasks if (t.get('priority') or 'medium') == 'high']
            
            if sort_by == 'due':
                tasks = sorted(tasks, key=lambda x: (x.get('due') is None, x.get('due') or ''))
            elif sort_by == 'priority':
                priority_order = {'high': 0, 'medium': 1, 'low': 2}
                tasks = sorted(tasks, key=lambda r: (priority_order.get(r.get('priority') or 'medium', 1), r.get('due') or ''))
            else:
                tasks = sorted(tasks, key=lambda r: r.get('created_at') or '', reverse=True)
            
            return jsonify([serialize_task(t) for t in tasks])
        except Exception:
            logger.exception('Get tasks error')
            return json_response(False, 'Server error', 500)
    
    # POST create
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    due_in = data.get('dueDate') or data.get('due') or ''
    priority = data.get('priority', 'medium').strip()
    notes = data.get('desc') or data.get('notes') or ''
    progress = int(data.get('progress') or 0)
    task_type = data.get('type') or 'assignment'
    completed = bool(data.get('completed'))
    
    if not title:
        return json_response(False, 'Title required', 400)
    
    due_dt = None
    if due_in:
        try:
            due_dt = datetime.fromisoformat(due_in)
        except Exception:
            try:
                due_dt = datetime.strptime(due_in, '%Y-%m-%d')
            except Exception:
                pass
    
    try:
        payload = {
            'title': title,
            'due': due_dt.isoformat() if due_dt else None,
            'priority': priority,
            'notes': notes,
            'status': 'pending',
            'progress': progress,
            'type': task_type,
            'completed': completed,
        }
        success, data, error = safe_execute(sb.table('tasks').insert(payload), 'create_task')
        if not success:
            return json_response(False, f'Failed to create task: {error}', 500)
        created = data[0] if data else None
        if not created:
            return json_response(False, 'Task created but data not returned', 500)
        return json_response(True, 'Task created', 201, task=serialize_task(created))
    except Exception:
        logger.exception('Create task error')
        return json_response(False, 'Server error', 500)


@app.route('/api/tasks/<task_id>', methods=['GET', 'PATCH', 'DELETE'])
@login_required
def api_task_item(task_id):
    sb = get_supabase()
    logger.debug('api_task_item called with task_id=%r (type=%s)', task_id, type(task_id))
    # Remove UUID check - support both int and UUID IDs
    if request.method == 'GET':
        task = fetch_one('tasks', id=task_id)
        if not task:
            return json_response(False, 'Not found', 404)
        return jsonify(serialize_task(task))

    if request.method == 'DELETE':
        try:
            task = fetch_one('tasks', id=task_id)
            if not task:
                return json_response(False, 'Not found', 404)
            
            undo_seconds = int(os.getenv('PLANNER_UNDO_SECONDS', '30'))
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=undo_seconds)
            
            snapshot = {
                'id': task.get('id'),
                'title': task.get('title'),
                'due': task.get('due'),
                'priority': task.get('priority'),
                'notes': task.get('notes'),
                'progress': int(task.get('progress') or 0),
                'type': task.get('type'),
                'completed': bool(task.get('completed')),
                'created_at': task.get('created_at'),
            }
            
            success1, data1, _ = safe_execute(
                sb.table('pending_deletes').insert({
                    'task_id': task_id, 
                    'snapshot': json.dumps(snapshot), 
                    'expires_at': expires_at.isoformat()
                }), 
                'store_pending_delete'
            )
            success2, _, _ = safe_execute(sb.table('tasks').delete().eq('id', task_id), 'delete_task')
            
            if not success2:
                return json_response(False, 'Failed to delete', 500)
            
            pending_id = data1[0].get('id') if (success1 and data1) else None
            return json_response(True, 'Task deleted', 200, undo_seconds=undo_seconds, pending_id=pending_id)
        except Exception:
            logger.exception('Delete task error')
            return json_response(False, 'Server error', 500)
    
    # PATCH update
    data = request.get_json() or {}
    allowed = {}
    if 'status' in data:
        allowed['status'] = data['status']
    if 'title' in data:
        allowed['title'] = data['title']
    if 'due' in data or 'dueDate' in data:
        due_val = data.get('due') or data.get('dueDate')
        if due_val:
            try:
                allowed['due'] = datetime.fromisoformat(due_val).isoformat()
            except Exception:
                try:
                    allowed['due'] = datetime.strptime(due_val, '%Y-%m-%d').isoformat()
                except Exception:
                    allowed['due'] = None
        else:
            allowed['due'] = None
    if 'priority' in data:
        allowed['priority'] = data['priority']
    if 'notes' in data or 'desc' in data:
        allowed['notes'] = data.get('notes') or data.get('desc')
    if 'progress' in data:
        allowed['progress'] = int(data['progress'] or 0)
    if 'type' in data:
        allowed['type'] = data['type']
    if 'completed' in data:
        allowed['completed'] = bool(data.get('completed'))
    
    if not allowed:
        return json_response(False, 'No valid fields to update', 400)
    
    try:
        success, _, error = safe_execute(sb.table('tasks').update(allowed).eq('id', task_id), 'update_task')
        if not success:
            return json_response(False, f'Failed to update: {error}', 500)
        return json_response(True, 'Task updated')
    except Exception:
        logger.exception('Update task error')
        return json_response(False, 'Server error', 500)

@app.route('/api/tasks/archive', methods=['GET'])
@login_required
def api_tasks_archive_list():
    """Return archived task snapshots (most-recent first)."""
    try:
        sb = get_supabase()
        success, data, error = safe_execute(
            sb.table('tasks_archives').select('*').order('archived_at', desc=True),
            'get_tasks_archives'
        )
        if not success:
            return json_response(False, 'Failed to fetch archives', 500)
        # Normalize snapshot to object if stored as string
        def norm(r):
            snap = r.get('snapshot')
            if isinstance(snap, str):
                try:
                    snap = json.loads(snap)
                except Exception:
                    snap = snap
            return {
                'id': r.get('id'),
                'task_id': r.get('task_id'),
                'snapshot': snap,
                'archived_by': r.get('archived_by'),
                'archived_at': r.get('archived_at')
            }
        return jsonify([norm(r) for r in (data or [])])
    except Exception:
        logger.exception('Get task archives error')
        return json_response(False, 'Server error', 500)


@app.route('/api/tasks/<task_id>/archive', methods=['POST'])
@login_required
def api_tasks_archive(task_id):
    sb = get_supabase()
    logger.debug('api_tasks_archive called with task_id=%r (type=%s)', task_id, type(task_id))

    try:
        # fetch task
        task = fetch_one('tasks', id=task_id)
        if not task:
            return json_response(False, 'Task not found', 404)
        
        # build snapshot (include the original task_id)
        snapshot = {
            'id': task.get('id'),
            'title': task.get('title'),
            'due': task.get('due'),
            'priority': task.get('priority'),
            'notes': task.get('notes'),
            'progress': int(task.get('progress') or 0),
            'type': task.get('type'),
            'completed': bool(task.get('completed')),
            'created_at': task.get('created_at'),
        }

        # Don't include task_id as a separate column - store it in snapshot
        payload = {
            'snapshot': json.dumps(snapshot),
            'archived_by': session.get('user_id'),
            'archived_at': datetime.now(timezone.utc).isoformat()
        }

        success_ins, data_ins, err_ins = safe_execute(
            sb.table('tasks_archives').insert(payload),
            'create_task_archive'
        )
        if not success_ins:
            return json_response(False, f'Failed to archive task: {err_ins}', 500)

        # delete original
        success_del, _, err_del = safe_execute(
            sb.table('tasks').delete().eq('id', task_id),
            'delete_task_after_archive'
        )
        if not success_del:
            # Try to remove archive record on failure to avoid duplicates
            try:
                if data_ins and isinstance(data_ins, list) and len(data_ins) > 0:
                    aid = data_ins[0].get('id')
                    if aid:
                        sb.table('tasks_archives').delete().eq('id', aid).execute()
            except Exception:
                logger.exception('Failed to rollback archive after delete failure')
            return json_response(False, 'Failed to remove task after archiving', 500)

        archive_id = data_ins[0].get('id') if (data_ins and isinstance(data_ins, list) and len(data_ins) > 0) else None
        return json_response(True, 'Task archived', 200, archive_id=archive_id)
    except Exception:
        logger.exception('Archive task error')
        return json_response(False, 'Server error', 500)
@app.route('/api/tasks/archive/<archive_id>/restore', methods=['POST'])
@login_required
def api_tasks_archive_restore(archive_id):
    """Restore an archived task into tasks table and remove archive record."""
    sb = get_supabase()
    try:
        arch = fetch_one('tasks_archives', id=archive_id)
        if not arch:
            return json_response(False, 'Archive not found', 404)

        snap = arch.get('snapshot')
        if isinstance(snap, str):
            try:
                snap = json.loads(snap)
            except Exception:
                snap = {}

        # Remove id if present in snapshot, to let DB create new id
        if isinstance(snap, dict) and 'id' in snap:
            snap.pop('id', None)

        # Ensure fields match tasks table columns - minimal required
        payload = {
            'title': snap.get('title'),
            'due': snap.get('due'),
            'priority': snap.get('priority') or 'medium',
            'notes': snap.get('notes'),
            'progress': int(snap.get('progress') or 0),
            'type': snap.get('type') or 'assignment',
            'completed': bool(snap.get('completed')),
            'created_at': snap.get('created_at') or datetime.now(timezone.utc).isoformat()
        }

        success_ins, data_ins, err_ins = safe_execute(
            sb.table('tasks').insert(payload),
            'restore_task_insert'
        )
        if not success_ins:
            return json_response(False, f'Failed to restore task: {err_ins}', 500)

        # delete archive record
        success_del, _, err_del = safe_execute(
            sb.table('tasks_archives').delete().eq('id', archive_id),
            'delete_task_archive_after_restore'
        )
        if not success_del:
            logger.warning(f"Restored task but failed to delete archive id={archive_id}: {err_del}")

        return json_response(True, 'Task restored', 200, task=data_ins[0] if data_ins else None)
    except Exception:
        logger.exception('Restore archive error')
        return json_response(False, 'Server error', 500)


@app.route('/api/tasks/archive/<archive_id>/permanent', methods=['DELETE'])
@login_required
def api_tasks_archive_delete_permanent(archive_id):
    """Permanently delete an archived snapshot."""
    sb = get_supabase()
    try:
        arch = fetch_one('tasks_archives', id=archive_id)
        if not arch:
            return json_response(False, 'Archive not found', 404)

        success, _, error = safe_execute(
            sb.table('tasks_archives').delete().eq('id', archive_id),
            'delete_task_archive_permanent'
        )
        if not success:
            return json_response(False, 'Failed to delete archive', 500)
        return json_response(True, 'Archive permanently deleted')
    except Exception:
        logger.exception('Permanent delete archive error')
        return json_response(False, 'Server error', 500)


@app.route('/api/tasks/stats', methods=['GET'])
@login_required
def api_tasks_stats():
    """Simple task stats used by planner UI."""
    sb = get_supabase()
    try:
        # pending
        success, pending_rows, err = safe_execute(
            sb.table('tasks').select('id').filter('completed', 'eq', False),
            'count_pending'
        )
        pending = len(pending_rows or []) if success else 0

        success, completed_rows, err = safe_execute(
            sb.table('tasks').select('id').filter('completed', 'eq', True),
            'count_completed'
        )
        completed = len(completed_rows or []) if success else 0

        success, high_rows, err = safe_execute(
            sb.table('tasks').select('id').eq('priority', 'high'),
            'count_high'
        )
        high = len(high_rows or []) if success else 0

        # due this week
        # simplest approach: fetch all with due not null and compute client-side
        success, all_rows, err = safe_execute(
            sb.table('tasks').select('id,due,progress,completed,priority,created_at'),
            'get_all_tasks_for_stats'
        )
        dueWeek = 0
        overdue = 0
        if success and all_rows:
            today = datetime.now(timezone.utc).date()
            in7 = today + timedelta(days=7)
            for r in (all_rows or []):
                due = r.get('due')
                if due:
                    try:
                        dt = datetime.fromisoformat(due.replace('Z', '+00:00')).date() if isinstance(due, str) else (due.date() if isinstance(due, datetime) else None)
                    except Exception:
                        try:
                            dt = datetime.strptime(str(due)[:10], '%Y-%m-%d').date()
                        except Exception:
                            dt = None
                    if dt:
                        if dt < today:
                            overdue += 1
                        if today <= dt <= in7:
                            dueWeek += 1

        return json_response(True, 'Stats fetched', 200, pending=pending, completed=completed, high=high, dueWeek=dueWeek, overdue=overdue)
    except Exception:
        logger.exception('Tasks stats error')
        return json_response(False, 'Server error', 500)

# -----------------------
# Budget API
# -----------------------
# ==================== CATEGORIES ====================
@app.route('/api/budget/categories', methods=['GET', 'POST'])
@login_required
def api_budget_categories():
    sb = get_supabase()
    
    if request.method == 'GET':
        try:
            success, data, error = safe_execute(
                sb.table('budget_categories')
                  .select('id,name,budget,created_at')
                  .order('name'), 
                'get_categories'
            )
            if not success:
                return json_response(False, 'Failed to fetch categories', 500)
            
            categories = [{
                'id': r['id'], 
                'name': r['name'], 
                'budget': float(r.get('budget') or 0), 
                'created_at': r.get('created_at')
            } for r in (data or [])]
            
            return jsonify(categories)
        except Exception as e:
            logger.exception('Get categories error')
            return json_response(False, 'Server error', 500)
    
    # POST - Admin only
    role = (session.get('role') or '').lower()
    if role not in ('admin', 'administrator', 'superuser'):
        return json_response(False, 'Admin access required', 403)
    
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    budget = data.get('budget') or 0
    
    if not name:
        return json_response(False, 'Category name required', 400)
    
    try:
        success, _, error = safe_execute(
            sb.table('budget_categories').insert({'name': name, 'budget': budget}), 
            'create_category'
        )
        if not success:
            return json_response(False, f'Failed to create: {error}', 500)
        return json_response(True, 'Category created', 201)
    except Exception as e:
        logger.exception('Create category error')
        return json_response(False, 'Server error', 500)


@app.route('/api/budget/categories/<int:cat_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
@login_required
def api_budget_category_item(cat_id):
    sb = get_supabase()
    
    if request.method == 'GET':
        category = fetch_one('budget_categories', id=cat_id)
        if not category:
            return json_response(False, "Not found", 404)
        return jsonify({
            "id": category['id'],
            "name": category['name'],
            "budget": float(category.get('budget') or 0),
            "created_at": category.get('created_at')
        })
    
    # Admin only for modifications
    role = (session.get('role') or '').lower()
    if role not in ('admin', 'administrator', 'superuser'):
        return json_response(False, 'Admin access required', 403)
    
    if request.method == 'DELETE':
        try:
            # Get category data before deletion
            category = fetch_one('budget_categories', id=cat_id)
            if not category:
                return json_response(False, 'Not found', 404)
            
            # Archive the category
            archive_data = {
                'archive_type': 'category',
                'original_id': cat_id,
                'data': category,
                'archived_by': session.get('user_id'),
                'reason': request.args.get('reason', 'User deleted')
            }
            safe_execute(
                sb.table('budget_archives').insert(archive_data),
                'archive_category'
            )
            
            # Delete the category
            success, _, error = safe_execute(
                sb.table('budget_categories').delete().eq('id', cat_id), 
                'delete_category'
            )
            if not success:
                return json_response(False, 'Failed to delete', 500)
            
            return json_response(True, 'Category archived')
        except Exception as e:
            logger.exception('Delete category failed')
            return json_response(False, 'Server error', 500)
    
    # PUT or PATCH - Update
    data = request.get_json(silent=True) or request.form.to_dict()
    allowed = {}
    
    if 'name' in data:
        allowed['name'] = data['name']
    if 'budget' in data:
        try:
            allowed['budget'] = float(data['budget'])
        except Exception:
            return json_response(False, "Invalid budget amount", 400)
    
    if not allowed:
        return json_response(False, "No fields to update", 400)
    
    try:
        success, _, error = safe_execute(
            sb.table('budget_categories').update(allowed).eq('id', cat_id), 
            'update_category'
        )
        if not success:
            return json_response(False, 'Failed to update', 500)
        return json_response(True, 'Category updated')
    except Exception as e:
        logger.exception('Update category failed')
        return json_response(False, 'Server error', 500)


# ==================== TRANSACTIONS ====================
@app.route('/api/budget/transactions', methods=['GET', 'POST'])
@login_required
def api_budget_transactions():
    sb = get_supabase()
    
    if request.method == 'GET':
        try:
            query = sb.table('budget_transactions').select('*')
            start = request.args.get('start')
            end = request.args.get('end')
            
            if start:
                query = query.gte('date', start)
            if end:
                query = query.lte('date', end)
            
            success, data, error = safe_execute(
                query.order('date', desc=True), 
                'get_transactions'
            )
            
            if not success:
                return json_response(False, 'Failed to fetch transactions', 500)
            
            transactions = []
            for r in (data or []):
                receipt = r.get('receipt')
                receipt_url = None
                if receipt:
                    receipt_url = get_receipt_url(receipt)
                
                transactions.append({
                    'id': r['id'],
                    'type': r.get('type'),
                    'category': r.get('category'),
                    'description': r.get('description'),
                    'amount': float(r.get('amount') or 0),
                    'date': r.get('date'),
                    'created_at': r.get('created_at'),
                    'receipt': receipt,
                    'receipt_url': receipt_url,
                    'added_by': r.get('added_by')  # Track who added it
                })
            
            return jsonify(transactions)
        except Exception as e:
            logger.exception('Get transactions error')
            return json_response(False, 'Server error', 500)
    
    # POST - Create transaction (both admin and users can add)
    form = {}
    files = {}
    
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        form = request.form.to_dict()
        files = request.files
    else:
        form = request.get_json(silent=True) or {}
    
    transaction_type = form.get('type') or 'expense'
    category = form.get('category') or ''
    description = form.get('description') or form.get('desc') or ''
    amount = form.get('amount') or 0
    date_val = form.get('date') or None
    
    # Validate category exists
    if category:
        cat_exists = fetch_one('budget_categories', name=category)
        if not cat_exists:
            return json_response(False, f'Category "{category}" does not exist. Please add it first.', 400)
    else:
        return json_response(False, 'Category is required', 400)
    
    date_parsed = None
    if date_val:
        try:
            date_parsed = datetime.fromisoformat(date_val).date().isoformat()
        except Exception:
            try:
                date_parsed = datetime.strptime(date_val, '%Y-%m-%d').date().isoformat()
            except Exception:
                pass
    
    receipt_filename = None
    uploaded = files.get('receipt') or files.get('file')
    
    if uploaded:
        try:
            receipt_filename = save_uploaded_file(uploaded)
        except ValueError as ve:
            return json_response(False, f'Invalid receipt: {str(ve)}', 400)
        except Exception as e:
            logger.exception('Failed to save receipt')
            return json_response(False, 'Failed to save receipt', 500)
    else:
        # Base64 fallback
        b64data = (form.get('receipt_data_base64') or '').strip()
        if not b64data:
            return json_response(False, 'Receipt is required for all transactions', 400)
        
        try:
            if b64data.startswith('data:'):
                header, data_part = b64data.split(',', 1)
                mimetype = None
                try:
                    mime_part = header.split(';')[0]
                    if mime_part.startswith('data:'):
                        mimetype = mime_part.split(':', 1)[1]
                except Exception:
                    mimetype = None
                b64_payload = data_part
            else:
                b64_payload = b64data
                mimetype = form.get('receipt_mime')
            
            binary = base64.b64decode(b64_payload)
            
            if len(binary) > MAX_CONTENT_LENGTH:
                return json_response(False, f'File too large (max {MAX_CONTENT_LENGTH} bytes)', 400)
            
            supplied_name = form.get('receipt_filename') or form.get('receipt_name') or ''
            if supplied_name:
                safe_name = secure_filename(supplied_name)
            else:
                ext = 'bin'
                if mimetype:
                    guessed = mimetypes.guess_extension(mimetype)
                    if guessed:
                        ext = guessed.lstrip('.')
                safe_name = f'receipt.{ext}'
            
            if not allowed_file(safe_name):
                return json_response(False, 'File type not allowed', 400)
            
            unique = f"{uuid.uuid4().hex}_{safe_name}"
            sb.storage.from_(SUPABASE_RECEIPT_BUCKET).upload(unique, binary)
            receipt_filename = unique
            
        except Exception as e:
            logger.exception('Failed to process base64 receipt')
            return json_response(False, 'Invalid receipt data', 400)
    
    try:
        payload = {
            'type': transaction_type,
            'category': category,
            'description': description,
            'amount': amount,
            'date': date_parsed,
            'receipt': receipt_filename,
            'added_by': session.get('user_id')
        }
        
        success, _, error = safe_execute(
            sb.table('budget_transactions').insert(payload), 
            'create_transaction'
        )
        
        if not success:
            if receipt_filename:
                try:
                    sb.storage.from_(SUPABASE_RECEIPT_BUCKET).remove([receipt_filename])
                except Exception:
                    pass
            return json_response(False, f'Failed to create: {error}', 500)
        
        return json_response(True, 'Transaction recorded', 201)
    except Exception as e:
        logger.exception('Create transaction error')
        if receipt_filename:
            try:
                sb.storage.from_(SUPABASE_RECEIPT_BUCKET).remove([receipt_filename])
            except Exception:
                pass
        return json_response(False, 'Server error', 500)


@app.route('/api/budget/transactions/<int:tx_id>', methods=['GET', 'PATCH', 'DELETE'])
@login_required
def api_budget_transaction_item(tx_id):
    sb = get_supabase()
    
    if request.method == 'GET':
        transaction = fetch_one('budget_transactions', id=tx_id)
        if not transaction:
            return json_response(False, "Not found", 404)
        
        receipt = transaction.get('receipt')
        receipt_url = get_receipt_url(receipt) if receipt else None
        
        return jsonify({
            'id': transaction['id'],
            'type': transaction.get('type'),
            'category': transaction.get('category'),
            'description': transaction.get('description'),
            'amount': float(transaction.get('amount') or 0),
            'date': transaction.get('date'),
            'created_at': transaction.get('created_at'),
            'receipt': receipt,
            'receipt_url': receipt_url,
            'added_by': transaction.get('added_by')
        })
    
    # Admin only for delete
    if request.method == 'DELETE':
        role = (session.get('role') or '').lower()
        if role not in ('admin', 'administrator', 'superuser'):
            return json_response(False, 'Admin access required', 403)
        
        try:
            transaction = fetch_one('budget_transactions', id=tx_id)
            if not transaction:
                return json_response(False, "Not found", 404)
            
            receipt = transaction.get('receipt')
            
            # Archive transaction
            archive_data = {
                'archive_type': 'transaction',
                'original_id': tx_id,
                'data': transaction,
                'archived_by': session.get('user_id'),
                'reason': request.args.get('reason', 'User deleted')
            }
            safe_execute(
                sb.table('budget_archives').insert(archive_data),
                'archive_transaction'
            )
            
            # Delete from main table
            success, _, error = safe_execute(
                sb.table('budget_transactions').delete().eq('id', tx_id), 
                'delete_transaction'
            )
            
            if not success:
                return json_response(False, 'Failed to delete', 500)
            
            # Remove receipt file
            if receipt:
                try:
                    sb.storage.from_(SUPABASE_RECEIPT_BUCKET).remove([receipt])
                except Exception as e:
                    logger.warning(f"Failed to remove receipt file {receipt}: {e}")
            
            return json_response(True, 'Transaction archived')
        except Exception as e:
            logger.exception('Delete transaction failed')
            return json_response(False, 'Server error', 500)
    
    # PATCH - Update (admin only)
    role = (session.get('role') or '').lower()
    if role not in ('admin', 'administrator', 'superuser'):
        return json_response(False, 'Admin access required', 403)
    
    data = request.get_json() or {}
    allowed = {}
    
    for k in ('type', 'category', 'description', 'amount'):
        if k in data:
            allowed[k] = data[k]
    
    if 'date' in data and data['date']:
        try:
            allowed['date'] = datetime.fromisoformat(data['date']).date().isoformat()
        except Exception:
            try:
                allowed['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date().isoformat()
            except Exception:
                allowed['date'] = None
    
    if not allowed:
        return json_response(False, "No fields to update", 400)
    
    try:
        success, _, error = safe_execute(
            sb.table('budget_transactions').update(allowed).eq('id', tx_id), 
            'update_transaction'
        )
        if not success:
            return json_response(False, 'Failed to update', 500)
        return json_response(True, 'Transaction updated')
    except Exception as e:
        logger.exception('Update transaction failed')
        return json_response(False, 'Server error', 500)


# ==================== TICKETS ====================
@app.route('/api/budget/tickets', methods=['GET', 'POST'])
@login_required
def api_budget_tickets():
    sb = get_supabase()
    
    if request.method == 'GET':
        try:
            success, data, error = safe_execute(
                sb.table('budget_tickets').select('*').order('created_at', desc=True),
                'get_tickets'
            )
            
            if not success:
                return json_response(False, 'Failed to fetch tickets', 500)
            
            tickets = []
            for r in (data or []):
                ticket_id = r['id']
                
                # Get sales for this ticket
                success_sales, sales_data, _ = safe_execute(
                    sb.table('budget_ticket_sales')
                      .select('*')
                      .eq('ticket_id', ticket_id)
                      .order('created_at', desc=True),
                    'get_ticket_sales'
                )
                
                tickets.append({
                    'id': r['id'],
                    'event': r.get('event'),
                    'price': float(r.get('price') or 0),
                    'total_tickets': r.get('total_tickets'),
                    'tickets_sold': r.get('tickets_sold', 0),
                    'tickets_remaining': r.get('total_tickets', 0) - r.get('tickets_sold', 0),
                    'created_at': r.get('created_at'),
                    'sales': [{
                        'id': s.get('id'),
                        'ticket_id': s.get('ticket_id'),
                        'buyer': s.get('buyer'),
                        'qty': s.get('qty'),
                        'date': s.get('date'),
                        'created_at': s.get('created_at'),
                        'added_by': s.get('added_by')
                    } for s in (sales_data or [])]
                })
            
            return jsonify(tickets)
        except Exception as e:
            logger.exception('Get tickets error')
            return json_response(False, 'Server error', 500)
    
    # POST - Admin only can create events
    role = (session.get('role') or '').lower()
    if role not in ('admin', 'administrator', 'superuser'):
        return json_response(False, 'Admin access required', 403)
    
    data = request.get_json() or {}
    event = (data.get('event') or '').strip()
    price = data.get('price') or 0
    total = data.get('total_tickets') or data.get('total') or 0
    
    if not event:
        return json_response(False, 'Event name required', 400)
    
    try:
        payload = {
            'event': event,
            'price': price,
            'total_tickets': total,
            'tickets_sold': 0
        }
        
        success, _, error = safe_execute(
            sb.table('budget_tickets').insert(payload),
            'create_ticket'
        )
        
        if not success:
            return json_response(False, f'Failed to create: {error}', 500)
        
        return json_response(True, 'Event created', 201)
    except Exception as e:
        logger.exception('Create ticket error')
        return json_response(False, 'Server error', 500)


@app.route('/api/budget/tickets/<int:ticket_id>', methods=['GET', 'PATCH', 'DELETE'])
@login_required
def api_budget_ticket_item(ticket_id):
    sb = get_supabase()
    
    if request.method == 'GET':
        ticket = fetch_one('budget_tickets', id=ticket_id)
        if not ticket:
            return json_response(False, "Not found", 404)
        
        return jsonify({
            'id': ticket['id'],
            'event': ticket.get('event'),
            'price': float(ticket.get('price') or 0),
            'total_tickets': ticket.get('total_tickets'),
            'tickets_sold': ticket.get('tickets_sold', 0),
            'tickets_remaining': ticket.get('total_tickets', 0) - ticket.get('tickets_sold', 0),
            'created_at': ticket.get('created_at')
        })
    
    # Admin only for modifications
    role = (session.get('role') or '').lower()
    if role not in ('admin', 'administrator', 'superuser'):
        return json_response(False, 'Admin access required', 403)
    
    if request.method == 'DELETE':
        try:
            ticket = fetch_one('budget_tickets', id=ticket_id)
            if not ticket:
                return json_response(False, "Not found", 404)
            
            # Archive ticket
            archive_data = {
                'archive_type': 'ticket',
                'original_id': ticket_id,
                'data': ticket,
                'archived_by': session.get('user_id'),
                'reason': request.args.get('reason', 'User deleted')
            }
            safe_execute(
                sb.table('budget_archives').insert(archive_data),
                'archive_ticket'
            )
            
            # Delete ticket and all its sales
            success, _, error = safe_execute(
                sb.table('budget_tickets').delete().eq('id', ticket_id),
                'delete_ticket'
            )
            
            if not success:
                return json_response(False, 'Failed to delete', 500)
            
            return json_response(True, 'Event archived')
        except Exception as e:
            logger.exception('Delete ticket failed')
            return json_response(False, 'Server error', 500)
    
    # PATCH - Update
    data = request.get_json() or {}
    allowed = {}
    
    if 'event' in data:
        allowed['event'] = data['event']
    if 'price' in data:
        allowed['price'] = data['price']
    if 'total_tickets' in data:
        allowed['total_tickets'] = data['total_tickets']
    
    if not allowed:
        return json_response(False, "No fields to update", 400)
    
    try:
        success, _, error = safe_execute(
            sb.table('budget_tickets').update(allowed).eq('id', ticket_id),
            'update_ticket'
        )
        
        if not success:
            return json_response(False, 'Failed to update', 500)
        
        return json_response(True, 'Event updated')
    except Exception as e:
        logger.exception('Update ticket failed')
        return json_response(False, 'Server error', 500)


@app.route('/api/budget/tickets/<int:ticket_id>/sales', methods=['GET', 'POST'])
@login_required
def api_budget_ticket_sales(ticket_id):
    sb = get_supabase()
    
    if request.method == 'GET':
        try:
            success, data, error = safe_execute(
                sb.table('budget_ticket_sales')
                  .select('*')
                  .eq('ticket_id', ticket_id)
                  .order('created_at', desc=True),
                'get_sales'
            )
            
            if not success:
                return json_response(False, 'Failed to fetch sales', 500)
            
            sales = [{
                'id': r['id'],
                'ticket_id': r['ticket_id'],
                'buyer': r['buyer'],
                'qty': r['qty'],
                'date': r.get('date'),
                'created_at': r.get('created_at'),
                'added_by': r.get('added_by')
            } for r in (data or [])]
            
            return jsonify(sales)
        except Exception as e:
            logger.exception('Get sales error')
            return json_response(False, 'Server error', 500)
    
    # POST - Record sale (both admin and users can add)
    data = request.get_json() or {}
    buyer = (data.get('buyer') or '').strip()
    qty = int(data.get('qty') or 1)
    date_val = data.get('date') or None
    
    date_parsed = None
    if date_val:
        try:
            date_parsed = datetime.fromisoformat(date_val).date().isoformat()
        except Exception:
            try:
                date_parsed = datetime.strptime(date_val, '%Y-%m-%d').date().isoformat()
            except Exception:
                pass
    
    try:
        # Get ticket details
        ticket = fetch_one('budget_tickets', id=ticket_id)
        if not ticket:
            return json_response(False, 'Event not found', 404)
        
        # Check if enough tickets available
        tickets_sold = ticket.get('tickets_sold', 0)
        total_tickets = ticket.get('total_tickets', 0)
        remaining = total_tickets - tickets_sold
        
        if qty > remaining:
            return json_response(False, f'Only {remaining} tickets remaining', 400)
        
        # Record the sale
        sale_payload = {
            'ticket_id': ticket_id,
            'buyer': buyer,
            'qty': qty,
            'date': date_parsed,
            'added_by': session.get('user_id')
        }
        
        success, _, error = safe_execute(
            sb.table('budget_ticket_sales').insert(sale_payload),
            'create_sale'
        )
        
        if not success:
            return json_response(False, f'Failed to record sale: {error}', 500)
        
        # Update tickets_sold count
        new_sold = tickets_sold + qty
        success, _, error = safe_execute(
            sb.table('budget_tickets')
              .update({'tickets_sold': new_sold})
              .eq('id', ticket_id),
            'update_tickets_sold'
        )
        
        if not success:
            logger.error(f'Failed to update tickets_sold: {error}')
        
        return json_response(True, 'Sale recorded successfully', 201)
    except Exception as e:
        logger.exception('Record sale error')
        return json_response(False, 'Server error', 500)


# ==================== ARCHIVES ====================
@app.route('/api/budget/archives', methods=['GET'])
@login_required
@admin_required
def api_budget_archives():
    """Get all archived items"""
    sb = get_supabase()
    
    try:
        archive_type = request.args.get('type')  # 'category', 'transaction', 'ticket'
        
        query = sb.table('budget_archives').select('*').order('archived_at', desc=True)
        
        if archive_type:
            query = query.eq('archive_type', archive_type)
        
        success, data, error = safe_execute(query, 'get_archives')
        
        if not success:
            return json_response(False, 'Failed to fetch archives', 500)
        
        return jsonify(data or [])
    except Exception as e:
        logger.exception('Get archives error')
        return json_response(False, 'Server error', 500)


@app.route('/api/budget/archives/<int:archive_id>/restore', methods=['POST'])
@login_required
@admin_required
def api_restore_archive(archive_id):
    """Restore an archived item"""
    sb = get_supabase()
    
    try:
        # Get archive record
        archive = fetch_one('budget_archives', id=archive_id)
        if not archive:
            return json_response(False, 'Archive not found', 404)
        
        archive_type = archive.get('archive_type')
        data = archive.get('data')
        
        if not data:
            return json_response(False, 'No data to restore', 400)
        
        # Remove id from data to allow new insert
        if 'id' in data:
            del data['id']
        
        # Restore to appropriate table
        table_map = {
            'category': 'budget_categories',
            'transaction': 'budget_transactions',
            'ticket': 'budget_tickets'
        }
        
        table = table_map.get(archive_type)
        if not table:
            return json_response(False, 'Unknown archive type', 400)
        
        success, _, error = safe_execute(
            sb.table(table).insert(data),
            f'restore_{archive_type}'
        )
        
        if not success:
            return json_response(False, f'Failed to restore: {error}', 500)
        
        # Delete from archives
        safe_execute(
            sb.table('budget_archives').delete().eq('id', archive_id),
            'delete_archive'
        )
        
        return json_response(True, f'{archive_type.title()} restored successfully')
    except Exception as e:
        logger.exception('Restore archive error')
        return json_response(False, 'Server error', 500)

@app.route('/api/budget/funds', methods=['GET', 'POST'])
@login_required
def api_budget_funds():
    """Get or create budget funds."""
    sb = get_supabase()
    
    if request.method == 'GET':
        try:
            success, data, error = safe_execute(
                sb.table('budget_funds').select('id,source,amount,date,receipt,created_at').order('created_at', desc=True),
                'get_funds'
            )
            
            if not success:
                return json_response(False, 'Failed to fetch funds', 500)
            
            funds = [{
                'id': r['id'],
                'source': r.get('source'),
                'amount': float(r.get('amount') or 0),
                'date': r.get('date'),
                'receipt': r.get('receipt'),
                'receipt_url': get_receipt_url(r.get('receipt')) if r.get('receipt') else None,
                'created_at': r.get('created_at')
            } for r in (data or [])]
            
            return jsonify(funds)
        except Exception as e:
            logger.exception(f'Get funds error: {e}')
            return json_response(False, 'Server error', 500)
    
    # POST - Create fund
    data = request.get_json() or {}
    source = (data.get('source') or '').strip()
    amount = data.get('amount') or 0
    date_val = data.get('date') or None
    
    date_parsed = None
    if date_val:
        try:
            date_parsed = datetime.fromisoformat(date_val).date()
        except Exception:
            try:
                date_parsed = datetime.strptime(date_val, '%Y-%m-%d').date()
            except Exception:
                pass
    
    try:
        success, _, error = safe_execute(
            sb.table('budget_funds').insert({
                'source': source,
                'amount': amount,
                'date': date_parsed
            }),
            'create_fund'
        )
        
        if not success:
            return json_response(False, f'Failed to create: {error}', 500)
        
        return json_response(True, 'Fund recorded', 201)
    except Exception as e:
        logger.exception(f'Create fund error: {e}')
        return json_response(False, 'Server error', 500)


# Aggregator endpoint for budget data
@app.route('/api/budget', methods=['GET'])
@login_required
def api_budget_root():
    """Return complete budget data: categories, funds, transactions, tickets"""
    try:
        sb = get_supabase()
        
        # Categories
        success, cats_data, _ = safe_execute(
            sb.table('budget_categories').select('id,name,budget,created_at').order('name'), 
            'get_categories'
        )
        categories = [{
            'id': r['id'], 
            'name': r['name'], 
            'budget': float(r.get('budget') or 0), 
            'created_at': r.get('created_at')
        } for r in (cats_data or [])]
        
        # Funds
        success, funds_data, _ = safe_execute(
            sb.table('budget_funds').select('id,source,amount,date,receipt,created_at').order('created_at', desc=True), 
            'get_funds'
        )
        funds = [{
            'id': r['id'], 
            'source': r.get('source'), 
            'amount': float(r.get('amount') or 0), 
            'date': r.get('date'),
            'receipt': r.get('receipt'),
            'receipt_url': get_receipt_url(r.get('receipt')) if r.get('receipt') else None,
            'created_at': r.get('created_at')
        } for r in (funds_data or [])]
        
        # Transactions
        success, txs_data, _ = safe_execute(
            sb.table('budget_transactions').select('*').order('date', desc=True), 
            'get_transactions'
        )
        transactions = []
        for r in (txs_data or []):
            receipt = r.get('receipt')
            transactions.append({
                'id': r['id'],
                'type': r.get('type'),
                'category': r.get('category'),
                'description': r.get('description'),
                'amount': float(r.get('amount') or 0),
                'date': r.get('date'),
                'created_at': r.get('created_at'),
                'receipt': receipt,
                'receipt_url': get_receipt_url(receipt) if receipt else None
            })
        
        # Tickets (if you have them)
        tickets = []
        try:
            success, tickets_data, _ = safe_execute(
                sb.table('budget_tickets').select('*').order('created_at', desc=True), 
                'get_tickets'
            )
            for r in (tickets_data or []):
                ticket_id = r['id']
                # Get sales for this ticket
                success_sales, sales_data, _ = safe_execute(
                    sb.table('budget_ticket_sales').select('*').eq('ticket_id', ticket_id).order('created_at', desc=True),
                    'get_ticket_sales'
                )
                tickets.append({
                    'id': r['id'],
                    'event': r.get('event'),
                    'price': float(r.get('price') or 0),
                    'total_tickets': r.get('total_tickets'),
                    'created_at': r.get('created_at'),
                    'sales': [{
                        'id': s.get('id'),
                        'ticket_id': s.get('ticket_id'),
                        'buyer': s.get('buyer'),
                        'qty': s.get('qty'),
                        'date': s.get('date'),
                        'created_at': s.get('created_at')
                    } for s in (sales_data or [])]
                })
        except Exception:
            logger.warning('Tickets table might not exist')
        
        return jsonify({
            'categories': categories,
            'funds': funds,
            'transactions': transactions,
            'tickets': tickets
        }), 200
    except Exception:
        logger.exception('Budget aggregator error')
        return json_response(False, 'Server error', 500)


# Serve receipt files
@app.route('/uploads/receipts/<path:filename>')
@login_required
def serve_receipt(filename):
    """Redirect to Supabase signed URL for receipt"""
    try:
        safe_name = secure_filename(filename)
        if not safe_name:
            abort(404)
        
        url = get_receipt_url(safe_name, expires_seconds=3600)
        if url and url.startswith('http'):
            return redirect(url)
        
        abort(404)
    except Exception:
        logger.exception('serve_receipt error')
        abort(404)

# -----------------------
# Profile API
# -----------------------
@app.route('/api/profile', methods=['GET'])
@login_required
def api_get_profile():
    """Get current user's profile data"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return json_response(False, 'Not authenticated', 401)
        
        sb = get_supabase()
        user = fetch_one('users', id=user_id)
        
        if not user:
            return json_response(False, 'User not found', 404)
        
        # Return profile data
        profile_data = {
            'profile': {
                'firstName': user.get('first_name') or '',
                'lastName': user.get('last_name') or '',
                'middleName': user.get('middle_name') or '',
                'suffix': user.get('suffix') or '',
                'email': user.get('email') or '',
                'status': user.get('status') or 'Active Student',
                'profilePicture': user.get('profile_picture')  # Include profile picture
            },
            'academic': {
                'school': user.get('school') or '',
                'strand': user.get('strand') or '',
                'gradeLevel': user.get('grade_level') or '',
                'schoolYear': user.get('school_year') or '',
                'lrn': user.get('lrn') or '',
                'adviserSection': user.get('adviser_section') or ''
            },
            'personal': {
                'phone': user.get('phone') or '',
                'dob': user.get('date_of_birth') or '',
                'address': user.get('address') or '',
                'emergency': user.get('emergency_contact') or ''
            },
            'settings': {
                'emailNotifications': bool(user.get('email_notifications', True)),
                'twoFactor': bool(user.get('two_factor_enabled', False))
            }
        }
        
        return jsonify(profile_data), 200
        
    except Exception:
        logger.exception('Get profile error')
        return json_response(False, 'Server error', 500)


@app.route('/api/profile', methods=['PATCH', 'PUT'])
@login_required
def api_update_profile():
    """Update current user's profile data"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return json_response(False, 'Not authenticated', 401)
        
        data = request.get_json() or {}
        section = data.get('section')  # 'profile', 'academic', 'personal', 'settings'
        fields = data.get('fields', {})
        
        if not section or not fields:
            return json_response(False, 'Section and fields required', 400)
        
        sb = get_supabase()
        update_data = {}
        
        # Map frontend fields to database columns
        if section == 'profile':
            if 'firstName' in fields:
                update_data['first_name'] = fields['firstName']
            if 'lastName' in fields:
                update_data['last_name'] = fields['lastName']
            if 'middleName' in fields:
                update_data['middle_name'] = fields['middleName']
            if 'suffix' in fields:
                update_data['suffix'] = fields['suffix']
            if 'status' in fields:
                update_data['status'] = fields['status']
            
            # Update display_name
            if 'firstName' in fields or 'lastName' in fields or 'middleName' in fields or 'suffix' in fields:
                user = fetch_one('users', id=user_id)
                first = fields.get('firstName', user.get('first_name', ''))
                middle = fields.get('middleName', user.get('middle_name', ''))
                last = fields.get('lastName', user.get('last_name', ''))
                suffix = fields.get('suffix', user.get('suffix', ''))
                
                display_name = first
                if middle:
                    display_name += f" {middle}"
                display_name += f" {last}"
                if suffix:
                    display_name += f", {suffix}"
                update_data['display_name'] = display_name.strip()
        
        elif section == 'academic':
            if 'school' in fields:
                update_data['school'] = fields['school']
            if 'strand' in fields:
                update_data['strand'] = fields['strand']
            if 'gradeLevel' in fields:
                update_data['grade_level'] = fields['gradeLevel']
            if 'schoolYear' in fields:
                update_data['school_year'] = fields['schoolYear']
            if 'lrn' in fields:
                update_data['lrn'] = fields['lrn']
            if 'adviserSection' in fields:
                update_data['adviser_section'] = fields['adviserSection']
        
        elif section == 'personal':
            if 'phone' in fields:
                update_data['phone'] = fields['phone']
            if 'dob' in fields:
                update_data['date_of_birth'] = fields['dob']
            if 'address' in fields:
                update_data['address'] = fields['address']
            if 'emergency' in fields:
                update_data['emergency_contact'] = fields['emergency']
        
        elif section == 'settings':
            if 'emailNotifications' in fields:
                update_data['email_notifications'] = bool(fields['emailNotifications'])
            if 'twoFactor' in fields:
                update_data['two_factor_enabled'] = bool(fields['twoFactor'])
        
        if not update_data:
            return json_response(False, 'No valid fields to update', 400)
        
        # Add updated timestamp
        update_data['profile_updated_at'] = datetime.now(timezone.utc).isoformat()
        
        # Update in database
        success, _, error = safe_execute(
            sb.table('users').update(update_data).eq('id', user_id),
            'update_profile'
        )
        
        if not success:
            return json_response(False, f'Failed to update profile: {error}', 500)
        
        # Update session data if name changed
        if 'display_name' in update_data:
            session['display_name'] = update_data['display_name']
        if 'first_name' in update_data:
            session['first_name'] = update_data['first_name']
        if 'last_name' in update_data:
            session['last_name'] = update_data['last_name']
        
        return json_response(True, 'Profile updated successfully', 200)
        
    except Exception:
        logger.exception('Update profile error')
        return json_response(False, 'Server error', 500)


@app.route('/api/profile/password', methods=['POST'])
@login_required
def api_change_password():
    """Change user password"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return json_response(False, 'Not authenticated', 401)
        
        data = request.get_json() or {}
        new_password = data.get('newPassword', '').strip()
        confirm_password = data.get('confirmPassword', '').strip()
        
        if not new_password or not confirm_password:
            return json_response(False, 'Both password fields required', 400)
        
        if new_password != confirm_password:
            return json_response(False, 'Passwords do not match', 400)
        
        if len(new_password) < 8:
            return json_response(False, 'Password must be at least 8 characters', 400)
        
        # Validate password strength
        if not re.search(r'\d', new_password):
            return json_response(False, 'Password must contain at least one number', 400)
        if not re.search(r'[!@#$%^&*()_\-+={[\]}\|\\:;"\'<>,.?/]', new_password):
            return json_response(False, 'Password must contain at least one special character', 400)
        
        sb = get_supabase()
        password_hash = generate_password_hash(new_password)
        
        success, _, error = safe_execute(
            sb.table('users').update({'password_hash': password_hash}).eq('id', user_id),
            'change_password'
        )
        
        if not success:
            return json_response(False, f'Failed to change password: {error}', 500)
        
        return json_response(True, 'Password changed successfully', 200)
        
    except Exception:
        logger.exception('Change password error')
        return json_response(False, 'Server error', 500)
# Profile picture configuration
PROFILE_PICTURE_BUCKET = os.getenv('SUPABASE_PROFILE_BUCKET', 'profile-pictures')
MAX_PROFILE_SIZE = 5 * 1024 * 1024  # 5MB

@app.route('/api/profile/picture', methods=['POST'])
@login_required
def api_upload_profile_picture():
    """Upload and update user's profile picture"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return json_response(False, 'Not authenticated', 401)
        
        # Check if file was uploaded
        if 'profile_picture' not in request.files:
            return json_response(False, 'No file uploaded', 400)
        
        file = request.files['profile_picture']
        
        if not file or file.filename == '':
            return json_response(False, 'No file selected', 400)
        
        # Validate file type
        if not allowed_file(file.filename):
            return json_response(False, 'Invalid file type. Use JPG, PNG, or GIF', 400)
        
        # Validate file size
        file.seek(0, 2)  # Seek to end
        size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if size > MAX_PROFILE_SIZE:
            return json_response(False, 'File too large. Maximum 5MB', 400)
        
        # Read and process image
        try:
            image = Image.open(file)
            
            # Convert to RGB if necessary
            if image.mode in ('RGBA', 'LA', 'P'):
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
                image = background
            
            # Resize to max 800x800 while maintaining aspect ratio
            max_size = (800, 800)
            image.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            # Save to bytes
            output = io.BytesIO()
            image.save(output, format='JPEG', quality=85, optimize=True)
            output.seek(0)
            file_content = output.read()
            
        except Exception as e:
            logger.exception(f"Error processing image: {e}")
            return json_response(False, 'Invalid image file', 400)
        
        # Generate unique filename
        ext = 'jpg'  # Always save as JPG after processing
        unique_filename = f"profile_{user_id}_{uuid.uuid4().hex}.{ext}"
        
        sb = get_supabase()
        
        # Get current profile picture to delete old one
        user = fetch_one('users', id=user_id)
        old_picture = user.get('profile_picture') if user else None
        
        # Upload new picture to Supabase Storage
        try:
            sb.storage.from_(PROFILE_PICTURE_BUCKET).upload(
                unique_filename, 
                file_content,
                file_options={"content-type": "image/jpeg"}
            )
        except Exception as e:
            logger.exception(f"Failed to upload to Supabase storage: {e}")
            return json_response(False, 'Failed to upload image', 500)
        
        # Get public URL
        try:
            url_response = sb.storage.from_(PROFILE_PICTURE_BUCKET).get_public_url(unique_filename)
            picture_url = url_response
        except Exception as e:
            logger.warning(f"Failed to get public URL, using path: {e}")
            picture_url = f"/api/profile/picture/{unique_filename}"
        
        # Update user record
        success, _, error = safe_execute(
            sb.table('users').update({'profile_picture': picture_url}).eq('id', user_id),
            'update_profile_picture'
        )
        
        if not success:
            # Clean up uploaded file
            try:
                sb.storage.from_(PROFILE_PICTURE_BUCKET).remove([unique_filename])
            except Exception:
                pass
            return json_response(False, f'Failed to update profile: {error}', 500)
        
        # Delete old picture if exists
        if old_picture:
            try:
                # Extract filename from URL or path
                old_filename = old_picture.split('/')[-1]
                if old_filename.startswith('profile_'):
                    sb.storage.from_(PROFILE_PICTURE_BUCKET).remove([old_filename])
            except Exception as e:
                logger.warning(f"Failed to delete old profile picture: {e}")
        
        return json_response(
            True, 
            'Profile picture updated successfully', 
            200, 
            picture_url=picture_url
        )
        
    except Exception as e:
        logger.exception('Upload profile picture error')
        return json_response(False, 'Server error', 500)


@app.route('/api/profile/picture/<filename>')
@login_required
def serve_profile_picture(filename):
    """Serve profile picture from Supabase storage"""
    try:
        safe_name = secure_filename(filename)
        if not safe_name:
            abort(404)
        
        sb = get_supabase()
        
        # Get public URL
        try:
            url = sb.storage.from_(PROFILE_PICTURE_BUCKET).get_public_url(safe_name)
            return redirect(url)
        except Exception:
            # Fallback to signed URL
            try:
                response = sb.storage.from_(PROFILE_PICTURE_BUCKET).create_signed_url(
                    safe_name, 
                    3600
                )
                signed_url = response.get('signedURL')
                if signed_url:
                    return redirect(signed_url)
            except Exception as e:
                logger.exception(f"Failed to get profile picture URL: {e}")
        
        abort(404)
    except Exception:
        logger.exception('serve_profile_picture error')
        abort(404)
# -----------------------
# Debug routes
# -----------------------
@app.route('/debug_urls')
@login_required
def debug_urls():
    urls = {
        'user_home': url_for('user_home'),
        'user_calendar_view': url_for('user_calendar_view'),
        'user_planner_view': url_for('user_planner_view'),
        'user_budget_view': url_for('user_budget_view'),
        'user_meetings_page': url_for('user_meetings_page'),
        'user_profile_view': url_for('user_profile_view'),
        'user_interface': url_for('user_interface'),
        'admin_interface': url_for('admin_interface'),
        'interface': url_for('interface'),
        'login': url_for('login'),
        'signup': url_for('signup'),
        'logout': url_for('logout'),
    }
    return jsonify(urls)


@app.route('/envtest')
def envtest():
    return jsonify({
        'smtp_email': SMTP_EMAIL is not None and SMTP_EMAIL != '',
        'sendgrid': SENDGRID_API_KEY is not None and SENDGRID_API_KEY != '',
        'supabase_url': SUPABASE_URL is not None and SUPABASE_URL != '',
        'supabase_key': SUPABASE_KEY is not None and SUPABASE_KEY != '',
        'supabase_available': SUPABASE_AVAILABLE,
        'supabase_bucket': SUPABASE_RECEIPT_BUCKET,
    })


@app.route('/debug_session')
def debug_session():
    info = {
        'has_session_cookie': 'session' in request.cookies,
        'cookie_keys': list(request.cookies.keys()),
        'session': {k: (v if isinstance(v, (str, int, bool)) else str(v)) for k, v in session.items()},
    }
    return jsonify(info)


@app.route('/debug_supabase')
def debug_supabase():
    result = {
        'configured': bool(SUPABASE_URL and SUPABASE_KEY), 
        'library_available': SUPABASE_AVAILABLE, 
        'url': SUPABASE_URL[:30] + '...' if SUPABASE_URL else None, 
        'connection_test': None, 
        'error': None
    }
    try:
        sb = get_supabase()
        success, data, error = safe_execute(sb.table('users').select('id').limit(1), 'connection_test')
        result['connection_test'] = 'success' if success else 'failed'
        if error:
            result['error'] = str(error)
    except Exception as e:
        result['connection_test'] = 'failed'
        result['error'] = str(e)
    return jsonify(result)


@app.route('/debug_get_code')
def debug_get_code():
    email = (request.args.get('email') or '').strip().lower()
    return jsonify({"stored_code": get_stored_code(email)})

# -----------------------
# Error handlers
# -----------------------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return json_response(False, 'Not found', 404)
    try:
        return render_template('errors/404.html'), 404
    except Exception:
        return '<h1>404 Not Found</h1>', 404


@app.errorhandler(500)
def internal_error(e):
    logger.exception('Internal server error')
    if request.path.startswith('/api/'):
        return json_response(False, 'Internal server error', 500)
    try:
        return render_template('errors/500.html'), 500
    except Exception:
        return '<h1>500 Internal Server Error</h1>', 500


@app.errorhandler(413)
def request_entity_too_large(e):
    return json_response(False, 'File too large', 413)

# -----------------------
# Startup check
# -----------------------

def check_startup_requirements():
    errors = []
    warnings = []
    skip_connection_test = os.getenv('SKIP_SUPABASE_TEST', '0') in ('1', 'true', 'True')
    
    if not SUPABASE_URL or not SUPABASE_KEY:
        errors.append('SUPABASE_URL and SUPABASE_KEY must be set in .env file')
    
    if not SUPABASE_AVAILABLE:
        errors.append('Supabase library not installed. Run: pip install supabase')
    
    if not SMTP_EMAIL and not SENDGRID_API_KEY:
        warnings.append('No email configuration found. Emails will be saved to local files.')
    
    if errors:
        for err in errors:
            logger.error(err)
        raise RuntimeError('Critical startup errors detected')
    
    if warnings:
        for w in warnings:
            logger.warning(w)
    
    if skip_connection_test:
        logger.warning('SKIP_SUPABASE_TEST enabled; skipping connection test')
        return
    
    try:
        sb = get_supabase()
        success, _, error = safe_execute(sb.table('users').select('id').limit(1), 'startup_test')
        if not success:
            raise RuntimeError(f'Supabase connection failed: {error}')
        logger.info('Supabase connection test successful')
    except Exception as e:
        logger.exception('Failed to connect to Supabase')
        raise

# -----------------------
# Main
# -----------------------
if __name__ == '__main__':
    logger.info('Starting Flask Application with Supabase')
    try:
        check_startup_requirements()
    except Exception as e:
        logger.warning(f'Startup checks failed: {e}')
    
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    try:
        port = int(os.getenv('FLASK_PORT', '5000'))
    except Exception:
        port = 5000
    
    app.run(debug=debug_mode, host=host, port=port)