"""
Cleaned and de-duplicated Flask app
- All routes restored (auth, API, budget, tasks, meetings, receipts, debug)
- No duplicate route definitions or duplicate __main__ blocks
- Single definitions for serve_receipt, debug routes, error handlers
- Handles missing optional libs gracefully

Save this file as cleaned_app.py and run with your venv.
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

# Optional imports that may not be present in minimal envs
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

# Supabase client (optional)
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except Exception:
    create_client = None
    Client = None
    SUPABASE_AVAILABLE = False

# requests optional
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

# Supabase configuration (may be empty)
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
    subject = 'Your Verification Code'
    html = f"""
    <html>
    <body>
        <h2>Verification Code</h2>
        <p>Your verification code is:</p>
        <h1 style=\"color: #4CAF50; font-family: monospace;\">{code}</h1>
        <p>This code will expire in {int(CODE_TTL/60)} minutes.</p>
        <p>If you didn't request this code, please ignore this email.</p>
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
# File upload helpers
# -----------------------

def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def save_uploaded_file(file_storage):
    if not file_storage or file_storage.filename == '':
        raise ValueError('No file provided')
    filename = secure_filename(file_storage.filename)
    if not allowed_file(filename):
        raise ValueError('File type not allowed')
    unique = f"{uuid.uuid4().hex}_{filename}"
    sb = get_supabase()
    file_storage.stream.seek(0)
    data = file_storage.stream.read()
    sb.storage.from_(SUPABASE_RECEIPT_BUCKET).upload(unique, data)
    logger.info(f'File uploaded successfully: {unique}')
    return unique


def get_receipt_url(filename, expires_seconds=3600):
    if not filename:
        return None
    try:
        sb = get_supabase()
        result = sb.storage.from_(SUPABASE_RECEIPT_BUCKET).create_signed_url(filename, expires_seconds)
        if isinstance(result, dict):
            return result.get('signedURL') or result.get('signedUrl')
        return f"/uploads/receipts/{filename}"
    except Exception:
        logger.exception('get_receipt_url failed')
        return f"/uploads/receipts/{filename}"

# -----------------------
# Serializers
# -----------------------

def serialize_meeting(row):
    meeting = {
        'id': row.get('id'),
        'title': row.get('title'),
        'type': row.get('type'),
        'purpose': row.get('purpose') or '',
        'datetime': None,
        'location': row.get('location') or '',
        'meetLink': row.get('meet_link') or '',
        'status': row.get('status') or 'Not Started',
        'attendees': [],
    }
    dt = row.get('datetime')
    if dt:
        meeting['datetime'] = dt.isoformat() if isinstance(dt, datetime) else dt
    attendees = row.get('attendees')
    if attendees:
        if isinstance(attendees, list):
            meeting['attendees'] = attendees
        elif isinstance(attendees, str):
            try:
                meeting['attendees'] = json.loads(attendees)
            except Exception:
                meeting['attendees'] = []
    return meeting


def serialize_task(row):
    task = {
        'id': row.get('id'),
        'title': row.get('title'),
        'due': None,
        'priority': row.get('priority') or 'medium',
        'notes': row.get('notes') or '',
        'status': row.get('status') or 'pending',
        'progress': int(row.get('progress') or 0),
        'type': row.get('type') or 'assignment',
        'completed': bool(row.get('completed')),
        'created_at': None,
    }
    due = row.get('due')
    if due:
        task['due'] = due.isoformat() if isinstance(due, datetime) else due
    created = row.get('created_at')
    if created:
        task['created_at'] = created.isoformat() if isinstance(created, datetime) else created
    return task

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
            user = fetch_one('users', email=email)
            if not user:
                flash('Invalid email or password', 'error')
                return redirect(url_for('login'))
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
            return resp
        except Exception:
            logger.exception('Login error')
            flash('Server error. Please try again.', 'error')
            return redirect(url_for('login'))
    return render_template('auth/login.html')


@app.route('/signup', methods=['GET'])
def signup():
    return render_template('auth/signup.html')


@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json(silent=True) or request.form.to_dict()
    first = (data.get('first_name') or '').strip()
    last = (data.get('last_name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    code = (data.get('code') or data.get('two_fa_code') or '').strip().upper()
    role = (data.get('role') or 'user').strip().lower()
    if not all([email, password, first]):
        return json_response(False, 'Missing required fields', 400)
    if not is_allowed_email_for_signup(email):
        return json_response(False, 'Email must be Gmail or admin@admin.com', 400)
    if len(password) < 8:
        return json_response(False, 'Password must be at least 8 characters', 400)
    try:
        existing = fetch_one('users', email=email)
        if existing:
            return json_response(False, 'Email already exists', 409)
        if code:
            stored = get_stored_code(email)
            if not stored:
                return json_response(False, 'Code expired or not found', 400)
            if stored != code:
                return json_response(False, 'Invalid code', 400)
            delete_stored_code(email)
        elif REQUIRE_2FA_BEFORE_CREATE:
            return json_response(False, 'Verification required', 400)
        sb = get_supabase()
        display_name = f"{first} {last}".strip()
        payload = {
            'first_name': first,
            'last_name': last,
            'display_name': display_name,
            'email': email,
            'password_hash': generate_password_hash(password),
            'two_fa_verified': bool(code),
            'role': role,
        }
        success, data, error = safe_execute(sb.table('users').insert(payload), 'create_user')
        if not success:
            return json_response(False, f'Database error: {error}', 500)
        if not data or len(data) == 0:
            return json_response(False, 'User created but data not returned', 500)
        created = data[0]
        session.update({
            'user_id': created['id'],
            'display_name': created.get('display_name') or display_name,
            'first_name': created.get('first_name') or first,
            'last_name': created.get('last_name') or last,
            'role': (created.get('role') or role).strip().lower(),
            'user_email': created.get('email'),
        })
        session.permanent = True
        token = generate_csrf_token()
        redirect_url = url_for('admin_interface') if session.get('role') in ('admin', 'administrator', 'superuser') else url_for('user_interface')
        resp = make_response(json_response(True, 'Account created', 201, redirect_url=redirect_url))
        resp.set_cookie('csrf_token', token, samesite='Lax')
        return resp
    except Exception:
        logger.exception('Signup error')
        return json_response(False, 'Server error', 500)


@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('login')))
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
    return json_response(True, 'Verification code sent', 200)


@app.route('/api/2fa/resend', methods=['POST'])
def api_2fa_resend():
    return api_2fa_send()


@app.route('/api/2fa/verify', methods=['POST'])
def api_2fa_verify():
    data = request.get_json(silent=True) or request.form.to_dict()
    code = str(data.get('code') or '').strip().upper()
    email = (data.get('email') or '').strip().lower()
    if not code or not email:
        return json_response(False, 'Missing email or code', 400)
    stored = get_stored_code(email)
    if not stored:
        return json_response(False, 'Code expired or not found', 400)
    if stored != code:
        return json_response(False, 'Invalid code', 400)
    delete_stored_code(email)
    try:
        user = fetch_one('users', email=email)
        if not user:
            return json_response(True, 'Email verified. Proceed with signup.', 200, redirect_url=url_for('signup'))
        sb = get_supabase()
        success, _, error = safe_execute(sb.table('users').update({'two_fa_verified': True}).eq('id', user['id']), 'update_2fa_verified')
        session.update({
            'user_id': user['id'],
            'display_name': user.get('display_name') or user.get('first_name', ''),
            'first_name': user.get('first_name', ''),
            'last_name': user.get('last_name', ''),
            'role': (user.get('role') or 'user').strip().lower(),
            'user_email': user.get('email'),
        })
        session.permanent = True
        token = generate_csrf_token()
        resp = make_response(json_response(True, 'Verification successful', 200, redirect_url=url_for('user_interface')))
        resp.set_cookie('csrf_token', token, samesite='Lax')
        return resp
    except Exception:
        logger.exception('2FA verify error')
        return json_response(False, 'Server error', 500)

# -----------------------
# Password reset
# -----------------------

def _get_serializer():
    secret = app.config.get('SECRET_KEY') or app.secret_key
    salt = app.config.get('SECURITY_PASSWORD_SALT') or secret
    if URLSafeTimedSerializer is None:
        raise RuntimeError('itsdangerous not available')
    return URLSafeTimedSerializer(secret_key=secret, salt=salt)


@app.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    data = request.get_json(silent=True) or request.form.to_dict()
    email = (data.get('email') or '').strip().lower()
    if not email:
        return json_response(False, 'Missing email', 400)
    if not is_allowed_email_for_signup(email):
        return json_response(False, 'Email must be Gmail or admin@admin.com', 400)
    if not can_send_code(email):
        return json_response(False, 'Too many requests', 429)
    alphabet = string.ascii_uppercase + string.digits
    code = ''.join(random.choices(alphabet, k=16))
    stored = store_code(email, code, user_id=None)
    if not stored:
        return json_response(False, 'Server error', 500)
    sent = send_otp_email(email, code)
    if not sent:
        delete_stored_code(email)
        return json_response(False, 'Failed to send email', 500)
    return json_response(True, 'Reset code sent if email exists', 200)


@app.route('/reset-password/<token>', methods=['GET'])
def reset_password_page(token):
    try:
        serializer = _get_serializer()
        max_age = int(app.config.get('PASSWORD_RESET_EXPIRES_MINUTES', 60)) * 60
        email = serializer.loads(token, max_age=max_age)
    except SignatureExpired:
        return '<p>Reset link expired. Request a new one.</p>', 400
    except BadSignature:
        return '<p>Invalid reset link.</p>', 400
    form_html = f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Reset Password</title></head>
      <body>
        <h2>Reset password for {email}</h2>
        <form method="POST" action="{url_for('api_reset_password', _external=True)}">
          <input type="hidden" name="token" value="{token}" />
          <div>
            <label>New password: <input name="password" type="password" required /></label>
          </div>
          <div>
            <label>Confirm: <input name="confirm_password" type="password" required /></label>
          </div>
          <div><button type="submit">Set new password</button></div>
        </form>
      </body>
    </html>
    """
    return form_html


@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    data = request.get_json(silent=True) or request.form.to_dict()
    token = (data.get('token') or '').strip()
    password = data.get('password') or ''
    confirm = data.get('confirm_password') or data.get('confirm') or ''
    if not token:
        return json_response(False, 'Missing token', 400)
    if not password or password != confirm:
        return json_response(False, 'Passwords do not match', 400)
    if len(password) < 8:
        return json_response(False, 'Password must be at least 8 characters', 400)
    try:
        serializer = _get_serializer()
        max_age = int(app.config.get('PASSWORD_RESET_EXPIRES_MINUTES', 60)) * 60
        email = serializer.loads(token, max_age=max_age)
    except SignatureExpired:
        return json_response(False, 'Reset link expired', 400)
    except BadSignature:
        return json_response(False, 'Invalid reset token', 400)
    try:
        user = fetch_one('users', email=email)
        if not user:
            return json_response(True, 'Password reset (if account exists)', 200)
        sb = get_supabase()
        new_hash = generate_password_hash(password)
        success, _, error = safe_execute(sb.table('users').update({'password_hash': new_hash}).eq('id', user['id']), 'reset_password')
        if not success:
            return json_response(False, 'Server error', 500)
        delete_stored_code(email)
        return json_response(True, 'Password reset successfully', 200)
    except Exception:
        logger.exception('Reset password error')
        return json_response(False, 'Server error', 500)

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
    return render_template('user/home.html', display_name=session.get('display_name'), first_name=session.get('first_name', ''), last_name=session.get('last_name', ''))


@app.route('/admin_interface')
@login_required
@admin_required
def admin_interface():
    return render_template('admin/home.html', display_name=session.get('display_name'), first_name=session.get('first_name', ''), last_name=session.get('last_name', ''))

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


@app.route('/api/tasks/<int:task_id>', methods=['GET', 'PATCH', 'DELETE'])
@login_required
def api_task_item(task_id):
    sb = get_supabase()
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
            success1, data1, _ = safe_execute(sb.table('pending_deletes').insert({'task_id': task_id, 'snapshot': json.dumps(snapshot), 'expires_at': expires_at.isoformat()}), 'store_pending_delete')
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

# -----------------------
# Budget categories/funds/transactions (consolidated)
# -----------------------
@app.route('/api/budget/categories', methods=['GET', 'POST'])
@login_required
def api_budget_categories():
    sb = get_supabase()
    if request.method == 'GET':
        try:
            success, data, error = safe_execute(sb.table('budget_categories').select('id,name,budget,created_at').order('name'), 'get_categories')
            if not success:
                return json_response(False, 'Failed to fetch categories', 500)
            categories = [{'id': r['id'], 'name': r['name'], 'budget': float(r.get('budget') or 0), 'created_at': r.get('created_at')} for r in (data or [])]
            return jsonify(categories)
        except Exception:
            logger.exception('Get categories error')
            return json_response(False, 'Server error', 500)
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    budget = data.get('budget') or 0
    if not name:
        return json_response(False, 'Name required', 400)
    try:
        success, _, error = safe_execute(sb.table('budget_categories').insert({'name': name, 'budget': budget}), 'create_category')
        if not success:
            return json_response(False, f'Failed to create: {error}', 500)
        return json_response(True, 'Category created', 201)
    except Exception:
        logger.exception('Create category error')
        return json_response(False, 'Server error', 500)


@app.route('/api/budget/funds', methods=['GET', 'POST'])
@login_required
def api_budget_funds():
    sb = get_supabase()
    if request.method == 'GET':
        try:
            success, data, error = safe_execute(sb.table('budget_funds').select('id,source,amount,date,created_at').order('created_at', desc=True), 'get_funds')
            if not success:
                return json_response(False, 'Failed to fetch funds', 500)
            funds = [{'id': r['id'], 'source': r.get('source'), 'amount': float(r.get('amount') or 0), 'date': r.get('date'), 'created_at': r.get('created_at')} for r in (data or [])]
            return jsonify(funds)
        except Exception:
            logger.exception('Get funds error')
            return json_response(False, 'Server error', 500)
    # POST create fund
    form = {}
    files = {}
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        form = request.form.to_dict()
        files = request.files
    else:
        form = request.get_json(silent=True) or {}
    source = (form.get('source') or '').strip()
    amount = form.get('amount') or 0
    date_val = form.get('date') or None
    date_parsed = None
    if date_val:
        try:
            date_parsed = datetime.fromisoformat(date_val).date()
        except Exception:
            try:
                date_parsed = datetime.strptime(date_val, '%Y-%m-%d').date()
            except Exception:
                pass
    receipt_filename = None
    uploaded = files.get('receipt') or files.get('file')
    if uploaded:
        try:
            receipt_filename = save_uploaded_file(uploaded)
        except ValueError as ve:
            return json_response(False, f'Invalid receipt: {str(ve)}', 400)
        except Exception:
            logger.exception('Failed to save receipt')
            return json_response(False, 'Failed to save receipt', 500)
    else:
        b64data = (form.get('receipt_data_base64') or '').strip()
        if b64data:
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
            except Exception:
                logger.exception('Failed to process base64 receipt')
                return json_response(False, 'Invalid receipt data', 400)
        else:
            # not required for funds? keep optional
            pass
    try:
        payload = {'source': source, 'amount': amount, 'date': date_parsed, 'receipt': receipt_filename}
        success, _, error = safe_execute(sb.table('budget_funds').insert(payload), 'create_fund')
        if not success:
            if receipt_filename:
                try:
                    sb.storage.from_(SUPABASE_RECEIPT_BUCKET).remove([receipt_filename])
                except Exception:
                    pass
            return json_response(False, f'Failed to create: {error}', 500)
        return json_response(True, 'Fund recorded', 201)
    except Exception:
        logger.exception('Create fund error')
        if receipt_filename:
            try:
                sb.storage.from_(SUPABASE_RECEIPT_BUCKET).remove([receipt_filename])
            except Exception:
                pass
        return json_response(False, 'Server error', 500)


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
            success, data, error = safe_execute(query.order('date', desc=True), 'get_transactions')
            if not success:
                return json_response(False, 'Failed to fetch transactions', 500)
            transactions = []
            for r in (data or []):
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
                    'receipt_url': get_receipt_url(receipt) if receipt else None,
                })
            return jsonify(transactions)
        except Exception:
            logger.exception('Get transactions error')
            return json_response(False, 'Server error', 500)
    # POST - create transaction
    form = {}
    files = {}
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        form = request.form.to_dict()
        files = request.files
    else:
        form = request.get_json(silent=True) or {}
    transaction_type = form.get('type') or ''
    category = form.get('category') or ''
    description = form.get('description') or form.get('desc') or ''
    amount = form.get('amount') or 0
    date_val = form.get('date') or None
    date_parsed = None
    if date_val:
        try:
            date_parsed = datetime.fromisoformat(date_val).date()
        except Exception:
            try:
                date_parsed = datetime.strptime(date_val, '%Y-%m-%d').date()
            except Exception:
                pass
    receipt_filename = None
    uploaded = files.get('receipt') or files.get('file')
    if uploaded:
        try:
            receipt_filename = save_uploaded_file(uploaded)
        except ValueError as ve:
            return json_response(False, f'Invalid receipt: {str(ve)}', 400)
        except Exception:
            logger.exception('Failed to save receipt')
            return json_response(False, 'Failed to save receipt', 500)
    else:
        b64data = (form.get('receipt_data_base64') or '').strip()
        if not b64data:
            return json_response(False, 'Receipt is required', 400)
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
        except Exception:
            logger.exception('Failed to process base64 receipt')
            return json_response(False, 'Invalid receipt data', 400)
    try:
        payload = {'type': transaction_type, 'category': category, 'description': description, 'amount': amount, 'date': date_parsed, 'receipt': receipt_filename}
        success, _, error = safe_execute(sb.table('budget_transactions').insert(payload), 'create_transaction')
        if not success:
            if receipt_filename:
                try:
                    sb.storage.from_(SUPABASE_RECEIPT_BUCKET).remove([receipt_filename])
                except Exception:
                    pass
            return json_response(False, f'Failed to create: {error}', 500)
        return json_response(True, 'Transaction recorded', 201)
    except Exception:
        logger.exception('Create transaction error')
        if receipt_filename:
            try:
                sb.storage.from_(SUPABASE_RECEIPT_BUCKET).remove([receipt_filename])
            except Exception:
                pass
        return json_response(False, 'Server error', 500)

# -----------------------
# Serve receipt (single route)
# -----------------------
@app.route('/uploads/receipts/<path:filename>')
@login_required
def serve_receipt(filename):
    try:
        safe_name = secure_filename(filename)
        if not safe_name:
            abort(404)
        url = get_receipt_url(safe_name, expires_seconds=3600)
        if url and url.startswith('http'):
            return redirect(url)
        fullpath = os.path.join(RECEIPT_FOLDER, safe_name)
        if not os.path.isfile(fullpath):
            for fn in os.listdir(RECEIPT_FOLDER):
                if fn.endswith(safe_name) or fn == safe_name:
                    fullpath = os.path.join(RECEIPT_FOLDER, fn)
                    break
        if not os.path.isfile(fullpath):
            abort(404)
        return send_file(fullpath, conditional=True)
    except Exception:
        logger.exception('serve_receipt error')
        abort(404)

# -----------------------
# Debug routes (single copies)
# -----------------------
@app.route('/debug_urls')
@login_required
def debug_urls():
    urls = {
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
    result = {'configured': bool(SUPABASE_URL and SUPABASE_KEY), 'library_available': SUPABASE_AVAILABLE, 'url': SUPABASE_URL[:30] + '...' if SUPABASE_URL else None, 'connection_test': None, 'error': None}
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

# -----------------------
# Error handlers (single copy)
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
# Rate limiting memory for 2FA
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
# Startup check (single copy)
# -----------------------

def check_startup_requirements():
    errors = []
    warnings = []
    skip_connection_test = os.getenv('SKIP_SUPABASE_TEST', '0') in ('1', 'true', 'True')
    if not SUPABASE_URL or not SUPABASE_KEY:
        errors.append('SUPABASE_URL and SUPABASE_KEY must be set in .env file')
    if not SUPABASE_AVAILABLE:
        errors.append('Supabase library not installed. Run: pip install supabase==2.10.0')
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
    except Exception as e:
        logger.exception('Failed to connect to Supabase')
        raise

# -----------------------
# Main
# -----------------------
if __name__ == '__main__':
    logger.info('Starting Flask Application')
    try:
        check_startup_requirements()
    except Exception as e:
        logger.warning(f'Startup checks failed or skipped: {e}')
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    try:
        port = int(os.getenv('FLASK_PORT', '5000'))
    except Exception:
        port = 5000
    app.run(debug=debug_mode, host=host, port=port)
