# app.py (Supabase-backed, Redis removed)
import os
import json
import logging
import traceback
import random
import smtplib
import string
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from uuid import uuid4
from io import BytesIO
from functools import wraps
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response, send_file, abort, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import pathlib
import uuid
import mimetypes
from werkzeug.utils import safe_join
import re

# itsdangerous for secure timed tokens
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Optional external libs
try:
    import requests
except Exception:
    requests = None

# Supabase client
try:
    from supabase import create_client
except Exception:
    create_client = None

# -----------------------
# Setup
# -----------------------
load_dotenv()
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# not used directly for Supabase migration
DB_CONFIG = {}
app.permanent_session_lifetime = timedelta(days=30)

UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', os.path.join(os.getcwd(), 'uploads'))
RECEIPT_SUBDIR = 'receipts'
RECEIPT_FOLDER = os.path.join(UPLOAD_FOLDER, RECEIPT_SUBDIR)
os.makedirs(RECEIPT_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = set(['png','jpg','jpeg','gif','pdf'])
MAX_CONTENT_LENGTH = int(os.getenv('MAX_UPLOAD_BYTES', 5 * 1024 * 1024))  # 5MB default
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Supabase config
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
SUPABASE_RECEIPT_BUCKET = os.getenv('SUPABASE_RECEIPT_BUCKET', 'receipts')

if not SUPABASE_URL or not SUPABASE_KEY:
    logger.warning('SUPABASE_URL / SUPABASE_KEY not set - Supabase integration will not work until configured.')

_supabase = None

def get_supabase():
    """Lazy-create supabase client (requires SUPABASE_URL & SUPABASE_KEY)."""
    global _supabase
    if _supabase is None:
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise RuntimeError('SUPABASE_URL and SUPABASE_KEY must be set for supabase client')
        if not create_client:
            raise RuntimeError('supabase-py client not installed (pip install supabase)')
        _supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _supabase

# Config: send limits & TTL
SEND_LIMIT_WINDOW = int(os.getenv('SEND_LIMIT_WINDOW', 3600))  # seconds
SEND_LIMIT_COUNT = int(os.getenv('SEND_LIMIT_COUNT', 5))
CODE_TTL = int(os.getenv('CODE_TTL', 300))  # seconds (default 5 minutes)
REQUIRE_2FA_BEFORE_CREATE = os.getenv('REQUIRE_2FA_BEFORE_CREATE', '0') in ('1', 'true', 'True')

# -----------------------
# Helpers
# -----------------------
def json_response(success, message=None, code=200, **kwargs):
    payload = {"success": success}
    if message:
        payload["message"] = message
    payload.update(kwargs)
    return jsonify(payload), code

def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Login required"}), 401
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrap

# -----------------------
# File upload helpers (Supabase-backed)
# -----------------------
def allowed_file(filename):
    if not filename:
        return False
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXTENSIONS

def save_uploaded_file(file_storage):
    """
    Upload incoming werkzeug FileStorage to Supabase Storage receipts bucket.
    Returns the object name on success.
    """
    if not file_storage or file_storage.filename == '':
        raise ValueError("No file provided")
    filename = secure_filename(file_storage.filename)
    if not allowed_file(filename):
        raise ValueError("File type not allowed")
    unique = f"{uuid.uuid4().hex}_{filename}"
    sb = get_supabase()
    try:
        file_storage.stream.seek(0)
        data = file_storage.stream.read()
        # supabase-py storage.upload expects bytes-like object; some versions accept file-like
        res = sb.storage.from_(SUPABASE_RECEIPT_BUCKET).upload(unique, data)
        # res may be a dict/object depending on client version
        if getattr(res, 'error', None):
            logger.error('Supabase storage upload error: %s', res.error)
            raise Exception('Storage upload failed')
        return unique
    except Exception as e:
        logger.exception('Failed uploading to Supabase storage: %s', e)
        raise

def get_receipt_url(filename, expires_seconds=3600):
    if not filename:
        return None
    try:
        sb = get_supabase()
        signed = sb.storage.from_(SUPABASE_RECEIPT_BUCKET).create_signed_url(filename, expires_seconds)
        # The return shape may vary by client version
        if isinstance(signed, dict):
            return signed.get('signedURL') or signed.get('signed_url') or signed.get('signedURL')
        if getattr(signed, 'get', None):
            return signed.get('signedURL') or signed.get('signed_url')
        # fallback to an internal path that maps to /uploads/receipts/<filename> route
        return f"/uploads/receipts/{filename}"
    except Exception as e:
        logger.exception('get_receipt_url failed: %s', e)
        return f"/uploads/receipts/{filename}"

# -----------------------
# Role-based decorators & interface router (unchanged)
# -----------------------
def role_required(*allowed_roles):
    allowed_norm = [r.lower() for r in allowed_roles]
    def deco(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                if request.path.startswith("/api/"):
                    return json_response(False, "Login required", 401)
                return redirect(url_for("login"))
            role = (session.get("role") or "").lower()
            if role not in allowed_norm:
                if request.path.startswith("/api/"):
                    return json_response(False, "Forbidden", 403)
                return redirect(url_for("interface"))
            return f(*args, **kwargs)
        return wrapped
    return deco

def admin_required(f):
    return role_required("admin", "administrator", "superuser")(f)

def user_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return json_response(False, "Login required", 401)
            return redirect(url_for("login"))
        role = (session.get('role') or '').lower()
        if role != 'user':
            if role in ("admin","administrator","superuser"):
                logger.info("user_required: detected admin in session, redirecting to admin_interface")
                return redirect(url_for("admin_interface"))
            if request.path.startswith("/api/"):
                return json_response(False, "Forbidden", 403)
            flash("Access forbidden for your account role.", "error")
            return redirect(url_for("interface"))
        return f(*a, **kw)
    return wrap

# -----------------------
# Email whitelist helper
# -----------------------
def is_allowed_email_for_signup(email):
    if not email:
        return False
    email = email.strip().lower()
    if email == "admin@admin.com":
        return True
    return email.endswith("@gmail.com")

# -----------------------
# Serializers & helpers
# -----------------------
def serialize_meeting(row):
    m = {
        "id": row.get("id"),
        "title": row.get("title"),
        "type": row.get("type"),
        "purpose": row.get("purpose") or "",
        "datetime": (row.get("datetime").isoformat() if isinstance(row.get("datetime"), datetime) else row.get("datetime")) if row.get("datetime") else None,
        "location": row.get("location") or "",
        "meetLink": row.get("meet_link") or "",
        "status": row.get("status") or "Not Started",
        "attendees": []
    }
    try:
        if row.get("attendees"):
            m["attendees"] = row.get("attendees") if isinstance(row.get("attendees"), list) else json.loads(row.get("attendees"))
    except Exception:
        m["attendees"] = []
    return m

def serialize_task(row):
    return {
        "id": row.get("id"),
        "title": row.get("title"),
        "due": (row.get("due").isoformat() if isinstance(row.get("due"), datetime) else row.get("due")) if row.get("due") else "",
        "priority": row.get("priority") or "medium",
        "notes": row.get("notes") or "",
        "status": row.get("status") or "pending",
        "progress": int(row.get("progress") or 0),
        "type": row.get("type") or "assignment",
        "completed": bool(row.get("completed")),
        "created_at": (row.get("created_at").isoformat() if isinstance(row.get("created_at"), datetime) else row.get("created_at")) if row.get("created_at") else None
    }

def generate_csrf_token():
    token = str(uuid4())
    session['csrf_token'] = token
    return token

# -----------------------
# Email sending helpers (complete)
# -----------------------
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDGRID_FROM = os.getenv('SENDGRID_FROM')
SMTP_EMAIL = os.getenv('SMTP_EMAIL')
SMTP_PASS = os.getenv('SMTP_PASS')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))

def _write_email_to_local_file(recipient_email, subject, html):
    """Dev fallback: write the email to a timestamped file in /tmp or uploads/email_dumps."""
    try:
        out_dir = os.getenv('EMAIL_DUMP_DIR', os.path.join(UPLOAD_FOLDER, 'email_dumps'))
        os.makedirs(out_dir, exist_ok=True)
        fname = f"email_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}_{secure_filename(recipient_email)}.html"
        path = os.path.join(out_dir, fname)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(f"To: {recipient_email}\nSubject: {subject}\n\n{html}")
        logger.info("Wrote email to local file: %s", path)
        return True
    except Exception as e:
        logger.exception("Failed to write email to local file: %s", e)
        return False

def send_via_smtp(recipient_email, subject, html, timeout=15):
    from_addr = SMTP_EMAIL or os.getenv('MAIL_FROM') or 'no-reply@example.com'
    server_addr = os.getenv('SMTP_SERVER', SMTP_SERVER)
    try:
        port = int(os.getenv('SMTP_PORT', SMTP_PORT))
    except Exception:
        port = SMTP_PORT

    msg = MIMEText(html, _subtype='html')
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = recipient_email

    try_methods = []

    if SENDGRID_API_KEY:
        try_methods.append(('sendgrid-smtp', 'apikey', SENDGRID_API_KEY))
    if SMTP_EMAIL and SMTP_PASS:
        try_methods.append(('smtp-login', SMTP_EMAIL, SMTP_PASS))
    if SMTP_EMAIL and not SMTP_PASS:
        try_methods.append(('smtp-noauth', None, None))

    if not try_methods:
        logger.warning("No SMTP or SendGrid SMTP credentials configured. Falling back to local email dump.")
        return _write_email_to_local_file(recipient_email, subject, html)

    last_exc = None
    for method, user, pwd in try_methods:
        server = None
        try:
            logger.info("Attempting SMTP send using method=%s server=%s:%s from=%s to=%s",
                        method, server_addr, port, from_addr, recipient_email)
            server = smtplib.SMTP(server_addr, port, timeout=timeout)
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception as e:
                logger.debug("starttls failed/unsupported: %s", e)
            if user and pwd:
                server.login(user, pwd)
            server.sendmail(from_addr, [recipient_email], msg.as_string())
            server.quit()
            logger.info("SMTP send (method=%s) succeeded for %s", method, recipient_email)
            return True
        except Exception as e:
            last_exc = e
            logger.warning("SMTP send (method=%s) failed for %s: %s", method, recipient_email, e)
            try:
                if server:
                    server.quit()
            except Exception:
                pass
    logger.exception("All SMTP methods failed for %s. Last error: %s", recipient_email, last_exc)
    return False

def send_via_sendgrid_api(recipient_email, subject, html, timeout=10):
    if not SENDGRID_API_KEY:
        logger.debug("send_via_sendgrid_api: SENDGRID_API_KEY not configured")
        return False
    if not requests:
        logger.error("send_via_sendgrid_api: requests library not available")
        return False

    url = "https://api.sendgrid.com/v3/mail/send"
    payload = {
        "personalizations": [{"to": [{"email": recipient_email}], "subject": subject}],
        "from": {"email": SENDGRID_FROM or SMTP_EMAIL or "no-reply@example.com"},
        "content": [{"type": "text/html", "value": html}]
    }
    headers = {"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if 200 <= getattr(r, "status_code", 0) < 300:
            logger.info("SendGrid API send succeeded for %s (status=%s)", recipient_email, r.status_code)
            return True
        logger.warning("SendGrid API returned non-success for %s status=%s text=%s", recipient_email, r.status_code, getattr(r, "text", None))
        return False
    except Exception as e:
        logger.exception("SendGrid API send failed for %s: %s", recipient_email, e)
        return False

def send_otp_email(recipient_email, code):
    subject = "Your verification code"
    body = f"Your verification code is: {code}\n\nThis 16-character code will expire in {int(CODE_TTL/60)} minutes. Copy it exactly and paste it into the verification box."
    html = f"<p>Your verification code is: <strong>{code}</strong></p><p>This code will expire in {int(CODE_TTL/60)} minutes.</p>"

    # 1) SendGrid API if configured
    if SENDGRID_API_KEY:
        ok = send_via_sendgrid_api(recipient_email, subject, html)
        if ok:
            return True
        else:
            logger.info("SendGrid API attempt failed; will try SMTP fallback")

    # 2) SMTP fallback
    smtp_ok = send_via_smtp(recipient_email, subject, html)
    if smtp_ok:
        return True

    # 3) fallback: dump to file
    logger.warning("No email provider worked for %s — falling back to local dump", recipient_email)
    dumped = _write_email_to_local_file(recipient_email, subject, html + "\n\n" + body)
    return dumped

# -----------------------
# Supabase-backed 2FA code storage (only)
# -----------------------
def _supabase_store_code(email, code, user_id=None):
    sb = get_supabase()
    expires = datetime.utcnow() + timedelta(seconds=CODE_TTL)
    payload = {"user_id": user_id, "email": email, "code": code, "expires_at": expires.isoformat()}
    try:
        res = sb.table('user_2fa_codes').insert(payload).execute()
        if getattr(res, 'error', None):
            logger.error('Supabase insert 2FA returned error: %s', res.error)
            return False
        return True
    except Exception as e:
        logger.exception('Supabase store code failed: %s', e)
        return False


def _supabase_get_latest_code(email):
    sb = get_supabase()
    try:
        res = sb.table('user_2fa_codes').select('*').eq('email', email).order('id', desc=True).limit(1).execute()
        if getattr(res, 'error', None):
            logger.error('Supabase get latest code error: %s', res.error)
            return None
        data = getattr(res, 'data', None) or (res.data if hasattr(res, 'data') else None)
        if not data:
            return None
        if isinstance(data, list):
            return data[0]
        return data
    except Exception as e:
        logger.exception('Supabase get latest code failed: %s', e)
        return None


def _supabase_delete_code(email):
    sb = get_supabase()
    try:
        res = sb.table('user_2fa_codes').delete().eq('email', email).execute()
        if getattr(res, 'error', None):
            logger.error('Supabase delete code error: %s', res.error)
            return False
        return True
    except Exception as e:
        logger.exception('Supabase delete code failed: %s', e)
        return False

# wrappers: use Supabase only (Redis removed)
def store_code(email, code, user_id=None):
    email = (email or '').strip().lower()
    return _supabase_store_code(email, code, user_id)


def get_stored_code(email):
    email = (email or '').strip().lower()
    row = _supabase_get_latest_code(email)
    if not row:
        return None
    expires_at = row.get('expires_at')
    expires_dt = None
    if isinstance(expires_at, str):
        try:
            expires_dt = datetime.fromisoformat(expires_at)
        except Exception:
            try:
                expires_dt = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S')
            except Exception:
                expires_dt = None
    elif isinstance(expires_at, datetime):
        expires_dt = expires_at
    if not expires_dt or datetime.utcnow() > expires_dt:
        return None
    code = row.get('code')
    return (code or '').strip().upper()


def delete_stored_code(email):
    email = (email or '').strip().lower()
    return _supabase_delete_code(email)

# -----------------------
# Rate limiting: in-memory sliding window per-email (since Redis removed)
# -----------------------
def can_send_code(email):
    """Rate-limit using a simple in-memory sliding window per-email."""
    now_ts = int(datetime.utcnow().timestamp())
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
# Auth & account flows (converted to Supabase table usage)
# -----------------------
@app.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    if not data:
        data = request.form.to_dict() or {}
    email = (data.get('email') or '').strip().lower()
    if not email:
        return json_response(False, 'Missing email', 400)
    if not is_allowed_email_for_signup(email):
        return json_response(False, 'Email must be a Gmail address (or admin@admin.com)', 400)
    try:
        if not can_send_code(email):
            logger.info('forgot-password: rate-limit exceeded for %s', email)
            return json_response(False, 'Too many requests. Try again later.', 429)
    except Exception as e:
        logger.exception('forgot-password: rate limiter error (allowing send): %s', e)
    alphabet = string.ascii_uppercase + string.digits
    code = ''.join(random.choices(alphabet, k=16))
    stored_ok = store_code(email, code, user_id=None)
    if not stored_ok:
        logger.error('forgot-password: failed to persist verification code for %s', email)
        return json_response(False, 'Server error: failed to store verification code', 500)
    try:
        sent_ok = send_otp_email(email, code)
    except Exception as e:
        logger.exception('forgot-password: send_otp_email raised exception for %s: %s', email, e)
        sent_ok = False
    if not sent_ok:
        try:
            delete_stored_code(email)
        except Exception:
            pass
        logger.error('forgot-password: Failed to send verification email to %s. Check logs/server config.', email)
        return json_response(False, 'Failed to send verification email. Check server configuration/logs.', 500)
    return json_response(True, 'If that address exists, a reset link or verification code has been sent.', 200)

# Password reset helpers (serializer + send)
def _get_serializer():
    secret = app.config.get('SECRET_KEY') or app.secret_key
    salt = app.config.get('SECURITY_PASSWORD_SALT') or secret
    return URLSafeTimedSerializer(secret_key=secret, salt=salt)

def _send_reset_email(recipient_email: str, reset_link: str) -> bool:
    try:
        return send_via_smtp(recipient_email, 'Reset', f'<a href="{reset_link}">Reset</a>')
    except Exception as e:
        logger.exception('Reset email send failed: %s', e)
        return False

@app.route('/reset-password/<token>', methods=['GET'])
def reset_password_page(token):
    serializer = _get_serializer()
    max_age = int(app.config.get('PASSWORD_RESET_EXPIRES_MINUTES', 60)) * 60
    try:
        email = serializer.loads(token, max_age=max_age)
    except SignatureExpired:
        return '<p>Reset link expired. Request a new one.</p>', 400
    except BadSignature:
        return '<p>Invalid reset link.</p>', 400
    form_html = f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Reset password</title></head>
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
    data = request.get_json(silent=True) or {}
    if not data:
        data = request.form.to_dict() or {}
    token = (data.get('token') or '').strip()
    password = data.get('password') or ''
    confirm = data.get('confirm_password') or data.get('confirm') or ''
    if not token:
        return json_response(False, 'Missing token', 400)
    if not password or password != confirm:
        return json_response(False, 'Passwords do not match', 400)
    # fixed regex quoting
    if len(password) < 8 or not re.search(r'\d', password) or not re.search(r'[!@#$%^&*()_\-+={[}\]|\\:;"\'\<>,.?/]', password):
        return json_response(False, 'Password does not meet complexity requirements', 400)
    serializer = _get_serializer()
    max_age = int(app.config.get('PASSWORD_RESET_EXPIRES_MINUTES', 60)) * 60
    try:
        email = serializer.loads(token, max_age=max_age)
    except SignatureExpired:
        return json_response(False, 'Reset link expired', 400)
    except BadSignature:
        return json_response(False, 'Invalid reset token', 400)
    try:
        sb = get_supabase()
        res = sb.table('users').select('*').eq('email', email).single().execute()
        if getattr(res, 'error', None) or not getattr(res, 'data', None):
            # Avoid enumeration: respond success
            return json_response(True, 'Password has been reset (if account exists).', 200)
        u = res.data
        new_hash = generate_password_hash(password)
        upd = sb.table('users').update({'password_hash': new_hash}).eq('id', u['id']).execute()
        try:
            delete_stored_code(email)
        except Exception:
            pass
        return json_response(True, 'Password successfully reset', 200)
    except Exception as e:
        logger.exception('Error resetting password: %s', e)
        return json_response(False, 'Server error', 500)

# -----------------------
# API: 2FA send/resend/verify (supabase-backed)
# -----------------------
@app.route('/api/2fa/send', methods=['POST'])
def api_2fa_send():
    data = request.get_json(silent=True) or {}
    if not data:
        data = request.form.to_dict() or {}
    email = (data.get('email') or '').strip().lower()
    user_id = data.get('user_id')
    if not email:
        return json_response(False, "Missing email", 400)
    if not is_allowed_email_for_signup(email):
        return json_response(False, "Email must be a Gmail address (or admin@admin.com)", 400)
    if not can_send_code(email):
        return json_response(False, "Too many requests. Try again later.", 429)
    alphabet = string.ascii_uppercase + string.digits
    code = ''.join(random.choices(alphabet, k=16))
    stored = store_code(email, code, user_id)
    if not stored:
        logger.error('Failed storing 2FA code; aborting send for %s', email)
        return json_response(False, 'Server error: failed to store verification code', 500)
    sent = send_otp_email(email, code)
    if not sent:
        try:
            delete_stored_code(email)
        except Exception:
            pass
        return json_response(False, 'Failed to send verification email. Check server configuration/logs.', 500)
    return json_response(True, 'Verification code sent', 200)

@app.route('/api/2fa/resend', methods=['POST'])
def api_2fa_resend():
    return api_2fa_send()

@app.route('/api/2fa/verify', methods=['POST'])
def api_2fa_verify():
    data = request.get_json(silent=True) or {}
    if not data:
        data = request.form.to_dict() or {}
    code = str(data.get('code') or '').strip().upper()
    email = (data.get('email') or '').strip().lower()
    if not code or not email:
        return json_response(False, 'Missing verification target (email) and/or code', 400)
    stored = get_stored_code(email)
    if not stored:
        return json_response(False, 'No verification code found or code expired', 400)
    if stored != code:
        return json_response(False, 'Invalid code', 400)
    try:
        delete_stored_code(email)
    except Exception:
        pass
    try:
        sb = get_supabase()
        res = sb.table('users').select('*').eq('email', email).single().execute()
        if getattr(res, 'error', None) or not getattr(res, 'data', None):
            return json_response(True, 'Email verified (pre-signup). Proceed with signup.', 200)
        u = res.data
        up = sb.table('users').update({'two_fa_verified': True}).eq('id', u['id']).execute()
        session.update({
            'user_id': u.get('id'),
            'display_name': u.get('display_name') or u.get('first_name',''),
            'first_name': u.get('first_name',''),
            'last_name': u.get('last_name',''),
            'role': (u.get('role') or 'user').strip().lower(),
            'user_email': u.get('email')
        })
        session.permanent = True
        token = generate_csrf_token()
        resp = make_response(json_response(True, 'Verification successful', 200, redirect_url=url_for('user_interface')))
        resp.set_cookie('csrf_token', token, samesite='Lax')
        return resp
    except Exception as e:
        logger.exception('Verify DB error: %s', e)
        return json_response(False, 'Server error', 500)

# -----------------------
# Auth routes (login/signup/logout)
# -----------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '')
        pw = request.form.get('password', '')
        try:
            sb = get_supabase()
            res = sb.table('users').select('*').eq('email', email).single().execute()
            if getattr(res, 'error', None) or not getattr(res, 'data', None):
                flash('Invalid credentials', 'error')
                return redirect(url_for('login'))
            u = res.data
            if not check_password_hash(u.get('password_hash',''), pw):
                flash('Invalid credentials', 'error')
                return redirect(url_for('login'))
            role = (u.get('role') or 'user').strip().lower()
            session.update({
                'user_id': u['id'],
                'display_name': u.get('display_name') or u.get('first_name') or '',
                'first_name': u.get('first_name') or '',
                'last_name': u.get('last_name') or '',
                'role': role,
                'user_email': u.get('email')
            })
            session.permanent = True
            token = generate_csrf_token()
            if role == 'admin':
                redirect_to = url_for('admin_interface')
            else:
                redirect_to = url_for('user_interface')
            resp = make_response(redirect(redirect_to))
            resp.set_cookie('csrf_token', token, samesite='Lax')
            return resp
        except Exception as e:
            logger.exception('Login error: %s', e)
            flash('Server error', 'error')
            return redirect(url_for('login'))
    return render_template('auth/login.html')

@app.route('/signup', methods=['GET'])
def signup():
    return render_template('auth/signup.html')

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('csrf_token')
    return resp

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json(silent=True)
    if not data:
        data = request.form.to_dict() or {}
    first = (data.get('first_name') or '').strip()
    last = (data.get('last_name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    pw = data.get('password') or ''
    code = (data.get('code') or data.get('two_fa_code') or '').strip().upper()
    role = (data.get('role') or 'user').strip().lower()
    if not all([email, pw, first]):
        return json_response(False, 'Missing fields', 400)
    if not is_allowed_email_for_signup(email):
        return json_response(False, 'Email must be a Gmail (or admin@admin.com)', 400)
    sb = get_supabase()
    if code:
        stored = get_stored_code(email)
        if not stored:
            return json_response(False, 'No verification code found or code expired', 400)
        if stored != code:
            return json_response(False, 'Invalid verification code', 400)
        try:
            delete_stored_code(email)
        except Exception:
            pass
        try:
            role = (role or 'user').strip().lower()
            payload = {'first_name': first, 'last_name': last, 'display_name': f"{first} {last}", 'email': email, 'password_hash': generate_password_hash(pw), 'two_fa_verified': True, 'role': role}
            res = sb.table('users').insert(payload).execute()
            if getattr(res, 'error', None):
                err = res.error
                if 'duplicate' in str(err).lower() or 'unique' in str(err).lower():
                    return json_response(False, 'Email already exists', 409)
                logger.exception('API signup (with code) error: %s', err)
                return json_response(False, 'Server error', 500)
            created = res.data[0] if isinstance(res.data, list) else res.data
            session.update({
                'user_id': created['id'],
                'display_name': created.get('display_name') or f"{created.get('first_name','')}",
                'first_name': created.get('first_name') or '',
                'last_name': created.get('last_name') or '',
                'role': (created.get('role') or role).strip().lower(),
                'user_email': created.get('email')
            })
            session.permanent = True
            token = generate_csrf_token()
            resp = make_response(json_response(True, 'Account created and verified', 201, redirect_url=url_for('user_interface')))
            resp.set_cookie('csrf_token', token, samesite='Lax')
            return resp
        except Exception as e:
            logger.exception('API signup (with code) error: %s', e)
            return json_response(False, 'Server error', 500)
    if REQUIRE_2FA_BEFORE_CREATE:
        return json_response(False, 'Verification required. Request a 2FA code first and resubmit with code.', 400)
    try:
        role = (role or 'user').strip().lower()
        payload = {'first_name': first, 'last_name': last, 'display_name': f"{first} {last}", 'email': email, 'password_hash': generate_password_hash(pw), 'role': role}
        res = sb.table('users').insert(payload).execute()
        if getattr(res, 'error', None):
            err = res.error
            if 'duplicate' in str(err).lower() or 'unique' in str(err).lower():
                return json_response(False, 'Email already exists', 409)
            logger.exception('API signup error: %s', err)
            return json_response(False, 'Server error', 500)
        created = res.data[0] if isinstance(res.data, list) else res.data
        return json_response(True, 'Account created (unverified). Please verify your email.', 201, user_id=created.get('id'), redirect_url=url_for('interface'))
    except Exception as e:
        logger.exception('API signup error: %s', e)
        return json_response(False, 'Server error', 500)

# -----------------------
# api_login / api_logout using Supabase
# -----------------------
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    if not data:
        data = request.form.to_dict() or {}
    email = data.get('email', '')
    pw = data.get('password', '')
    try:
        sb = get_supabase()
        res = sb.table('users').select('*').eq('email', email).single().execute()
        if getattr(res, 'error', None) or not getattr(res, 'data', None):
            return json_response(False, 'Invalid credentials', 401)
        u = res.data
        if not check_password_hash(u.get('password_hash',''), pw):
            return json_response(False, 'Invalid credentials', 401)
        role_val = (u.get('role') or 'user').strip().lower()
        session.update({
            'user_id': u['id'],
            'display_name': u.get('display_name') or f"{u.get('first_name','')}",
            'first_name': u.get('first_name') or '',
            'last_name': u.get('last_name') or '',
            'role': role_val,
            'user_email': u.get('email')
        })
        session.permanent = True
        token = generate_csrf_token()
        resp = make_response(json_response(True, 'Login successful', 200, user={'id': u['id'], 'name': u.get('display_name'), 'email': u.get('email')}, redirect_url=url_for('interface')))
        resp.set_cookie('csrf_token', token, samesite='Lax')
        return resp
    except Exception as e:
        logger.exception('Login error: %s', e)
        return json_response(False, 'Server error', 500)

@app.route('/api/logout', methods=['GET'])
@login_required
def api_logout():
    session.clear()
    resp = make_response(json_response(True, 'Logged out'))
    resp.delete_cookie('csrf_token')
    return resp

# -----------------------
# Students & Meetings API (converted to Supabase)
# -----------------------
# ... (rest of handlers unchanged) - see original for full list

# -----------------------
# serve_receipt - optional local bridge (still keep for compatibility)
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
    except Exception as e:
        logger.error(f'serve_receipt error: {e}')
        abort(404)

# -----------------------
# UI routes & misc (abbreviated to mirror original)
# -----------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/interface')
@login_required
def interface():
    role = (session.get('role') or '').strip().lower()
    if role in ('admin','administrator','superuser'):
        return redirect(url_for('admin_interface'))
    return redirect(url_for('user_interface'))

@app.route('/user_interface')
@login_required
@user_required
def user_interface():
    return render_template('user/home.html', display_name=session.get('display_name'), first_name=session.get('first_name',''), last_name=session.get('last_name',''))

@app.route('/admin_interface')
@login_required
@admin_required
def admin_interface():
    return render_template('admin/home.html', display_name=session.get('display_name'), first_name=session.get('first_name',''), last_name=session.get('last_name',''))

# Debug helpers
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
    }
    return jsonify(urls)

@app.route('/envtest')
def envtest():
    return {
        'smtp_email': os.getenv('SMTP_EMAIL'),
        'sendgrid': os.getenv('SENDGRID_API_KEY') is not None,
        'supabase_url': SUPABASE_URL is not None
    }

@app.route('/debug_get_code')
def debug_get_code():
    email = (request.args.get('email') or '').strip().lower()
    return jsonify({'stored_code': get_stored_code(email)})

@app.route('/debug_session')
def debug_session():
    info = {
        'has_session_cookie': 'session' in request.cookies,
        'cookie_keys': list(request.cookies.keys()),
        'session': {k:(v if isinstance(v,(str,int,bool)) else str(v)) for k,v in session.items()}
    }
    return jsonify(info)

if __name__ == '__main__':
    # DB init is handled by SUPABASE_MIGRATION.md SQL script
    app.run(debug=True)

