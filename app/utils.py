import os
import uuid
import jwt
import pyotp
import qrcode
import qrcode.image.svg
import bleach
from io import BytesIO
from datetime import datetime, timedelta
from base64 import b64encode
from flask import current_app, url_for
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
ALLOWED_MIMETYPES = {
    'image/png', 'image/jpeg', 'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}

MAX_FILE_SIZE = 10 * 1024 * 1024


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_mimetype(mimetype):
    return mimetype in ALLOWED_MIMETYPES


def secure_save_file(file):
    if file and allowed_file(file.filename):
        original_name = secure_filename(file.filename)
        ext = original_name.rsplit('.', 1)[1].lower()
        unique_name = f"{uuid.uuid4().hex}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{ext}"
        upload_dir = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, unique_name)
        file.save(filepath)
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            os.remove(filepath)
            return None, 'File too large'
        return unique_name, None
    return None, 'Invalid file type'


def sanitize_html(text):
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li']
    allowed_attrs = {'a': ['href', 'title']}
    return bleach.clean(text, tags=allowed_tags, attributes=allowed_attrs, strip=True)


def sanitize_text(text):
    if not text:
        return ''
    return bleach.clean(text, tags=[], attributes={}, strip=True)


def generate_jwt_token(user_id, role):
    payload = {
        'sub': user_id,
        'role': role,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=current_app.config['JWT_ACCESS_TOKEN_EXPIRES']),
        'jti': uuid.uuid4().hex
    }
    token = jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
    return token


def decode_jwt_token(token):
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def generate_2fa_secret():
    return pyotp.random_base32()


def get_2fa_otp_uri(secret, email):
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name='MedSecure'
    )


def generate_2fa_qrcode(secret, email):
    uri = get_2fa_otp_uri(secret, email)
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage)
    buffer = BytesIO()
    img.save(buffer)
    return b64encode(buffer.getvalue()).decode()


def verify_2fa_code(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_csrf_token():
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps('csrf-token')


def validate_csrf_token(token):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        serializer.loads(token, max_age=3600)
        return True
    except Exception:
        return False


def log_audit(app, user_id, action, details, ip_address=None):
    if hasattr(app, 'audit_logger'):
        log_entry = f"{user_id or 'anonymous'} | {action} | {details} | {ip_address or 'unknown'}"
        app.audit_logger.info(log_entry)

    from app.models import AuditLog
    from app import db
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details[:500] if details else '',
            ip_address=ip_address or ''
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()
