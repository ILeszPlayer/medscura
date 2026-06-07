import os
import uuid
import jwt
import pyotp
import qrcode
import qrcode.image.svg
import bleach
import hashlib
import hmac
from io import BytesIO
from datetime import datetime, timedelta
from base64 import b64encode, b64decode
from flask import current_app, url_for, request
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
ALLOWED_MIMETYPES = {
    'image/png', 'image/jpeg', 'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}

MAX_FILE_SIZE = 10 * 1024 * 1024


def get_encryption_key():
    key_file = current_app.config.get('ENCRYPTION_KEY_FILE', 'encryption.key')
    key_path = os.path.join(current_app.instance_path, key_file)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(key_path, 'wb') as f:
        f.write(key)
    return key


def encrypt_file_data(data):
    key = get_encryption_key()
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_file_data(data):
    key = get_encryption_key()
    f = Fernet(key)
    return f.decrypt(data)


def encrypt_filename(filename):
    key = get_encryption_key()
    f = Fernet(key)
    return f.encrypt(filename.encode()).decode()


def decrypt_filename(encrypted_name):
    key = get_encryption_key()
    f = Fernet(key)
    return f.decrypt(encrypted_name.encode()).decode()


def hash_ip(ip_address):
    salt = current_app.config['SECRET_KEY'].encode()
    return hashlib.sha256(salt + ip_address.encode()).hexdigest()


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
        if current_app.config.get('ENCRYPT_UPLOADS', True):
            with open(filepath, 'rb') as f:
                file_data = f.read()
            encrypted_data = encrypt_file_data(file_data)
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
        return unique_name, None
    return None, 'Invalid file type'


def read_encrypted_file(filename):
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'rb') as f:
        data = f.read()
    if current_app.config.get('ENCRYPT_UPLOADS', True):
        return decrypt_file_data(data)
    return data


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


def log_audit(app, user_id, action, details, ip_address=None, user_agent=None):
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
            ip_address=ip_address or '',
            user_agent=(user_agent or '')[:500]
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()


def track_suspicious_ip(ip_address, reason):
    from app import db
    from app.models import SuspiciousIP
    from datetime import datetime, timedelta

    record = SuspiciousIP.query.filter_by(ip_address=ip_address).first()
    if record:
        record.attempt_count += 1
        threshold = current_app.config.get('SUSPICIOUS_IP_THRESHOLD', 10)
        if record.attempt_count >= threshold:
            block_minutes = current_app.config.get('SUSPICIOUS_IP_BLOCK_MINUTES', 60)
            record.blocked_until = datetime.utcnow() + timedelta(minutes=block_minutes)
            record.reason = f'Auto-blocked after {record.attempt_count} suspicious attempts'
        else:
            record.reason = reason
    else:
        record = SuspiciousIP(
            ip_address=ip_address,
            reason=reason,
            attempt_count=1
        )
        db.session.add(record)
    db.session.commit()


def is_ip_blocked(ip_address):
    from app.models import SuspiciousIP
    record = SuspiciousIP.query.filter_by(ip_address=ip_address).first()
    if record and record.is_blocked():
        return True
    return False


def generate_reset_token(user_id):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(str(user_id), salt='password-reset')


def verify_reset_token(token, max_age=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        user_id = serializer.loads(token, salt='password-reset', max_age=max_age)
        return int(user_id)
    except Exception:
        return None
