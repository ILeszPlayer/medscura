from functools import wraps
from flask import abort, current_app, request
from flask_login import current_user
import re


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return role_required('admin')(f)


def doctor_required(f):
    return role_required('doctor', 'admin')(f)


def patient_required(f):
    return role_required('patient', 'admin')(f)


def validate_json_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return {'error': 'Content-Type must be application/json'}, 415
        if not request.get_json(silent=True):
            return {'error': 'Invalid JSON'}, 400
        return f(*args, **kwargs)
    return decorated_function


def sanitize_input(value):
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        value = re.sub(r'[<>\'";()]', '', value)
        return value
    return value


def sanitize_params(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'PATCH'):
            if request.form:
                clean = {}
                for key, val in request.form.items(multi=True):
                    clean[key] = sanitize_input(val)
                request.clean_form = clean
        if request.args:
            clean = {}
            for key, val in request.args.items(multi=True):
                clean[key] = sanitize_input(val)
            request.clean_args = clean
        return f(*args, **kwargs)
    return decorated_function
