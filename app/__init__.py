import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import Flask, redirect, url_for, flash, session as flask_session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
talisman = Talisman()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['LOG_DIR'], exist_ok=True)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    limiter.init_app(app)

    csp = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        'style-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
        'img-src': "'self' data:",
        'font-src': "'self' https://cdnjs.cloudflare.com",
        'connect-src': "'self'",
        'frame-src': "'none'",
        'object-src': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'",
    }

    talisman.init_app(
        app,
        force_https=False,
        strict_transport_security=False,
        session_cookie_secure=False,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src'],
        referrer_policy='strict-origin-when-cross-origin',
        x_xss_protection=False,
        x_content_type_options=True,
        frame_options='SAMEORIGIN',
    )

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = 'strong'

    app.jinja_env.globals.update(now=datetime.utcnow)

    @app.route('/')
    def index():
        from flask import render_template
        return render_template('landing.html')

    @app.route('/.well-known/security.txt')
    def security_txt():
        from flask import Response
        content = (
            "Contact: mailto:admin@medsecure.com\n"
            "Expires: 2027-12-31T23:59:59.000Z\n"
            "Preferred-Languages: en, id\n"
            "Canonical: http://localhost:5000/.well-known/security.txt\n"
            "Policy: http://localhost:5000/security-policy\n"
            "Hiring: https://medsecure.com/careers\n"
        )
        return Response(content, mimetype='text/plain')

    @app.route('/robots.txt')
    def robots_txt():
        from flask import Response
        content = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /api/\n"
            "Disallow: /auth/\n"
            "Disallow: /patient/\n"
            "Disallow: /doctor/\n"
            "Disallow: /uploads/\n"
        )
        return Response(content, mimetype='text/plain')

    setup_logging(app)

    from app.routes import auth, patient, doctor, admin, api
    app.register_blueprint(auth.bp)
    app.register_blueprint(patient.bp)
    app.register_blueprint(doctor.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(api.bp)

    with app.app_context():
        db.create_all()
        from app.models import User
        if not User.query.filter_by(role='admin').first():
            from werkzeug.security import generate_password_hash
            admin_user = User(
                username='admin',
                email='admin@medsecure.com',
                password_hash=generate_password_hash('Admin123!'),
                role='admin',
                is_active=True
            )
            db.session.add(admin_user)
            db.session.commit()

    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def ratelimit_error(e):
        from flask import render_template
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def server_error(e):
        from flask import render_template
        return render_template('errors/500.html'), 500

    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        if 'Content-Type' in response.headers and 'text/html' in response.headers['Content-Type']:
            response.headers['X-Download-Options'] = 'noopen'
        return response

    @app.before_request
    def check_session_timeout():
        if current_user.is_authenticated:
            last_active = flask_session.get('last_active')
            now = datetime.utcnow()
            if last_active:
                elapsed = (now - last_active).total_seconds()
                if elapsed > 1800:
                    logout_user()
                    flask_session.clear()
                    flash('Session expired due to inactivity.', 'info')
                    return redirect(url_for('auth.login'))
            flask_session['last_active'] = now

    return app


def setup_logging(app):
    log_file = os.path.join(app.config['LOG_DIR'], app.config['LOG_FILE'])
    audit_log_file = os.path.join(app.config['LOG_DIR'], app.config['AUDIT_LOG_FILE'])

    file_handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] %(module)s:%(lineno)d - %(message)s'
    ))
    file_handler.setLevel(logging.INFO)

    audit_handler = RotatingFileHandler(audit_log_file, maxBytes=10485760, backupCount=10)
    audit_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s'
    ))
    audit_handler.setLevel(logging.INFO)

    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

    app.audit_logger = logging.getLogger('audit')
    app.audit_logger.addHandler(audit_handler)
    app.audit_logger.setLevel(logging.INFO)
