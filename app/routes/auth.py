from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, current_app, jsonify, session
)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from app import db, limiter
from app.models import User, Patient, Doctor, AuditLog
from app.forms import LoginForm, RegistrationForm, ChangePasswordForm, Setup2FAForm, Disable2FAForm
from app.decorators import sanitize_params
from app.utils import (
    generate_2fa_secret, generate_2fa_qrcode, verify_2fa_code,
    log_audit, sanitize_text
)

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('10/minute', methods=['POST'])
@sanitize_params
def login():
    if current_user.is_authenticated:
        return redirect(url_for('patient.dashboard' if current_user.role == 'patient'
                                else 'doctor.dashboard' if current_user.role == 'doctor'
                                else 'admin.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        username = sanitize_text(form.username.data)
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if not user:
            user = User.query.filter_by(email=username).first()

        if not user:
            flash('Invalid credentials', 'danger')
            log_audit(current_app._get_current_object(), None,
                      'LOGIN_FAILED', f'Invalid username/email: {username}',
                      request.remote_addr)
            return render_template('auth/login.html', form=form)

        if not user.is_active:
            flash('Account is disabled. Contact administrator.', 'danger')
            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_BLOCKED', 'Account disabled',
                      request.remote_addr)
            return render_template('auth/login.html', form=form)

        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining = (user.locked_until - datetime.utcnow()).seconds // 60
            flash(f'Account locked. Try again in {remaining} minutes.', 'danger')
            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_BLOCKED', f'Account locked until {user.locked_until}',
                      request.remote_addr)
            return render_template('auth/login.html', form=form)

        if check_password_hash(user.password_hash, password):
            if user.is_2fa_enabled:
                session['2fa_user_id'] = user.id
                session['2fa_remember'] = form.remember_me.data if hasattr(form, 'remember_me') else False
                return redirect(url_for('auth.verify_2fa'))

            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(user, remember=False)
            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_SUCCESS', f'User {user.username} logged in',
                      request.remote_addr)

            next_page = request.args.get('next')
            if user.role == 'patient':
                return redirect(next_page or url_for('patient.dashboard'))
            elif user.role == 'doctor':
                return redirect(next_page or url_for('doctor.dashboard'))
            else:
                return redirect(next_page or url_for('admin.dashboard'))
        else:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= current_app.config['ACCOUNT_LOCKOUT_ATTEMPTS']:
                user.locked_until = datetime.utcnow() + timedelta(
                    minutes=current_app.config['ACCOUNT_LOCKOUT_MINUTES']
                )
                flash(f'Account locked for {current_app.config["ACCOUNT_LOCKOUT_MINUTES"]} minutes due to too many failed attempts.', 'danger')
            else:
                attempts_left = current_app.config['ACCOUNT_LOCKOUT_ATTEMPTS'] - user.failed_login_attempts
                flash(f'Invalid credentials. {attempts_left} attempts remaining.', 'danger')

            db.session.commit()
            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_FAILED', f'Wrong password for {user.username}',
                      request.remote_addr)

    return render_template('auth/login.html', form=form)


@bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('auth.login'))

    user = User.query.get(session['2fa_user_id'])
    if not user:
        session.pop('2fa_user_id', None)
        return redirect(url_for('auth.login'))

    form = Setup2FAForm()
    if form.validate_on_submit():
        if verify_2fa_code(user.twofa_secret, form.totp_code.data):
            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(user, remember=False)
            session.pop('2fa_user_id', None)

            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_SUCCESS_2FA', f'User {user.username} logged in with 2FA',
                      request.remote_addr)
            flash('Logged in successfully with 2FA.', 'success')

            if user.role == 'patient':
                return redirect(url_for('patient.dashboard'))
            elif user.role == 'doctor':
                return redirect(url_for('doctor.dashboard'))
            else:
                return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid 2FA code', 'danger')

    return render_template('auth/verify_2fa.html', form=form)


@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit('3/minute', methods=['POST'])
@sanitize_params
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = sanitize_text(form.username.data)
        email = sanitize_text(form.email.data)
        password = form.password.data
        role = form.role.data

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role
        )
        db.session.add(user)
        db.session.flush()

        if role == 'patient':
            profile = Patient(user_id=user.id, full_name=username)
            db.session.add(profile)
        elif role == 'doctor':
            profile = Doctor(user_id=user.id, full_name=username, specialization='General')
            db.session.add(profile)

        db.session.commit()

        log_audit(current_app._get_current_object(), user.id,
                  'REGISTER', f'New {role} registered: {username}',
                  request.remote_addr)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@bp.route('/logout')
@login_required
def logout():
    log_audit(current_app._get_current_object(), current_user.id,
              'LOGOUT', f'User {current_user.username} logged out',
              request.remote_addr)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
@sanitize_params
def profile():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password_hash, form.current_password.data):
            current_user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            log_audit(current_app._get_current_object(), current_user.id,
                      'CHANGE_PASSWORD', 'Password changed',
                      request.remote_addr)
            flash('Password changed successfully!', 'success')
            return redirect(url_for('auth.profile'))
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('auth/profile.html', form=form)


@bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.is_2fa_enabled:
        flash('2FA is already enabled.', 'info')
        return redirect(url_for('auth.profile'))

    if not current_user.twofa_secret:
        current_user.twofa_secret = generate_2fa_secret()
        db.session.commit()

    secret = current_user.twofa_secret
    qrcode_data = generate_2fa_qrcode(secret, current_user.email)

    form = Setup2FAForm()
    if form.validate_on_submit():
        if verify_2fa_code(secret, form.totp_code.data):
            current_user.is_2fa_enabled = True
            db.session.commit()
            log_audit(current_app._get_current_object(), current_user.id,
                      'ENABLE_2FA', '2FA enabled',
                      request.remote_addr)
            flash('2FA has been enabled successfully!', 'success')
            return redirect(url_for('auth.profile'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')

    return render_template('auth/setup_2fa.html', form=form, secret=secret, qrcode=qrcode_data)


@bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    if not current_user.is_2fa_enabled:
        flash('2FA is not enabled.', 'info')
        return redirect(url_for('auth.profile'))

    form = Disable2FAForm()
    if form.validate_on_submit():
        if verify_2fa_code(current_user.twofa_secret, form.totp_code.data):
            current_user.is_2fa_enabled = False
            current_user.twofa_secret = None
            db.session.commit()
            log_audit(current_app._get_current_object(), current_user.id,
                      'DISABLE_2FA', '2FA disabled',
                      request.remote_addr)
            flash('2FA has been disabled.', 'warning')
        else:
            flash('Invalid 2FA code.', 'danger')

    return redirect(url_for('auth.profile'))
