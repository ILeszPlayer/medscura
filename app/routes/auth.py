from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, current_app, jsonify, session
)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from app import db, limiter
from app.models import User, Patient, Doctor, AuditLog, PasswordResetToken, SuspiciousIP, UserSession
from app.forms import LoginForm, RegistrationForm, ChangePasswordForm, Setup2FAForm, Disable2FAForm, ForgotPasswordForm, ResetPasswordForm, DeleteAccountForm
from app.decorators import sanitize_params, check_ip_blocked
from app.utils import (
    generate_2fa_secret, generate_2fa_qrcode, verify_2fa_code,
    log_audit, sanitize_text, generate_reset_token, verify_reset_token,
    track_suspicious_ip, is_ip_blocked, hash_ip
)
from itsdangerous import URLSafeTimedSerializer

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('10/minute', methods=['POST'])
@check_ip_blocked
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
            track_suspicious_ip(request.remote_addr, 'Failed login attempt - invalid username')
            flash('Invalid credentials', 'danger')
            log_audit(current_app._get_current_object(), None,
                      'LOGIN_FAILED', f'Invalid username/email: {username}',
                      request.remote_addr, request.user_agent.string if request.user_agent else None)
            return render_template('auth/login.html', form=form)

        if not user.is_active:
            flash('Account is disabled. Contact administrator.', 'danger')
            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_BLOCKED', 'Account disabled',
                      request.remote_addr, request.user_agent.string if request.user_agent else None)
            return render_template('auth/login.html', form=form)

        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining = (user.locked_until - datetime.utcnow()).seconds // 60
            flash(f'Account locked. Try again in {remaining} minutes.', 'danger')
            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_BLOCKED', f'Account locked until {user.locked_until}',
                      request.remote_addr, request.user_agent.string if request.user_agent else None)
            return render_template('auth/login.html', form=form)

        if check_password_hash(user.password_hash, password):
            if user.is_2fa_enabled:
                trusted = request.cookies.get('trusted_device')
                if trusted:
                    try:
                        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt='trusted-device')
                        data = s.loads(trusted, max_age=2592000)
                        if data.get('user_id') == user.id:
                            user.failed_login_attempts = 0
                            user.last_login = datetime.utcnow()
                            user.last_login_ip = request.remote_addr
                            db.session.commit()
                            login_user(user, remember=False)
                            log_audit(current_app._get_current_object(), user.id,
                                      'LOGIN_SUCCESS_TRUSTED', 'Login via trusted device (skipped 2FA)',
                                      request.remote_addr, request.user_agent.string if request.user_agent else None)
                            if user.role == 'patient':
                                return redirect(url_for('patient.dashboard'))
                            elif user.role == 'doctor':
                                return redirect(url_for('doctor.dashboard'))
                            return redirect(url_for('admin.dashboard'))
                    except Exception:
                        pass
                session['2fa_user_id'] = user.id
                return redirect(url_for('auth.verify_2fa'))

            is_new_ip = False
            if user.last_login_ip and user.last_login_ip != request.remote_addr:
                is_new_ip = True
                log_audit(current_app._get_current_object(), user.id,
                          'LOGIN_NEW_IP', f'Login from new IP: {request.remote_addr} (previous: {user.last_login_ip})',
                          request.remote_addr, request.user_agent.string if request.user_agent else None)
                flash('Login from a new device or location detected.', 'warning')

            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            user.last_login_ip = request.remote_addr
            db.session.commit()

            login_user(user, remember=False)

            if user.password_expires_at and user.password_expires_at < datetime.utcnow():
                flash('Your password has expired. Please change it now.', 'warning')
                return redirect(url_for('auth.profile'))

            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_SUCCESS', f'User {user.username} logged in',
                      request.remote_addr, request.user_agent.string if request.user_agent else None)

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

            track_suspicious_ip(request.remote_addr, 'Failed login - wrong password')
            db.session.commit()
            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_FAILED', f'Wrong password for {user.username}',
                      request.remote_addr, request.user_agent.string if request.user_agent else None)

    return render_template('auth/login.html', form=form)


@bp.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit('10/minute', methods=['POST'])
@check_ip_blocked
def verify_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('auth.login'))

    user = User.query.get(session['2fa_user_id'])
    if not user:
        session.pop('2fa_user_id', None)
        return redirect(url_for('auth.login'))

    twofa_attempts = session.get('twofa_attempts', 0)
    if twofa_attempts >= current_app.config.get('TWOFA_MAX_ATTEMPTS', 5):
        flash('Too many 2FA attempts. Please login again.', 'danger')
        session.pop('2fa_user_id', None)
        session.pop('twofa_attempts', None)
        return redirect(url_for('auth.login'))

    form = Setup2FAForm()
    if form.validate_on_submit():
        if verify_2fa_code(user.twofa_secret, form.totp_code.data):
            is_new_ip = False
            if user.last_login_ip and user.last_login_ip != request.remote_addr:
                is_new_ip = True
                log_audit(current_app._get_current_object(), user.id,
                          'LOGIN_NEW_IP', f'2FA Login from new IP: {request.remote_addr}',
                          request.remote_addr, request.user_agent.string if request.user_agent else None)
                flash('Login from a new device or location detected.', 'warning')

            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            user.last_login_ip = request.remote_addr
            db.session.commit()

            login_user(user, remember=False)
            session.pop('2fa_user_id', None)
            session.pop('twofa_attempts', None)

            log_audit(current_app._get_current_object(), user.id,
                      'LOGIN_SUCCESS_2FA', f'User {user.username} logged in with 2FA',
                      request.remote_addr, request.user_agent.string if request.user_agent else None)
            flash('Logged in successfully with 2FA.', 'success')

            resp = None
            if form.trust_device.data:
                s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt='trusted-device')
                token = s.dumps({'user_id': user.id})
                resp = redirect(url_for('patient.dashboard' if user.role == 'patient'
                                        else 'doctor.dashboard' if user.role == 'doctor'
                                        else 'admin.dashboard'))
                resp.set_cookie('trusted_device', token, max_age=2592000,
                                httponly=True, samesite='Lax',
                                secure=current_app.config['SESSION_COOKIE_SECURE'])
                log_audit(current_app._get_current_object(), user.id,
                          'TRUST_DEVICE', 'Device trusted for 30 days, 2FA skipped on future logins',
                          request.remote_addr, request.user_agent.string if request.user_agent else None)

            if user.role == 'patient':
                return resp or redirect(url_for('patient.dashboard'))
            elif user.role == 'doctor':
                return resp or redirect(url_for('doctor.dashboard'))
            else:
                return resp or redirect(url_for('admin.dashboard'))
        else:
            session['twofa_attempts'] = twofa_attempts + 1
            remaining = current_app.config.get('TWOFA_MAX_ATTEMPTS', 5) - session['twofa_attempts']
            track_suspicious_ip(request.remote_addr, 'Failed 2FA code')

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
            role=role,
            last_password_change=datetime.utcnow()
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
                  request.remote_addr, request.user_agent.string if request.user_agent else None)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@bp.route('/logout')
@login_required
def logout():
    log_audit(current_app._get_current_object(), current_user.id,
              'LOGOUT', f'User {current_user.username} logged out',
              request.remote_addr, request.user_agent.string if request.user_agent else None)
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
            current_user.last_password_change = datetime.utcnow()
            current_user.password_expires_at = datetime.utcnow() + timedelta(days=90)
            UserSession.query.filter_by(
                user_id=current_user.id, is_active=True
            ).filter(UserSession.id != session.get('session_id', 0)).update(
                {'is_active': False}
            )
            db.session.commit()
            log_audit(current_app._get_current_object(), current_user.id,
                      'CHANGE_PASSWORD', 'Password changed, other sessions revoked',
                      request.remote_addr, request.user_agent.string if request.user_agent else None)
            flash('Password changed successfully! Other sessions revoked. Password expires in 90 days.', 'success')
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
                      request.remote_addr, request.user_agent.string if request.user_agent else None)
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
                      request.remote_addr, request.user_agent.string if request.user_agent else None)
            flash('2FA has been disabled.', 'warning')
        else:
            flash('Invalid 2FA code.', 'danger')

    return redirect(url_for('auth.profile'))


@bp.route('/clear-trusted-devices', methods=['POST'])
@login_required
def clear_trusted_devices():
    resp = redirect(url_for('auth.profile'))
    resp.delete_cookie('trusted_device')
    log_audit(current_app._get_current_object(), current_user.id,
              'CLEAR_TRUSTED_DEVICES', 'All trusted devices cleared',
              request.remote_addr, request.user_agent.string if request.user_agent else None)
    flash('Trusted devices list cleared.', 'info')
    return resp


@bp.route('/sessions')
@login_required
def list_sessions():
    sessions = UserSession.query.filter_by(
        user_id=current_user.id, is_active=True
    ).order_by(UserSession.last_activity.desc()).all()
    return render_template('auth/sessions.html', sessions=sessions)


@bp.route('/sessions/<int:session_id>/revoke', methods=['POST'])
@login_required
def revoke_session(session_id):
    user_session = UserSession.query.filter_by(
        id=session_id, user_id=current_user.id
    ).first()
    if not user_session:
        flash('Session not found.', 'danger')
        return redirect(url_for('auth.list_sessions'))

    user_session.is_active = False
    db.session.commit()

    log_audit(current_app._get_current_object(), current_user.id,
              'REVOKE_SESSION', f'Revoked session {session_id}',
              request.remote_addr, request.user_agent.string if request.user_agent else None)
    flash('Session revoked.', 'success')
    return redirect(url_for('auth.list_sessions'))


@bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit('5/minute', methods=['POST'])
@check_ip_blocked
@sanitize_params
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('auth.profile'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = sanitize_text(form.email.data)
        user = User.query.filter_by(email=email).first()

        if user:
            existing = PasswordResetToken.query.filter_by(
                user_id=user.id, used=False
            ).filter(PasswordResetToken.expires_at > datetime.utcnow()).first()
            if existing:
                flash('A reset link has already been sent to your email.', 'info')
                return redirect(url_for('auth.login'))

            token = generate_reset_token(user.id)
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(
                    hours=current_app.config.get('RESET_TOKEN_EXPIRY_HOURS', 1)
                )
            )
            db.session.add(reset_token)
            db.session.commit()

            log_audit(current_app._get_current_object(), user.id,
                      'PASSWORD_RESET_REQUEST',
                      f'Password reset requested for {email}',
                      request.remote_addr, request.user_agent.string if request.user_agent else None)

            reset_url = url_for('auth.reset_password', token=token, _external=True)
            flash(f'Reset link sent! (Demo: {reset_url})', 'success')
        else:
            flash('If that email is registered, a reset link has been sent.', 'info')

        return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password.html', form=form)


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit('5/minute', methods=['POST'])
@check_ip_blocked
@sanitize_params
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('auth.profile'))

    user_id = verify_reset_token(token)
    if not user_id:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    reset_record = PasswordResetToken.query.filter_by(
        token=token, used=False
    ).filter(PasswordResetToken.expires_at > datetime.utcnow()).first()

    if not reset_record or reset_record.is_expired():
        flash('Reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data)
        user.failed_login_attempts = 0
        user.locked_until = None
        reset_record.used = True
        db.session.commit()

        log_audit(current_app._get_current_object(), user.id,
                  'PASSWORD_RESET_COMPLETE', 'Password reset completed',
                  request.remote_addr, request.user_agent.string if request.user_agent else None)

        flash('Password has been reset successfully. Please login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', form=form, token=token)


@bp.route('/delete-account', methods=['GET', 'POST'])
@login_required
@sanitize_params
def delete_account():
    form = DeleteAccountForm()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password_hash, form.password.data):
            flash('Current password is incorrect.', 'danger')
            return render_template('auth/delete_account.html', form=form)

        if form.confirmation.data != 'DELETE':
            flash('Please type "DELETE" to confirm.', 'danger')
            return render_template('auth/delete_account.html', form=form)

        user_id = current_user.id
        username = current_user.username

        Patient.query.filter_by(user_id=user_id).delete()
        Doctor.query.filter_by(user_id=user_id).delete()
        PasswordResetToken.query.filter_by(user_id=user_id).delete()

        log_audit(current_app._get_current_object(), user_id,
                  'DELETE_ACCOUNT', f'User {username} deleted own account',
                  request.remote_addr, request.user_agent.string if request.user_agent else None)

        User.query.filter_by(id=user_id).delete()
        db.session.commit()

        logout_user()
        flash('Your account has been deleted.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('auth/delete_account.html', form=form)
