from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, current_app, jsonify
)
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from app import db
from app.models import User, Patient, Doctor, Appointment, MedicalRecord, AuditLog
from app.forms import AdminUserEditForm
from app.decorators import role_required, sanitize_params
from app.utils import sanitize_text, log_audit
from datetime import datetime, timedelta

bp = Blueprint('admin', __name__, url_prefix='/admin')


@bp.route('/dashboard')
@login_required
@role_required('admin')
def dashboard():
    total_users = User.query.count()
    total_patients = Patient.query.count()
    total_doctors = Doctor.query.count()
    total_appointments = Appointment.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    locked_users = User.query.filter(User.locked_until > datetime.utcnow()).count()

    recent_logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).limit(10).all()

    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           total_patients=total_patients,
                           total_doctors=total_doctors,
                           total_appointments=total_appointments,
                           active_users=active_users,
                           locked_users=locked_users,
                           recent_logs=recent_logs)


@bp.route('/users')
@login_required
@role_required('admin')
def list_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template('admin/users.html', users=users)


@bp.route('/users/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
@sanitize_params
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminUserEditForm(obj=user)

    if form.validate_on_submit():
        user.username = sanitize_text(form.username.data)
        user.email = sanitize_text(form.email.data)
        user.role = form.role.data
        user.is_active = form.is_active.data
        db.session.commit()

        log_audit(current_app._get_current_object(), current_user.id,
                  'ADMIN_EDIT_USER', f'Edited user {user_id}: {user.username}',
                  request.remote_addr)
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/edit_user.html', form=form, edit_user=user)


@bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@role_required('admin')
def toggle_user_active(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot deactivate yourself.', 'danger')
        return redirect(url_for('admin.list_users'))

    user.is_active = not user.is_active
    db.session.commit()

    log_audit(current_app._get_current_object(), current_user.id,
              'ADMIN_TOGGLE_USER',
              f'{'Activated' if user.is_active else 'Deactivated'} user {user_id}',
              request.remote_addr)
    flash(f'User {user.username} {"activated" if user.is_active else "deactivated"}.', 'success')
    return redirect(url_for('admin.list_users'))


@bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@login_required
@role_required('admin')
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()

    log_audit(current_app._get_current_object(), current_user.id,
              'ADMIN_UNLOCK_USER', f'Unlocked user {user_id}',
              request.remote_addr)
    flash(f'User {user.username} unlocked.', 'success')
    return redirect(url_for('admin.list_users'))


@bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@role_required('admin')
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = 'TempPass123!'
    user.password_hash = generate_password_hash(new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()

    log_audit(current_app._get_current_object(), current_user.id,
              'ADMIN_RESET_PASSWORD', f'Reset password for user {user_id}',
              request.remote_addr)
    flash(f'Password for {user.username} reset to: {new_password}', 'warning')
    return redirect(url_for('admin.list_users'))


@bp.route('/logs')
@login_required
@role_required('admin')
def view_logs():
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user_id', type=int)

    query = AuditLog.query

    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    if user_filter:
        query = query.filter(AuditLog.user_id == user_filter)

    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )

    actions = db.session.query(AuditLog.action).distinct().all()
    actions = [a[0] for a in actions]

    return render_template('admin/logs.html', logs=logs, actions=actions)


@bp.route('/appointments')
@login_required
@role_required('admin')
def list_appointments():
    appointments = Appointment.query.order_by(
        Appointment.appointment_date.desc()
    ).all()
    return render_template('admin/appointments.html', appointments=appointments)
