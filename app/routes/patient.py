from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, current_app, send_from_directory
)
from flask_login import login_required, current_user
from datetime import datetime
from app import db
from app.models import User, Patient, Doctor, Appointment, MedicalRecord, AuditLog
from app.forms import PatientProfileForm, AppointmentForm
from app.decorators import role_required, sanitize_params
from app.utils import secure_save_file, sanitize_text, log_audit
import os

bp = Blueprint('patient', __name__, url_prefix='/patient')


@bp.route('/dashboard')
@login_required
@role_required('patient')
def dashboard():
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        flash('Please complete your profile first.', 'warning')
        return redirect(url_for('patient.edit_profile'))

    upcoming_appointments = Appointment.query.filter_by(
        patient_id=patient.id,
        status='scheduled'
    ).order_by(Appointment.appointment_date.asc()).limit(5).all()

    recent_records = MedicalRecord.query.filter_by(
        patient_id=patient.id
    ).order_by(MedicalRecord.created_at.desc()).limit(5).all()

    return render_template('patient/dashboard.html',
                           patient=patient,
                           upcoming_appointments=upcoming_appointments,
                           recent_records=recent_records)


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
@role_required('patient')
@sanitize_params
def edit_profile():
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        patient = Patient(user_id=current_user.id, full_name=current_user.username)
        db.session.add(patient)
        db.session.commit()

    form = PatientProfileForm(obj=patient)
    if form.validate_on_submit():
        patient.full_name = sanitize_text(form.full_name.data)
        patient.date_of_birth = form.date_of_birth.data
        patient.gender = form.gender.data
        patient.phone = sanitize_text(form.phone.data)
        patient.address = sanitize_text(form.address.data)
        patient.blood_type = form.blood_type.data
        patient.allergies = sanitize_text(form.allergies.data)
        db.session.commit()

        log_audit(current_app._get_current_object(), current_user.id,
                  'UPDATE_PROFILE', 'Patient profile updated',
                  request.remote_addr)
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('patient.dashboard'))

    return render_template('patient/profile.html', form=form, patient=patient)


@bp.route('/appointments')
@login_required
@role_required('patient')
def list_appointments():
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return redirect(url_for('patient.edit_profile'))

    appointments = Appointment.query.filter_by(
        patient_id=patient.id
    ).order_by(Appointment.appointment_date.desc()).all()

    return render_template('patient/appointments.html', appointments=appointments)


@bp.route('/appointments/book', methods=['GET', 'POST'])
@login_required
@role_required('patient')
@sanitize_params
def book_appointment():
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        flash('Please complete your profile first.', 'warning')
        return redirect(url_for('patient.edit_profile'))

    form = AppointmentForm()
    doctors = Doctor.query.all()
    form.doctor_id.choices = [(d.id, f'{d.full_name} - {d.specialization}') for d in doctors]

    if form.validate_on_submit():
        appointment = Appointment(
            patient_id=patient.id,
            doctor_id=form.doctor_id.data,
            appointment_date=form.appointment_date.data,
            appointment_time=form.appointment_time.data,
            reason=sanitize_text(form.reason.data),
            status='scheduled'
        )
        db.session.add(appointment)
        db.session.commit()

        log_audit(current_app._get_current_object(), current_user.id,
                  'BOOK_APPOINTMENT',
                  f'Appointment booked with doctor {form.doctor_id.data} on {form.appointment_date.data}',
                  request.remote_addr)
        flash('Appointment booked successfully!', 'success')
        return redirect(url_for('patient.list_appointments'))

    return render_template('patient/book_appointment.html', form=form)


@bp.route('/appointments/<int:appointment_id>/cancel', methods=['POST'])
@login_required
@role_required('patient')
def cancel_appointment(appointment_id):
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    appointment = Appointment.query.filter_by(
        id=appointment_id, patient_id=patient.id
    ).first()

    if not appointment:
        flash('Appointment not found.', 'danger')
        return redirect(url_for('patient.list_appointments'))

    if appointment.status != 'scheduled':
        flash('Cannot cancel this appointment.', 'danger')
        return redirect(url_for('patient.list_appointments'))

    appointment.status = 'cancelled'
    db.session.commit()

    log_audit(current_app._get_current_object(), current_user.id,
              'CANCEL_APPOINTMENT', f'Appointment {appointment_id} cancelled',
              request.remote_addr)
    flash('Appointment cancelled.', 'info')
    return redirect(url_for('patient.list_appointments'))


@bp.route('/medical-records')
@login_required
@role_required('patient')
def medical_records():
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return redirect(url_for('patient.edit_profile'))

    records = MedicalRecord.query.filter_by(
        patient_id=patient.id
    ).order_by(MedicalRecord.created_at.desc()).all()

    return render_template('patient/medical_records.html', records=records)


@bp.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    record = MedicalRecord.query.filter_by(file_path=filename).first()
    if not patient or not record or record.patient_id != patient.id:
        if current_user.role != 'admin' and current_user.role != 'doctor':
            flash('Access denied.', 'danger')
            return redirect(url_for('patient.dashboard'))
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)
