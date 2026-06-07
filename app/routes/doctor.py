from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, current_app, Response
)
from flask_login import login_required, current_user
from datetime import datetime
from app import db
from app.models import User, Patient, Doctor, Appointment, MedicalRecord, AuditLog, VitalSign, LabResult
from app.forms import DoctorProfileForm, MedicalRecordForm, VitalSignForm, LabResultForm
from app.decorators import role_required, sanitize_params
from app.utils import secure_save_file, sanitize_text, sanitize_html, log_audit, read_encrypted_file

bp = Blueprint('doctor', __name__, url_prefix='/doctor')


@bp.route('/dashboard')
@login_required
@role_required('doctor')
def dashboard():
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        flash('Please complete your profile first.', 'warning')
        return redirect(url_for('doctor.edit_profile'))

    today = datetime.utcnow().date()
    today_appointments = Appointment.query.filter_by(
        doctor_id=doctor.id,
        appointment_date=today,
        status='scheduled'
    ).order_by(Appointment.appointment_time.asc()).all()

    upcoming_appointments = Appointment.query.filter_by(
        doctor_id=doctor.id,
        status='scheduled'
    ).filter(Appointment.appointment_date > today).order_by(
        Appointment.appointment_date.asc()
    ).limit(10).all()

    recent_patients = db.session.query(Patient).join(
        Appointment, Patient.id == Appointment.patient_id
    ).filter(
        Appointment.doctor_id == doctor.id
    ).distinct().limit(10).all()

    return render_template('doctor/dashboard.html',
                           doctor=doctor,
                           today_appointments=today_appointments,
                           upcoming_appointments=upcoming_appointments,
                           recent_patients=recent_patients)


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
@sanitize_params
def edit_profile():
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        doctor = Doctor(user_id=current_user.id, full_name=current_user.username, specialization='General')
        db.session.add(doctor)
        db.session.commit()

    form = DoctorProfileForm(obj=doctor)
    if form.validate_on_submit():
        doctor.full_name = sanitize_text(form.full_name.data)
        doctor.specialization = sanitize_text(form.specialization.data)
        doctor.phone = sanitize_text(form.phone.data)
        doctor.available_days = sanitize_text(form.available_days.data)
        doctor.bio = sanitize_text(form.bio.data)
        db.session.commit()

        log_audit(current_app._get_current_object(), current_user.id,
                  'UPDATE_PROFILE', 'Doctor profile updated',
                  request.remote_addr)
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('doctor.dashboard'))

    return render_template('doctor/profile.html', form=form, doctor=doctor)


@bp.route('/appointments')
@login_required
@role_required('doctor')
def list_appointments():
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return redirect(url_for('doctor.edit_profile'))

    appointments = Appointment.query.filter_by(
        doctor_id=doctor.id
    ).order_by(Appointment.appointment_date.desc()).all()

    return render_template('doctor/appointments.html', appointments=appointments)


@bp.route('/appointments/<int:appointment_id>/complete', methods=['POST'])
@login_required
@role_required('doctor')
def complete_appointment(appointment_id):
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    appointment = Appointment.query.filter_by(
        id=appointment_id, doctor_id=doctor.id
    ).first()

    if not appointment:
        flash('Appointment not found.', 'danger')
        return redirect(url_for('doctor.list_appointments'))

    appointment.status = 'completed'
    db.session.commit()

    log_audit(current_app._get_current_object(), current_user.id,
              'COMPLETE_APPOINTMENT', f'Appointment {appointment_id} completed',
              request.remote_addr)
    flash('Appointment marked as completed.', 'success')
    return redirect(url_for('doctor.list_appointments'))


@bp.route('/patients')
@login_required
@role_required('doctor')
def list_patients():
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return redirect(url_for('doctor.edit_profile'))

    patients = db.session.query(Patient).join(
        Appointment, Patient.id == Appointment.patient_id
    ).filter(
        Appointment.doctor_id == doctor.id
    ).distinct().all()

    return render_template('doctor/patients.html', patients=patients)


@bp.route('/patients/<int:patient_id>')
@login_required
@role_required('doctor')
def view_patient(patient_id):
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    patient = Patient.query.get_or_404(patient_id)

    appointments = Appointment.query.filter_by(
        patient_id=patient_id, doctor_id=doctor.id
    ).order_by(Appointment.appointment_date.desc()).all()

    records = MedicalRecord.query.filter_by(
        patient_id=patient_id, doctor_id=doctor.id
    ).order_by(MedicalRecord.created_at.desc()).all()

    vital_signs = VitalSign.query.filter_by(
        patient_id=patient.id
    ).order_by(VitalSign.recorded_at.desc()).limit(10).all()

    lab_results = LabResult.query.filter_by(
        patient_id=patient.id
    ).order_by(LabResult.test_date.desc()).limit(20).all()

    return render_template('doctor/view_patient.html',
                           patient=patient,
                           appointments=appointments,
                           records=records,
                           vital_signs=vital_signs,
                           lab_results=lab_results)


@bp.route('/patients/<int:patient_id>/add-record', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
@sanitize_params
def add_medical_record(patient_id):
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    patient = Patient.query.get_or_404(patient_id)

    form = MedicalRecordForm()
    if form.validate_on_submit():
        file_path = None
        if form.file.data:
            filename, error = secure_save_file(form.file.data)
            if error:
                flash(error, 'danger')
                return render_template('doctor/add_record.html', form=form, patient=patient)
            file_path = filename

        record = MedicalRecord(
            patient_id=patient.id,
            doctor_id=doctor.id,
            diagnosis=sanitize_html(form.diagnosis.data),
            prescription=sanitize_html(form.prescription.data),
            notes=sanitize_html(form.notes.data),
            file_path=file_path
        )
        db.session.add(record)
        db.session.commit()

        log_audit(current_app._get_current_object(), current_user.id,
                  'ADD_MEDICAL_RECORD',
                  f'Medical record added for patient {patient_id}',
                  request.remote_addr)
        flash('Medical record added successfully!', 'success')
        return redirect(url_for('doctor.view_patient', patient_id=patient_id))

    return render_template('doctor/add_record.html', form=form, patient=patient)


@bp.route('/patients/<int:patient_id>/vital-signs', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
@sanitize_params
def add_vital_signs(patient_id):
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    patient = Patient.query.get_or_404(patient_id)

    form = VitalSignForm()
    if form.validate_on_submit():
        vital = VitalSign(
            patient_id=patient.id,
            recorded_by_id=current_user.id,
            blood_pressure_systolic=form.blood_pressure_systolic.data,
            blood_pressure_diastolic=form.blood_pressure_diastolic.data,
            heart_rate=form.heart_rate.data,
            temperature=float(form.temperature.data) if form.temperature.data else None,
            oxygen_saturation=form.oxygen_saturation.data,
            weight_kg=float(form.weight_kg.data) if form.weight_kg.data else None,
            height_cm=float(form.height_cm.data) if form.height_cm.data else None,
            respiratory_rate=form.respiratory_rate.data,
            notes=sanitize_text(form.notes.data)
        )
        db.session.add(vital)
        db.session.commit()

        log_audit(current_app._get_current_object(), current_user.id,
                  'ADD_VITAL_SIGNS', f'Vital signs recorded for patient {patient_id}',
                  request.remote_addr)
        flash('Vital signs recorded successfully!', 'success')
        return redirect(url_for('doctor.view_patient', patient_id=patient_id))

    return render_template('doctor/add_vital_signs.html', form=form, patient=patient)


@bp.route('/patients/<int:patient_id>/lab-results', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
@sanitize_params
def add_lab_result(patient_id):
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    patient = Patient.query.get_or_404(patient_id)

    form = LabResultForm()
    if form.validate_on_submit():
        lab = LabResult(
            patient_id=patient.id,
            ordered_by_id=current_user.id,
            test_name=sanitize_text(form.test_name.data),
            test_value=sanitize_text(form.test_value.data),
            reference_range=sanitize_text(form.reference_range.data),
            unit=sanitize_text(form.unit.data),
            is_abnormal=form.is_abnormal.data,
            notes=sanitize_text(form.notes.data)
        )
        db.session.add(lab)
        db.session.commit()

        log_audit(current_app._get_current_object(), current_user.id,
                  'ADD_LAB_RESULT', f'Lab result added for patient {patient_id}: {form.test_name.data}',
                  request.remote_addr)
        flash('Lab result added successfully!', 'success')
        return redirect(url_for('doctor.view_patient', patient_id=patient_id))

    return render_template('doctor/add_lab_result.html', form=form, patient=patient)


@bp.route('/uploads/<filename>')
@login_required
@role_required('doctor')
def uploaded_file(filename):
    file_data = read_encrypted_file(filename)
    if file_data is None:
        flash('File not found.', 'danger')
        return redirect(url_for('doctor.dashboard'))

    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'bin'
    mimetypes = {
        'pdf': 'application/pdf',
        'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'gif': 'image/gif',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    }
    mimetype = mimetypes.get(ext, 'application/octet-stream')

    return Response(file_data, mimetype=mimetype,
                    headers={'Content-Disposition': f'inline; filename="{filename}"'})
