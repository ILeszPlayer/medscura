from flask import Blueprint, jsonify, request, current_app
from app import db
from app.models import User, Patient, Doctor, Appointment, MedicalRecord, AuditLog
from app.decorators import validate_json_request
from app.utils import decode_jwt_token, generate_jwt_token, log_audit
from werkzeug.security import check_password_hash
from functools import wraps
import re

bp = Blueprint('api', __name__, url_prefix='/api')


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401

        request.current_user_id = payload['sub']
        request.current_user_role = payload['role']
        return f(*args, **kwargs)
    return decorated


def api_role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.current_user_role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@bp.route('/auth/login', methods=['POST'])
@validate_json_request
def api_login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        user = User.query.filter_by(email=username).first()

    if not user or not user.is_active:
        return jsonify({'error': 'Invalid credentials'}), 401

    if check_password_hash(user.password_hash, password):
        token = generate_jwt_token(user.id, user.role)
        log_audit(current_app._get_current_object(), user.id,
                  'API_LOGIN', 'API login successful',
                  request.remote_addr)
        return jsonify({
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        }), 200

    return jsonify({'error': 'Invalid credentials'}), 401


@bp.route('/doctors', methods=['GET'])
def list_doctors():
    doctors = Doctor.query.all()
    return jsonify([{
        'id': d.id,
        'name': d.full_name,
        'specialization': d.specialization,
        'phone': d.phone,
        'available_days': d.available_days
    } for d in doctors])


@bp.route('/appointments', methods=['GET'])
@jwt_required
def get_appointments():
    if request.current_user_role == 'patient':
        patient = Patient.query.filter_by(user_id=request.current_user_id).first()
        if not patient:
            return jsonify({'error': 'Patient profile not found'}), 404
        appointments = Appointment.query.filter_by(patient_id=patient.id).all()
    elif request.current_user_role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=request.current_user_id).first()
        if not doctor:
            return jsonify({'error': 'Doctor profile not found'}), 404
        appointments = Appointment.query.filter_by(doctor_id=doctor.id).all()
    else:
        appointments = Appointment.query.all()

    return jsonify([{
        'id': a.id,
        'patient_name': a.patient.full_name if a.patient else 'N/A',
        'doctor_name': a.doctor.full_name if a.doctor else 'N/A',
        'date': a.appointment_date.isoformat() if a.appointment_date else None,
        'time': a.appointment_time.isoformat() if a.appointment_time else None,
        'status': a.status,
        'reason': a.reason
    } for a in appointments])


@bp.route('/appointments', methods=['POST'])
@jwt_required
@api_role_required('patient')
@validate_json_request
def create_appointment():
    data = request.get_json()
    patient = Patient.query.filter_by(user_id=request.current_user_id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404

    doctor_id = data.get('doctor_id')
    appointment_date = data.get('appointment_date')
    appointment_time = data.get('appointment_time')
    reason = data.get('reason', '')

    if not all([doctor_id, appointment_date, appointment_time]):
        return jsonify({'error': 'Missing required fields'}), 400

    doctor = Doctor.query.get(doctor_id)
    if not doctor:
        return jsonify({'error': 'Doctor not found'}), 404

    try:
        from datetime import datetime as dt
        date_obj = dt.strptime(appointment_date, '%Y-%m-%d').date()
        time_obj = dt.strptime(appointment_time, '%H:%M').time()
    except ValueError:
        return jsonify({'error': 'Invalid date/time format'}), 400

    appointment = Appointment(
        patient_id=patient.id,
        doctor_id=doctor_id,
        appointment_date=date_obj,
        appointment_time=time_obj,
        reason=reason,
        status='scheduled'
    )
    db.session.add(appointment)
    db.session.commit()

    return jsonify({'message': 'Appointment created', 'id': appointment.id}), 201


@bp.route('/medical-records/<int:patient_id>', methods=['GET'])
@jwt_required
def get_medical_records(patient_id):
    if request.current_user_role == 'patient':
        patient = Patient.query.filter_by(user_id=request.current_user_id).first()
        if not patient or patient.id != patient_id:
            return jsonify({'error': 'Access denied'}), 403
    elif request.current_user_role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=request.current_user_id).first()
        if not doctor:
            return jsonify({'error': 'Doctor profile not found'}), 404
        appointment = Appointment.query.filter_by(
            doctor_id=doctor.id, patient_id=patient_id
        ).first()
        if not appointment:
            return jsonify({'error': 'No doctor-patient relationship'}), 403

    records = MedicalRecord.query.filter_by(patient_id=patient_id).all()
    return jsonify([{
        'id': r.id,
        'doctor_name': r.doctor.full_name if r.doctor else 'N/A',
        'diagnosis': r.diagnosis,
        'prescription': r.prescription,
        'notes': r.notes,
        'file_url': f'/uploads/{r.file_path}' if r.file_path else None,
        'created_at': r.created_at.isoformat() if r.created_at else None
    } for r in records])


@bp.route('/profile', methods=['GET'])
@jwt_required
def get_profile():
    user = User.query.get(request.current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    profile_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'is_2fa_enabled': user.is_2fa_enabled,
        'created_at': user.created_at.isoformat() if user.created_at else None
    }

    if user.role == 'patient' and user.patient_profile:
        p = user.patient_profile
        profile_data['profile'] = {
            'full_name': p.full_name,
            'date_of_birth': p.date_of_birth.isoformat() if p.date_of_birth else None,
            'gender': p.gender,
            'phone': p.phone,
            'blood_type': p.blood_type,
            'allergies': p.allergies
        }
    elif user.role == 'doctor' and user.doctor_profile:
        d = user.doctor_profile
        profile_data['profile'] = {
            'full_name': d.full_name,
            'specialization': d.specialization,
            'phone': d.phone,
            'available_days': d.available_days,
            'bio': d.bio
        }

    return jsonify(profile_data)


@bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'MedSecure API',
        'version': '1.0.0'
    })
