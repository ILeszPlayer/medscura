from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='patient')
    is_active = db.Column(db.Boolean, default=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.String(64), nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    password_expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    patient_profile = db.relationship('Patient', backref='user', uselist=False, lazy=True)
    doctor_profile = db.relationship('Doctor', backref='user', uselist=False, lazy=True)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class Patient(db.Model):
    __tablename__ = 'patients'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(150), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    blood_type = db.Column(db.String(5), nullable=True)
    allergies = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    appointments = db.relationship('Appointment', backref='patient', lazy=True, foreign_keys='Appointment.patient_id')
    medical_records = db.relationship('MedicalRecord', backref='patient', lazy=True, foreign_keys='MedicalRecord.patient_id')

    def __repr__(self):
        return f'<Patient {self.full_name}>'


class Doctor(db.Model):
    __tablename__ = 'doctors'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(150), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    available_days = db.Column(db.String(200), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    appointments = db.relationship('Appointment', backref='doctor', lazy=True, foreign_keys='Appointment.doctor_id')
    medical_records = db.relationship('MedicalRecord', backref='doctor', lazy=True, foreign_keys='MedicalRecord.doctor_id')

    def __repr__(self):
        return f'<Doctor {self.full_name} ({self.specialization})>'


class Appointment(db.Model):
    __tablename__ = 'appointments'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    appointment_date = db.Column(db.Date, nullable=False)
    appointment_time = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='scheduled')
    reason = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Appointment {self.id}: {self.appointment_date} {self.appointment_time}>'


class MedicalRecord(db.Model):
    __tablename__ = 'medical_records'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    diagnosis = db.Column(db.Text, nullable=True)
    prescription = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<MedicalRecord {self.id}>'


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship('User', backref='audit_logs', lazy=True)

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user_id} at {self.timestamp}>'


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(256), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='reset_tokens', lazy=True)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def __repr__(self):
        return f'<PasswordResetToken for user {self.user_id}>'


class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(256), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='sessions', lazy=True)

    def __repr__(self):
        return f'<UserSession {self.id} for user {self.user_id}>'


class SuspiciousIP(db.Model):
    __tablename__ = 'suspicious_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    reason = db.Column(db.String(200), nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=True)
    attempt_count = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def is_blocked(self):
        return self.blocked_until and self.blocked_until > datetime.utcnow()

    def __repr__(self):
        return f'<SuspiciousIP {self.ip_address}>'
