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
        from app.models import User, Patient, Doctor, Appointment
        return render_template('landing.html',
                               User=User, Patient=Patient,
                               Doctor=Doctor, Appointment=Appointment)

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
        from app.models import User, Patient, Doctor, Appointment, Disease, Medication
        from werkzeug.security import generate_password_hash

        if not User.query.filter_by(role='admin').first():
            admin_user = User(
                username='admin',
                email='admin@medsecure.com',
                password_hash=generate_password_hash('Admin123!'),
                role='admin',
                is_active=True
            )
            db.session.add(admin_user)
            db.session.commit()

        if not User.query.filter_by(role='doctor').first():
            doctor_user = User(
                username='dr.sari',
                email='drsari@medsecure.com',
                password_hash=generate_password_hash('Dokter123!'),
                role='doctor',
                is_active=True
            )
            db.session.add(doctor_user)
            db.session.flush()
            doctor_profile = Doctor(
                user_id=doctor_user.id,
                full_name='dr. Sari Dewi, Sp.PD',
                specialization='Penyakit Dalam',
                phone='081234567890',
                available_days='Senin, Selasa, Rabu, Kamis, Jumat',
                bio='Dokter spesialis penyakit dalam dengan pengalaman 10 tahun.'
            )
            db.session.add(doctor_profile)

            doctor_user2 = User(
                username='dr.budi',
                email='drbudi@medsecure.com',
                password_hash=generate_password_hash('Dokter123!'),
                role='doctor',
                is_active=True
            )
            db.session.add(doctor_user2)
            db.session.flush()
            doctor_profile2 = Doctor(
                user_id=doctor_user2.id,
                full_name='dr. Budi Santoso, Sp.A',
                specialization='Pediatri (Anak)',
                phone='081234567891',
                available_days='Senin, Rabu, Jumat',
                bio='Dokter spesialis anak yang ramah dan berpengalaman.'
            )
            db.session.add(doctor_profile2)

            doctor_user3 = User(
                username='dr.anita',
                email='dranita@medsecure.com',
                password_hash=generate_password_hash('Dokter123!'),
                role='doctor',
                is_active=True
            )
            db.session.add(doctor_user3)
            db.session.flush()
            doctor_profile3 = Doctor(
                user_id=doctor_user3.id,
                full_name='dr. Anita Putri, Sp.OG',
                specialization='Obstetri & Ginekologi',
                phone='081234567892',
                available_days='Selasa, Kamis, Sabtu',
                bio='Dokter spesialis kebidanan dan kandungan.'
            )
            db.session.add(doctor_profile3)

        if not User.query.filter_by(role='patient').first():
            patient_user = User(
                username='rina',
                email='rina@email.com',
                password_hash=generate_password_hash('Pasien123!'),
                role='patient',
                is_active=True
            )
            db.session.add(patient_user)
            db.session.flush()
            patient_profile = Patient(
                user_id=patient_user.id,
                full_name='Rina Amelia',
                date_of_birth=datetime(1995, 6, 15),
                gender='female',
                phone='081234567893',
                address='Jl. Merdeka No. 45, Jakarta',
                blood_type='O+',
                allergies='Amoxicillin'
            )
            db.session.add(patient_profile)

            patient_user2 = User(
                username='bambang',
                email='bambang@email.com',
                password_hash=generate_password_hash('Pasien123!'),
                role='patient',
                is_active=True
            )
            db.session.add(patient_user2)
            db.session.flush()
            patient_profile2 = Patient(
                user_id=patient_user2.id,
                full_name='Bambang Suprapto',
                date_of_birth=datetime(1988, 3, 22),
                gender='male',
                phone='081234567894',
                address='Jl. Sudirman No. 88, Bandung',
                blood_type='A+'
            )
            db.session.add(patient_profile2)

            patient_user3 = User(
                username='siti',
                email='siti@email.com',
                password_hash=generate_password_hash('Pasien123!'),
                role='patient',
                is_active=True
            )
            db.session.add(patient_user3)
            db.session.flush()
            patient_profile3 = Patient(
                user_id=patient_user3.id,
                full_name='Siti Rahmawati',
                date_of_birth=datetime(2000, 11, 8),
                gender='female',
                phone='081234567895',
                address='Jl. Diponegoro No. 12, Surabaya',
                blood_type='B+',
                allergies='Kacang-kacangan'
            )
            db.session.add(patient_profile3)
            db.session.commit()

        if not Appointment.query.first():
            from datetime import time, date, timedelta
            doctors = Doctor.query.all()
            patients = Patient.query.all()
            if doctors and patients:
                tomorrow = date.today() + timedelta(days=1)
                day_after = date.today() + timedelta(days=2)
                appointments = [
                    Appointment(
                        patient_id=patients[0].id,
                        doctor_id=doctors[0].id,
                        appointment_date=tomorrow,
                        appointment_time=time(9, 0),
                        status='scheduled',
                        reason='Kontrol rutin tekanan darah tinggi'
                    ),
                    Appointment(
                        patient_id=patients[1].id,
                        doctor_id=doctors[1].id,
                        appointment_date=tomorrow,
                        appointment_time=time(10, 30),
                        status='scheduled',
                        reason='Demam dan batuk sejak 3 hari'
                    ),
                    Appointment(
                        patient_id=patients[2].id,
                        doctor_id=doctors[2].id,
                        appointment_date=day_after,
                        appointment_time=time(14, 0),
                        status='scheduled',
                        reason='Pemeriksaan kehamilan rutin'
                    ),
                    Appointment(
                        patient_id=patients[0].id,
                        doctor_id=doctors[0].id,
                        appointment_date=date.today(),
                        appointment_time=time(8, 0),
                        status='completed',
                        reason='Cek lab rutin'
                    ),
                    Appointment(
                        patient_id=patients[1].id,
                        doctor_id=doctors[0].id,
                        appointment_date=date.today() - timedelta(days=7),
                        appointment_time=time(11, 0),
                        status='completed',
                        reason='Keluhan sakit kepala'
                    ),
                ]
                db.session.add_all(appointments)
                db.session.commit()

            from app.models import VitalSign, LabResult
            if patients and not VitalSign.query.first():
                vitals = [
                    VitalSign(
                        patient_id=patients[0].id,
                        blood_pressure_systolic=130,
                        blood_pressure_diastolic=85,
                        heart_rate=78,
                        temperature=36.5,
                        oxygen_saturation=98,
                        weight_kg=65,
                        height_cm=160,
                        respiratory_rate=18,
                    ),
                    VitalSign(
                        patient_id=patients[1].id,
                        blood_pressure_systolic=120,
                        blood_pressure_diastolic=80,
                        heart_rate=88,
                        temperature=38.2,
                        oxygen_saturation=96,
                        weight_kg=72,
                        height_cm=170,
                        respiratory_rate=22,
                    ),
                ]
                db.session.add_all(vitals)
                db.session.commit()

            if patients and not LabResult.query.first():
                labs = [
                    LabResult(
                        patient_id=patients[0].id,
                        test_name='Hemoglobin',
                        test_value='13.5',
                        reference_range='12.0 - 16.0',
                        unit='g/dL',
                        is_abnormal=False
                    ),
                    LabResult(
                        patient_id=patients[0].id,
                        test_name='Gula Darah Puasa',
                        test_value='145',
                        reference_range='70 - 110',
                        unit='mg/dL',
                        is_abnormal=True
                    ),
                    LabResult(
                        patient_id=patients[1].id,
                        test_name='Hemoglobin',
                        test_value='11.2',
                        reference_range='12.0 - 16.0',
                        unit='g/dL',
                        is_abnormal=True
                    ),
                ]
                db.session.add_all(labs)
                db.session.commit()

        if not Disease.query.first():
            diseases = [
                Disease(icd10_code='A00', name='Cholera', category='Infectious Diseases'),
                Disease(icd10_code='A09', name='Infectious Gastroenteritis', category='Infectious Diseases'),
                Disease(icd10_code='A15', name='Tuberculosis of Respiratory System', category='Infectious Diseases'),
                Disease(icd10_code='B20', name='HIV Disease', category='Infectious Diseases'),
                Disease(icd10_code='C50', name='Malignant Neoplasm of Breast', category='Neoplasms'),
                Disease(icd10_code='C61', name='Malignant Neoplasm of Prostate', category='Neoplasms'),
                Disease(icd10_code='C80', name='Malignant Neoplasm without Specification', category='Neoplasms'),
                Disease(icd10_code='E10', name='Type 1 Diabetes Mellitus', category='Endocrine Diseases'),
                Disease(icd10_code='E11', name='Type 2 Diabetes Mellitus', category='Endocrine Diseases'),
                Disease(icd10_code='E66', name='Obesity', category='Endocrine Diseases'),
                Disease(icd10_code='E78', name='Hyperlipidemia', category='Endocrine Diseases'),
                Disease(icd10_code='F32', name='Major Depressive Disorder', category='Mental Disorders'),
                Disease(icd10_code='F41', name='Anxiety Disorder', category='Mental Disorders'),
                Disease(icd10_code='G40', name='Epilepsy', category='Nervous System'),
                Disease(icd10_code='I10', name='Essential Hypertension', category='Circulatory System'),
                Disease(icd10_code='I25', name='Chronic Ischemic Heart Disease', category='Circulatory System'),
                Disease(icd10_code='I48', name='Atrial Fibrillation', category='Circulatory System'),
                Disease(icd10_code='I50', name='Heart Failure', category='Circulatory System'),
                Disease(icd10_code='J15', name='Bacterial Pneumonia', category='Respiratory System'),
                Disease(icd10_code='J45', name='Asthma', category='Respiratory System'),
                Disease(icd10_code='K21', name='Gastroesophageal Reflux Disease', category='Digestive System'),
                Disease(icd10_code='K29', name='Gastritis', category='Digestive System'),
                Disease(icd10_code='M05', name='Rheumatoid Arthritis', category='Musculoskeletal'),
                Disease(icd10_code='M54', name='Dorsalgia (Back Pain)', category='Musculoskeletal'),
                Disease(icd10_code='N18', name='Chronic Kidney Disease', category='Genitourinary System'),
                Disease(icd10_code='N39', name='Urinary Tract Infection', category='Genitourinary System'),
                Disease(icd10_code='R05', name='Cough', category='Symptoms'),
                Disease(icd10_code='R10', name='Abdominal Pain', category='Symptoms'),
                Disease(icd10_code='R51', name='Headache', category='Symptoms'),
                Disease(icd10_code='Z23', name='Immunization', category='Health Status'),
            ]
            db.session.add_all(diseases)
            db.session.commit()

        if not Medication.query.first():
            medications = [
                Medication(name='Amlodipine', generic_name='Amlodipine Besylate', dosage_form='Tablet', strength='5 mg, 10 mg', description='Calcium channel blocker for hypertension'),
                Medication(name='Metformin', generic_name='Metformin Hydrochloride', dosage_form='Tablet', strength='500 mg, 850 mg, 1000 mg', description='First-line for type 2 diabetes'),
                Medication(name='Atorvastatin', generic_name='Atorvastatin Calcium', dosage_form='Tablet', strength='10 mg, 20 mg, 40 mg', description='Statin for hyperlipidemia'),
                Medication(name='Lisinopril', generic_name='Lisinopril', dosage_form='Tablet', strength='5 mg, 10 mg, 20 mg', description='ACE inhibitor for hypertension'),
                Medication(name='Omeprazole', generic_name='Omeprazole', dosage_form='Capsule', strength='20 mg, 40 mg', description='Proton pump inhibitor for GERD'),
                Medication(name='Metoprolol', generic_name='Metoprolol Tartrate', dosage_form='Tablet', strength='25 mg, 50 mg, 100 mg', description='Beta blocker for hypertension and heart failure'),
                Medication(name='Salbutamol', generic_name='Albuterol Sulfate', dosage_form='Inhaler', strength='100 mcg/dose', description='Bronchodilator for asthma'),
                Medication(name='Paracetamol', generic_name='Acetaminophen', dosage_form='Tablet', strength='500 mg, 650 mg', description='Analgesic and antipyretic'),
                Medication(name='Ibuprofen', generic_name='Ibuprofen', dosage_form='Tablet', strength='200 mg, 400 mg', description='NSAID for pain and inflammation'),
                Medication(name='Amoxicillin', generic_name='Amoxicillin Trihydrate', dosage_form='Capsule', strength='250 mg, 500 mg', description='Broad-spectrum antibiotic'),
                Medication(name='Azithromycin', generic_name='Azithromycin', dosage_form='Tablet', strength='250 mg, 500 mg', description='Macrolide antibiotic'),
                Medication(name='Ciprofloxacin', generic_name='Ciprofloxacin', dosage_form='Tablet', strength='250 mg, 500 mg', description='Fluoroquinolone antibiotic'),
                Medication(name='Furosemide', generic_name='Furosemide', dosage_form='Tablet', strength='20 mg, 40 mg', description='Loop diuretic for heart failure'),
                Medication(name='Warfarin', generic_name='Warfarin Sodium', dosage_form='Tablet', strength='1 mg, 2 mg, 5 mg', description='Anticoagulant'),
                Medication(name='Insulin Glargine', generic_name='Insulin Glargine', dosage_form='Injection', strength='100 U/mL', description='Long-acting insulin for diabetes'),
                Medication(name='Levothyroxine', generic_name='Levothyroxine Sodium', dosage_form='Tablet', strength='25 mcg, 50 mcg, 100 mcg', description='Thyroid hormone replacement'),
                Medication(name='Prednisone', generic_name='Prednisone', dosage_form='Tablet', strength='5 mg, 10 mg, 20 mg', description='Corticosteroid anti-inflammatory'),
                Medication(name='Sertraline', generic_name='Sertraline Hydrochloride', dosage_form='Tablet', strength='25 mg, 50 mg, 100 mg', description='SSRI antidepressant'),
                Medication(name='Aspirin', generic_name='Acetylsalicylic Acid', dosage_form='Tablet', strength='81 mg, 325 mg', description='Antiplatelet therapy'),
                Medication(name='Losartan', generic_name='Losartan Potassium', dosage_form='Tablet', strength='25 mg, 50 mg, 100 mg', description='ARB for hypertension'),
            ]
            db.session.add_all(medications)
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
            if last_active and isinstance(last_active, datetime):
                if last_active.tzinfo is not None:
                    last_active = last_active.replace(tzinfo=None)
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
