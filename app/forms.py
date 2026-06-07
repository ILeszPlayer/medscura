from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, DateField, TimeField, FileField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional
from app.models import User
import re


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    totp_code = StringField('2FA Code', validators=[Optional(), Length(min=6, max=6)])


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=80),
        lambda form, field: validate_username(field)
    ])
    email = StringField('Email', validators=[
        DataRequired(), Email(), Length(max=120),
        lambda form, field: validate_email(field)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        lambda form, field: validate_password_strength(field)
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match')
    ])
    role = SelectField('Register As', choices=[
        ('patient', 'Patient'),
        ('doctor', 'Doctor')
    ], validators=[DataRequired()])

    def validate_username(form, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')
        if not re.match(r'^[a-zA-Z0-9_]+$', field.data):
            raise ValidationError('Username must contain only letters, numbers, and underscores')

    def validate_email(form, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')


def validate_password_strength(field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain an uppercase letter')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain a lowercase letter')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain a digit')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_]', password):
        raise ValidationError('Password must contain a special character')


class PatientProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=150)])
    date_of_birth = DateField('Date of Birth', validators=[Optional()], format='%Y-%m-%d')
    gender = SelectField('Gender', choices=[
        ('', 'Select Gender'), ('male', 'Male'), ('female', 'Female')
    ], validators=[Optional()])
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    address = TextAreaField('Address', validators=[Optional(), Length(max=500)])
    blood_type = SelectField('Blood Type', choices=[
        ('', 'Select Blood Type'), ('A+', 'A+'), ('A-', 'A-'),
        ('B+', 'B+'), ('B-', 'B-'), ('AB+', 'AB+'), ('AB-', 'AB-'),
        ('O+', 'O+'), ('O-', 'O-')
    ], validators=[Optional()])
    allergies = TextAreaField('Allergies', validators=[Optional(), Length(max=500)])


class DoctorProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=150)])
    specialization = StringField('Specialization', validators=[DataRequired(), Length(max=100)])
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    available_days = StringField('Available Days (comma separated)', validators=[Optional(), Length(max=200)])
    bio = TextAreaField('Bio', validators=[Optional(), Length(max=1000)])


class AppointmentForm(FlaskForm):
    doctor_id = SelectField('Doctor', coerce=int, validators=[DataRequired()])
    appointment_date = DateField('Date', validators=[DataRequired()], format='%Y-%m-%d')
    appointment_time = TimeField('Time', validators=[DataRequired()], format='%H:%M')
    reason = TextAreaField('Reason for Visit', validators=[Optional(), Length(max=500)])


class MedicalRecordForm(FlaskForm):
    diagnosis = TextAreaField('Diagnosis', validators=[DataRequired(), Length(max=2000)])
    prescription = TextAreaField('Prescription', validators=[Optional(), Length(max=2000)])
    notes = TextAreaField('Additional Notes', validators=[Optional(), Length(max=2000)])
    file = FileField('Attach File', validators=[Optional()])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        lambda form, field: validate_password_strength(field)
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), EqualTo('new_password', message='Passwords must match')
    ])


class Setup2FAForm(FlaskForm):
    totp_code = StringField('Verify Code', validators=[
        DataRequired(), Length(min=6, max=6)
    ])
    trust_device = BooleanField('Trust this device for 30 days', validators=[Optional()])


class Disable2FAForm(FlaskForm):
    totp_code = StringField('Current 2FA Code', validators=[
        DataRequired(), Length(min=6, max=6)
    ])


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        lambda form, field: validate_password_strength(field)
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match')
    ])


class DeleteAccountForm(FlaskForm):
    password = PasswordField('Confirm Password', validators=[DataRequired()])
    confirmation = StringField('Type "DELETE" to confirm', validators=[DataRequired()])


class AdminUserEditForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField('Role', choices=[
        ('patient', 'Patient'),
        ('doctor', 'Doctor'),
        ('admin', 'Admin')
    ], validators=[DataRequired()])
    is_active = BooleanField('Active')
