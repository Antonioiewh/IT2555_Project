from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp, AnyOf
from flask_wtf.recaptcha import RecaptchaField
from flask_login import current_user

class SignupForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=14, max=50, message="Password must be at least 14 characters."),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\'\\:"|<,./<>?]).{14,}$',
                message="Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 14 characters long."
            )
        ]
    )
    phone_no = StringField(
        'Phone Number',
        validators=[
            DataRequired(),
            Length(min=8, max=8, message="Phone number must be exactly 8 digits."),
            Regexp(r'^\d{8}$', message="Phone number must contain exactly 8 digits.")
        ]
    )
    recaptcha = RecaptchaField() 
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField(
        'Name',
        validators=[
            DataRequired(message="Username is required."),
            Length(min=2, max=50, message="Username must be between 2 and 50 characters."),
            Regexp(r'^[a-zA-Z0-9_]+$', message="Username must be alphanumeric or underscore.")
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=14, max=50, message="Password must be at least 14 characters."),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\'\\:"|<,./<>?]).{14,}$',
                message="Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 14 characters long."
            )
        ]
    )
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

class FriendRequestForm(FlaskForm):
    submit = SubmitField('Request')

class ReportForm(FlaskForm):
    reported_username = StringField(
        'Username of User to Report',
        validators=[
            DataRequired(message='Please enter the username of the user you wish to report.'),
            Length(min=3, max=80, message='Username must be between 3 and 80 characters.'),
            Regexp(r'^[a-zA-Z0-9_]+$', message="Username must be alphanumeric or underscore")
        ]
    )
    report_type = SelectField(
        'Type of Report',
        choices=[
            ('spam', 'Spam/Bots'),
            ('harassment', 'Harassment/Bullying'),
            ('impersonation', 'Impersonation'),
            ('inappropriate_content', 'Inappropriate Content'),
            ('fraud', 'Fraud/Scam'),
            ('other', 'Other (Please specify)')
        ],
        validators=[
            DataRequired(message='Please select a report type.'),
            AnyOf(
                ['spam', 'harassment', 'impersonation', 'inappropriate_content', 'fraud', 'other'],
                message="Invalid report type."
            )
        ]
    )
    description = TextAreaField(
        'Description (Please be detailed)',
        validators=[
            DataRequired(message='A description is required.'),
            Length(min=20, max=1000, message='Description must be between 20 and 1000 characters.'),
            Regexp(r'^[\s\S]*$', message="Description contains invalid characters.")  # Accepts any character, but you can restrict if needed
        ]
    )
    recaptcha = RecaptchaField()
    submit = SubmitField('Submit Report')

    def validate_reported_username(self, field):
        from app import db, User
        user_to_report = User.query.filter_by(username=field.data).first()
        if not user_to_report:
            raise ValidationError('User with this username does not exist.')
        if current_user.is_authenticated and user_to_report.user_id == current_user.user_id:
            raise ValidationError('You cannot report yourself.')
        self.user_to_report_obj = user_to_report

    def validate_description(self, field):
        # Example: Prevent only-whitespace or repeated spammy content
        if not field.data.strip():
            raise ValidationError('Description cannot be empty or only whitespace.')
        if len(set(field.data.lower().split())) == 1:
            raise ValidationError('Description appears to be spammy or repetitive.')



class UpdateUserStatusForm(FlaskForm):
    status = SelectField(
        'Select Action',
        choices=[
            ('offline', 'Restore User Account'),
            ('suspended', 'Suspend User Account'),
            ('terminated', 'Terminate User Account')
        ],
        validators=[
            DataRequired(),
            AnyOf(['offline', 'suspended', 'terminated'], message="Invalid status.")
        ],
        render_kw={"class": "form-select"}
    )
    recaptcha = RecaptchaField()
    submit = SubmitField('Submit', render_kw={"class": "btn btn-primary"})

class UpdateReportStatusForm(FlaskForm):
    status = SelectField(
        'Update Status',
        choices=[
            ('open', 'Open'),
            ('in_review', 'In Review'),
            ('action_taken', 'Action Taken'),
            ('rejected', 'Rejected')
        ],
        validators=[
            DataRequired(),
            AnyOf(['open', 'in_review', 'action_taken', 'rejected'], message="Invalid status.")
        ],
        render_kw={"class": "form-select"}
    )
    admin_notes = TextAreaField(
        'Admin Notes',
        validators=[
            Length(max=1000, message="Admin notes must be less than 1000 characters.")
        ],
        render_kw={"class": "form-control"}
    )
    submit = SubmitField('Submit', render_kw={"class": "btn btn-primary"})