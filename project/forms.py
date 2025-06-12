#where all your form objects are defined
#Basic signup form - name, password + phone no.
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField,SelectField,TextAreaField,HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo,ValidationError
from flask_wtf.recaptcha import RecaptchaField # Import RecaptchaField

from flask_login import current_user

class SignupForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    phone_no = StringField('Phone Number', validators=[DataRequired(), Length(min=8, max=15)])
    recaptcha = RecaptchaField() 
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')


class ReportForm(FlaskForm):
    
    reported_username = StringField(
        'Username of User to Report',
        validators=[
            DataRequired(message='Please enter the username of the user you wish to report.'),
            Length(min=3, max=80, message='Username must be between 3 and 80 characters.')
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
        validators=[DataRequired(message='Please select a report type.')]
    )
    description = TextAreaField(
        'Description (Please be detailed)',
        validators=[
            DataRequired(message='A description is required.'),
            Length(min=20, max=1000, message='Description must be between 20 and 1000 characters.')
        ]
    )
    recaptcha = RecaptchaField()
    submit = SubmitField('Submit Report')

    # Custom validator to find the reported user and prevent self-reporting
    
    def validate_reported_username(self, field):
        from app import db, User
        user_to_report = User.query.filter_by(username=field.data).first()
        if not user_to_report:
            raise ValidationError('User with this username does not exist.')

        # Prevent self-reporting
        if current_user.is_authenticated and user_to_report.user_id == current_user.user_id:
            raise ValidationError('You cannot report yourself.')

        # Store the found user object on the form instance for easy access in the route
        self.user_to_report_obj = user_to_report

class UpdateUserStatusForm(FlaskForm):
    # Dropdown to select the action (status)
    status = SelectField(
        'Select Action',
        choices=[
            ('offline', 'Restore User Account'),
            ('suspended', 'Suspend User Account'),
            ('terminated', 'Terminate User Account')
        ],
        render_kw={"class": "form-select"}  # Optional: Add Bootstrap class for styling
    )
    
    # CAPTCHA field for security
    recaptcha = RecaptchaField()
    
    # Submit button
    submit = SubmitField('Submit', render_kw={"class": "btn btn-primary"})