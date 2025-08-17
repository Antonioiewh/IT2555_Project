#where all your form objects are defined
#Basic signup form - name, password + phone no.
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField,SelectField,TextAreaField,HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo,ValidationError, Optional
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask_wtf.recaptcha import RecaptchaField # Import RecaptchaField
from wtforms.fields import DateTimeLocalField, BooleanField
import re

from flask_login import current_user

# Custom password validator
def validate_password_policy(form, field):
    """
    Validate password policy:
    - At least 12 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character
    """
    password = field.data
    
    if len(password) < 12:
        raise ValidationError('Password must be at least 12 characters long.')
    
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    
    if not re.search(r'\d', password):
        raise ValidationError('Password must contain at least one number.')
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/~`]', password):
        raise ValidationError('Password must contain at least one special character (!@#$%^&*(),.?":{}|<>_-+=[]\\\/~`).')

class SignupForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=12, max=50, message='Password must be between 12 and 50 characters.'),
        validate_password_policy
    ])
    phone_no = StringField('Phone Number', validators=[DataRequired(), Length(min=8, max=15)])
    recaptcha = RecaptchaField() 
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    recaptcha = RecaptchaField()

    submit = SubmitField('Login')

class FriendRequestForm(FlaskForm):
    submit = SubmitField('Request')

    
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
        pass

class UpdateUserStatusForm(FlaskForm):
    # Dropdown to select the action (status)
    status = SelectField(
        'Select Action',
        choices=[
            ('offline', 'Restore User Account'),
            ('suspended', 'Suspend User Account'),
            ('terminated', 'Terminate User Account')
        ],
        render_kw={"class": "form-select"}    )

# --- create post form ---
class CreatePostForm(FlaskForm):
    #title = StringField('Title', validators=[DataRequired(), Length(max=50)])
    post_content = TextAreaField('Content', validators=[DataRequired(), Length(max=300)])
    image = FileField('Upload Image', validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    submit = SubmitField('Create Post')

    # CAPTCHA field for security
    recaptcha = RecaptchaField()
    
    # Submit button
    submit = SubmitField('Submit', render_kw={"class": "btn btn-primary"})

# --- edit profile form ---

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=50)])
    bio = TextAreaField('Bio', validators=[Optional(), Length(max=500)])
    profile_pic = FileField('Profile Picture', validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    banner_pic = FileField('Banner Picture', validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    submit = SubmitField('Update Profile')

class UpdateReportStatusForm(FlaskForm):
    status = SelectField('Status', choices=[
        ('pending', 'Pending'),
        ('in_review', 'Under Review'),
        ('action_taken', 'Resolved'),
        ('rejected', 'Dismissed')
    ])
    admin_notes = TextAreaField('Admin Notes', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Update Status')

class Enable2FAForm(FlaskForm):
    totp_code = StringField('2FA Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Enable 2FA')

class Disable2FAForm(FlaskForm):
    totp_code = StringField('2FA Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Disable 2FA')

class RemovePassKeyForm(FlaskForm):
    submit = SubmitField('Remove Passkey')

class EventForm(FlaskForm):
    event_name = StringField('Event Name', validators=[DataRequired(), Length(min=3, max=100)])
    event_description = TextAreaField('Description', validators=[DataRequired(), Length(min=10, max=1000)])
    event_location = StringField('Location', validators=[DataRequired(), Length(min=5, max=200)])
    event_start_time = DateTimeLocalField('Start Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    recaptcha = RecaptchaField()
    submit = SubmitField('Create Event')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        'Current Password',
        validators=[
            DataRequired(message='Please enter your current password.'),
            Length(min=6, max=50, message='Password must be between 6 and 50 characters.')
        ],
        render_kw={"placeholder": "Enter your current password", "class": "form-control"}
    )
    new_password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message='Please enter a new password.'),
            Length(min=12, max=50, message='Password must be between 12 and 50 characters.'),
            validate_password_policy
        ],
        render_kw={"placeholder": "Enter your new password", "class": "form-control"}
    )
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(message='Please confirm your new password.'),
            EqualTo('new_password', message='Passwords must match.')
        ],
        render_kw={"placeholder": "Confirm your new password", "class": "form-control"}
    )
    totp_code = StringField(
        '2FA Code (if enabled)',
        validators=[
            Optional(),
            Length(min=6, max=6, message='2FA code must be 6 digits.')
        ],
        render_kw={"placeholder": "Enter 6-digit code (if 2FA enabled)", "class": "form-control"}
    )
    # Hidden field to track authentication method used
    auth_method = HiddenField()
    
    recaptcha = RecaptchaField()
    submit = SubmitField('Change Password', render_kw={"class": "btn btn-primary"})

    def validate_current_password(self, field):
        from flask_login import current_user
        if not current_user.check_password(field.data):
            raise ValidationError('Current password is incorrect.')

    def validate_new_password(self, field):
        from flask_login import current_user
        if current_user.check_password(field.data):
            raise ValidationError('New password must be different from current password.')