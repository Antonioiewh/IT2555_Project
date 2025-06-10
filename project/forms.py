#where all your form objects are defined
#Basic signup form - name, password + phone no.
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf.recaptcha import RecaptchaField # Import RecaptchaField

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

    