#where all your form objects are defined
#Basic signup form - name, password + phone no.
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo
class SignupForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    phone_no = StringField('Phone Number', validators=[DataRequired(), Length(min=8, max=15)])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Login')

    