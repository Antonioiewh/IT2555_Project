from flask import Flask, render_template, url_for,request,redirect,session,jsonify, send_file,flash
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import sqlconnect
from sqlalchemy import create_engine,URL
#may be useful later for mysql queries
from sqlalchemy.sql import text
#antonio: impt to ensure can connect to mysql
import cryptography
#antonio: forms
from forms import SignupForm
#antonio: to generate secret KEY to use for CSRF for Flask-WTF
import os
import binascii
def generate_key():
  """Generates a random key for Flask-WTF."""
  return binascii.hexlify(os.urandom(24)).decode()
#antonio: this is the connection string to connect to mysql



key = generate_key()
app = Flask(__name__)
app.config['SECRET_KEY'] =  key
#set this to false when in production
app.config['TEMPLATES_AUTO_RELOAD'] = True
'''
app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.permanent_session_lifetime = timedelta(minutes=5)`
db = SQLAlchemy(app)
app.app_context().push()

result = db.session.execute(text("SHOW DATABASES"))
print(result.all())
'''

#antonio: VERY IMPT STRING DO NOT DELETE!!!!!!!
mysql_database_URL = URL.create(
    "mysql+pymysql",
    username=sqlconnect.mysql_user,
    password=sqlconnect.mysql_password,
    host=sqlconnect.mysql_host,
    port=sqlconnect.mysql_port,
    database=sqlconnect.mysqldb_name
)
#signup page
@app.route('/', methods=['GET', 'POST'])
def signup():
    Signupform = SignupForm()
    #uses sqlalchemy to connect to mysql
    #engine = create_engine(mysql_database_URL)
    #connection = engine.connect()
    #if request method code here
    #code to test if sms works
    if Signupform.validate_on_submit():
        #antonio: this is where you can add code to insert into mysql
        #connection.execute(text("INSERT INTO users (name, password, phone_no) VALUES (:name, :password, :phone_no)"),
        #                   name=Signupform.username.data,
        #                   password=Signupform.password.data,
        #                   phone_no=Signupform.phone_no.data)
        #connection.close()
        print("Form submitted successfully!")

    
    
    return render_template('UserSignup.html',form=Signupform)
#home page
@app.route('/home', methods=['GET'])
def home():
    #antonio: this is where you can add code to check if user is logged in
    #if session.get('logged_in'):
    #    return render_template('home.html')
    #else:
    #    return redirect(url_for('signup'))
    engine = create_engine(mysql_database_URL)
    connection = engine.connect()
    rs = connection.execute(text("SHOW DATABASES"))
    test_list = []
    for row in rs:
        test_list.append(row)
        print(row)
    return render_template('home.html', test_list=test_list)

#rate limit page
@app.route('/rate_limit', methods=['GET'])
def rate_limit():
    return render_template('rate_limit.html')

#error 404 page
@app.errorhandler(404)
def not_found(error):
    return render_template('404_error.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500_error.html'), 500

#antonio: i forgot what this does, but it is important to have it here
if __name__ == "__main__":
    #app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    #set debug to false when prod
    app.run(debug=True)



#hello 
#hello from SJ