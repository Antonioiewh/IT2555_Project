from flask import Flask, render_template, url_for,request,redirect,session,jsonify, send_file
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
#for some fucking reason you have to do .(filename) to import it for docker, no idea why but whatever
import sqlconnect
#no idea what this does, but it is important to have it here
from sqlalchemy.sql import text
conn = "mysql+pymysql://{0}:{1}@{2}/{3}".format(sqlconnect.mysql_user,sqlconnect.mysql_password,sqlconnect.mysql_host,sqlconnect.mysql_name)

app = Flask(__name__)
'''
app.config['SECRET_KEY'] = 'hermos12345'
app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.permanent_session_lifetime = timedelta(minutes=5)
db = SQLAlchemy(app)
app.app_context().push()
'''




@app.route('/', methods = ['GET'])
def index():
    return render_template('index.html')


#antonio: i forgot what this does, but it is important to have it here
if __name__ == "__main__":
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    #determine the create the obj
    app.run(debug=True)

'''
result = db.session.execute(text("SHOW DATABASES"))
print(result.all())
'''