from flask import Flask, render_template, url_for,request,redirect,session,jsonify, send_file
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=5)

#antonio: just to verify things work 
@app.route('/', methods = ['GET'])
def index():
    return render_template('index.html')


#antonio: i forgot what this does, but it is important to have it here
if __name__ == "__main__":
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    #determine the create the obj
    app.run(debug=True)