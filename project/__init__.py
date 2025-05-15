from flask import Flask, render_template, url_for,request,redirect,session,jsonify, send_file
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import sqlconnect
from sqlalchemy import create_engine,URL
#may be useful later for mysql queries
from sqlalchemy.sql import text
#antonio: impt to ensure can connect to mysql
import cryptography

#antonio: this is the connection string to connect to mysql

app = Flask(__name__)
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
@app.route('/', methods = ['GET'])
def index():
    engine = create_engine(mysql_database_URL)
    connection = engine.connect()
    rs = connection.execute(text("SHOW DATABASES"))
    test_list = []
    for row in rs:
        test_list.append(row)
        print(row)
    return render_template('index.html', test_list=test_list)


#antonio: i forgot what this does, but it is important to have it here
if __name__ == "__main__":
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    #determine the create the obj
    app.run(debug=True)



