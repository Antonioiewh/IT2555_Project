from __init__ import db
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
import sqlconnect  
from sqlalchemy.sql import text
#sqlconnect is a seperate file that contains the information to connect to the database
conn = "mysql+pymysql://{0}:{1}@{2}/{3}".format(sqlconnect.mysql_user,sqlconnect.mysql_password,sqlconnect.mysql_host,sqlconnect.mysql_name)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = conn
db = SQLAlchemy(app)
app.app_context().push()

#antonio: just to verify can contact server, we will be executing this command
result = db.session.execute(text("SHOW DATABASES"))
print(result.all())