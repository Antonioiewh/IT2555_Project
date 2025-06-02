FROM python:3.12.3-slim
WORKDIR /code
#ENV FLASK_APP=__init__.py
#ENV FLASK_RUN_HOST=0.0.0.0
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . . 
#use 127.0.0.1

CMD gunicorn --reload -b 0.0.0.0:5000 app:app