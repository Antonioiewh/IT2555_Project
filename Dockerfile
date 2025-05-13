FROM python:3.12.3-slim
WORKDIR /code
ENV FLASK_APP=__init__.py
ENV FLASK_RUN_HOST=0.0.0.0
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
EXPOSE 5000

COPY . . 
CMD ["flask", "run"]    
