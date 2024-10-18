FROM python:3.10

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

# EXPOSE 4000

CMD ["python","login.py","run"]