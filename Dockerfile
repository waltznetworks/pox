FROM python:2-alpine
MAINTAINER Archit Baweja <archit@waltznetworks.com>

ADD . /app

EXPOSE 6633

ENTRYPOINT ["python", "/app/pox.py"]
