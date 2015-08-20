FROM ubuntu:14.04

MAINTAINER Archit Baweja <architbaweja@gmail.com>

RUN sudo apt-get update && sudo apt-get install -y python2.7-minimal python-dev python-pip

ADD . /app

ENTRYPOINT ["python", "/app/pox.py"]
