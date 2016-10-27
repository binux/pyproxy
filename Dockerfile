FROM python:2-alpine

ADD . /opt/pyproxy
WORKDIR /opt/pyproxy
RUN pip install .

ENTRYPOINT ["pyproxy"]

EXPOSE 80 8888
