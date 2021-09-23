# latest hash as of 2 SEPTEMBER 2021
FROM alpine@sha256:e15947432b813e8ffa90165da919953e2ce850bef511a0ad1287d7cb86de84b5

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1
ENV SH_SCRIPTS_BUCKET=SH_SCRIPTS_BUCKET
ENV SHODAN_API_KEY_PARAM=SHODAN_API_KEY_PARAM
ENV DOPS_CLIENT_ID_PARAM=DOPS_CLIENT_ID_PARAM
ENV DOPS_API_KEY_PARAM=DOPS_API_KEY_PARAM

LABEL maintainer="https://github.com/jonrau1" \
    version="3.0" \
    license="GPL-3.0" \
    description="Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis."

COPY requirements.txt /tmp/requirements.txt
# NOTE: This will copy all application files and auditors to the container
COPY ./eeauditor/ ./eeauditor/
# Installing dependencies
RUN \
    apk add bash && \
    apk add --no-cache python3 postgresql-libs && \
    apk add --no-cache --virtual .build-deps gcc python3-dev musl-dev postgresql-dev && \
    python3 -m ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install -r /tmp/requirements.txt --no-cache-dir && \
    apk --purge del .build-deps
# Create a System Group and User for ElectricEye so we don't run as root
RUN \
    addgroup -S eeuser && \ 
    adduser -S -G eeuser eeuser && \
    chown eeuser ./eeauditor && \
    chgrp eeuser ./eeauditor && \
    chown -R eeuser:eeuser ./eeauditor/*
# Bye bye root :)
USER eeuser
# Upon startup we will run all checks and auditors - we grab the latest from S3
# in case there are updates so you can just grab the latest auditors from the
# bucket versus rebuilding the entire Docker image!
CMD \
    aws s3 cp s3://${SH_SCRIPTS_BUCKET}/ ./eeauditor/auditors --recursive && \
    python3 eeauditor/controller.py