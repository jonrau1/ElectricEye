# latest hash as of 14 APRIL 2021
FROM alpine@sha256:a9c28c813336ece5bb98b36af5b66209ed777a394f4f856c6e62267790883820

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
    apk add --no-cache python3 && \
    python3 -m ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install -r /tmp/requirements.txt
# Create a System Group and User for ElectricEye so we don't run as root
RUN \
    addgroup -S eeuser && \ 
    adduser -S -G eeuser eeuser && \
    chown eeuser ./eeauditor && \
    chgrp eeuser ./eeauditor && \
    chown -R eeuser:eeuser ./eeauditor/*
# Bye bye root :)
USER eeuser
# Upon startup we will run all checks and auditors
CMD python3 eeauditor/controller.py