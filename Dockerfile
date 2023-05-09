#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

# latest hash as of 5 MAY 2023 - Alpine 3.17.3 / alpine:latest
# https://hub.docker.com/layers/library/alpine/3.17.3/images/sha256-b6ca290b6b4cdcca5b3db3ffa338ee0285c11744b4a6abaa9627746ee3291d8d?context=explore
# use as builder image to pull in required deps
FROM alpine@sha256:b6ca290b6b4cdcca5b3db3ffa338ee0285c11744b4a6abaa9627746ee3291d8d AS builder

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /tmp/requirements.txt

# NOTE: This will copy all application files and auditors to the container
# IMPORTANT: ADD YOUR TOML CONFIGURATIONS BEFORE YOU BUILD THIS!

COPY ./eeauditor/ /eeauditor/

# Installing dependencies
RUN \
    apk update && \
    apk add --no-cache python3 postgresql-libs bash nmap git && \
    apk add --no-cache --virtual .build-deps gcc python3-dev musl-dev postgresql-dev && \
    python3 -m ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install -r /tmp/requirements.txt --no-cache-dir && \
    apk --purge del .build-deps && \
    rm -f /var/cache/apk/*

# new stage to bring in Labels and ENV Vars
FROM builder as electriceye

ENV SHODAN_API_KEY_PARAM=SHODAN_API_KEY_PARAM

LABEL \ 
    maintainer="https://github.com/jonrau1" \
    version="3.0" \
    license="Apache-2.0" \
    description="ElectricEye is a multi-cloud, multi-SaaS Python CLI tool for Asset Management, Security Posture Management, and External Attack Surface Management supporting 100s of services and evaluations to harden your public cloud & SaaS environments."

# Create a System Group and User for ElectricEye so we don't run as root
RUN \
    addgroup -S eeuser && \ 
    adduser -S -G eeuser eeuser && \
    chown eeuser /eeauditor && \
    chown eeuser /eeauditor/* && \
    chgrp eeuser /eeauditor && \
    chown -R eeuser:eeuser /eeauditor/* && \
    chown -R eeuser:eeuser /eeauditor

USER eeuser

# IMPORTANT: Modify the controller.py command to run other clouds/SaaS or modify outputs
CMD python3 eeauditor/controller.py