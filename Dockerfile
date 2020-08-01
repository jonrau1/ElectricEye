# latest hash as of 20 JULY 2020
FROM alpine@sha256:a15790640a6690aa1730c38cf0a440e2aa44aaca9b0e8931a9f2b0d7cc90fd65

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1
ENV SH_SCRIPTS_BUCKET=SH_SCRIPTS_BUCKET
ENV SHODAN_API_KEY_PARAM=SHODAN_API_KEY_PARAM
ENV DOPS_CLIENT_ID_PARAM=DOPS_CLIENT_ID_PARAM
ENV DOPS_API_KEY_PARAM=DOPS_API_KEY_PARAM

LABEL maintainer="https://github.com/jonrau1" \
    version="2.0" \
    license="GPL-3.0" \
    description="Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis."

COPY requirements.txt /tmp/requirements.txt
# NOTE: This will copy all application files and auditors to the container
# TODO: update this to prevent baking the auditor files into the docker image
COPY ./eeauditor/ ./eeauditor/

RUN \
    apk add bash && \
    apk add --no-cache python3 && \
    python3 -m ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install -r /tmp/requirements.txt

CMD \
    echo "Copying auditor files to ECS container..." && \
    aws s3 cp s3://${SH_SCRIPTS_BUCKET}/ ./eeauditor/auditors/aws --recursive --quiet && \
    echo "Starting auditor run via ECS container..." && \
    python3 eeauditor/controller.py