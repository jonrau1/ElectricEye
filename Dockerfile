FROM python:3.8-slim

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1
ENV SH_SCRIPTS_BUCKET=SH_SCRIPTS_BUCKET
ENV SHODAN_API_KEY_PARAM=SHODAN_API_KEY_PARAM

LABEL maintainer="https://github.com/jonrau1" \
    version="2.0" \
    license="GPL-3.0" \
    description="Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis."

COPY requirements.txt /tmp/requirements.txt
# NOTE: this will copy current auditors to container along with the required controller files
COPY ./eeauditor/ ./

RUN pip3 install -r /tmp/requirements.txt

CMD \
    aws s3 cp s3://${SH_SCRIPTS_BUCKET}/ ./auditors --recursive && \
    python controller.py