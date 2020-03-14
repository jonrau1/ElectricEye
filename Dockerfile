FROM alpine:latest

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1
ENV SH_SCRIPTS_BUCKET=SH_SCRIPTS_BUCKET
ENV SHODAN_API_KEY_PARAM=SHODAN_API_KEY_PARAM

LABEL maintainer="https://github.com/jonrau1" \
      version="2.0" \
      license="GPL-3.0" \
      description="Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis."

RUN \
    apk update && \
    apk upgrade && \
    apk add bash && \
    apk add --no-cache python3 && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    pip3 install awscli && \
    pip3 install requests && \
    pip3 install boto3

CMD \
    aws s3 cp s3://${SH_SCRIPTS_BUCKET}/ ./ --recursive && \
    bash script.sh