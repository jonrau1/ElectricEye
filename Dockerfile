FROM ubuntu:latest

ENV SH_SCRIPTS_BUCKET=SH_SCRIPTS_BUCKET

LABEL maintainer="https://github.com/jonrau1" \
      version="1.0" \
      description="Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis."

RUN \
    apt-get update && \
    apt-get install python3 -y && \
    apt-get install python3-pip -y && \
    pip3 install awscli && \
    pip3 install boto3

CMD \
    aws s3 cp s3://${SH_SCRIPTS_BUCKET}/ ./ --recursive && \
    bash script.sh