FROM ubuntu:latest

ENV SH_SCRIPTS_BUCKET=SH_SCRIPTS_BUCKET

RUN \
    apt-get update && \
    apt-get install python3 -y && \
    apt-get install python3-pip -y && \
    pip3 install awscli && \
    pip3 install boto3

CMD \
    aws s3 cp s3://${SH_SCRIPTS_BUCKET}/ ./ --recursive && \
    bash script.sh