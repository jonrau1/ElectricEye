# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.  
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

FROM ubuntu:latest

ENV SH_SCRIPTS_BUCKET=SH_SCRIPTS_BUCKET
ENV SHODAN_API_KEY_PARAM=SHODAN_API_KEY_PARAM

LABEL maintainer="https://github.com/jonrau1" \
      version="2.0" \
      license="GPL-3.0" \
      description="Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis."

RUN \
    apt-get update && \
    apt-get install python3 -y && \
    apt-get install python3-pip -y && \
    pip3 install awscli && \
    pip3 install requests && \
    pip3 install boto3

CMD \
    aws s3 cp s3://${SH_SCRIPTS_BUCKET}/ ./ --recursive && \
    bash script.sh