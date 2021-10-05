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
import boto3
import os
def lambda_handler(event, context):
    # boto3 clients
    sts = boto3.client('sts')
    securityhub = boto3.client('securityhub')
    # create env vars
    awsRegion = os.environ['AWS_REGION']
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    # this is set via Lambda env var
    wafv1IpSet = os.environ['WAFV1_IPSET']
    masterAccountId = sts.get_caller_identity()['Account']
    # parse Security Hub CWE
    securityHubEvent = (event['detail']['findings'])
    for findings in securityHubEvent:
        # parse finding ID
        findingId =str(findings['Id'])
        # parse Account from SecHub Finding
        findingOwner = str(findings['AwsAccountId'])
        # parse GuardDuty detector
        gdDetector = str(findings['ProductFields']['detectorId'])
        gdFinding = findingId.replace('arn:aws:guardduty:' + awsRegion + ':' + findingOwner + ':detector/' + gdDetector + '/finding/', '' )
        if findingOwner != masterAccountId:
            memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
            # retrieve creds from member account
            xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
            xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
            xAcctSeshToken = memberAcct['Credentials']['SessionToken']
            # create service client using the assumed role credentials
            guardduty = boto3.client('guardduty',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
            waf = boto3.client('waf',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
            try:
                # loop through GuardDuty Finding
                response = guardduty.get_findings(DetectorId=gdDetector,FindingIds=[gdFinding])
                for gdfindings in response['Findings']:
                    for probedetails in gdfindings['Service']['Action']['PortProbeAction']['PortProbeDetails']:
                        badCallerIpv4 = str(probedetails['RemoteIpDetails']['IpAddressV4'])
                        getWafChangeToken = waf.get_change_token()
                        wafChgToken = str(getWafChangeToken['ChangeToken'])
                        try:
                            response = waf.update_ip_set(
                                IPSetId=wafv1IpSet,
                                ChangeToken=wafChgToken,
                                Updates=[{'Action': 'INSERT','IPSetDescriptor': {'Type': 'IPV4','Value':badCallerIpv4+'/32'}}]
                            )
                            print(response)
                            try:
                                response = securityhub.update_findings(
                                    Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                    Note={'Text': 'The malicious caller IP addresses have been parsed from the original GuardDuty finding and added to all Regional WAF IP Sets and the finding was archived. Consider performing forensics on the host that received the port probe if other behavior suggests an indicator of compromise.','UpdatedBy': lambdaFunctionName},
                                    RecordState='ARCHIVED'
                                )
                                print(response)
                            except Exception as e:
                                print(e)
                        except Exception as e:
                            print(e)
            except Exception as e:
                print(e)
        else:
            try:
                guardduty = boto3.client('guardduty')
                waf = boto3.client('waf')
                # loop through GuardDuty Finding
                response = guardduty.get_findings(DetectorId=gdDetector,FindingIds=[gdFinding])
                for gdfindings in response['Findings']:
                    for probedetails in gdfindings['Service']['Action']['PortProbeAction']['PortProbeDetails']:
                        badCallerIpv4 = str(probedetails['RemoteIpDetails']['IpAddressV4'])
                        getWafChangeToken = waf.get_change_token()
                        wafChgToken = str(getWafChangeToken['ChangeToken'])
                        try:
                            response = waf.update_ip_set(
                                IPSetId=wafv1IpSet,
                                ChangeToken=wafChgToken,
                                Updates=[{'Action': 'INSERT','IPSetDescriptor': {'Type': 'IPV4','Value':badCallerIpv4+'/32'}}]
                            )
                            print(response)
                            try:
                                response = securityhub.update_findings(
                                    Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                    Note={'Text': 'The malicious caller IP addresses have been parsed from the original GuardDuty finding and added to all Regional WAF IP Sets and the finding was archived. Consider performing forensics on the host that received the port probe if other behavior suggests an indicator of compromise.','UpdatedBy': lambdaFunctionName},
                                    RecordState='ARCHIVED'
                                )
                                print(response)
                            except Exception as e:
                                print(e)
                        except Exception as e:
                            print(e)
            except Exception as e:
                print(e)  