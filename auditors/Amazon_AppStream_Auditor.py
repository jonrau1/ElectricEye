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

import boto3
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
appstream = boto3.client('appstream')
sts = boto3.client('sts')
# create account id & region variables
awsAccount = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']

def default_internet_access_check():
    # loop through AppStream 2.0 fleets
    response = appstream.describe_fleets()
    myAppstreamFleets = response['Fleets']
    for fleet in myAppstreamFleets:
        fleetArn = str(fleet['Arn'])
        fleetName = str(fleet['DisplayName'])
        # find fleets that are configured to provide default internet access
        defaultInternetAccessCheck = str(fleet['EnableDefaultInternetAccess'])
        if defaultInternetAccessCheck == 'True':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': fleetArn + '/appstream-default-internet-access',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': fleetArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
                            'Confidence': 99,
                            'Title': '[AppStream.1] AppStream 2.0 fleets should not provide default internet access',
                            'Description': 'AppStream 2.0 fleet ' + fleetName + ' is configured to provide default internet access. If you use the Default Internet Access option for enabling internet access, the NAT configuration is not limited to 100 fleet instances. If your deployment must support more than 100 concurrent users, use this configuration. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your fleet should not have default internet access refer to the instructions in the Amazon AppStream 2.0 Administration Guide',
                                    'Url': 'https://docs.aws.amazon.com/appstream2/latest/developerguide/internet-access.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsAppStreamFleet',
                                    'Id': fleetArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'fleetName': fleetName 
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-3'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': fleetArn + '/appstream-default-internet-access',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': fleetArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[AppStream.1] AppStream 2.0 fleets should not provide default internet access',
                            'Description': 'AppStream 2.0 fleet ' + fleetName + ' is not configured to provide default internet access.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your fleet should not have default internet access refer to the instructions in the Amazon AppStream 2.0 Administration Guide',
                                    'Url': 'https://docs.aws.amazon.com/appstream2/latest/developerguide/internet-access.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsAppStreamFleet',
                                    'Id': fleetArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'fleetName': fleetName 
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-3'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def public_image_check():
    # loop through AppStream 2.0 images
    response = appstream.describe_images(Type='PUBLIC',MaxResults=25)
    myAppstreamImages = response['Images']
    for images in myAppstreamImages:
        imageName = str(images['Name'])
        imageArn = str(images['Arn'])
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # create Sec Hub finding
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': imageArn + '/appstream-public-image',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                        'GeneratorId': imageArn,
                        'AwsAccountId': awsAccount,
                        'Types': [
                            'Software and Configuration Checks/AWS Security Best Practices',
                            'Effects/Data Exposure'
                        ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'MEDIUM' },
                        'Confidence': 99,
                        'Title': '[AppStream.2] AppStream 2.0 images you build should not be publicly accessible',
                        'Description': 'AppStream 2.0 image ' + imageName + ' is publicly accessible. Permissions set on images that are shared with you may limit what you can do with those images. Refer to the remediation instructions if this configuration is not intended. Note that AWS managed AppStream 2.0 images will always be publicly accessible',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'If your image should not be publicly accessible refer to the instructions in the Amazon AppStream 2.0 Administration Guide',
                                'Url': 'https://docs.aws.amazon.com/appstream2/latest/developerguide/administer-images.html#stop-sharing-image-with-all-accounts'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'Other',
                                'Id': imageArn,
                                'Partition': 'aws',
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'Image Name': imageName }
                                }
                            }
                        ],
                        'Compliance': { 
                            'Status': 'FAILED',
                            'RelatedRequirements': [
                                'NIST CSF ID.AM-2',
                                'NIST CSF PR.AC-3'
                            ]
                        },
                        'Workflow': {
                            'Status': 'NEW'
                        },
                        'RecordState': 'ACTIVE'
                    }
                ]
            )
            print(response)
        except Exception as e:
            print(e)

def compromised_appstream_user_check():
    # loop through AppStream 2.0 users
    response = appstream.describe_users(AuthenticationType='USERPOOL')
    myAppStreamUsers = response['Users']
    for users in myAppStreamUsers:
        userArn = str(users['Arn'])
        userName = str(users['UserName'])
        userStatus = str(users['Status'])
        if userStatus == 'COMPROMISED':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': userArn + '/appstream-compromised-user',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userArn,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Unusual Behaviors/User'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'CRITICAL' },
                            'Confidence': 99,
                            'Title': '[AppStream.3] AppStream 2.0 users should be monitored for signs of compromise',
                            'Description': 'AppStream 2.0 user ' + userName + ' is compromised. COMPROMISED – The user is disabled because of a potential security threat. Refer to the remediation instructions for information on how to remove them',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'To disable and remove compromised users refer to the instructions in the User Pool Administration section of the Amazon AppStream 2.0 Administration Guide',
                                    'Url': 'https://docs.aws.amazon.com/appstream2/latest/developerguide/user-pool-admin.html#user-pool-admin-disabling'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'userName': userName
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.RA-3',
                                    'NIST CSF ID.RA-4',
                                    'NIST CSF DE.CM-7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': userArn + '/appstream-compromised-user',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userArn,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Unusual Behaviors/User'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[AppStream.3] AppStream 2.0 users should be monitored for signs of compromise',
                            'Description': 'AppStream 2.0 user ' + userName + ' is not compromised.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'To disable and remove compromised users refer to the instructions in the User Pool Administration section of the Amazon AppStream 2.0 Administration Guide',
                                    'Url': 'https://docs.aws.amazon.com/appstream2/latest/developerguide/user-pool-admin.html#user-pool-admin-disabling'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'userName': userName
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.RA-3',
                                    'NIST CSF ID.RA-4',
                                    'NIST CSF DE.CM-7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def userpool_auth_check():
    # loop through AppStream 2.0 users
    response = appstream.describe_users(AuthenticationType='USERPOOL')
    myAppStreamUsers = response['Users']
    for users in myAppStreamUsers:
        userArn = str(users['Arn'])
        userName = str(users['UserName'])
        # find users that do not auth with SAML
        # basic auth & API access will show as non-compliant
        userAuthType = str(users['AuthenticationType'])
        if userAuthType != 'SAML':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': userArn + '/appstream-compromised-user',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userArn,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
                            'Confidence': 99,
                            'Title': '[AppStream.4] AppStream 2.0 users should be configured to authenticate using SAML',
                            'Description': 'AppStream 2.0 user ' + userName + ' is not configured to authenticate using SAML. This feature offers your users the convenience of one-click access to their AppStream 2.0 applications using their existing identity credentials. You also have the security benefit of identity authentication by your IdP. By using your IdP, you can control which users have access to a particular AppStream 2.0 stack. Refer to the remediation instructions for information on how to remove them',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on setting up SAML refer to the Setting Up SAML section of the Amazon AppStream 2.0 Administration Guide',
                                    'Url': 'https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html#external-identity-providers-create-saml-provider'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'userName': userName
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-1',
                                    'NIST CSF PR.AC-3',
                                    'NIST CSF PR.AC-4',
                                    'NIST CSF PR.AC-6',
                                    'NIST CSF PR.AC-7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': userArn + '/appstream-compromised-user',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userArn,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[AppStream.4] AppStream 2.0 users should be configured to authenticate using SAML',
                            'Description': 'AppStream 2.0 user ' + userName + ' is configured to authenticate using SAML.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on setting up SAML refer to the Setting Up SAML section of the Amazon AppStream 2.0 Administration Guide',
                                    'Url': 'https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html#external-identity-providers-create-saml-provider'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'userName': userName
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-1',
                                    'NIST CSF PR.AC-3',
                                    'NIST CSF PR.AC-4',
                                    'NIST CSF PR.AC-6',
                                    'NIST CSF PR.AC-7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def appstream_auditor():
    default_internet_access_check()
    public_image_check()
    compromised_appstream_user_check()
    userpool_auth_check()

appstream_auditor()