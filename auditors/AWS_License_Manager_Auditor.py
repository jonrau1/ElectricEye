import boto3
import datetime
import os
# import boto3 clients
sts = boto3.client('sts')
licensemanager = boto3.client('license-manager')
securityhub = boto3.client('securityhub')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']

def license_manager_hard_count_check():
    try:
        response = licensemanager.list_license_configurations()
        lmCheck = str(response['LicenseConfigurations'])
        if lmCheck == '[]':
            pass
        else:
            myLiscMgrConfigs = response['LicenseConfigurations']
            for lmconfigs in myLiscMgrConfigs:
                liscConfigArn = str(lmconfigs['LicenseConfigurationArn'])
                try:
                    response = licensemanager.get_license_configuration(LicenseConfigurationArn=liscConfigArn)
                    liscConfigId = str(response['LicenseConfigurationId'])
                    liscConfigName = str(response['Name'])
                    hardLimitCheck = str(response['LicenseCountHardLimit'])
                    if hardLimitCheck == 'False':
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': liscConfigArn + '/license-manager-enforce-hard-limit-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': liscConfigArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'LOW' },
                                        'Confidence': 99,
                                        'Title': '[LicenseManager.1] License Manager license configurations should be configured to enforce a hard limit',
                                        'Description': 'License Manager license configuration ' + liscConfigName + ' does not enforce a hard limit. Enforcing a hard limit prevents new instances from being created that if you have already provisioned all available licenses. Refer to the remediation instructions to remediate this behavior',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For information on hard limits refer to the License Configuration Parameters and Rules section of the AWS License Manager User Guide',
                                                'Url': 'https://docs.aws.amazon.com/license-manager/latest/userguide/config-overview.html'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Other',
                                                'Id': liscConfigArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'licenseConfigurationId': liscConfigId,
                                                        'licenseConfigurationName': liscConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 'Status': 'FAILED' },
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
                                        'Id': liscConfigArn + '/license-manager-enforce-hard-limit-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': liscConfigArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'INFORMATIONAL' },
                                        'Confidence': 99,
                                        'Title': '[LicenseManager.1] License Manager license configurations should be configured to enforce a hard limit',
                                        'Description': 'License Manager license configuration ' + liscConfigName + ' enforces a hard limit.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For information on hard limits refer to the License Configuration Parameters and Rules section of the AWS License Manager User Guide',
                                                'Url': 'https://docs.aws.amazon.com/license-manager/latest/userguide/config-overview.html'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Other',
                                                'Id': liscConfigArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'licenseConfigurationId': liscConfigId,
                                                        'licenseConfigurationName': liscConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 'Status': 'PASSED' },
                                        'RecordState': 'ARCHIVED'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                except Exception as e:
                    print(e)
    except Exception as e:
        print(e)

def license_manager_auditor():
    license_manager_hard_count_check()

license_manager_auditor()