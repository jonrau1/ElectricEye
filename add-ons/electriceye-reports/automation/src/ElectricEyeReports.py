import os
import boto3
import json
import botocore
from datetime import datetime

# Import Boto3 Clients
sts = boto3.client('sts')
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
quicksight = boto3.client('quicksight')

# Set Global Variables and Lists
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
reportBucket = os.environ['QUICKSIGHT_DATASOURCE_BUCKET']
groupName = 'ElectricEyeReports'
dataSourceName = 'ElectricEyeComplianceFindingsV2'

# Create empty lists for processing of Regions
regionList = []
findingsJsonFileName = 'electriceye-qs-findingsV2.json'
manifestJsonFileName = 'electriceye-qs-manifestV2.json'

# Loop through all Opted-In AWS Regions and write
# To a Global list for the Security Hub pagination
for r in ec2.describe_regions()['Regions']:
    regionName = str(r['RegionName'])
    optInStatus = str(r['OptInStatus'])
    if optInStatus == 'not-opted-in':
        pass
    else:
        regionList.append(regionName)

def parse_securityhub_findings():
    print('ElectricEye findings JSON file creation in progress')
    # Create empty lists for processing of SecHub findings
    findingsList = []
    # Loop through the list of AWS Regions we created
    for region in regionList:
        session = boto3.Session(region_name=region)
        sechub = session.client('securityhub')
        paginator = sechub.get_paginator('get_findings')
        # We will retrieve all ElectricEye findings updated in the last Week
        iterator = paginator.paginate(
            Filters={
                'ProductFields': [
                    {
                        'Key': 'Product Name',
                        'Value': 'ElectricEye',
                        'Comparison': 'EQUALS'
                    }
                ],
                'UpdatedAt': [
                    {
                        'DateRange': {
                            'Value': 7,
                            'Unit': 'DAYS'
                        }
                    }
                ]
            }
        )
        for page in iterator:
            for f in page['Findings']:
                # Parse elements out of the findings - we have different logic in case a finding
                # did not have any ComplianceRequirements for some reason (or to use for other Products)
                # we do not include the finding date due to an unsupported ISO Format in QS...
                awsAccountId = str(f['AwsAccountId'])
                updatedAt = str(f['UpdatedAt']).replace('Z', '+00:00')
                fromIso = datetime.fromisoformat(updatedAt)
                findingId = str(f['Id'])
                findingType = str(f['Types'][0])
                severityLabel = str(f['Severity']['Label'])
                findingTitle = str(f['Title'])
                resourceType = str(f['Resources'][0]['Type'])
                resourceId = str(f['Resources'][0]['Id'])
                resourceRegion = str(f['Resources'][0]['Region'])
                complianceStatus = str(f['Compliance']['Status'])
                workflowState = str(f['Workflow']['Status'])
                try:
                    complianceReqs = str(f['Compliance']['RelatedRequirements'])
                    if complianceReqs == '[]':
                        control = 'NoControl'
                        newFinding = {
                            'Finding Type': findingType,
                            'Finding ID': findingId,
                            'Account ID': awsAccountId,
                            'Finding Timestamp': str(fromIso).split('.')[0],
                            'Severity': severityLabel,
                            'Title': findingTitle,
                            'Resource Type': resourceType,
                            'Resource ID': resourceId,
                            'Region': resourceRegion,
                            'Compliance Status': complianceStatus,
                            'Workflow State': workflowState,
                            'Compliance Control': control
                        }
                        findingsList.append(newFinding)
                    else:
                        for c in f['Compliance']['RelatedRequirements']:
                            control = str(c)
                            newFinding = {
                                'Finding Type': findingType,
                                'Finding ID': findingId,
                                'Account ID': awsAccountId,
                                'Finding Timestamp': str(fromIso).split('.')[0],
                                'Severity': severityLabel,
                                'Title': findingTitle,
                                'Resource Type': resourceType,
                                'Resource ID': resourceId,
                                'Region': resourceRegion,
                                'Compliance Status': complianceStatus,
                                'Workflow State': workflowState,
                                'Compliance Control': control
                            }
                            findingsList.append(newFinding)
                except:
                    control = 'NoControl'
                    newFinding = {
                        'Finding Type': findingType,
                        'Finding ID': findingId,
                        'Account ID': awsAccountId,
                        'Finding Timestamp': str(fromIso).split('.')[0],
                        'Severity': severityLabel,
                        'Title': findingTitle,
                        'Resource Type': resourceType,
                        'Resource ID': resourceId,
                        'Region': resourceRegion,
                        'Compliance Status': complianceStatus,
                        'Workflow State': workflowState,
                        'Compliance Control': control
                    }
                    findingsList.append(newFinding)

    with open(findingsJsonFileName, 'w') as jsonfile:
        json.dump(findingsList, jsonfile, indent=2, default=str)

    print('ElectricEye findings JSON file created!')

def create_manifest():
    print('Creating Manifest for ElectricEye Findings')
    waiter = s3.get_waiter('object_exists')
    # Upload the Security Hub JSON file to S3
    try:
        s3.upload_file(findingsJsonFileName, reportBucket, findingsJsonFileName)
        waiter.wait(
            Bucket=reportBucket,
            Key=findingsJsonFileName
        )
        print('Security Hub JSON uploaded to S3')
    except Exception as e:
        raise e
    # Create a new JSON file that contains the QuickSight Manifest
    # See here for more details: https://docs.aws.amazon.com/console/quicksight/manifest
    manifestRaw = {
        'fileLocations': [
            {
                'URIs': [ 'https://' + reportBucket + '.s3.amazonaws.com/' + findingsJsonFileName ]
            }
        ],
        'globalUploadSettings': {
            'format': 'JSON'
        }
    }
    with open(manifestJsonFileName, 'w') as jsonfile:
        json.dump(manifestRaw, jsonfile, indent=2)
    
    print('Manifest file created')
    # Upload Manifest JSON to S3
    try:
        s3.upload_file(manifestJsonFileName, reportBucket, manifestJsonFileName)
        waiter.wait(
            Bucket=reportBucket,
            Key=manifestJsonFileName
        )
        print('Manifest uploaded to S3')
    except Exception as e:
        raise e

def create_quicksight_group():
    print('Creating or updating QuickSight Group for ElectricEye')
    try:
        response = quicksight.create_group(
            GroupName=groupName,
            Description='ElectricEye Security Hub Findings Group consists of all current Admins and Authors within QuickSight',
            AwsAccountId=awsAccountId,
            Namespace='default' # this MUST be 'default'
        )
        groupPrincipalArn = str(response['Group']['Arn'])
        print(groupName + ' was created succesfully')
        print(groupName + ' ARN is ' + groupPrincipalArn)
    except botocore.exceptions.ClientError as error:
        # If the Group exists already, handle the error gracefully
        if error.response['Error']['Code'] == 'ResourceExistsException':
            response = quicksight.describe_group(
                GroupName=groupName,
                AwsAccountId=awsAccountId,
                Namespace='default' # this MUST be 'default'
            )
            groupArn = str(response['Group']['Arn'])
            print('A Group with the name ' + groupName + ' already exists! Attempting to add Users into it')
            print('As a reminder the ARN for ' + groupName + ' is: ' + groupArn)
        else:
            raise error
    
    try:
        response = quicksight.list_users(
            AwsAccountId=awsAccountId,
            MaxResults=100,
            Namespace='default' # this MUST be 'default'
        )
        for u in response['UserList']:
            userName = str(u['UserName'])
            roleLevel = str(u['Role'])
            if roleLevel == 'ADMIN' or 'AUTHOR':
                quicksight.create_group_membership(
                    MemberName=userName,
                    GroupName=groupName,
                    AwsAccountId=awsAccountId,
                    Namespace='default' # this MUST be 'default'
                )
                print('User ' + userName + ' added to Group ' + groupName)
            else:
                pass
    except Exception as e:
        print(e)

def create_quicksight_datasource():
    print('Creating QuickSight Datasource based off of the ElectricEye Findings')
    try:
        response = quicksight.create_data_source(
            AwsAccountId=awsAccountId,
            DataSourceId=dataSourceName,
            Name=dataSourceName,
            Type='S3',
            Permissions=[
                {
                    'Principal': 'arn:aws:quicksight:' + awsRegion + ':' + awsAccountId + ':group/default/' + groupName,
                    'Actions': [
                        'quicksight:DescribeDataSource',
                        'quicksight:DescribeDataSourcePermissions',
                        'quicksight:PassDataSource',
                        'quicksight:UpdateDataSource',
                        'quicksight:DeleteDataSource',
                        'quicksight:UpdateDataSourcePermissions'
                    ]
                }
            ],
            DataSourceParameters={
                'S3Parameters': {
                    'ManifestFileLocation': {
                        'Bucket': reportBucket,
                        'Key': manifestJsonFileName
                    }
                } 
            }
        )
        print('Data Source ' + dataSourceName + ' was created')
        dataSourceArn = str(response['Arn'])
    except botocore.exceptions.ClientError as error:
        # If the Group exists already, handle the error gracefull
        if error.response['Error']['Code'] == 'ResourceExistsException':
            print('The Data Source ' + dataSourceName + ' already exists, attempting to update it')
            response = quicksight.update_data_source(
                AwsAccountId=awsAccountId,
                DataSourceId=dataSourceName,
                Name=dataSourceName,
                DataSourceParameters={
                    'S3Parameters': {
                        'ManifestFileLocation': {
                            'Bucket': reportBucket,
                            'Key': manifestJsonFileName
                        }
                    } 
                }
            )
            print('Data Source ' + dataSourceName + ' was updated')
            dataSourceArn = str(response['Arn'])
        else:
            raise error

    return dataSourceArn

'''
It is important to note that many of the values within the Dataset Creation are hard-coded
and directly dependent on the 'Shape' of the JSON Data. If the Order or Content of the JSON
file created from parsing ElectricEye Findings from Security Hub is changed this Dataset creation
will likely either fail or create the wrong mapping of fields from the JSON Columns. Modify the above
Datasource / JSON file creation AT YOUR OWN RISK!

For the best way to reverse engineer a created dataset using the QuickSight DescribeDataSet API, save it
to a JSON file and use the outputs to provide into the CreateDataSet API - DO NOT INCLUDE OutputColumns within
the Parameters that you will get from DescribeDataSet - it will fail as that is a Describe*-only output
'''

def create_quicksight_dataset():
    print('Creating Quicksight Data Set from Data Source')
    try:
        response = quicksight.create_data_set(
            AwsAccountId=awsAccountId,
            DataSetId=dataSourceName + 'Dataset',
            Name=dataSourceName + 'Dataset',
            PhysicalTableMap={
                's3PhysicalTable': {
                    'S3Source': {
                        'DataSourceArn': str(create_quicksight_datasource()),
                        'UploadSettings': {
                            'Format': 'JSON',
                            'StartFromRow': 1,
                            'ContainsHeader': True,
                            'TextQualifier': 'DOUBLE_QUOTE'
                        },
                        'InputColumns': [
                            {
                            'Name': 'ColumnId-1',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-2',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-3',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-4',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-5',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-6',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-7',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-8',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-9',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-10',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-11',
                            'Type': 'STRING'
                            },
                            {
                            'Name': 'ColumnId-12',
                            'Type': 'STRING'
                            }
                        ]
                    }
                }
            },
            LogicalTableMap={
                's3PhysicalTable': {
                'Alias': 'Group 1',
                'DataTransforms': [
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-2',
                        'NewColumnName': 'Finding ID'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-3',
                        'NewColumnName': 'Account ID'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-1',
                        'NewColumnName': 'Finding Type'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-12',
                        'NewColumnName': 'Compliance Control'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-6',
                        'NewColumnName': 'Title'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-11',
                        'NewColumnName': 'Workflow State'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-7',
                        'NewColumnName': 'Resource Type'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-4',
                        'NewColumnName': 'Finding Timestamp'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-5',
                        'NewColumnName': 'Severity'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-10',
                        'NewColumnName': 'Compliance Status'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-8',
                        'NewColumnName': 'Resource ID'
                        }
                    },
                    {
                        'RenameColumnOperation': {
                        'ColumnName': 'ColumnId-9',
                        'NewColumnName': 'Region'
                        }
                    },
                    {
                        'CastColumnTypeOperation': {
                        'ColumnName': 'Finding Timestamp',
                        'NewColumnType': 'DATETIME',
                        'Format': 'yyyy-MM-dd HH:mm:ss'
                        }
                    },
                    {
                        'ProjectOperation': {
                            'ProjectedColumns': [
                                'Region',
                                'Resource ID',
                                'Compliance Status',
                                'Severity',
                                'Finding Timestamp',
                                'Resource Type',
                                'Workflow State',
                                'Title',
                                'Compliance Control',
                                'Finding Type',
                                'Account ID',
                                'Finding ID'
                            ]
                        }
                    }
                ],
                'Source': {
                    'PhysicalTableId': 's3PhysicalTable'
                    }
                }
            },
            ImportMode='SPICE',
            Permissions=[
                {
                    'Principal': 'arn:aws:quicksight:' + awsRegion + ':' + awsAccountId + ':group/default/' + groupName,
                    'Actions': [
                        'quicksight:DescribeDataSet',
                        'quicksight:DescribeDataSetPermissions',
                        'quicksight:PassDataSet',
                        'quicksight:DescribeIngestion',
                        'quicksight:ListIngestions',
                        'quicksight:UpdateDataSet',
                        'quicksight:DeleteDataSet',
                        'quicksight:CreateIngestion',
                        'quicksight:CancelIngestion',
                        'quicksight:UpdateDataSetPermissions'
                    ]
                }
            ]
        )
        print('Dataset ' + dataSourceName + 'Dataset created')
        dataSetArn = str(response['Arn'])
    except botocore.exceptions.ClientError as error:
        # If the Group exists already, handle the error gracefull
        if error.response['Error']['Code'] == 'ResourceExistsException':
            print('Dataset ' + dataSourceName + 'Dataset already exists. Attemtping to return ARN')
            response = quicksight.describe_data_set(
                AwsAccountId=awsAccountId,
                DataSetId=dataSourceName + 'Dataset'
            )
            dataSetArn = str(response['DataSetArn'])
        else:
            raise error

    #return dataSetArn

def main():
    parse_securityhub_findings()
    create_manifest()
    create_quicksight_group()
    create_quicksight_dataset()

main()