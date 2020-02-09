import boto3

securityhub = boto3.client('securityhub')

try:
    activeInsight = securityhub.create_insight(
        Name='ElectricEye Active Findings',
        Filters={
            'ProductFields': [
                {
                    'Key': 'Product Name',
                    'Value': 'ElectricEye',
                    'Comparison': 'EQUALS'
                },
            ],
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                },
            ]
        },
        GroupByAttribute='ResourceType'
    )
    print(activeInsight)
except Exception as e:
    print(e)
try:
    remediatedInsight = securityhub.create_insight(
        Name='ElectricEye Remediated Findings',
        Filters={
            'ProductFields': [
                {
                    'Key': 'Product Name',
                    'Value': 'ElectricEye',
                    'Comparison': 'EQUALS'
                },
            ],
            'RecordState': [
                {
                    'Value': 'ARCHIVED',
                    'Comparison': 'EQUALS'
                },
            ]
        },
        GroupByAttribute='ResourceType'
    )
    print(remediatedInsight)
except Exception as e:
    print(e)