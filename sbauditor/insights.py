import boto3


def create_sechub_insights():

    securityhub = boto3.client("securityhub")

    try:
        activeInsight = securityhub.create_insight(
            Name="SecurityBot Active Findings",
            Filters={
                "ProductFields": [
                    {"Key": "Product Name", "Value": "SecurityBot", "Comparison": "EQUALS"},
                ],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"},],
            },
            GroupByAttribute="ResourceType",
        )
        print(activeInsight)
    except Exception as e:
        print(e)

    try:
        remediatedInsight = securityhub.create_insight(
            Name="SecurityBot Remediated Findings",
            Filters={
                "ProductFields": [
                    {"Key": "Product Name", "Value": "SecurityBot", "Comparison": "EQUALS"},
                ],
                "RecordState": [{"Value": "ARCHIVED", "Comparison": "EQUALS"},],
            },
            GroupByAttribute="ResourceType",
        )
        print(remediatedInsight)
    except Exception as e:
        print(e)

    try:
        shodanInsight = securityhub.create_insight(
            Name="SecurityBot Shodan Findings",
            Filters={
                "ProductFields": [
                    {"Key": "Product Name", "Value": "SecurityBot", "Comparison": "EQUALS"},
                ],
                "ThreatIntelIndicatorSource": [{"Value": "Shodan.io", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"},],
            },
            GroupByAttribute="ResourceType",
        )
        print(shodanInsight)
    except Exception as e:
        print(e)
