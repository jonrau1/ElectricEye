import datetime
import os
from typing import NewType
import pytest
import sys

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.Amazon_CloudFront_Auditor import (
    cloudfront_active_trusted_signers_check,
    cloudfront_origin_shield_check,
    cloudfront_default_viewer_check,
    cloudfront_georestriction_check,
    cloudfront_field_level_encryption_check,
    cloudfront_waf_enabled_check,
    cloudfront_default_tls_check,
    cloudfront_custom_origin_tls_check,
    cloudfront,
)

list_distributions_response = {
    'DistributionList': {
        'Marker': 'string',
        'NextMarker': 'string',
        'MaxItems': 123,
        'IsTruncated': False,
        'Quantity': 123,
        'Items': [
            {
                'Id': 'string',
                'ARN': 'string',
                'Status': 'string',
                'LastModifiedTime': datetime.datetime(2015, 1, 1),
                'DomainName': 'string',
                'Aliases': {
                    'Quantity': 123,
                    'Items': [
                        'string',
                    ]
                },
                'Origins': {
                    'Quantity': 123,
                    'Items': [
                        {
                            'Id': 'string',
                            'DomainName': 'string',
                            'OriginPath': 'string',
                            'CustomHeaders': {
                                'Quantity': 123,
                                'Items': [
                                    {
                                        'HeaderName': 'string',
                                        'HeaderValue': 'string'
                                    },
                                ]
                            },
                            'S3OriginConfig': {
                                'OriginAccessIdentity': 'string'
                            },
                            'CustomOriginConfig': {
                                'HTTPPort': 123,
                                'HTTPSPort': 123,
                                'OriginProtocolPolicy': 'https-only',
                                'OriginSslProtocols': {
                                    'Quantity': 123,
                                    'Items': [
                                        'TLSv1.2',
                                    ]
                                },
                                'OriginReadTimeout': 123,
                                'OriginKeepaliveTimeout': 123
                            },
                            'ConnectionAttempts': 123,
                            'ConnectionTimeout': 123,
                            'OriginShield': {
                                'Enabled': True,
                                'OriginShieldRegion': 'string'
                            }
                        },
                    ]
                },
                'OriginGroups': {
                    'Quantity': 123,
                    'Items': [
                        {
                            'Id': 'string',
                            'FailoverCriteria': {
                                'StatusCodes': {
                                    'Quantity': 123,
                                    'Items': [
                                        500,
                                    ]
                                }
                            },
                            'Members': {
                                'Quantity': 2,
                                'Items': [
                                    {
                                        'OriginId': 'string'
                                    },
                                    {
                                        'OriginId': 'string'
                                    },
                                ]
                            }
                        },
                    ]
                },
                'DefaultCacheBehavior': {
                    'TargetOriginId': 'string',
                    'TrustedSigners': {
                        'Enabled': True,
                        'Quantity': 123,
                        'Items': [
                            'string',
                        ]
                    },
                    'TrustedKeyGroups': {
                        'Enabled': True,
                        'Quantity': 123,
                        'Items': [
                            'string',
                        ]
                    },
                    'ViewerProtocolPolicy': 'https-only',
                    'AllowedMethods': {
                        'Quantity': 123,
                        'Items': [
                            'GET',
                        ],
                        'CachedMethods': {
                            'Quantity': 123,
                            'Items': [
                                'GET',
                            ]
                        }
                    },
                    'SmoothStreaming': True,
                    'Compress': True,
                    'LambdaFunctionAssociations': {
                        'Quantity': 123,
                        'Items': [
                            {
                                'LambdaFunctionARN': 'string',
                                'EventType': 'viewer-request',
                                'IncludeBody': True
                            },
                        ]
                    },
                    'FunctionAssociations': {
                        'Quantity': 123,
                        'Items': [
                            {
                                'FunctionARN': 'string',
                                'EventType': 'viewer-request'
                            },
                        ]
                    },
                    'FieldLevelEncryptionId': 'string',
                    'RealtimeLogConfigArn': 'string',
                    'CachePolicyId': 'string',
                    'OriginRequestPolicyId': 'string',
                    'ForwardedValues': {
                        'QueryString': True,
                        'Cookies': {
                            'Forward': 'none',
                            'WhitelistedNames': {
                                'Quantity': 123,
                                'Items': [
                                    'string',
                                ]
                            }
                        },
                        'Headers': {
                            'Quantity': 123,
                            'Items': [
                                'string',
                            ]
                        },
                        'QueryStringCacheKeys': {
                            'Quantity': 123,
                            'Items': [
                                'string',
                            ]
                        }
                    },
                    'MinTTL': 123,
                    'DefaultTTL': 123,
                    'MaxTTL': 123
                },
                'CacheBehaviors': {
                    'Quantity': 123,
                    'Items': [
                        {
                            'PathPattern': 'string',
                            'TargetOriginId': 'string',
                            'TrustedSigners': {
                                'Enabled': True,
                                'Quantity': 123,
                                'Items': [
                                    'string',
                                ]
                            },
                            'TrustedKeyGroups': {
                                'Enabled': True,
                                'Quantity': 123,
                                'Items': [
                                    'string',
                                ]
                            },
                            'ViewerProtocolPolicy': 'https-only',
                            'AllowedMethods': {
                                'Quantity': 123,
                                'Items': [
                                    'GET',
                                ],
                                'CachedMethods': {
                                    'Quantity': 123,
                                    'Items': [
                                        'GET',
                                    ]
                                }
                            },
                            'SmoothStreaming': True,
                            'Compress': True,
                            'LambdaFunctionAssociations': {
                                'Quantity': 123,
                                'Items': [
                                    {
                                        'LambdaFunctionARN': 'string',
                                        'EventType': 'viewer-request',
                                        'IncludeBody': True
                                    },
                                ]
                            },
                            'FunctionAssociations': {
                                'Quantity': 123,
                                'Items': [
                                    {
                                        'FunctionARN': 'string',
                                        'EventType': 'viewer-request'
                                    },
                                ]
                            },
                            'FieldLevelEncryptionId': 'string',
                            'RealtimeLogConfigArn': 'string',
                            'CachePolicyId': 'string',
                            'OriginRequestPolicyId': 'string',
                            'ForwardedValues': {
                                'QueryString': True,
                                'Cookies': {
                                    'Forward': 'none',
                                    'WhitelistedNames': {
                                        'Quantity': 123,
                                        'Items': [
                                            'string',
                                        ]
                                    }
                                },
                                'Headers': {
                                    'Quantity': 123,
                                    'Items': [
                                        'string',
                                    ]
                                },
                                'QueryStringCacheKeys': {
                                    'Quantity': 123,
                                    'Items': [
                                        'string',
                                    ]
                                }
                            },
                            'MinTTL': 123,
                            'DefaultTTL': 123,
                            'MaxTTL': 123
                        },
                    ]
                },
                'CustomErrorResponses': {
                    'Quantity': 123,
                    'Items': [
                        {
                            'ErrorCode': 123,
                            'ResponsePagePath': 'string',
                            'ResponseCode': 'string',
                            'ErrorCachingMinTTL': 123
                        },
                    ]
                },
                'Comment': 'string',
                'PriceClass': 'PriceClass_100',
                'Enabled': True,
                'ViewerCertificate': {
                    'CloudFrontDefaultCertificate': True,
                    'IAMCertificateId': 'string',
                    'ACMCertificateArn': 'string',
                    'SSLSupportMethod': 'sni-only',
                    'MinimumProtocolVersion': 'TLSv1.2_2019',
                    'Certificate': 'string',
                    'CertificateSource': 'cloudfront'
                },
                'Restrictions': {
                    'GeoRestriction': {
                        'RestrictionType': 'blacklist',
                        'Quantity': 123,
                        'Items': [
                            'string',
                        ]
                    }
                },
                'WebACLId': 'string',
                'HttpVersion': 'http1.1',
                'IsIPV6Enabled': True,
                'AliasICPRecordals': [
                    {
                        'CNAME': 'string',
                        'ICPRecordalStatus': 'APPROVED'
                    },
                ]
            },
        ]
    }
}

get_distribution_response_trusted_user_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_trusted_user_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_origin_shield_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_origin_shield_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_default_viewer_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_default_viewer_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": False,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_geo_restriction_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_geo_restriction_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": False,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "none", "Quantity": 0,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_field_level_encryption_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
                "FieldLevelEncryptionId": "string"
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_field_level_encryption_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
                "FieldLevelEncryptionId": ""
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": False,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "none", "Quantity": 0,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_waf_enabled_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
                "FieldLevelEncryptionId": "string"
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_waf_enabled_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
                "FieldLevelEncryptionId": ""
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {"CloudFrontDefaultCertificate": False,},
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "none", "Quantity": 0,}
            },
            "WebACLId": "",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_default_tls_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
                "FieldLevelEncryptionId": "string"
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {
                "CloudFrontDefaultCertificate": True,
                "MinimumProtocolVersion": "TLSv1",
            },
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_default_tls_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {"Id": "string", "DomainName": "string", "OriginPath": "string",}
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
                "FieldLevelEncryptionId": ""
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {
                "CloudFrontDefaultCertificate": True,
                "MinimumProtocolVersion": "",
            },
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "none", "Quantity": 0,}
            },
            "WebACLId": "",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_custom_origin_tls_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {
                        "Id": "string",
                        "DomainName": "string",
                        "OriginPath": "",
                        "CustomHeaders": {
                            "Quantity": 0
                        },
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                            "OriginSslProtocols": {
                                "Quantity": 1,
                                "Items": [
                                    "TLSv1.2"
                                ]
                            }
                        }
                    }
                ]
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
                "FieldLevelEncryptionId": "string"
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {
                "CloudFrontDefaultCertificate": True,
                "MinimumProtocolVersion": "",
            },
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 123,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_custom_origin_tls_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 123,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 123,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 123,
                "Items": [
                    {
                        "ErrorCode": 123,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 123,
                    },
                ],
            },
            "Origins": {
                "Quantity": 123,
                "Items": [
                    {
                        "Id": "string",
                        "DomainName": "string",
                        "OriginPath": "",
                        "CustomHeaders": {
                            "Quantity": 0
                        },
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                            "OriginSslProtocols": {
                                "Quantity": 1,
                                "Items": [
                                    "TLSv1"
                                ]
                            }
                        }
                    }
                ]
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "string",
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {
                    "Enabled": True,
                    "Quantity": 123,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 123,
                "AllowedMethods": {
                    "Quantity": 123,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 123, "Items": ["GET",]},
                },
                "FieldLevelEncryptionId": ""
            },
            "Comment": "string",
            "Logging": {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": "string",
                "Prefix": "string",
            },
            "PriceClass": "PriceClass_100",
            "Enabled": True,
            "ViewerCertificate": {
                "CloudFrontDefaultCertificate": True,
                "MinimumProtocolVersion": "",
            },
            "Restrictions": {
                "GeoRestriction": {"RestrictionType": "none", "Quantity": 0,}
            },
            "WebACLId": "",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

@pytest.fixture(scope="function")
def cloudfront_stubber():
    cloudfront_stubber = Stubber(cloudfront)
    cloudfront_stubber.activate()
    yield cloudfront_stubber
    cloudfront_stubber.deactivate()


def test_trusted_signers_pass(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_trusted_user_pass
    )
    results = cloudfront_active_trusted_signers_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudfront_stubber.assert_no_pending_responses()


def test_trusted_signers_fail(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_trusted_user_fail
    )
    results = cloudfront_active_trusted_signers_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()

def test_origin_shield_pass(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_origin_shield_pass
    )
    results = cloudfront_origin_shield_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudfront_stubber.assert_no_pending_responses()

def test_origin_shield_fail(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_origin_shield_fail
    )
    results = cloudfront_origin_shield_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()

def test_default_viewer_pass(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_default_viewer_pass
    )
    results = cloudfront_default_viewer_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudfront_stubber.assert_no_pending_responses()

def test_default_viewer_fail(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_default_viewer_fail
    )
    results = cloudfront_default_viewer_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()

def test_geo_restriction_pass(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_geo_restriction_pass
    )
    results = cloudfront_georestriction_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudfront_stubber.assert_no_pending_responses()

def test_geo_restriction_fail(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_geo_restriction_fail
    )
    results = cloudfront_georestriction_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()

def test_field_level_encryption_pass(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_field_level_encryption_pass
    )
    results = cloudfront_field_level_encryption_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudfront_stubber.assert_no_pending_responses()

def test_field_level_encryption_fail(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_field_level_encryption_fail
    )
    results = cloudfront_field_level_encryption_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()    

def test_waf_enabled_pass(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_waf_enabled_pass
    )
    results = cloudfront_waf_enabled_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudfront_stubber.assert_no_pending_responses()

def test_waf_enabled_fail(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_waf_enabled_fail
    )
    results = cloudfront_waf_enabled_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()    

def test_default_tls_pass(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_default_tls_pass
    )
    results = cloudfront_default_tls_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudfront_stubber.assert_no_pending_responses()

def test_default_tls_fail(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_default_tls_fail
    )
    results = cloudfront_default_tls_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()    

def test_custom_origin_tls_pass(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_custom_origin_tls_pass
    )
    results = cloudfront_custom_origin_tls_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudfront_stubber.assert_no_pending_responses()

def test_custom_origin_tls_fail(cloudfront_stubber):
    cloudfront_stubber.add_response("list_distributions", list_distributions_response)
    cloudfront_stubber.add_response(
        "get_distribution", get_distribution_response_custom_origin_tls_fail
    )
    results = cloudfront_custom_origin_tls_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()    