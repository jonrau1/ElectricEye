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
        'MaxItems': 12,
        'IsTruncated': True,
        'Quantity': 12,
        'Items': [
            {
                'Id': 'string',
                'ARN': 'string',
                'Status': 'string',
                'LastModifiedTime': datetime.datetime(2015, 1, 1),
                'DomainName': 'string',
                'Aliases': {
                    'Quantity': 12,
                    'Items': [
                        'string',
                    ]
                },
                'Origins': {
                    'Quantity': 12,
                    'Items': [
                        {
                            'Id': 'string',
                            'DomainName': 'string',
                            'OriginPath': 'string',
                            'CustomHeaders': {
                                'Quantity': 12,
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
                                'HTTPPort': 12,
                                'HTTPSPort': 12,
                                'OriginProtocolPolicy': 'https-only',
                                'OriginSslProtocols': {
                                    'Quantity': 12,
                                    'Items': [
                                        'TLSv1.2',
                                    ]
                                },
                                'OriginReadTimeout': 12,
                                'OriginKeepaliveTimeout': 12
                            },
                            'ConnectionAttempts': 12,
                            'ConnectionTimeout': 12,
                            'OriginShield': {
                                'Enabled': True,
                                'OriginShieldRegion': 'string'
                            }
                        },
                    ]
                },
                'OriginGroups': {
                    'Quantity': 12,
                    'Items': [
                        {
                            'Id': 'string',
                            'FailoverCriteria': {
                                'StatusCodes': {
                                    'Quantity': 12,
                                    'Items': [
                                        12,
                                    ]
                                }
                            },
                            'Members': {
                                'Quantity': 12,
                                'Items': [
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
                        'Quantity': 12,
                        'Items': [
                            'string',
                        ]
                    },
                    'TrustedKeyGroups': {
                        'Enabled': True,
                        'Quantity': 12,
                        'Items': [
                            'string',
                        ]
                    },
                    'ViewerProtocolPolicy': 'redirect-to-https',
                    'AllowedMethods': {
                        'Quantity': 12,
                        'Items': [
                            'GET',
                        ],
                        'CachedMethods': {
                            'Quantity': 12,
                            'Items': [
                                'GET',
                            ]
                        }
                    },
                    'SmoothStreaming': True,
                    'Compress': True,
                    'LambdaFunctionAssociations': {
                        'Quantity': 12,
                        'Items': [
                            {
                                'LambdaFunctionARN': 'string',
                                'EventType': 'viewer-request',
                                'IncludeBody': True
                            },
                        ]
                    },
                    'FunctionAssociations': {
                        'Quantity': 12,
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
                            'Forward': 'all',
                            'WhitelistedNames': {
                                'Quantity': 12,
                                'Items': [
                                    'string',
                                ]
                            }
                        },
                        'Headers': {
                            'Quantity': 12,
                            'Items': [
                                'string',
                            ]
                        },
                        'QueryStringCacheKeys': {
                            'Quantity': 12,
                            'Items': [
                                'string',
                            ]
                        }
                    },
                    'MinTTL': 12,
                    'DefaultTTL': 12,
                    'MaxTTL': 12
                },
                'CacheBehaviors': {
                    'Quantity': 12,
                    'Items': [
                        {
                            'PathPattern': 'string',
                            'TargetOriginId': 'string',
                            'TrustedSigners': {
                                'Enabled': True,
                                'Quantity': 12,
                                'Items': [
                                    'string',
                                ]
                            },
                            'TrustedKeyGroups': {
                                'Enabled': True,
                                'Quantity': 12,
                                'Items': [
                                    'string',
                                ]
                            },
                            'ViewerProtocolPolicy': 'redirect-to-https',
                            'AllowedMethods': {
                                'Quantity': 12,
                                'Items': [
                                    'GET',
                                ],
                                'CachedMethods': {
                                    'Quantity': 12,
                                    'Items': [
                                        'GET',
                                    ]
                                }
                            },
                            'SmoothStreaming': True,
                            'Compress': True,
                            'LambdaFunctionAssociations': {
                                'Quantity': 12,
                                'Items': [
                                    {
                                        'LambdaFunctionARN': 'string',
                                        'EventType': 'viewer-request',
                                        'IncludeBody': True
                                    },
                                ]
                            },
                            'FunctionAssociations': {
                                'Quantity': 12,
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
                                        'Quantity': 12,
                                        'Items': [
                                            'string',
                                        ]
                                    }
                                },
                                'Headers': {
                                    'Quantity': 12,
                                    'Items': [
                                        'string',
                                    ]
                                },
                                'QueryStringCacheKeys': {
                                    'Quantity': 12,
                                    'Items': [
                                        'string',
                                    ]
                                }
                            },
                            'MinTTL': 12,
                            'DefaultTTL': 12,
                            'MaxTTL': 12
                        },
                    ]
                },
                'CustomErrorResponses': {
                    'Quantity': 12,
                    'Items': [
                        {
                            'ErrorCode': 12,
                            'ResponsePagePath': 'string',
                            'ResponseCode': 'string',
                            'ErrorCachingMinTTL': 12
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
                        'Quantity': 12,
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
                        'ICPRecordalStatus': 'PENDING'
                    },
                ]
            },
        ]
    }
}

#     "DistributionList": {
#         "Marker": "string",
#         "MaxItems": 12,
#         "IsTruncated": True,
#         "Quantity": 1,
#         "Items": [
#             {
#                 "Id": "string",
#                 "ARN": "string",
#                 "Status": "string",
#                 "LastModifiedTime": datetime.datetime(2015, 1, 1),
#                 "DomainName": "string",
#                 "Aliases": {"Quantity": 1, "Items": ["string",]},
#                 "Origins": {
#                     "Quantity": 1,
#                     "Items": [{"Id": "string", "DomainName": "string",}],
#                 },
#                 "DefaultCacheBehavior": {
#                     "TargetOriginId": "string",
#                     "ForwardedValues": {
#                         "QueryString": True,
#                         "Cookies": {"Forward": "none"},
#                     },
#                     "TrustedSigners": {"Enabled": True, "Quantity": 1,},
#                     "ViewerProtocolPolicy": "allow-all",
#                     "MinTTL": 12,
#                 },
#                 "CacheBehaviors": {"Quantity": 12,},
#                 "CustomErrorResponses": {"Quantity": 12,},
#                 "Comment": "string",
#                 "PriceClass": "PriceClass_100",
#                 "Enabled": True,
#                 "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
#                 "Restrictions": {
#                     "GeoRestriction": {
#                         "RestrictionType": "blacklist",
#                         "Quantity": 12,
#                         "Items": ["string",],
#                     }
#                 },
#                 "WebACLId": "string",
#                 "HttpVersion": "http1.1",
#                 "IsIPV6Enabled": True,
#             }
#         ],
#     }
# }

get_distribution_response_trusted_user_pass = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
            },
            "WebACLId": "string",
            "HttpVersion": "http1.1",
            "IsIPV6Enabled": True,
        },
    },
}

get_distribution_response_origin_shield_pass = {
    "ETag": "E2QWRUHEXAMPLE",
    "Distribution": {
        "Id": "EDFDVBD6EXAMPLE",
        "ARN": "arn:aws:cloudfront::12456789012:distribution/EDFDVBD6EXAMPLE",
        "Status": "Deployed",
        "LastModifiedTime": "2019-12-04T23:35:41.433Z",
        "InProgressInvalidationBatches": 0,
        "DomainName": "d111111abcdef8.cloudfront.net",
        "ActiveTrustedSigners": {
            "Enabled": "false",
            "Quantity": 0
        },
        "DistributionConfig": {
            "CallerReference": "cli-example",
            "Aliases": {
                "Quantity": 0
            },
            "DefaultRootObject": "index.html",
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "awsexamplebucket.s3.amazonaws.com-cli-example",
                        "DomainName": "awsexamplebucket.s3.amazonaws.com",
                        "OriginPath": "",
                        "CustomHeaders": {
                            "Quantity": 0
                        },
                        "S3OriginConfig": {
                            "OriginAccessIdentity": ""
                        }
                    }
                ]
            },
            "OriginGroups": {
                "Quantity": 0
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "awsexamplebucket.s3.amazonaws.com-cli-example",
                "ForwardedValues": {
                    "QueryString": "false",
                    "Cookies": {
                        "Forward": "none"
                    },
                    "Headers": {
                        "Quantity": 0
                    },
                    "QueryStringCacheKeys": {
                        "Quantity": 0
                    }
                },
                "TrustedSigners": {
                    "Enabled": "false",
                    "Quantity": 0
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 0,
                "AllowedMethods": {
                    "Quantity": 2,
                    "Items": [
                        "HEAD",
                        "GET"
                    ],
                    "CachedMethods": {
                        "Quantity": 2,
                        "Items": [
                            "HEAD",
                            "GET"
                        ]
                    }
                },
                "SmoothStreaming": "false",
                "DefaultTTL": 86400,
                "MaxTTL": 31536000,
                "Compress": "false",
                "LambdaFunctionAssociations": {
                    "Quantity": 0
                },
                "FieldLevelEncryptionId": ""
            },
            "CacheBehaviors": {
                "Quantity": 0
            },
            "CustomErrorResponses": {
                "Quantity": 0
            },
            "Comment": "",
            "Logging": {
                "Enabled": "false",
                "IncludeCookies": "false",
                "Bucket": "",
                "Prefix": ""
            },
            "PriceClass": "PriceClass_All",
            "Enabled": "true",
            "ViewerCertificate": {
                "CloudFrontDefaultCertificate": "true",
                "MinimumProtocolVersion": "TLSv1",
                "CertificateSource": "cloudfront"
            },
            "Restrictions": {
                "GeoRestriction": {
                    "RestrictionType": "none",
                    "Quantity": 0
                }
            },
            "WebACLId": "",
            "HttpVersion": "http2",
            "IsIPV6Enabled": "true"
        }
    }
}

# get_distribution_response_origin_shield_pass = {
#     "Distribution": {
#         "Id": "string",
#         "ARN": "string",
#         "Status": "string",
#         "LastModifiedTime": datetime.datetime(2015, 1, 1),
#         "InProgressInvalidationBatches": 12,
#         "DomainName": "string",
#         "ActiveTrustedSigners": {"Enabled": True, "Quantity": 12,},
#         "DistributionConfig": {
#             "CallerReference": "string",
#             "CustomErrorResponses": {
#                 "Quantity": 12,
#                 "Items": [
#                     {
#                         "ErrorCode": 12,
#                         "ResponsePagePath": "string",
#                         "ResponseCode": "string",
#                         "ErrorCachingMinTTL": 12,
#                     },
#                 ],
#             },
#             "Origins": {
#                 "Quantity": 12,
#                 "Items": [
#                     {"Id": "string", "DomainName": "string", "OriginPath": "string",}
#                 ],
#             },
#             "DefaultCacheBehavior": {
#                 "TargetOriginId": "string",
#                 "ForwardedValues": {
#                     "QueryString": True,
#                     "Cookies": {"Forward": "none"},
#                 },
#                 "TrustedSigners": {
#                     "Enabled": True,
#                     "Quantity": 12,
#                     "Items": ["string",],
#                 },
#                 "ViewerProtocolPolicy": "allow-all",
#                 "MinTTL": 12,
#                 "AllowedMethods": {
#                     "Quantity": 12,
#                     "Items": ["GET",],
#                     "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
#                 },
#             },
#             "Comment": "string",
#             "Logging": {
#                 "Enabled": True,
#                 "IncludeCookies": True,
#                 "Bucket": "string",
#                 "Prefix": "string",
#             },
#             "PriceClass": "PriceClass_100",
#             "Enabled": True,
#             "ViewerCertificate": {"CloudFrontDefaultCertificate": True,},
#             "Restrictions": {
#                 "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
#             },
#             "WebACLId": "string",
#             "HttpVersion": "http1.1",
#             "IsIPV6Enabled": True,
#         },
#     },
# }

get_distribution_response_origin_shield_fail = {
    "Distribution": {
        "Id": "string",
        "ARN": "string",
        "Status": "string",
        "LastModifiedTime": datetime.datetime(2015, 1, 1),
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": True, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
                "GeoRestriction": {"RestrictionType": "blacklist", "Quantity": 12,}
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
        "InProgressInvalidationBatches": 12,
        "DomainName": "string",
        "ActiveTrustedSigners": {"Enabled": False, "Quantity": 12,},
        "DistributionConfig": {
            "CallerReference": "string",
            "CustomErrorResponses": {
                "Quantity": 12,
                "Items": [
                    {
                        "ErrorCode": 12,
                        "ResponsePagePath": "string",
                        "ResponseCode": "string",
                        "ErrorCachingMinTTL": 12,
                    },
                ],
            },
            "Origins": {
                "Quantity": 12,
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
                    "Quantity": 12,
                    "Items": ["string",],
                },
                "ViewerProtocolPolicy": "allow-all",
                "MinTTL": 12,
                "AllowedMethods": {
                    "Quantity": 12,
                    "Items": ["GET",],
                    "CachedMethods": {"Quantity": 12, "Items": ["GET",]},
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
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
        cache={}, awsAccountId="01245678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudfront_stubber.assert_no_pending_responses()    