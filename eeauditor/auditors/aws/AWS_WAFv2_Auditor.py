import boto3
import datetime
import json
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
wafv2 = boto3.client("wafv2")

# loop through WAFs
def list_wafs(cache):
    response = cache.get("list_web_acls")
    if response:
        return response
    cache["list_web_acls"] = wafv2.list_web_acls(Scope='REGIONAL')
    return cache["list_web_acls"]

@registry.register_check("wafv2")
def wafv2_web_acl_metrics_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """aaa"""
    for w in list_wafs(cache=cache)["WebACLs"]:
        print(json.dumps(w,indent=2,default=str))