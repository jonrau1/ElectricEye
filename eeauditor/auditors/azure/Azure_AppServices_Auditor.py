from azure.mgmt.web  import WebSiteManagementClient, models
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_app_services_apps(cache: dict, azureCredential, azSubId: str) -> list[models.Site]:
    """
    Returns a list of all Azure Database for MySQL Servers in a Subscription
    """
    azAppServicesClient = WebSiteManagementClient(azureCredential, azSubId)

    response = cache.get("get_all_app_services_apps")
    if response:
        return response

    appServicesList = [serv for serv in azAppServicesClient.web_apps.list()]
    if not appServicesList or appServicesList is None:
        appServicesList = []

    cache["get_all_app_services_apps"] = appServicesList
    return cache["get_all_app_services_apps"]

'''
@registry.register_check("azure.application_services")
def azure_app_services_service_authentication_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.AppServices.1] Azure App Services web applications should use Azure App Service Authentication 
    """
    azAppServicesClient = WebSiteManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for webapp in get_all_app_services_apps(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(webapp.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appServicesWebAppName = webapp.name
        appServicesWebAppId = str(webapp.id)
        azRegion = webapp.location
        rgName = appServicesWebAppId.split("/")[4]


        print(webapp.as_dict())
'''