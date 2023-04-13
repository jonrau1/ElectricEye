import datetime
import nmap3
from check_register import CheckRegister
import googleapiclient.discovery

registry = CheckRegister()

# Instantiate a NMAP scanner for TCP scans to define ports
nmap = nmap3.NmapScanTechniques()

def get_compute_engine_instances(cache: dict, gcpProjectId: str):
    '''
    AggregatedList result provides Zone information as well as every single Instance in a Project
    '''
    if cache:
        return cache
    
    results = []

    compute = googleapiclient.discovery.build('compute', 'v1')

    aggResult = compute.instances().aggregatedList(project=gcpProjectId).execute()

    # Write all Zones to list
    zoneList = []
    for zone in aggResult["items"].keys():
        zoneList.append(zone)

    # If the Zone has a top level key of "warning" it does not contain entries
    for z in zoneList:
        for agg in aggResult["items"][z]:
            if agg == 'warning':
                continue
            # reloop the list except looking at instances - this is a normal List we can loop
            else:
                for i in aggResult["items"][z]["instances"]:
                    results.append(i)

    del aggResult
    del zoneList

    return results

# This function performs the actual NMAP Scan
def scan_host(host_ip, host_name, asset_type):
    try:
        results = nmap.nmap_tcp_scan(
            host_ip,
            # FTP, SSH, TelNet, SMTP, HTTP, POP3, NetBIOS, SMB, RDP, MSSQL, MySQL/MariaDB, NFS, Docker, Oracle, PostgreSQL, 
            # Kibana, VMWare, Proxy, Splunk, K8s, Redis, Kafka, Mongo, Rabbit/AmazonMQ, SparkUI
            args="-Pn -p 21,22,23,25,80,110,139,445,3389,1433,3306,2049,2375,1521,5432,5601,8182,8080,8089,10250,6379,9092,27017,5672,4040"
        )

        print(f"Scanning {asset_type} {host_name} on {host_ip}")
        return results
    except KeyError:
        results = None

@registry.register_check("gce")
def gce_attack_surface_open_tcp_port_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """[AttackSurface.GCP.GCE.{checkIdNumber}] Google Compute Engine VM instances should not be publicly reachable on {serviceName}"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        # Check if a Public IP is available in the NICs via "natIP"
        try:
            pubIp = gce["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
        except KeyError:
            pubIp = None
        # Skip over instances without a public IP
        if pubIp == None:
            continue
        # Submit details to the scanner function
        scanner = scan_host(pubIp, name, "GCE VM instance")
        # NoneType returned on KeyError due to Nmap errors
        if scanner == None:
            continue
        else:
            # Loop the results of the scan - starting with Open Ports which require a combination of
            # a Public Instance, an open SG rule, and a running service/server on the host itself
            # use enumerate and a fixed offset to product the Check Title ID number
            for index, p in enumerate(scanner[pubIp]["ports"]):
                # Parse out the Protocol, Port, Service, and State/State Reason from NMAP Results
                checkIdNumber = str(int(index + 1))
                portNumber = int(p["portid"])
                if portNumber == 8089:
                    serviceName = 'SPLUNKD'
                elif portNumber == 10250:
                    serviceName = 'KUBERNETES-API'
                elif portNumber == 5672:
                    serviceName = 'RABBITMQ'
                elif portNumber == 4040:
                    serviceName = 'SPARK-WEBUI'
                else:
                    try:
                        serviceName = str(p["service"]["name"]).upper()
                    except KeyError:
                        serviceName = "Unknown"
                serviceStateReason = str(p["reason"])
                serviceState = str(p["state"])
                # This is a failing check
                if serviceState == "open":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{gcpProjectId}/{zone}/{id}/gcp-attack-surface-gce-open-{serviceName}-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gcp-attack-surface-gce-open-{serviceName}-check",
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices/Network Reachability",
                            "TTPs/Discovery"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": f"[AttackSurface.GCP.GCE.{checkIdNumber}] Google Compute Engine VM instances should not be publicly reachable on {serviceName}",
                        "Description": f"Google Compute Engine VM instance {name} in {zone} is publicly reachable on port {portNumber} which corresponds to the {serviceName} service. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is public (mapped 'natIp`), has an open VPC Firewall rule, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure EC2 instances.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "GCE VM instances should only have the minimum necessary ports open to achieve their purposes, allow traffic from authorized sources, and use other defense-in-depth and hardening strategies. For a basic view on traffic authorization into your instances refer to the Access control overview section of the Google Compute Engine guide",
                                "Url": "https://cloud.google.com/compute/docs/access"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "GcpGceVmInstance",
                                "Id": f"{id}",
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "GcpProjectId": gcpProjectId,
                                        "Zone": zone,
                                        "Name": name,
                                        "Id": id,
                                        "Description": description,
                                        "MachineType": machineType,
                                        "CreatedAt": createdAt,
                                        "LastStartedAt": lastStartedAt,
                                        "Status": status
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
                                "MITRE ATT&CK T1040",
                                "MITRE ATT&CK T1046",
                                "MITRE ATT&CK T1580",
                                "MITRE ATT&CK T1590",
                                "MITRE ATT&CK T1592",
                                "MITRE ATT&CK T1595"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{gcpProjectId}/{zone}/{id}/gcp-attack-surface-gce-open-{serviceName}-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gcp-attack-surface-gce-open-{serviceName}-check",
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices/Network Reachability",
                            "TTPs/Discovery"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": f"[AttackSurface.GCP.GCE.{checkIdNumber}] Google Compute Engine VM instances should not be publicly reachable on {serviceName}",
                        "Description": f"Google Compute Engine VM instance {name} in {zone} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. VM instances and their respective VPC Firewall Rules should still be reviewed for minimum necessary access.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "GCE VM instances should only have the minimum necessary ports open to achieve their purposes, allow traffic from authorized sources, and use other defense-in-depth and hardening strategies. For a basic view on traffic authorization into your instances refer to the Access control overview section of the Google Compute Engine guide",
                                "Url": "https://cloud.google.com/compute/docs/access"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "GcpGceVmInstance",
                                "Id": f"{id}",
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "GcpProjectId": gcpProjectId,
                                        "Zone": zone,
                                        "Name": name,
                                        "Id": id,
                                        "Description": description,
                                        "MachineType": machineType,
                                        "CreatedAt": createdAt,
                                        "LastStartedAt": lastStartedAt,
                                        "Status": status
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
                                "MITRE ATT&CK T1040",
                                "MITRE ATT&CK T1046",
                                "MITRE ATT&CK T1580",
                                "MITRE ATT&CK T1590",
                                "MITRE ATT&CK T1592",
                                "MITRE ATT&CK T1595"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding