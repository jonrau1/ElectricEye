# ElectricEye

![Logo](./screenshots/logo.svg)

ElectricEye is a multi-cloud, multi-SaaS Python CLI tool for Asset Management, Security Posture Management, and External Attack Surface Management supporting 100s of services and evaluations to harden your public cloud & SaaS environments.

***Up here in space***<br/>
***I'm looking down on you***<br/>
***My lasers trace***<br/>
***Everything you do***<br/>
<sub>*Judas Priest, 1982*</sub>

## Super Quick Start :triangular_flag_on_post: :triangular_flag_on_post:

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye
pip3 install -r requirements.txt
python3 eeauditor/controller.py -t AWS -o stdout
```

## Table of Contents

- [Architecture](#architecture)
- [Quick Run Down](#quick-run-down-running-running)
- [Tell me more!](#tell-me-more-raised_eyebrow-raised_eyebrow)
- [Using ElectricEye](#using-electriceye)
- [Cloud Asset Management](./docs/asset_management/ASSET_MANAGEMENT.md)
- [Custom Outputs](./docs/outputs/OUTPUTS.md)
- [FAQ](./docs/faq/FAQ.md)
- [Supported Services and Checks](#supported-services-and-checks)
- [Contributing](#contributing)
- [Developer Guide](./docs/new_checks/DEVELOPER_GUIDE.md)
    - [Auditor testing](./docs/new_checks/DEVELOPER_GUIDE.md#auditor-testing)
- [License](#license)

## Architecture

![Architecture](./screenshots/ElectricEye2023Architecture.jpg)

## Quick Run Down :running: :running:

- ElectricEye is a Python CLI tool that offers cross-Account, cross-Region, multi-Cloud CAM, CSPM, SSPM, and EASM capabilities across AWS, GCP, and ServiceNow (*with more on the way!*). All Partitions are supported for AWS!

- ElectricEye offers over 500 checks for security, reliability, monitoring, and exposure across 100 CSP & SaaS services, including atypical services not supported by AWS Config/Google Cloud Asset API or mainstream CSPM & CNAPP tools.

- All checks are currently mapped to NIST Cybersecurity Framework V1.1, NIST Special Publication 800-53 Revision 4, AICPA 2020 Trust Service Criteria (TSCs), and ISO 27001:2013 ISMS controls.

- The EASM module uses NMAP for service discovery and reachability assessment of over 20 highly-dangerous ports and protocols for nearly every public-facing CSP service

- Outputs to AWS Security Hub, AWS DocumentDB, JSON, CSV, HTML Executive Reports, MongoDB, Amazon SQS, PostgreSQL, Amazon Simple Queue Service (SQS), Amazon DynamoDB, and [**FireMon Cloud Defense**](https://www.firemon.com/introducing-disruptops/).

## Tell Me More! :raised_eyebrow: :raised_eyebrow:

ElectricEye's core concept is the **Auditor** which are sets of Python scripts that run **Checks** per Service dedicated to a specific SaaS vendor or public cloud service provider called an **Assessment Target**. You can run an entire Assessment Target, a specific Auditor, or a specific Check within an Auditor. After ElectricEye is done with evaluations, it supports over a dozen types of **Outputs** ranging from an HTML executive report to AWS DocumentDB clusters. ElectricEye also uses other tools such as Shodan, `detect-secrets`, and NMAP for carrying out its Checks. While mainly a security tool, ElectricEye can be used for Cloud Asset Management use cases such as discovery and inventory and has Checks aligned to several best-practice regimes that cover resiliency, recovery, performance optimization, monitoring, as well as several 100 security checks against your cloud infrastructure and identities.

First, clone this repository and install the requirements using `pip3`: `pip3 install -r requirements.txt`.

Then, modify the [TOML file](./eeauditor/external_providers.toml) located in `ElectricEye/eeauditor/external_providers.toml` to specify various configurations for the CSP(s) and SaaS Provider(s) you want to assess.

Finally, run the Controller to learn about the various Checks, Auditors, Assessment Targets, and Outputs.

```bash
$ python3 eeauditor/controller.py --help
Usage: controller.py [OPTIONS]

Options:
  -t, --target-provider [AWS|Azure|OracleCloud|GCP|Servicenow]
                                  CSP or SaaS Vendor Assessment Target, ensure
                                  that any -a or -c arg maps to your target
                                  provider e.g., -t AWS -a
                                  Amazon_APGIW_Auditor
  -a, --auditor-name TEXT         Specify which Auditor you want to run by
                                  using its name NOT INCLUDING .py. Defaults
                                  to ALL Auditors
  -c, --check-name TEXT           A specific Check in a specific Auditor you
                                  want to run, this correlates to the function
                                  name. Defaults to ALL Checks
  -d, --delay INTEGER             Time in seconds to sleep between Auditors
                                  being ran, defaults to 0
  -o, --outputs TEXT              A list of Outputs (files, APIs, databases)
                                  to send ElectricEye Findings - can provide
                                  more than one  [default: stdout]
  --output-file TEXT              For file outputs such as JSON and CSV, the
                                  name of the file, DO NOT SPECIFY .file_type
                                  [default: output]
  --list-options                  Lists all valid Output options
  --list-checks                   List all Checks, Assets, and Check
                                  Description within every Auditor for a
                                  specific Assessment Target
  --create-insights               Create SecurityHub insights for ElectricEye.
                                  This only needs to be done once per Security
                                  Hub instance
  --list-controls                 Lists all Controls (Check Titles) for an
                                  Assessment Target, used for mapping...
  --help                          Show this message and exit.                     Show this message and exit.
```

For more information see [here](#using-electriceye), you can read the [FAQ here](./docs/faq/FAQ.md), or if you want a more in-depth analysis of the control flow and concepts review [the Developer Guide](./docs/new_checks/DEVELOPER_GUIDE.md).

## Using ElectricEye

Refer to sub-headings for per-CSP or per-SaaS setup instructions.

### Public Cloud Service Providers

- [For Amazon Web Services (AWS)](./docs/setup/Setup_AWS.md)
- [For Google Cloud Platform (GCP)](./docs/setup/Setup_GCP.md)
- [For Microsoft Azure (*Coming Soon*)](./docs/setup/Setup_Azure.md)
- [For Oracle Cloud Infrastructure (*Coming Soon*)](./docs/setup/Setup_OCI.md)

### Software-as-a-Service (SaaS) Providers

- [For ServiceNow](./docs/setup/Setup_ServiceNow.md)
- [For Microsoft M365 (E5) (*Coming Soon*)](./docs//Setup_M365.md)
- [For Workday ERP (*Coming Soon*)](./docs/setup/Setup_WorkDay.md)
- [For GitHub (*Coming Soon*)](./docs/setup/Setup_GitHub.md)

## Cloud Asset Management (CAM)

For more information on ElectricEye's CAM concept of operations and output, refer to [the Asset Management documentation](./docs/asset_management/ASSET_MANAGEMENT.md)

Individual information is located at:

- [CAM Concept of Operations](./docs/asset_management/ASSET_MANAGEMENT.md#cam-concept-of-operations-conops)
- [CAM Reporting](./docs/asset_management/ASSET_MANAGEMENT.md#cloud-asset-management-cam-reporting)
- [Asset Class Mapping](./docs/asset_management/ASSET_MANAGEMENT.md#asset-class-mapping)

## Supported Services and Checks

In total there are:

> - **3** Supported Public CSPs

> - **1** Supported SaaS Provider

> - **830** Security & Resilience Best Practice Checks supported across all Public CSPs & SaaS Providers

> - **122** Supported CSP & SaaS Resources / Asset Types

> - **102** Auditor Plugins

### AWS Checks & Services
___

These are the following services and checks perform by each Auditor, there are currently...

- :boom: **556 Checks** :boom:
- :exclamation: **103 supported AWS services/components** :exclamation:
- :fire: **77 Auditors** :fire:

**Regarding AWS ElasticSearch Service/OpenSearch Service:** AWS has stopped supporting Elastic after Version 7.10 and released a new service named OpenSearch. The APIs/SDKs/CLI are interchangable. Only ASFF metadata has changed to reflect this, the Auditor Names, Check Names, and ASFF ID's have stayed the same.

**Regarding AWS Shield Advanced:** You must be actively subscribed to Shield Advanced with at least one Protection assigned to assess this Service.

**Regarding AWS Trusted Advisor:** You must be on AWS Business or Enterprise Support to interact with the `support` API for Trusted Advisor.

**Regarding AWS Health:** You must be on AWS Business or Enterprise Support to interact with the `support` API for Health.

| Auditor File Name | Scanned Resource Name | Auditor Scan Description |
|---|---|---|
| Amazon_APIGW_Auditor | API Gateway Stage | Are stage metrics enabled |
| Amazon_APIGW_Auditor | API Gateway Stage | Is stage API logging enabled |
| Amazon_APIGW_Auditor | API Gateway Stage | Is stage caching enabled |
| Amazon_APIGW_Auditor | API Gateway Stage | Is cache encryption enabled |
| Amazon_APIGW_Auditor | API Gateway Stage | Is stage xray tracing configured |
| Amazon_APIGW_Auditor | API Gateway Stage | Is the stage protected by a WAF WACL |
| Amazon_APIGW_Auditor | API Gateway Rest API | Do Rest APIs use Policies |
| Amazon_APIGW_Auditor | API Gateway Rest API | Do Rest APIs use Authorizers |
| Amazon_AppStream_Auditor | AppStream 2.0 (Fleets) | Do Fleets allow Default Internet Access |
| Amazon_AppStream_Auditor | AppStream 2.0 (Images) | Are Images Public |
| Amazon_AppStream_Auditor | AppStream 2.0 (Users) | Are users reported as Compromised |
| Amazon_AppStream_Auditor | AppStream 2.0 (Users) | Do users use SAML authentication |
| Amazon_Athena_Auditor | Athena workgroup | Do workgroups enforce query result encryption |
| Amazon_Athena_Auditor | Athena workgroup | Do workgroups with query result encryption override client settings |
| Amazon_Athena_Auditor | Athena workgroup | Do workgroups publish metrics |
| Amazon_Athena_Auditor | Athena workgroup | Do workgroups auto-update the Athena engine version |
| Amazon_Autoscaling_Auditor | Autoscaling groups | Do ASGs protect instances from scale-in |
| Amazon_Autoscaling_Auditor | Autoscaling groups | Do ASGs with ELB or Target Groups use ELB health checks |
| Amazon_Autoscaling_Auditor | Autoscaling groups | Do ASGs use at least half or more of a Region's open AZs |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros with trusted signers use key pairs |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distro origins have Origin Shield enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros use the default viewer certificate |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have Georestriction enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have Field-Level Encryption enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have WAF enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Default Viewer TLS 1.2 |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Custom Origin TLS 1.2 |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Custom Origin HTTPS-only connections |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Default Viewer HTTPS with SNI |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have logging enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have default root objects |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Default Viewer HTTPS-only connections |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce S3 Origin Object Access Identity |
| Amazon_CloudSearch_Auditor | CloudSearch Domain | Do Domains enforce HTTPS-only |
| Amazon_CloudSearch_Auditor | CloudSearch Domain | Do Domains use TLS 1.2 |
| Amazon_CognitoIdP_Auditor | Cognito Identity Pool | Does the Password policy comply with AWS CIS Foundations Benchmark |
| Amazon_CognitoIdP_Auditor | Cognito Identity Pool | Cognito Temporary Password Age |
| Amazon_CognitoIdP_Auditor | Cognito Identity Pool | Does the Identity pool enforce MFA |
| Amazon_CognitoIdP_Auditor | Cognito Identity Pool | Is the Identity pool protected by WAF |
| Amazon_DocumentDB_Auditor | DocumentDB Instance | Are Instances publicly accessible |
| Amazon_DocumentDB_Auditor | DocumentDB Instance | Are Instance encrypted |
| Amazon_DocumentDB_Auditor | DocumentDB Instance | Is audit logging enabled |
| Amazon_DocumentDB_Auditor | DocumentDB Cluster | Is the Cluster configured for HA |
| Amazon_DocumentDB_Auditor | DocumentDB Cluster | Is the Cluster deletion protected |
| Amazon_DocumentDB_Auditor | DocumentDB Cluster | Is cluster audit logging on |
| Amazon_DocumentDB_Auditor | DocumentDB Cluster | Is cluster TLS enforcement on |
| Amazon_DocumentDB_Auditor | DocDB Snapshot | Are docdb cluster snapshots encrypted |
| Amazon_DocumentDB_Auditor | DocDB Snapshot | Are docdb cluster snapshots public |
| Amazon_DynamoDB_Auditor | DynamoDB Table | Do tables use KMS CMK for encryption |
| Amazon_DynamoDB_Auditor | DynamoDB Table | Do tables have PITR enabled |
| ~~Amazon_DynamoDB_Auditor~~ | ~~DynamoDB Table~~ | ~~Do tables have TTL enabled~~ **THIS FINDING HAS BEEN RETIRED** |
| Amazon_DAX_Auditor | DAX Cluster | Do clusters encrypt data at rest |
| Amazon_DAX_Auditor | DAX Cluster | Do clusters encrypt data in transit |
| Amazon_DAX_Auditor | DAX Cluster | Do clusters have cache item TTL defined |
| Amazon_EBS_Auditor | EBS Volume | Is the Volume attached |
| Amazon_EBS_Auditor | EBS Volume | Is the Volume configured to be deleted on instance termination |
| Amazon_EBS_Auditor | EBS Volume | Is the Volume encrypted |
| Amazon_EBS_Auditor | EBS Snapshot | Is the Snapshot encrypted |
| Amazon_EBS_Auditor | EBS Snapshot | Is the Snapshot public |
| Amazon_EBS_Auditor | Account | Is account level encryption by default enabled |
| Amazon_EBS_Auditor | EBS Volume | Does the Volume have a snapshot |
| Amazon_EC2_Auditor | EC2 Instance | Is IMDSv2 enabled |
| Amazon_EC2_Auditor | EC2 Instance | Is Secure Enclave used |
| Amazon_EC2_Auditor | EC2 Instance | Is the instance internet-facing |
| Amazon_EC2_Auditor | EC2 Instance | Is Source/Dest Check disabled |
| Amazon_EC2_Auditor | AWS Account | Is Serial Port Access restricted |
| Amazon_EC2_Auditor | EC2 Instance | Is instance using an AMI baked in last 3 months |
| Amazon_EC2_Auditor | EC2 Instance | Is instance using a correctly registered AMI |
| Amazon_EC2_Auditor | Account | Are instances spread across Multiple AZs |
| Amazon_EC2_Image_Builder_Auditor | Image Builder | Are pipeline tests enabled |
| Amazon_EC2_Image_Builder_Auditor | Image Builder | Is EBS encrypted |
| Amazon_EC2_Security_Group_Auditor | Security Group | Are all ports (-1) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is FTP (tcp20-21) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is TelNet (tcp23) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is WSDCOM-RPC (tcp135) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is SMB (tcp445) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is MSSQL (tcp1433) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is OracleDB (tcp1521) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is MySQL/MariaDB (tcp3306) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is RDP (tcp3389) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is PostgreSQL (tcp5432) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Kibana (tcp5601) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Redis (tcp6379) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Splunkd (tcp8089) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Elasticsearch (tcp9200) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Elasticsearch (tcp9300) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Memcached (udp11211) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Redshift (tcp5439) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is DocDB (tcp27017) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Cassandra (tcp9142) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Kafka (tcp9092) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is NFS (tcp2049) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Rsync (tcp873) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is TFTP (udp69) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Docker API (tcp2375) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is K8s API (tcp10250) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is SMTP (tcp25) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is NetBioas (tcp137-139) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is OpenVPN (udp1194) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is RabbitMQ (tcp5672) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Spark WebUI (tcp4040) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is POP3 (tcp110) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is VMWare ESXi (tcp8182) open to the internet |
| Amazon_EC2_SSM_Auditor | EC2 Instance | Is the instance managed by SSM |
| Amazon_EC2_SSM_Auditor | EC2 Instance | Does the instance have a successful SSM association |
| Amazon_EC2_SSM_Auditor | EC2 Instance | Is the SSM Agent up to date |
| Amazon_EC2_SSM_Auditor | EC2 Instance | Is the Patch status up to date |
| Amazon_ECR_Auditor | ECR Registry (Account) | Is there a registry access policy |
| Amazon_ECR_Auditor | ECR Registry (Account) | Is image replication configured |
| Amazon_ECR_Auditor | ECR Repository | Does the repository support scan-on-push |
| Amazon_ECR_Auditor | ECR Repository | Is there an image lifecycle policy |
| Amazon_ECR_Auditor | ECR Repository | Is there a repo access policy |
| Amazon_ECR_Auditor | Image (Container) | Does the latest container have any vulns |
| Amazon_ECS_Auditor | ECS Cluster | Is container insights enabled |
| Amazon_ECS_Auditor | ECS Cluster | Is a default cluster provider configured |
| Amazon_ECS_Auditor | ECS Task Definition | Is the Task Definition using a Privileged container |
| Amazon_ECS_Auditor | ECS Task Definition | Do EC2-ECS containers use SELinux or AppArmor |
| Amazon_ECS_Auditor | ECS Task Definition | Do containers use a Root user |
| Amazon_EFS_Auditor | EFS File System | Are file systems encrypted |
| Amazon_EFS_Auditor | EFS File System | Does the File system have a custom policy attached |
| Amazon_EKS_Auditor | EKS Cluster | Is the API Server publicly accessible |
| Amazon_EKS_Auditor | EKS Cluster | Are one of the *three* latest K8s version used |
| Amazon_EKS_Auditor | EKS Cluster | Are auth or audit logs enabled |
| Amazon_EKS_Auditor | EKS Cluster | Is K8s Secrets envelope encryption used |
| Amazon_EKS_Auditor | EKS Cluster | Is a deprecated K8s version used |
| Amazon_Elasticache_Redis_Auditor | Elasticache Redis Cluster | Is an AUTH Token used |
| Amazon_Elasticache_Redis_Auditor | Elasticache Redis Cluster | Is the cluster encrypted at rest |
| Amazon_Elasticache_Redis_Auditor | Elasticache Redis Cluster | Does the cluster encrypt in transit |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is IMDSv1 disabled |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is platform auto-update and instance refresh enabled |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is enhanced health reporting enabled |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is CloudWatch log streaming enabled |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is AWS X-Ray tracing enabled |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Are dedicated masters used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is Cognito auth used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is encryption at rest used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is Node2Node encryption used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is HTTPS-only enforced |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is a TLS 1.2 policy used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Are there available version updates |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is ES in a VPC |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is ES Publicly Accessible |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Do internet facing ELBs have a secure listener |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Do secure listeners enforce TLS 1.2 |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Is cross zone load balancing enabled |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Is connection draining enabled |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Is access logging enabled |
| Amazon_ELBv2_Auditor | ELBv2 (ALB) | Is access logging enabled for ALBs |
| Amazon_ELBv2_Auditor | ELBv2 (ALB/NLB) | Is deletion protection enabled |
| Amazon_ELBv2_Auditor | ELBv2 (ALB/NLB) | Do internet facing ELBs have a secure listener |
| Amazon_ELBv2_Auditor | ELBv2 (ALB/NLB) | Do secure listeners enforce TLS 1.2 |
| Amazon_ELBv2_Auditor | ELBv2 (ALB/NLB) | Are invalid HTTP headers dropped |
| Amazon_ELBv2_Auditor | ELBv2 (NLB) | Do NLBs with TLS listeners have access logging enabled |
| Amazon_ELBv2_Auditor | ELBv2 (ALB) | Do ALBs have HTTP Desync protection enabled |
| Amazon_ELBv2_Auditor | ELBv2 (ALB) | Do ALBs SGs allow access to non-Listener ports |
| Amazon_ELBv2_Auditor | ELBv2 (ALB) | Ares ALBs protected by WAF |
| Amazon_EMR_Auditor | EMR Cluster | Do clusters have a sec configuration attached |
| Amazon_EMR_Auditor | EMR Cluster | Do cluster sec configs enforce encryption in transit |
| Amazon_EMR_Auditor | EMR Cluster | Do cluster sec configs enforce encryption at rest for EMRFS |
| Amazon_EMR_Auditor | EMR Cluster | Do cluster sec configs enforce encryption at rest for EBS |
| Amazon_EMR_Auditor | EMR Cluster | Do cluster sec configs enforce Kerberos authN |
| Amazon_EMR_Auditor | EMR Cluster | Is cluster termination protection enabled |
| Amazon_EMR_Auditor | EMR Cluster | Is cluster logging enabled |
| Amazon_EMR_Auditor | AWS Account | Is EMR public SG block configured for the Account in the region |
| Amazon_EMR_Serverless_Auditor | EMR Serverless Application | Is Application in a VPC |
| Amazon_EMR_Serverless_Auditor | EMR Serverless Application | Does Application use custom container runtime |
| Amazon_Kinesis_Analytics_Auditor | Kinesis analytics application | Does application log to CloudWatch |
| Amazon_Kinesis_Data_Streams_Auditor | Kinesis data stream | Is stream encryption enabled |
| Amazon_Kinesis_Data_Streams_Auditor | Kinesis data stream | Is enhanced monitoring enabled |
| Amazon_Kinesis_Firehose_Auditor | Firehose delivery stream | Is delivery stream encryption enabled |
| Amazon_Managed_Blockchain_Auditor | Fabric peer node | Are chaincode logs enabled |
| Amazon_Managed_Blockchain_Auditor | Fabric peer node | Are peer node logs enabled |
| Amazon_Managed_Blockchain_Auditor | Fabric member | Are member CA logs enabled |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message brokers should be encrypted with customer-managed KMS CMKs |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message brokers should have audit logging enabled |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message brokers should have general logging enabled |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message broker should not be publicly accessible |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message brokers should be configured to auto upgrade to the latest minor version |
| Amazon_MSK_Auditor | MSK Cluster | Is inter-cluster encryption used |
| Amazon_MSK_Auditor | MSK Cluster | Is client-broker communications TLS-only |
| Amazon_MSK_Auditor | MSK Cluster | Is enhanced monitoring used |
| Amazon_MSK_Auditor | MSK Cluster | Is Private CA TLS auth used |
| Amazon_MWAA_Auditor | Airflow Environment | Is a KMS CMK used for encryption |
| Amazon_MWAA_Auditor | Airflow Environment | Is the Airflow URL Public |
| Amazon_MWAA_Auditor | Airflow Environment | Are DAG Processing logs configured |
| Amazon_MWAA_Auditor | Airflow Environment | Are Scheduler logs configured |
| Amazon_MWAA_Auditor | Airflow Environment | Are Task logs configured |
| Amazon_MWAA_Auditor | Airflow Environment | Are Webserver logs configured |
| Amazon_MWAA_Auditor | Airflow Environment | Are Worker logs configured |
| Amazon_Neptune_Auditor | Neptune instance | Is Neptune instance configured for HA |
| Amazon_Neptune_Auditor | Neptune instance | Is Neptune instance storage encrypted |
| Amazon_Neptune_Auditor | Neptune instance | Does Neptune instance use IAM DB Auth |
| Amazon_Neptune_Auditor | Neptune cluster | Is SSL connection enforced |
| ~~Amazon_Neptune_Auditor~~ | ~~Neptune cluster~~ | ~~Is audit logging enabled~~ **THIS FINDING HAS BEEN RETIRED** |
| Amazon_Neptune_Auditor | Neptune instance | Does Neptune instance export audit logs |
| Amazon_Neptune_Auditor | Neptune instance | Is Neptune instance deletion protected |
| Amazon_Neptune_Auditor | Neptune instance | Does Neptune instance automatically update minor versions |
| Amazon_Neptune_Auditor | Neptune cluster | Are Neptune clusters configured to auto-scale |
| Amazon_Neptune_Auditor | Neptune cluster | Are Neptune clusters configured to cache query results |
| Amazon_QLDB_Auditor | QLDB Ledger | Does ledger have deletion protection |
| Amazon_QLDB_Auditor | QLDB Export | Is export encryption enabled |
| Amazon_RDS_Auditor | RDS DB Instance | Is HA configured |
| Amazon_RDS_Auditor | RDS DB Instance | Are DB instances publicly accessible |
| Amazon_RDS_Auditor | RDS DB Instance | Is DB storage encrypted |
| Amazon_RDS_Auditor | RDS DB Instance | Do supported DBs use IAM Authentication |
| Amazon_RDS_Auditor | RDS DB Instance | Are supported DBs joined to a domain |
| Amazon_RDS_Auditor | RDS DB Instance | Is performance insights enabled |
| Amazon_RDS_Auditor | RDS DB Instance | Is deletion protection enabled |
| Amazon_RDS_Auditor | RDS DB Instance | Is database CloudWatch logging enabled |
| Amazon_RDS_Auditor | RDS Snapshot | Are snapshots encrypted |
| Amazon_RDS_Auditor | RDS Snapshot | Are snapshots public |
| Amazon_RDS_Auditor | RDS DB Cluster (Aurora) | Is Database Activity Stream configured |
| Amazon_RDS_Auditor | RDS DB Cluster (Aurora) | Is the cluster encrypted |
| Amazon_RDS_Auditor | RDS DB Instance | Does Instance have any snapshots |
| Amazon_RDS_Auditor | RDS DB Instance | Does the instance security group allow risky access |
| Amazon_RDS_Auditor | Event Subscription (Account) | Does an Event Subscription to monitor DB instances exist |
| Amazon_RDS_Auditor | Event Subscription (Account) | Does an Event Subscription to monitor paramter groups exist |
| Amazon_RDS_Auditor | RDS DB Instance | Do PostgreSQL instances use a version susceptible to Lightspin "log_fwd" attack |
| Amazon_RDS_Auditor | RDS DB Instance | Do Aurora PostgreSQL instances use a version susceptible to Lightspin "log_fwd" attack |
| Amazon_Redshift_Auditor | Redshift cluster | Is the cluster publicly accessible |
| Amazon_Redshift_Auditor | Redshift cluster | Is the cluster encrypted at rest |
| Amazon_Redshift_Auditor | Redshift cluster | Is enhanced VPC routing enabled |
| Amazon_Redshift_Auditor | Redshift cluster | Is cluster audit logging enabled |
| Amazon_Redshift_Auditor | Redshift cluster | Does the cluster use the default Admin username |
| Amazon_Redshift_Auditor | Redshift cluster | Is cluster user activity logging enabled |
| Amazon_Redshift_Auditor | Redshift cluster | Does the cluster enforce encrypted in transit |
| Amazon_Redshift_Auditor | Redshift cluster | Does the cluster take automated snapshots |
| Amazon_Redshift_Auditor | Redshift cluster | Is the cluster configured for automated major version upgrades |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless namespace | Do namespaces use IAM Roles for cross-service access |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless namespace | Do namespaces export all audit logs |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless namespace | Do namespaces use KMS CMKs |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless workgroup | Do workgroups use enhanced VPC routing |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless workgroup | Are workgroups publicly accessible |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless workgroup | Do workgroups enable user activity logging parameters |
| Amazon_Route53_Auditor | Route53 Hosted Zone | Do Hosted Zones have Query Logging enabled |
| Amazon_Route53_Auditor | Route53 Hosted Zone | Do Hosted Zones have traffic policies associated |
| Amazon_Route53_Resolver_Auditor | VPC | Do VPCs have Query Logging enabled |
| Amazon_Route53_Resolver_Auditor | VPC | Do VPCs have DNS Firewalls associated |
| Amazon_Route53_Resolver_Auditor | VPC | Do VPCs enabled DNSSEC resolution |
| Amazon_Route53_Resolver_Auditor | VPC | Do VPCs with DNS Firewall fail open |
| Amazon_S3_Auditor | S3 Bucket | Is bucket encryption enabled |
| Amazon_S3_Auditor | S3 Bucket | Is a bucket lifecycle enabled |
| Amazon_S3_Auditor | S3 Bucket | Is bucket versioning enabled |
| Amazon_S3_Auditor | S3 Bucket | Does the bucket policy allow public access |
| Amazon_S3_Auditor | S3 Bucket | Does the bucket have a policy |
| Amazon_S3_Auditor | S3 Bucket | Is server access logging enabled |
| Amazon_S3_Auditor | Account | Is account level public access block configured |
| Amazon_SageMaker_Auditor | SageMaker Notebook | Is notebook encryption enabled |
| Amazon_SageMaker_Auditor | SageMaker Notebook | Is notebook direct internet access enabled |
| Amazon_SageMaker_Auditor | SageMaker Notebook | Is the notebook in a vpc |
| Amazon_SageMaker_Auditor | SageMaker Endpoint | Is endpoint encryption enabled |
| Amazon_SageMaker_Auditor | SageMaker Model | Is model network isolation enabled |
| Amazon_Shield_Advanced_Auditor | Route53 Hosted Zone | Are Rt53 hosted zones protected by Shield Advanced |
| Amazon_Shield_Advanced_Auditor | Classic Load Balancer | Are CLBs protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | ELBv2 (ALB/NLB) | Are ELBv2s protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | Elastic IP | Are EIPs protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | CloudFront Distribution | Are CF Distros protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | Account (DRT IAM Role) | Does the DRT have account authZ via IAM role |
| Amazon_Shield_Advanced_Auditor | Account (DRT S3 Access) | Does the DRT have access to WAF logs S3 buckets |
| Amazon_Shield_Advanced_Auditor | Account (Shield subscription) | Is Shield Adv subscription on auto renew |
| Amazon_Shield_Advanced_Auditor | Global Accelerator Accelerator | Are GA Accelerators protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | Account | Has Shield Adv mitigated any attacks in the last 7 days |
| Amazon_SNS_Auditor | SNS Topic | Is the topic encrypted |
| Amazon_SNS_Auditor | SNS Topic | Does the topic have plaintext (HTTP) subscriptions |
| Amazon_SNS_Auditor | SNS Topic | Does the topic allow public access |
| Amazon_SNS_Auditor | SNS Topic | Does the topic allow cross-account access |
| Amazon_SQS_Auditor | SQS Queue | Are there old messages |
| Amazon_SQS_Auditor | SQS Queue | Is Server Side Encryption Enabled |
| Amazon_SQS_Auditor | SQS Queue | Is the SQS Queue publically accessible |
| Amazon_VPC_Auditor | VPC | Is the default VPC out and about |
| Amazon_VPC_Auditor | VPC | Is flow logging enabled |
| Amazon_VPC_Auditor | Subnet | Do subnets map public IPs |
| Amazon_VPC_Auditor | Subnet | Do subnets have available IP space |
| Amazon_WorkSpaces_Auditor | Workspace | Is user volume encrypted |
| Amazon_WorkSpaces_Auditor | Workspace | Is root volume encrypted |
| Amazon_WorkSpaces_Auditor | Workspace | Is running mode set to auto-off |
| Amazon_WorkSpaces_Auditor | DS Directory | Does directory allow default internet access |
| Amazon_Xray_Auditor | XRay Encryption Config | Is KMS CMK encryption used |
| AMI_Auditor | Amazon Machine Image (AMI) | Are owned AMIs public |
| AMI_Auditor | Amazon Machine Image (AMI) | Are owned AMIs encrypted |
| AWS_ACM_Auditor | ACM Certificate | Are certificates revoked |
| AWS_ACM_Auditor | ACM Certificate | Are certificates in use |
| AWS_ACM_Auditor | ACM Certificate | Is certificate transparency logging enabled |
| AWS_ACM_Auditor | ACM Certificate | Have certificates been correctly renewed |
| AWS_ACM_Auditor | ACM Certificate | Are certificates correctly validated |
| AWS_Amplify_Auditor | AWS Amplify | Does the app have basic auth enabled on the branches |
| AWS_Amplify_Auditor | AWS Amplify | Does the app have auto deletion for branches enabled |
| AWS_AppMesh_Auditor | App Mesh mesh | Does the mesh egress filter DROP_ALL |
| AWS_AppMesh_Auditor | App Mesh virtual node | Does the backend default client policy enforce TLS |
| AWS_AppMesh_Auditor | App Mesh virtual node | Do virtual node backends have STRICT TLS mode configured for inbound connections |
| AWS_AppMesh_Auditor | App Mesh virtual node | Do virtual nodes have an HTTP access log location defined |
| AWS_Backup_Auditor | EC2 Instance | Are EC2 instances backed up |
| AWS_Backup_Auditor | EBS Volume | Are EBS volumes backed up |
| AWS_Backup_Auditor | DynamoDB tables | Are DynamoDB tables backed up |
| AWS_Backup_Auditor | RDS DB Instance | Are RDS DB instances backed up |
| AWS_Backup_Auditor | EFS File System | Are EFS file systems backed up |
| AWS_Backup_Auditor | Neptune cluster | Are Neptune clusters backed up |
| AWS_Backup_Auditor | DocumentDB cluster | Are DocumentDB clusters backed up |
| AWS_Cloud9_Auditor | Cloud9 Environment | Are Cloud9 Envs using SSM for access |
| AWS_CloudFormation_Auditor | CloudFormation Stack | Is drift detection enabled |
| AWS_CloudFormation_Auditor | CloudFormation Stack | Are stacks monitored |
| AWS_CloudHSM_Auditor | CloudHSM Cluster | Is the CloudHSM Cluster in a degraded state |
| AWS_CloudHSM_Auditor | CloudHSM HSM Module | Is the CloudHSM hardware security module in a degraded state |
| AWS_CloudHSM_Auditor | CloudHSM Backups | Is there at least one backup in a READY state |
| AWS_CloudTrail_Auditor | CloudTrail | Is the trail multi-region |
| AWS_CloudTrail_Auditor | CloudTrail | Does the trail send logs to CWL |
| AWS_CloudTrail_Auditor | CloudTrail | Is the trail encrypted by KMS |
| AWS_CloudTrail_Auditor | CloudTrail | Are global/management events logged |
| AWS_CloudTrail_Auditor | CloudTrail | Is log file validation enabled |
| AWS_CodeArtifact_Auditor | CodeArtifact Repo | Does the CodeArtifact Repo have a least privilege resource policy attached |
| AWS_CodeArtifact_Auditor | CodeArtifact Domain | Does the CodeArtifact Domain have a least privilege resource policy attached |
| AWS_CodeBuild_Auditor | CodeBuild project | Is artifact encryption enabled |
| AWS_CodeBuild_Auditor | CodeBuild project | Is Insecure SSL enabled |
| AWS_CodeBuild_Auditor | CodeBuild project | Are plaintext environmental variables used |
| AWS_CodeBuild_Auditor | CodeBuild project | Is S3 logging encryption enabled |
| AWS_CodeBuild_Auditor | CodeBuild project | Is CloudWatch logging enabled |
| AWS_CodeBuild_Auditor | CodeBuild project | Does CodeBuild store PATs or Basic Auth creds |
| AWS_CodeBuild_Auditor | CodeBuild project | Is the CodeBuild project public |
| AWS_CodeBuild_Auditor | CodeBuild project | Are CodeBuild projects using privileged containers |
| AWS_Directory_Service_Auditor | DS Directory | Is RADIUS enabled |
| AWS_Directory_Service_Auditor | DS Directory | Is CloudWatch log forwarding enabled |
| AWS_DMS_Auditor | DMS Replication Instance | Are DMS instances publicly accessible |
| AWS_DMS_Auditor | DMS Replication Instance | Is DMS multi-az configured |
| AWS_DMS_Auditor | DMS Replication Instance | Are minor version updates configured |
| AWS_Global_Accelerator_Auditor | Global Accelerator Endpoint | Is the endpoint healthy |
| AWS_Global_Accelerator_Auditor | Global Accelerator Accelerator | Are flow logs enabled for accelerator |
| AWS_Health_Auditor | AWS Health Event | Are there active Security Events |
| AWS_Health_Auditor | AWS Health Event | Are there active Abuse Events |
| AWS_Health_Auditor | AWS Health Event | Are there active Risk Events |
| AWS_Glue_Auditor | Glue Crawler | Is S3 encryption configured for the crawler |
| AWS_Glue_Auditor | Glue Crawler | Is CWL encryption configured for the crawler |
| AWS_Glue_Auditor | Glue Crawler | Is job bookmark encryption configured for the crawler |
| AWS_Glue_Auditor | Glue Data Catalog | Is data catalog encryption configured |
| AWS_Glue_Auditor | Glue Data Catalog | Is connection password encryption configured |
| AWS_Glue_Auditor | Glue Data Catalog | Is a resource policy configured |
| AWS_IAM_Auditor | IAM Access Key | Are access keys over 90 days old |
| AWS_IAM_Auditor | IAM User | Do users have permissions boundaries |
| AWS_IAM_Auditor | IAM User | Do users have MFA |
| AWS_IAM_Auditor | IAM User | Do users have in-line policies attached |
| AWS_IAM_Auditor | IAM User | Do users have managed policies attached |
| AWS_IAM_Auditor | Password policy (Account) | Does the IAM password policy meet or exceed AWS CIS Foundations Benchmark standards |
| AWS_IAM_Auditor | Server certs (Account) | Are they any Server certificates stored by IAM |
| AWS_IAM_Auditor | IAM Policy | Do managed IAM policies adhere to least privilege principles |
| AWS_IAM_Auditor | IAM User | Do User IAM inline policies adhere to least privilege principles |
| AWS_IAM_Auditor | IAM Group | Do Group IAM inline policies adhere to least privilege principles |
| AWS_IAM_Auditor | IAM Role | Do Role IAM inline policies adhere to least privilege principles |
| AWS_IAMRA_Auditor | IAMRA Trust Anchor | Do Trust Anchors contain self-signed certificates |
| AWS_IAMRA_Auditor | IAMRA Trust Anchor | Do Trust Anchors use a Certificate Revocation List (CRL) |
| AWS_IAMRA_Auditor | IAMRA Profile | Do IAMRA Profiles specify a Session Policy |
| AWS_IAMRA_Auditor | IAMRA Profile | Do IAMRA Profiles specify a Permission Boundary |
| AWS_IAMRA_Auditor | IAM Role | Do IAM Roles associated with IAMRA use Condition statements in the Trust Policy |
| AWS_Keyspaces_Auditor | Keyspaces table | Are Keyspaces Tables encrypted with a KMS CMK |
| AWS_Keyspaces_Auditor | Keyspaces table | Do Keyspaces Tables have PTR enabled |
| AWS_Keyspaces_Auditor | Keyspaces table | Are Keyspaces Tables in an unusable state |
| AWS_KMS_Auditor | KMS key | Is key rotation enabled |
| AWS_KMS_Auditor | KMS key | Does the key allow public access |
| AWS_Lambda_Auditor | Lambda function | Has function been used or updated in the last 30 days |
| AWS_Lambda_Auditor | Lambda function | Is tracing enabled |
| AWS_Lambda_Auditor | Lambda function | Is code signing used |
| AWS_Lambda_Auditor | Lambda layer | Is the layer public |
| AWS_Lambda_Auditor | Lambda function | Is the function public |
| AWS_Lambda_Auditor | Lambda function | Is the function using a supported runtime |
| AWS_Lambda_Auditor | Lambda function | Are functions in VPCs highly available in at least 2 AZs |
| AWS_License_Manager_Auditor | License Manager configuration | Do LM configurations enforce a hard limit on license consumption |
| AWS_License_Manager_Auditor | License Manager configuration | Do LM configurations enforce auto-disassociation |
| AWS_MemoryDB_Auditor | MemoryDB Cluster | Do clusters use TLS |
| AWS_MemoryDB_Auditor | MemoryDB Cluster | Do clusters use KMS CMK for encryption at rest |
| AWS_MemoryDB_Auditor | MemoryDB Cluster | Are clusters configured for auto minor version updates |
| AWS_MemoryDB_Auditor | MemoryDB Cluster | Are cluster events monitored with SNS |
| AWS_MemoryDB_Auditor | MemoryDB User | MemDB Admin users should be reviewed |
| AWS_MemoryDB_Auditor | MemoryDB User | MemDB users should use passwords |
| AWS_RAM_Auditor | RAM Resource Share | Is the resource share status not failed |
| AWS_RAM_Auditor | RAM Resource Share | Does the resource allow external principals |
| AWS_Secrets_Manager_Auditor | Secrets Manager secret | Is the secret over 90 days old |
| AWS_Secrets_Manager_Auditor | Secrets Manager secret | Is secret auto-rotation enabled |
| AWS_Security_Hub_Auditor | Security Hub (Account) | Are there active high or critical findings in Security Hub |
| AWS_Security_Services_Auditor | IAM Access Analyzer (Account) | Is IAM Access Analyzer enabled |
| AWS_Security_Services_Auditor | GuardDuty (Account) | Is GuardDuty enabled |
| AWS_Security_Services_Auditor | Detective (Account) | Is Detective enabled |
| AWS_Security_Services_Auditor | Macie2 | Is Macie enabled |
| ~~AWS_Security_Services_Auditor~~ | ~~AWS WAFv2 (Regional)~~ | ~~Are Regional Web ACLs configured~~ **THIS FINDING HAS BEEN RETIRED** |
| ~~AWS_Security_Services_Auditor~~ | ~~AWS WAFv2 (Global)~~ | ~~Are Global Web ACLs (for CloudFront) configured~~ **THIS FINDING HAS BEEN RETIRED** |
| AWS_Systems_Manager_Auditor | SSM Document | Are self owned SSM Documents publicly shared |
| AWS_Systems_Manager_Auditor | SSM Association | Does an SSM Association that targets all Instances conduct SSM Agent updates |
| AWS_Systems_Manager_Auditor | SSM Association | Does an SSM Association that targets all Instances conduct patching |
| AWS_Systems_Manager_Auditor | SSM Association | Does an SSM Association that targets all Instances conduct inventory gathering |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for MFA on Root Account failing |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for ELB Listener Security failing |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for CloudFront SSL Certs in IAM Cert Store failing |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for CloudFront SSL Cert on Origin Server failing |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for Exposed Access Keys failing |
| AWS_WAFv2_Auditor | AWS WAFv2 (Regional) | Do Regional WAFs use Cloudwatch Metrics |
| AWS_WAFv2_Auditor | AWS WAFv2 (Regional) | Do Regional WAFs use Request Sampling |
| AWS_WAFv2_Auditor | AWS WAFv2 (Regional) | Do Regional WAFs have Logging enabled |
| AWS_WAFv2_Auditor | AWS WAFv2 (Global) | Do Global WAFs use Cloudwatch Metrics |
| AWS_WAFv2_Auditor | AWS WAFv2 (Global) | Do Global WAFs use Request Sampling |
| AWS_WAFv2_Auditor | AWS WAFv2 (Global) | Do Global WAFs have Logging enabled |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SparkUI service publicly accessible |
| Amazon_Secrets_Auditor | CodeBuild project | Do CodeBuild projects have secrets in plaintext env vars |
| Amazon_Secrets_Auditor | CloudFormation Stack | Do CloudFormation Stacks have secrets in parameters |
| Amazon_Secrets_Auditor | ECS Task Definition | Do ECS Task Definitions have secrets in env vars |
| Amazon_Secrets_Auditor | EC2 Instance | Do EC2 instances have secrets in User Data |
| Amazon_Shodan_Auditor | EC2 Instance | Are EC2 instances w/ public IPs indexed |
| Amazon_Shodan_Auditor | ELBv2 (ALB) | Are internet-facing ALBs indexed |
| Amazon_Shodan_Auditor | RDS Instance | Are public accessible RDS instances indexed |
| Amazon_Shodan_Auditor | OpenSearch domain | Are ES Domains outside a VPC indexed |
| Amazon_Shodan_Auditor | ELB (CLB) | Are internet-facing CLBs indexed |
| Amazon_Shodan_Auditor | DMS Replication Instance | Are public accessible DMS instances indexed |
| Amazon_Shodan_Auditor | Amazon MQ message broker | Are public accessible message brokers indexed |
| Amazon_Shodan_Auditor | CloudFront Distribution | Are CloudFront distros indexed |
| Amazon_Shodan_Auditor | Global Accelerator Accelerator | Are Global Accelerator Accelerators indexed |

### GCP Checks & Services
___

These are the following services and checks perform by each Auditor, there are currently...
- :boom: **53 Checks** :boom:
- :exclamation: **2 supported GCP services/components** :exclamation:
- :fire: **3 Auditors** :fire:


| Auditor File Name | Scanned Resource Name | Auditor Scan Description |
|---|---|---|
| GCP_ComputeEngine_Auditor | GCE VM Instance | Is deletion protection enabled |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Is IP forwarding disabled |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Is auto-restart enabled |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Is Secure Boot enabled |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Is Virtual Trusted Platform Module enabled |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Is Instance Integrity Monitoring enabled |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Is Secure Integrity Monitoring Auto-learning Policy set to Update |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Is Serial Port access disabled |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Are Linux VM Instances access with OS Logon |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Are Linux VM Instances acessed with OS Logon using 2FA/MFA |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Are project-wide SSH keys blocked from access VM instances |
| GCP_ComputeEngine_Auditor | GCE VM Instance | Are instances publicly facing |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Are instances publicly facing |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances enabled auto-backup |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do MySQL instances enable PITR |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do PostgreSQL instances enable PITR |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have a private network enabled |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances allowe GCP services connectivity |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have a password policy enabled |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have a password min length |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have a password reuse check |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have a configuration to disallow usernames in the password |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have a password change interval check |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have storage auto-resize enabled |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have deletion protection enabled |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have query insights enabled |
| GCP_CloudSQL_Auditor | CloudSQL Instance | Do DB instances have SSL/TLS Enforcement enabled |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_GCP_Auditor | GCE VM Instance | Is a SparkUI service publicly accessible |

### Oracle Cloud Infrastructure Checks & Services
___

These are the following services and checks perform by each Auditor, there are currently...
- :boom: **129 Checks** :boom:
- :exclamation: **14 supported OCI services/components** :exclamation:
- :fire: **11 Auditors** :fire:

| Auditor File Name | Scanned Resource Name | Auditor Scan Description |
|---|---|---|
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should be encrypted with a Customer-managed Master Encryption Key
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs with available upgrade versions should be reviewed for upgrade
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should have an Oracle Object Storage bucket configured for manual and long-term backup storage
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should be registered with Oracle Data Safe
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should be registered with Database Management
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should have a customer contact detail to receive upgrade and other important notices
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should be configured to autoscale database compute resources
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should be configured to autoscale database storage resources
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should have Autonomous Data Guard enabled
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should enforce mutual TLS (mTLS) connections
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should schedule long term backups
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee |ADBs with Private Access should have at least one Network Security Group (NSG) assigned
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should have Operations Insights enabled
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should be configured for Private Access connectivity through a Virtual Cloud Network (VCN)
| OCI_AutonomousDatabase_Auditor | Oracle Autonomous Databasee | ADBs should configure an IP-based Allow-list to reduce permissible network access
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should have Secure Boot enabled
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should have Measured Boot enabled
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should have the Trusted Platform Module enabled
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should enable block volume in-transit encryption
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should be encrypted with a Customer-managed Master Encryption Key
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should disable access to legacy Instance Metadata Service (IMDSv1) endpoints
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should have the Management Agent enabled
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should have the Monitoring Agent enabled
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should have the Vulnerability Scanning plugin enabled
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should not be publicly discoverable on the internet
| OCI_ComputeInstance_Auditor | Oracle Cloud Compute instances | instances should have at least one Network Security Group (NSG) assigned
| OCI_FileStorage_Auditor | Oracle File Storage file system | File Storage file systems should be encrypted with a Customer-managed Master Encryption Key
| OCI_FileStorage_Auditor | Oracle File Storage file system | File Storage file systems should enforce secure export options by requiring that NFS clients use privileged source ports
| OCI_FileStorage_Auditor | Oracle File Storage file system | File Storage file systems should enforce secure export options by configuring NFS identity squashing
| OCI_FileStorage_Auditor | Oracle File Storage mount target | File Storage Mount Targets should have at least one Network Security Group (NSG) assigned
| OCI_KubernetesEngine_Auditor | OKE cluster | OKE cluster API servers should not be accessible from the internet
| OCI_KubernetesEngine_Auditor | OKE cluster | OKE cluster should have at least one Network Security Group (NSG) assigned
| OCI_KubernetesEngine_Auditor | OKE cluster | OKE clusters should enable image verification policies
| OCI_KubernetesEngine_Auditor | OKE cluster | OKE clusters with the Kubernetes dashboard enabled should be reviewed
| OCI_KubernetesEngine_Auditor | OKE cluster | OKE clusters should use one of the latest supported Kubernetes versions
| OCI_KubernetesEngine_Auditor | OKE cluster | OKE clusters should not use deprecated versions of Kubernetes
| OCI_KubernetesEngine_Auditor | OKE node pool | OKE node pools should enable block volume in-transit encryption
| OCI_KubernetesEngine_Auditor | OKE node pool | OKE node pools should have at least one Network Security Group (NSG) assigned
| OCI_KubernetesEngine_Auditor | OKE node pool | OKE node pools should be configured to protect pods with a Network Security Group (NSG)
| OCI_KubernetesEngine_Auditor | OKE node pool | OKE node pools should be configured to force terminate evicted worker nodes after the draining grace period
| OCI_KubernetesEngine_Auditor | OKE node pool | OKE node pools should use the latest supported Kubernetes versions
| OCI_KubernetesEngine_Auditor | OKE node pool | OKE node pools should not use deprecated versions of Kubernetes
| OCI_KubernetesEngine_Auditor | OKE virtual node pool | OKE virtual node pools should have at least one Network Security Group (NSG) assigned
| OCI_KubernetesEngine_Auditor | OKE virtual node pool | OKE virtual node pools should be configured to protect pods with a Network Security Group (NSG)
| OCI_KubernetesEngine_Auditor | OKE virtual node pool | OKE virtual node pools should use the latest supported Kubernetes versions
| OCI_KubernetesEngine_Auditor | OKE virtual node pool | OKE virtual node pools should not use deprecated versions of Kubernetes
| OCI_LoadBalancer_Auditor | Oracle Load Balancer | Load Balancers should have Network Security Groups (NSGs) assigned
| OCI_LoadBalancer_Auditor | Oracle Load Balancer | Load Balancer listeners should be configured to use HTTPS/TLS
| OCI_LoadBalancer_Auditor | Oracle Load Balancer | Load Balancer backend sets should be configured to use HTTPS/TLS
| OCI_LoadBalancer_Auditor | Oracle Load Balancer | Load Balancers with health checks reporting Critical or Warning should be investigated
| OCI_MySQL_DatabaseService_Auditor | Oracle MySQL DB System | DB systems should be configured to take automatic backups
| OCI_MySQL_DatabaseService_Auditor | Oracle MySQL DB System | DB systems should have Point-in-Time Recovery (PITR) enabled
| OCI_MySQL_DatabaseService_Auditor | Oracle MySQL DB System | DB systems should have Crash Recovery enabled
| OCI_MySQL_DatabaseService_Auditor | Oracle MySQL DB System | DB systems should have Deletion Protection enabled
| OCI_MySQL_DatabaseService_Auditor | Oracle MySQL DB System | DB systems should enforce creating a final manual snapshot before deletion
| OCI_MySQL_DatabaseService_Auditor | Oracle MySQL DB System | DB systems should be configured to automatically delete automatic snapshots after system deletion
| OCI_MySQL_DatabaseService_Auditor | Oracle MySQL DB System | DB systems should be configured to be highly available
| OCI_NoSQL_Auditor | Oracle NoSQL Table |  Oracle NoSQL Database Cloud Service tables should be configured for on-demand scaling (autoscaling)
| OCI_ObjectStorage_Auditor | Oracle Cloud Storage bucket | buckets should be encrypted with a Customer-managed Master Encryption Key
| OCI_ObjectStorage_Auditor | Oracle Cloud Storage bucket | buckets should have a lifecycle policy defined
| OCI_ObjectStorage_Auditor | Oracle Cloud Storage bucket | buckets should define a lifecycle policy rule to delete failed multipart uploads
| OCI_ObjectStorage_Auditor | Oracle Cloud Storage bucket | buckets should not allow public access to objects
| OCI_ObjectStorage_Auditor | Oracle Cloud Storage bucket | buckets should be configured to use object replication to promote resilience and recovery
| OCI_ObjectStorage_Auditor | Oracle Cloud Storage bucket | buckets should be configured to use object versioning to promote resilience and recovery
| OCI_OpenSearch_Auditor | Oracle Search with OpenSearch clusteer | clusters should have Security Mode enabled and set to Enforcing
| OCI_VCN_SecurityList_Auditor | OCI Security List | Are all ports (-1) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is FTP (tcp20-21) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is TelNet (tcp23) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is WSDCOM-RPC (tcp135) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is SMB (tcp445) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is MSSQL (tcp1433) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is OracleDB (tcp1521) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is MySQL/MariaDB (tcp3306) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is RDP (tcp3389) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is PostgreSQL (tcp5432) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Kibana (tcp5601) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Redis (tcp6379) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Splunkd (tcp8089) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Elasticsearch (tcp9200) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Elasticsearch (tcp9300) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Memcached (udp11211) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Redshift (tcp5439) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is DocDB (tcp27017) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Cassandra (tcp9142) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Kafka (tcp9092) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is NFS (tcp2049) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Rsync (tcp873) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is TFTP (udp69) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Docker API (tcp2375) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is K8s API (tcp10250) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is SMTP (tcp25) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is NetBioas (tcp137-139) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is OpenVPN (udp1194) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is RabbitMQ (tcp5672) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is Spark WebUI (tcp4040) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is POP3 (tcp110) open to the internet |
| OCI_VCN_SecurityList_Auditor | OCI Security List | Is VMWare ESXi (tcp8182) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Are all ports (-1) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is FTP (tcp20-21) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is TelNet (tcp23) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is WSDCOM-RPC (tcp135) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is SMB (tcp445) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is MSSQL (tcp1433) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is OracleDB (tcp1521) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is MySQL/MariaDB (tcp3306) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is RDP (tcp3389) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is PostgreSQL (tcp5432) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Kibana (tcp5601) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Redis (tcp6379) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Splunkd (tcp8089) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Elasticsearch (tcp9200) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Elasticsearch (tcp9300) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Memcached (udp11211) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Redshift (tcp5439) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is DocDB (tcp27017) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Cassandra (tcp9142) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Kafka (tcp9092) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is NFS (tcp2049) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Rsync (tcp873) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is TFTP (udp69) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Docker API (tcp2375) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is K8s API (tcp10250) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is SMTP (tcp25) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is NetBioas (tcp137-139) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is OpenVPN (udp1194) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is RabbitMQ (tcp5672) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is Spark WebUI (tcp4040) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is POP3 (tcp110) open to the internet |
| OCI_VCN_NetworkSecurityGroup_Auditor | OCI Network Security Group | Is VMWare ESXi (tcp8182) open to the internet |

### Azure Checks & Services
___

*Coming Soon!*

### SSPM: GitHub Checks & Services
___

*Coming Soon!*

### SSPM: Servicenow Checks & Services
___

These are the following services and checks perform by each Auditor, there are currently...
- :boom: **92 Checks** :boom:
- :exclamation: **3 supported ServiceNow services/components** :exclamation:
- :fire: **9 Auditors** :fire:

| Auditor File Name | Scanned Resource Name | Auditor Scan Description |
|---|---|---|
| Servicenow_Users_Auditor | Servicenow User | Do active users have MFA enabled |
| Servicenow_Users_Auditor | Servicenow User | Audit active users for {X} failed login attempts |
| Servicenow_Users_Auditor | Servicenow User | Audit active users that are locked out |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance block unsanitized messages |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance specify a script execution role |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for JSONv2 API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for SOAP API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does instance block delegated developer grant roles |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for CSV API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce default deny |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance double-check inbound form transactions |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance control live profile details |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for GlideAjax API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for Excel API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for the import API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for PDF API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance protect performance monitoring for unauthorized access |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance restrict performance monitoring to specific IP |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enable privacy control for client-callable scripts |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance restrict Favorites access |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance have an IP Allowlist |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for RSS API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for Script Requests API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance perform validation for SOAP requests |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance restrict ServiceNow employee access
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for Unload API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for WSDL API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for XML API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for XSD API |
| Servicenow_Attachments_Auditor | System Property | Attachments: Does the instance restrict files from being rendered in the browser |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should restrict questionable file attachments |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should configure file download restrictions |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should enable access control for profile pictures |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should enforce downloading of attachments |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should define file type allowlist for uploads |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should prevent unauthorized access to attachments |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should prevent specific file extensions upload |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should prevent specific file type upload |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should prevent specific file type download |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should enable MIME type validation |
| Servicenow_EmailSecurity_Auditor | System Property | Email Security: Instance should restrict email HTML bodies from rendering |
| Servicenow_EmailSecurity_Auditor | System Property | Email Security: Instance should restrict acccess to emails with empty target tables |
| Servicenow_EmailSecurity_Auditor | System Property | Email Security: Instance should specify trusted domain allowlists |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should disallow embedded HTML code |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should disallow JavaScript in embedded HTML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should check unsanitized HTML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should enable script sandboxing |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should disable AJAXEvaluate |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape Excel formula injection |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape HTML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape JavaScript |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape Jelly |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape XML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should sanitize HTML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should prevent JavaScript injection with Jelly interpolation |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should enable SOAP request strict security |
| Servicenow_SecureCommunications_Auditor | System Property | Secure Communications: Instance should enable certficate validation on outbound connections |
| Servicenow_SecureCommunications_Auditor | System Property | Secure Communications: Instance should disable SSLv2 & SSLv3 |
| Servicenow_SecureCommunications_Auditor | System Property | Secure Communications: Instance should verify HTTP client hostnames |
| Servicenow_SecureCommunications_Auditor | System Property | Secure Communications: Instance should check revoked certificate status |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should enable URL allow list for cross-origin iframe communication |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should enforce relative links |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should specify URL allow list for cross-origin iframe communication |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should specify URL allow list for logout redirects |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set virtual agent embedded client content security policy |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set virtual agent embedded client X-Frame-Options |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set X-Frame-Options: SAMEORIGIN |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set XXE entity expansion threshold |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set XMLdoc/XMLUtil entity validation allow list |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should disable XXE entity expansion |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set XMLdoc2 entity validation allow list |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should enable XML external entity processing allow lists |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set absolute session timeouts |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set an Anti-CSRF token |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set the HTTPOnly property for sensitive cookies |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should enable Anti-CSRF token strict validation |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should disable passwordless authentication |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should globally enable MFA |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should enforce password change validation |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should disable password autocompletes |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should disable Remember Me checkboxes |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should rotate HTTP SessionIDs |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should validate session cookies |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set a strong security reference policy |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set a strong session activity timeout |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: If using Remember Me, instance should set a strong rotation timeout |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the Contextual Security: Role Management Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the Explicit Role Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the SAML 2.0 SSO Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the Security Jump Start Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the SNC Access Control Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the Email Filters Plugin intalled and active |

### SSPM: M365 Checks & Services
___

*Coming Soon!*

## Contributing

Refer to the [Developer Guide](./docs/new_checks/DEVELOPER_GUIDE.md) for instructions on how to produce new checks, for new SaaS and CSP support please open an Issue.

Feel free to open PRs and Issues where syntax, grammatic, and implementation errors are encountered in the code base.

**ElectricEye is for sale**: contact the maintainer for more imformation!

### Early Contributors

Quick shout-outs to the folks who answered the call early to test out ElectricEye and make it not-a-shit-sandwich.

##### Alpha Testing:

- [Mark Yancey](https://www.linkedin.com/in/mark-yancey-jr-aspiring-cloud-security-professional-a52bb9126/)

##### Beta Testing:

- [Martin Klie](https://www.linkedin.com/in/martin-klie-0600845/)
- [Joel Castillo](https://www.linkedin.com/in/joelbcastillo/)
- [Juhi Gupta](https://www.linkedin.com/in/juhi-gupta-09/)
- [Bulent Yidliz](https://www.linkedin.com/in/bulent-yildiz/)
- [Guillermo Ojeda](https://www.linkedin.com/in/guillermoojeda/)
- [Dhilip Anand Shivaji](https://www.linkedin.com/in/dhilipanand/)
- [Arek Bar](https://www.linkedin.com/in/arkadiuszbar/)
- [Ryan Russel](https://www.linkedin.com/in/pioneerrussell/)
- [Jonathan Nguyen](https://www.linkedin.com/in/jonanguyen/)
- [Jody Brazil](https://www.linkedin.com/in/jodybrazil/)
- [Dylan Shields](https://www.linkedin.com/in/dylan-shields-6802b1168/)
- [Manuel Leos Rivas](https://www.linkedin.com/in/manuel-lr/)
- [Andrew Alaniz](https://www.linkedin.com/in/andrewdalaniz/)
- [Christopher Childers](https://www.linkedin.com/in/christopher-childers-28950537/)

## License

This library is licensed under the Apache-2.0 License. See the LICENSE file.