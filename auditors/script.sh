#!/bin/bash
echo "Executing security checks"
python3 Amazon_AppStream_Auditor.py
python3 Amazon_CognitoIdP_Auditor.py
python3 Amazon_DocumentDB_Auditor.py
python3 Amazon_ECR_Auditor.py
python3 Amazon_EKS_Auditor.py
python3 Amazon_Elasticache_Redis_Auditor.py
python3 Amazon_ElasticsearchService_Auditor.py
python3 Amazon_MSK_Auditor.py
python3 Amazon_RDS_Auditor.py
python3 AMI_Auditor.py
python3 AWS_Backup_Auditor.py
python3 AWS_CloudFormation_Auditor.py
python3 AWS_CodeBuild_Auditor.py
python3 AWS_Secrets_Manager_Auditor.py
python3 AWS_Security_Services_Auditor.py
python3 AWS_Security_Hub_Auditor.py
echo "All scans complete, exiting"
exit 1