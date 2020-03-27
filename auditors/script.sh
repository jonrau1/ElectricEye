# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.  
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

#!/bin/bash
echo "Executing security checks"
python3 Amazon_APIGW_Auditor.py
sleep 2
python3 Amazon_AppStream_Auditor.py
sleep 2
python3 Amazon_CognitoIdP_Auditor.py
sleep 2
python3 Amazon_DocumentDB_Auditor.py
sleep 2
python3 Amazon_EBS_Auditor.py
sleep 2
python3 Amazon_EC2_Security_Group_Auditor.py
sleep 2
python3 Amazon_EC2_SSM_Auditor.py
sleep 2
python3 Amazon_ECR_Auditor.py
sleep 2
python3 Amazon_ECS_Auditor.py
sleep 2
python3 Amazon_EFS_Auditor.py
sleep 2
python3 Amazon_EKS_Auditor.py
sleep 2
python3 Amazon_Elasticache_Redis_Auditor.py
sleep 2
python3 Amazon_ElasticsearchService_Auditor.py
sleep 2
python3 Amazon_ELB_Auditor.py
sleep 2
python3 Amazon_ELBv2_Auditor.py
sleep 2
python3 Amazon_EMR_Auditor.py
sleep 2
python3 Amazon_Kinesis_Data_Streams_Auditor.py
sleep 2
python3 Amazon_MSK_Auditor.py
sleep 2
python3 Amazon_Neptune_Auditor.py
sleep 2
python3 Amazon_RDS_Auditor.py
sleep 2
python3 Amazon_Redshift_Auditor.py
sleep 2
python3 Amazon_S3_Auditor.py
sleep 2
python3 Amazon_SageMaker_Auditor.py
sleep 2
python3 Amazon_Shield_Advanced_Auditor.py
sleep 2
python3 Amazon_SNS_Auditor.py
sleep 2
python3 Amazon_VPC_Auditor.py
sleep 2
python3 Amazon_WorkSpaces_Auditor.py
sleep 2
python3 AMI_Auditor.py
sleep 2
python3 AWS_AppMesh_Auditor.py
sleep 2
python3 AWS_Backup_Auditor.py
sleep 2
python3 AWS_CloudFormation_Auditor.py
sleep 2
python3 AWS_CodeBuild_Auditor.py
sleep 2
python3 AWS_Directory_Service_Auditor.py
sleep 2
python3 AWS_DMS_Auditor.py
sleep 2
python3 AWS_License_Manager_Auditor.py
sleep 2
python3 AWS_Secrets_Manager_Auditor.py
sleep 2
python3 AWS_Security_Services_Auditor.py
sleep 2
python3 Shodan_Auditor.py
sleep 2
python3 AWS_Security_Hub_Auditor.py
echo "All scans complete, exiting"
exit 1