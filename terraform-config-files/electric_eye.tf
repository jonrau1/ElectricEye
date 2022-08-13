#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

resource "aws_ecs_cluster" "Electric_Eye_ECS_Cluster" {
  name = "${var.Electric_Eye_VPC_Name_Tag}-ecs-cluster"
  capacity_providers = ["FARGATE"]
  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"      
  }
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
resource "aws_ecr_repository_policy" "foopolicy" {
  repository = var.Electric_Eye_ECR_Repository_Name
  policy = <<EOF
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Sid": "new statement",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "${aws_iam_role.Electric_Eye_ECS_Task_Execution_Role.arn}",
          "${aws_iam_role.Electric_Eye_ECS_Task_Role.arn}"
        ],
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:DescribeImages",
        "ecr:DescribeRepositories",
        "ecr:GetAuthorizationToken",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:ListImages"
      ]
    }
  ]
}
EOF
}
resource "aws_s3_bucket" "Electric_Eye_Security_Artifact_Bucket" {
  bucket = "${var.Electric_Eye_ECS_Resources_Name}-artifact-bucket-${var.AWS_Region}-${data.aws_caller_identity.current.account_id}"
  acl    = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}
resource "aws_ssm_parameter" "Electric_Eye_Bucket_Parameter" {
  name       = "electriceye-bucket"
  type        = "String"
  value       = aws_s3_bucket.Electric_Eye_Security_Artifact_Bucket.id
  description = "Contains the location of the S3 bucket with ElectricEye Auditor files"
}
resource "aws_cloudwatch_log_group" "Electric_Eye_ECS_Task_Definition_CW_Logs_Group" {
  name = "/ecs/${var.Electric_Eye_ECS_Resources_Name}"
}
resource "aws_ecs_task_definition" "Electric_Eye_ECS_Task_Definition" {
  family                   = "electric-eye"
  execution_role_arn       = aws_iam_role.Electric_Eye_ECS_Task_Execution_Role.arn
  task_role_arn            = aws_iam_role.Electric_Eye_ECS_Task_Role.arn
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 2048
  memory                   = 4096

  container_definitions = <<DEFINITION
[
  {
    "cpu": 2048,
    "image": "${var.Electric_Eye_Docker_Image_URI}",
    "memory": 4096,
    "memoryReservation": 4096,
    "essential": true,
    "environment": [
      {
        "value": "${var.Shodan_API_Key_SSM_Parameter}",
        "name": "SHODAN_API_KEY_PARAM"
      },
      {
        "value": "${var.Dops_client_id_SSM_Parameter}",
        "name": "DOPS_CLIENT_ID_PARAM"
      },
      {
        "value": "${var.Dops_api_key_SSM_Parameter}",
        "name": "DOPS_API_KEY_PARAM"
      },
      {
        "value": "${var.postgres_username}",
        "name": "POSTGRES_USERNAME"
      },
      {
        "value": "${var.postgres_endpoint}",
        "name": "POSTGRES_DB_ENDPOINT"
      },
      {
        "value": "${var.postgres_db_name}",
        "name": "ELECTRICEYE_POSTGRESQL_DB_NAME"
      },
      {
        "value": "${var.postgres_port}",
        "name": "POSTGRES_DB_PORT"
      },
      {
        "value": "${var.postgre_password_SSM_Parameter}",
        "name": "POSTGRES_PASSWORD_SSM_PARAM_NAME"
      },
      {
        "value": "${var.mongo_hostname}",
        "name": "MONGODB_HOSTNAME"
      },
      {
        "value": "${var.mongo_username}",
        "name": "MONGODB_USERNAME"
      },
      {
        "value": "${var.mongo_password_parameter}",
        "name": "MONGODB_PASSWORD_PARAMETER"
      },
    ],
    "name": "${var.Electric_Eye_ECS_Resources_Name}",
    "networkMode": "awsvpc",
    "logConfiguration": {
      "logDriver": "awslogs",
      "secretOptions": null,
      "options": {
        "awslogs-group": "/ecs/${var.Electric_Eye_ECS_Resources_Name}",
        "awslogs-region": "${var.AWS_Region}",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "portMappings": [],
    "volumesFrom": [],
    "mountPoints": [],
    "secrets": [
      {
        "valueFrom": "${aws_ssm_parameter.Electric_Eye_Bucket_Parameter.arn}",
        "name": "SH_SCRIPTS_BUCKET"
      }
    ]
  }
]
DEFINITION
}
resource "aws_iam_role" "Electric_Eye_ECS_Task_Execution_Role" {
  name               = "${var.Electric_Eye_ECS_Resources_Name}-exec-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "Electric_Eye_Task_Execution_Role_Policy" {
  name   = "${var.Electric_Eye_ECS_Resources_Name}-exec-policy"
  role   = aws_iam_role.Electric_Eye_ECS_Task_Execution_Role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:DescribeImages",
        "ecr:BatchGetImage",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "kms:Decrypt",
        "kms:DescribeKey",
        "ssm:GetParametersByPath",
        "ssm:GetParameters",
        "ssm:GetParameter"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}
resource "aws_iam_role" "Electric_Eye_ECS_Task_Role" {
  name               = "${var.Electric_Eye_ECS_Resources_Name}-task-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "Electric_Eye_Task_Role_Policy" {
  name   = "${var.Electric_Eye_ECS_Resources_Name}-task-policy"
  role   = aws_iam_role.Electric_Eye_ECS_Task_Role.id
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "athena:GetWorkGroup",
                "athena:ListWorkGroups",
                "airflow:GetEnvironment",
                "airflow:ListEnvironments",
                "autoscaling:DescribeAutoScalingGroups",
                "cloudtrail:DescribeTrails",
                "cloudtrail:ListTrails",
                "kms:DescribeKey",
                "kms:Decrypt",
                "access-analyzer:ListAnalyzers",
                "ec2:Describe*",
                "ec2:Get*",
                "cassandra:Select",
                "ssm:ListDocuments",
                "ssm:ListAssociations",
                "ecs:ListClusters",
                "ecs:DescribeClusters",
                "elasticloadbalancing:DescribeLoadBalancers",
                "kinesis:ListStreams",
                "cognito-idp:DescribeUserPool",
                "dynamodb:DescribeTable",
                "dynamodb:DescribeContinuousBackups",
                "dynamodb:DescribeTimeToLive",
                "dynamodb:ListTables",
                "dax:DescribeParameters",
                "dax:DescribeClusters",
                "detective:ListGraphs",
                "shield:DescribeSubscription",
                "acm:DescribeCertificate",
                "acm:ListCertificates",
                "elasticmapreduce:DescribeCluster",
                "elasticmapreduce:DescribeSecurityConfiguration",
                "elasticmapreduce:GetBlockPublicAccessConfiguration",
                "elasticmapreduce:ListClusters",
                "firehose:DescribeDeliveryStream",
                "firehose:ListDeliveryStreams",
                "glue:GetSecurityConfiguration",
                "glue:GetResourcePolicy",
                "glue:GetCrawler",
                "glue:GetDataCatalogEncryptionSettings",
                "glue:ListCrawlers",
                "appmesh:DescribeMesh",
                "appmesh:DescribeVirtualNode",
                "appmesh:ListMeshes",
                "appmesh:ListVirtualNodes",
                "support:DescribeTrustedAdvisorCheckResult",
                "support:DescribeTrustedAdvisorChecks",
                "health:DescribeEvents",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:ListMfaDevices",
                "iam:ListUserPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListServerCertificates",
                "rolesanywhere:ListProfiles",
                "rolesanywhere:ListTrustAnchors",
                "rolesanywhere:ListCrls",
                "macie2:GetMacieSession",
                "managedblockchain:Get*",
                "managedblockchain:List*",
                "mq:Describe*",
                "mq:List*",
                "memorydb:Describe*",
                "license-manager:GetLicenseConfiguration",
                "license-manager:ListLicenseConfigurations",
                "ecr:DescribeImages",
                "ecr:GetRegistryPolicy",
                "ecr:DescribeRegistry",
                "securityhub:GetFindings",
                "codebuild:ListProjects",
                "codebuild:ListSourceCredentials",
                "workspaces:DescribeWorkspaces",
                "ecr:GetLifecyclePolicy",
                "sns:ListSubscriptionsByTopic",
                "appstream:DescribeImages",
                "kafka:DescribeCluster",
                "cognito-idp:ListUserPools",
                "cloudformation:DescribeStacks",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeListeners",
                "elasticbeanstalk:DescribeEnvironments",
                "elasticbeanstalk:DescribeConfigurationSettings",
                "ds:ListLogSubscriptions",
                "s3:GetObject",
                "eks:DescribeCluster",
                "eks:ListClusters",
                "elasticache:DescribeCacheClusters",
                "shield:DescribeDRTAccess",
                "secretsmanager:ListSecrets",
                "s3:GetLifecycleConfiguration",
                "appstream:DescribeUsers",
                "kafka:ListClusters",
                "shield:DescribeProtection",
                "sagemaker:DescribeNotebookInstance",
                "sns:ListTopics",
                "elasticfilesystem:DescribeFileSystems",
                "apigateway:GET",
                "rds:DescribeDB*",
                "rds:DescribeEventCategories",
                "s3:ListBucket",
                "backup:DescribeProtectedResource",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketLogging",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketVersioning",
                "es:DescribeElasticsearchDomain",
                "ssm:DescribeInstance*",
                "redshift:DescribeLoggingStatus",
                "redshift:DescribeClusters",
                "redshift:DescribeClusterParameters",
                "appstream:DescribeFleets",
                "ecr:DescribeRepositories",
                "sagemaker:DescribeEndpoint",
                "workspaces:DescribeWorkspaceDirectories",
                "sagemaker:ListNotebookInstances",
                "codebuild:BatchGetProjects",
                "guardduty:ListDetectors",
                "dms:DescribeReplicationInstances",
                "sns:GetTopicAttributes",
                "route53:ListTrafficPolicyInstancesByHostedZone",
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets",
                "route53:ListQueryLoggingConfigs",
                "sagemaker:DescribeModel",
                "kinesis:DescribeStream",
                "sns:ListSubscriptions",
                "es:ListDomainNames",
                "s3:GetAccountPublicAccessBlock",
                "s3:ListAllMyBuckets",
                "ssm:GetP*",
                "wafv2:ListWebACLs",
                "wafv2:GetLoggingConfiguration",
                "wafv2:GetWebACL",
                "wafv2:GetWebACLForResource",
                "cloudfront:ListDistributions",
                "sagemaker:ListModels",
                "ds:DescribeDirectories",
                "securityhub:BatchImportFindings",
                "sagemaker:ListEndpoints",
                "ecr:GetRepositoryPolicy",
                "sqs:ListQueues",
                "sqs:GetQueueAttributes",
                "globalaccelerator:ListAccelerators",
                "globalaccelerator:ListListeners",
                "globalaccelerator:ListEndpointGroups",
                "xray:GetEncryptionConfig",
                "cloud9:DescribeEnvironments",
                "cloud9:ListEnvironments",
                "cloudsearch:DescribeDomainEndpointOptions",
                "cloudsearch:DescribeDomains",
                "lambda:GetFunction",
                "lambda:GetLayerVersion",
                "lambda:GetLayerVersionPolicy",
                "lambda:GetPolicy",
                "lambda:ListFunctions",
                "lambda:ListLayerVersions",
                "lambda:ListLayers",
                "ecs:DescribeTaskDefinition",
                "ecs:ListTaskDefinitionFamilies",
                "ecs:ListTaskDefinitions",
                "datasync:DescribeAgent",
                "datasync:DescribeTask",
                "datasync:ListAgents",
                "datasync:ListTasks",
                "fsx:DescribeBackups",
                "fsx:DescribeFileSystems",
                "amplify:ListApps",
                "elasticfilesystem:DescribeFileSystemPolicy",
                "codeartifact:GetDomainPermissionsPolicy",
                "codeartifact:ListDomains",
                "codeartifact:ListRepositories",
                "codeartifact:GetRepositoryPermissionsPolicy",
                "shield:ListAttacks",
                "cloudhsm:DescribeClusters",
                "cloudhsm:DescribeBackups",
                "iam:ListRolePolicies",
                "iam:ListRoles",
                "iam:GetRolePolicy",
                "iam:GetUserPolicy",
                "iam:ListGroupPolicies",
                "iam:ListGroups",
                "iam:GetGroupPolicy",
                "iam:ListPolicies",
                "iam:GetPolicyVersion",
                "route53resolver:ListResolverQueryLogConfigAssociations",
                "route53resolver:GetFirewallConfig",
                "route53resolver:ListResolverDnssecConfigs",
                "route53resolver:ListFirewallRuleGroupAssociations"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}
resource "aws_cloudwatch_event_rule" "Electric_Eye_Task_Scheduling_CW_Event_Rule" {
  name                = "${var.Electric_Eye_ECS_Resources_Name}-scheduler"
  description         = "Run ${var.Electric_Eye_ECS_Resources_Name} Task at a scheduled time (${var.Electric_Eye_Schedule_Task_Expression}) - Managed by Terraform"
  schedule_expression = var.Electric_Eye_Schedule_Task_Expression
}
resource "aws_iam_role" "Electric_Eye_Scheduled_Task_Event_Role" {
  name               = "${var.Electric_Eye_ECS_Resources_Name}-event-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "Electric_Eye_Scheduled_Task_Event_Role_Policy" {
  role       = aws_iam_role.Electric_Eye_Scheduled_Task_Event_Role.id
  policy_arn = data.aws_iam_policy.AWS_Managed_ECS_Events_Role.arn
}

resource "aws_cloudwatch_event_target" "Electric_Eye_Scheduled_Scans" {
  rule       = aws_cloudwatch_event_rule.Electric_Eye_Task_Scheduling_CW_Event_Rule.name
  arn        = aws_ecs_cluster.Electric_Eye_ECS_Cluster.arn
  role_arn   = aws_iam_role.Electric_Eye_Scheduled_Task_Event_Role.arn
  ecs_target {
      launch_type         = "FARGATE"
      task_definition_arn = aws_ecs_task_definition.Electric_Eye_ECS_Task_Definition.arn
      task_count          = "1"
      platform_version    = "LATEST"
      network_configuration {
        subnets         = [element(aws_subnet.Electric_Eye_Public_Subnets[*].id, 0)]
        security_groups = [aws_security_group.Electric_Eye_Sec_Group.id]
    }
  }
}