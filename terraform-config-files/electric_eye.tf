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

resource "aws_ecs_cluster" "Electric_Eye_ECS_Cluster" {
  name = "${var.Electric_Eye_VPC_Name_Tag}-ecs-cluster"
  capacity_providers = ["FARGATE"]
  default_capacity_provider_strategy = {
    capacity_provider = "FARGATE"
  }
  setting = {
    name  = "containerInsights"
    value = "enabled"
  }
}
resource "aws_ecr_repository_policy" "foopolicy" {
  repository = "${var.Electric_Eye_ECR_Repository_Name}"
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
  value       = "${aws_s3_bucket.Electric_Eye_Security_Artifact_Bucket.id}"
  description = "Contains the location of the S3 bucket with ElectricEye Auditor files"
}
resource "aws_cloudwatch_log_group" "Electric_Eye_ECS_Task_Definition_CW_Logs_Group" {
  name = "/ecs/${var.Electric_Eye_ECS_Resources_Name}"
}
resource "aws_ecs_task_definition" "Electric_Eye_ECS_Task_Definition" {
  family                   = "electric-eye"
  execution_role_arn       = "${aws_iam_role.Electric_Eye_ECS_Task_Execution_Role.arn}"
  task_role_arn            = "${aws_iam_role.Electric_Eye_ECS_Task_Role.arn}"
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
      }
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
  role   = "${aws_iam_role.Electric_Eye_ECS_Task_Execution_Role.id}"
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
  role   = "${aws_iam_role.Electric_Eye_ECS_Task_Role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:ListTrails",
                "access-analyzer:ListAnalyzers",
                "ec2:DescribeInstances",
                "ec2:GetEbsEncryptionByDefault",
                "ssm:DescribeInstancePatches",
                "ec2:DescribeSnapshots",
                "ecs:ListClusters",
                "ecs:DescribeClusters",
                "elasticloadbalancing:DescribeLoadBalancers",
                "kinesis:ListStreams",
                "cognito-idp:DescribeUserPool",
                "dynamodb:DescribeTable",
                "dynamodb:DescribeContinuousBackups",
                "dynamodb:DescribeTimeToLive",
                "dynamodb:ListTables",
                "shield:DescribeSubscription",
                "ec2:DescribeVolumes",
                "ec2:GetEbsDefaultKmsKeyId",
                "securityhub:GetFindings",
                "codebuild:ListProjects",
                "workspaces:DescribeWorkspaces",
                "ecr:GetLifecyclePolicy",
                "kms:Decrypt",
                "ecr:DescribeImages",
                "kms:DescribeKey",
                "sns:ListSubscriptionsByTopic",
                "rds:DescribeDBSnapshots",
                "ec2:DescribeSnapshotAttribute",
                "appstream:DescribeImages",
                "kafka:DescribeCluster",
                "cognito-idp:ListUserPools",
                "cloudformation:DescribeStacks",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "ds:ListLogSubscriptions",
                "detective:ListGraphs",
                "s3:GetObject",
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
                "license-manager:GetLicenseConfiguration",
                "license-manager:ListLicenseConfigurations",
                "ec2:DescribeImageAttribute",
                "eks:DescribeCluster",
                "eks:ListClusters",
                "elasticache:DescribeCacheClusters",
                "shield:DescribeDRTAccess",
                "secretsmanager:ListSecrets",
                "s3:GetLifecycleConfiguration",
                "ec2:DescribeAddresses",
                "appstream:DescribeUsers",
                "kafka:ListClusters",
                "shield:DescribeProtection",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeFlowLogs",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:ListMfaDevices",
                "iam:ListUserPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListServerCertificates",
                "mq:DescribeBroker",
                "mq:ListBrokers",
                "macie2:GetMacieSession",
                "managedblockchain:GetNetwork",
                "managedblockchain:ListMembers",
                "managedblockchain:ListNetworks",
                "managedblockchain:GetNode",
                "managedblockchain:GetMember",
                "managedblockchain:ListNodes",
                "sagemaker:DescribeNotebookInstance",
                "sns:ListTopics",
                "elasticfilesystem:DescribeFileSystems",
                "apigateway:GET",
                "ssm:GetParameter",
                "ssm:GetParameters",
                "ssm:GetParametersByPath",
                "sts:GetCallerIdentity",
                "rds:DescribeDBParameterGroups",
                "s3:ListBucket",
                "backup:DescribeProtectedResource",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketLogging",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketVersioning",
                "elasticloadbalancing:DescribeListeners",
                "es:DescribeElasticsearchDomain",
                "ssm:DescribeInstancePatchStates",
                "rds:DescribeDBInstances",
                "redshift:DescribeLoggingStatus",
                "appstream:DescribeFleets",
                "ecr:DescribeRepositories",
                "rds:DescribeDBParameters",
                "sagemaker:DescribeEndpoint",
                "ssm:DescribeInstanceAssociationsStatus",
                "workspaces:DescribeWorkspaceDirectories",
                "sagemaker:ListNotebookInstances",
                "ssm:DescribeInstanceProperties",
                "codebuild:BatchGetProjects",
                "rds:DescribeDBClusterSnapshotAttributes",
                "rds:DescribeDBClusterParameters",
                "guardduty:ListDetectors",
                "dms:DescribeReplicationInstances",
                "sns:GetTopicAttributes",
                "route53:ListHostedZones",
                "sagemaker:DescribeModel",
                "kinesis:DescribeStream",
                "sns:ListSubscriptions",
                "ec2:DescribeSecurityGroups",
                "rds:DescribeDBSnapshotAttributes",
                "ec2:DescribeImages",
                "es:ListDomainNames",
                "s3:GetAccountPublicAccessBlock",
                "s3:ListAllMyBuckets",
                "ssm:DescribeInstanceInformation",
                "ec2:DescribeSecurityGroupReferences",
                "ec2:DescribeVpcs",
                "rds:DescribeDBClusterSnapshots",
                "redshift:DescribeClusters",
                "cloudfront:ListDistributions",
                "sagemaker:ListModels",
                "ds:DescribeDirectories",
                "securityhub:BatchImportFindings",
                "rds:DescribeDBClusters",
                "sagemaker:ListEndpoints",
                "ecr:GetRepositoryPolicy",
                "rds:DescribeDBClusterParameterGroups",
                "lambda:ListFunctions",
                "cloudwatch:GetMetricData",
                "kms:ListAliases",
                "kms:GetKeyPolicy",
                "kms:ListKeys",
                "kms:GetKeyRotationStatus",
                "sqs:ListQueues",
                "sqs:GetQueueAttributes",
                "qldb:ListLedgers",
                "qldb:DescribeLedger",
                "qldb:ListJournalS3Exports",
                "globalaccelerator:ListAccelerators",
                "globalaccelerator:ListListeners",
                "globalaccelerator:ListEndpointGroups",
                "globalaccelerator:DescribeAcceleratorAttributes",
                "ram:GetResourceShares",
                "kinesisanalyticsv2:ListApplications",
                "kinesisanalyticsv2:DescribeApplication"
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
  schedule_expression = "${var.Electric_Eye_Schedule_Task_Expression}"
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
  role       = "${aws_iam_role.Electric_Eye_Scheduled_Task_Event_Role.id}"
  policy_arn = "${data.aws_iam_policy.AWS_Managed_ECS_Events_Role.arn}"
}
resource "aws_cloudwatch_event_target" "Electric_Eye_Scheduled_Scans" {
  rule       = "${aws_cloudwatch_event_rule.Electric_Eye_Task_Scheduling_CW_Event_Rule.name}"
  arn        = "${aws_ecs_cluster.Electric_Eye_ECS_Cluster.arn}"
  role_arn   = "${aws_iam_role.Electric_Eye_Scheduled_Task_Event_Role.arn}"
  ecs_target = {
      launch_type         = "FARGATE"
      task_definition_arn = "${aws_ecs_task_definition.Electric_Eye_ECS_Task_Definition.arn}"
      task_count          = "1"
      platform_version    = "LATEST"
      network_configuration  {
        subnets         = ["${element(aws_subnet.Electric_Eye_Public_Subnets.*.id, count.index)}"]
        security_groups = ["${aws_security_group.Electric_Eye_Sec_Group.id}"]
    }
  }
}
