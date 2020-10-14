# Day2 Security Bot Setup guide

  1.  Creating an S3 bucket
         - `aws s3api create-bucket --bucket {some_dummy_bucket} --profile platform` where some-dummy-bucket-us-east-1-13465 is the bucket name

  2. Sync of S3 bucket
      - `aws s3 sync . s3://{some_dummy_bucket} --profile platform`

  **SecurityBot Auditors Bucket is where the python scripts reside. These get downloaded to a Fargate Task**
     - `http://s3.amazonaws.com/{some_dummy_bucket}`

  3. Modify the bucket policy for public access. The bucket becomes a public S3 bucket

     - `aws ecr create-repository --repository-name security_bot --profile {profile_name} --region us-east-1`

  4. Check for successfull authentication before pushing image at Step 7
     **For AWS CLI v2**
 
     - `cd into folder ElectricEye`
     - `aws ecr get-login-password --region us-east-1 --profile platform | docker login --username AWS --password-stdin 13456.dkr.ecr.us-east-1.amazonaws.com/security_bot`

     **For AWS CLI v1**
        - `aws ecr get-login --registry-ids 1346579 --region us-east-1 --no-include-email`

 5. Build a docker image
     - `docker build -t security_bot .`
  
 6. Tag the docker image
      - `docker tag security_bot:latest 13456.dkr.ecr.us-east-1.amazonaws.com/security_bot`
  
 7. Push the docker image
      - `docker push 13456.dkr.ecr.us-east-1.amazonaws.com/security_bot`
  
 8. Restrict the ECR Policy. Needs a Policy JSON File.
      - `aws ecr set-repository-policy --repository-name repository_name --policy-text file://my-policy.json --profile profile_name --region us-east-1`

Sample ECR Policy JSON File 

```
     {
      "Version": "2008-10-17",
      "Statement": [
        {
          "Sid": "AllowSameAccountPull",
          "Effect": "Allow",
          "Principal": {
            "AWS": [
                "arn:aws:iam::132465:role/Stg1-Day2-Security-Bot-ElectricEyeExecutionRole-123456789",
                "arn:aws:iam::13456:role/Stg1-Day2-Security-Bot-ElectricEyeTaskRole-13246579"
            ],
            "Service": "ecs-tasks.amazonaws.com"
          },
          "Action": [
            "ecr:BatchCheckLayerAvailability",
            "ecr:BatchGetImage",
            "ecr:CompleteLayerUpload",
            "ecr:DescribeImages",
            "ecr:DescribeRepositories",
            "ecr:GetAuthorizationToken",
            "ecr:GetDownloadUrlForLayer",
            "ecr:GetRepositoryPolicy",
            "ecr:InitiateLayerUpload",
            "ecr:ListImages",
            "ecr:PutImage"
          ]
        }
      ]
    }
  ```
  
