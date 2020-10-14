# Day2 Security Bot Setup guide

  1.  Creating an S3 bucket
         - `aws s3api create-bucket --bucket dev-artifact-bucket-us-east-1-13465 --profile platform` where some-dummy-bucket-us-east-1-13465 is the bucket name

  2. Sync of S3 bucket
      - `aws s3 sync . s3://some-dummy-bucket-us-east-1-13465 --profile platform`

  **SecurityBot Auditors Bucket is where the python scripts reside. These get downloaded to a Fargate Task**
     - `http://s3.amazonaws.com/some-dummy-bucket-us-east-1-13465`

  3. Modify the bucket policy for public access. The bucket becomes a public S3 bucket

     - `aws ecr create-repository --repository-name security_bot --profile platform --region us-east-1`

  4. Check for successfull authentication
     **Requires AWS CLI v2**
 
     - `cd ElectricEye`
     - `aws ecr get-login-password --region us-east-1 --profile platform | docker login --username AWS --password-stdin 13456.dkr.ecr.us-east-1.amazonaws.com/security_bot`

     **Works with AWS CLI v1**
        - `aws ecr get-login --registry-ids 1346579 --region us-east-1 --no-include-email`

 5. Build a docker image
     - `docker build -t security_bot .`
  
 6. Tag the docker image
      - `docker tag security_bot:latest 13456.dkr.ecr.us-east-1.amazonaws.com/security_bot`
  
 7. Push the docker image
      - `docker push 13456.dkr.ecr.us-east-1.amazonaws.com/security_bot`
  
 8. Restrict the ECR Policy 
      - `aws ecr set-repository-policy --repository-name repository_name --policy-text file://my-policy.json --profile profile_name --region us-east-1` **for AWS cli v2**


