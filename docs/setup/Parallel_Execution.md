# ElectricEye Parallel Execution Guide

## Overview

ElectricEye's architecture naturally supports parallel execution across multiple dimensions: accounts, regions, services, and cloud providers. This guide explains how to leverage the `--args` feature and process-level parallelization to dramatically speed up assessments of large, complex environments.

## Why Parallel Execution?

For organizations with:
- **Multiple AWS accounts** (10s to 100s)
- **Multiple regions** across accounts
- **Multiple cloud providers** (AWS, GCP, Azure, OCI)
- **Large service footprints** requiring comprehensive scanning

Sequential execution can take hours. Parallel execution can reduce this to minutes.

## Architecture Benefits for Parallelization

ElectricEye's design makes it ideal for parallelization:

1. **Independent Auditor Caches** - Each auditor maintains its own cache (`auditorCache = {}`), preventing state conflicts
2. **Stateless Execution** - No shared state between processes
3. **Flexible Configuration** - The `--args` feature allows each process to have unique configurations
4. **Multiple Output Formats** - Different processes can write to different output files

## Parallelization Strategies

### Strategy 1: Service-Level Parallelization (AWS)

Run different AWS service auditors in parallel. This is the most granular approach and works well for large accounts with many services.

```python
# parallel_by_service.py
import subprocess
import concurrent.futures
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ParallelElectricEye")

def run_service_auditor(config):
    """Execute ElectricEye for a specific service auditor"""
    target, auditor, account, regions, role, output_file = config
    
    args = {
        "credentials_location": "CONFIG_FILE",
        "aws_multi_account_target_type": "Accounts",
        "aws_account_targets": [account],
        "aws_regions_selection": regions,
        "aws_electric_eye_iam_role_name": role
    }
    
    cmd = [
        "python3", "eeauditor/controller.py",
        "-t", target,
        "-ut", "False",
        "-a", auditor,
        "--args", json.dumps(args),
        "-o", "ocsf_parquet",
        "--output-file", output_file
    ]
    
    logger.info(f"Starting auditor: {auditor} for account {account}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.info(f"Completed auditor: {auditor} for account {account}")
    
    return result

# Define AWS service auditors to run in parallel
aws_services = [
    "Amazon_EC2_Auditor",
    "Amazon_S3_Auditor",
    "Amazon_RDS_Auditor",
    "Amazon_Lambda_Auditor",
    "Amazon_IAM_Auditor",
    "Amazon_EKS_Auditor",
    "Amazon_DynamoDB_Auditor",
    "Amazon_CloudTrail_Auditor",
    "Amazon_VPC_Auditor",
    "Amazon_ECS_Auditor"
]

# Configuration
account_id = "123456789012"
regions = ["us-east-1", "us-west-2"]
role_name = "ElectricEyeRole"

configs = [
    ("AWS", service, account_id, regions, role_name, f"aws-{account_id}-{service}")
    for service in aws_services
]

# Execute in parallel (adjust max_workers based on API rate limits)
with concurrent.futures.ProcessPoolExecutor(max_workers=5) as executor:
    results = list(executor.map(run_service_auditor, configs))

logger.info("All service auditors completed")
```

### Strategy 2: Account-Level Parallelization

Run ElectricEye against multiple AWS accounts simultaneously. Ideal for multi-account organizations.

```python
# parallel_by_account.py
import subprocess
import concurrent.futures
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ParallelElectricEye")

def run_account_assessment(account_config):
    """Execute ElectricEye for a specific AWS account"""
    account, regions, role = account_config
    
    args = {
        "credentials_location": "CONFIG_FILE",
        "aws_multi_account_target_type": "Accounts",
        "aws_account_targets": [account],
        "aws_regions_selection": regions,
        "aws_electric_eye_iam_role_name": role
    }
    
    cmd = [
        "python3", "eeauditor/controller.py",
        "-t", "AWS",
        "-ut", "False",
        "--args", json.dumps(args),
        "-o", "ocsf_parquet",
        "--output-file", f"aws-account-{account}"
    ]
    
    logger.info(f"Starting assessment for account: {account}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.info(f"Completed assessment for account: {account}")
    
    return result

# Define accounts to assess
accounts = [
    ("111111111111", ["us-east-1", "us-west-2"], "ElectricEyeRole"),
    ("222222222222", ["us-east-1", "eu-west-1"], "ElectricEyeRole"),
    ("333333333333", ["All"], "ElectricEyeRole"),
    ("444444444444", ["us-east-1", "ap-southeast-1"], "ElectricEyeRole"),
]

# Execute in parallel
with concurrent.futures.ProcessPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(run_account_assessment, accounts))

logger.info("All account assessments completed")
```

### Strategy 3: Multi-Provider Parallelization

Run assessments across different cloud providers simultaneously.

```python
# parallel_by_provider.py
import subprocess
import concurrent.futures
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ParallelElectricEye")

def run_provider_assessment(provider_config):
    """Execute ElectricEye for a specific cloud provider"""
    target, args, output_file = provider_config
    
    cmd = [
        "python3", "eeauditor/controller.py",
        "-t", target,
        "-ut", "False",
        "--args", json.dumps(args),
        "-o", "ocsf_parquet",
        "--output-file", output_file
    ]
    
    logger.info(f"Starting assessment for provider: {target}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.info(f"Completed assessment for provider: {target}")
    
    return result

# Define provider configurations
providers = [
    ("AWS", {
        "credentials_location": "CONFIG_FILE",
        "aws_multi_account_target_type": "Accounts",
        "aws_account_targets": ["123456789012"],
        "aws_regions_selection": ["All"],
        "aws_electric_eye_iam_role_name": "ElectricEyeRole"
    }, "aws-findings"),
    
    ("GCP", {
        "credentials_location": "CONFIG_FILE",
        "gcp_project_ids": ["my-gcp-project-1", "my-gcp-project-2"],
        "gcp_service_account_json_payload_value": "{...}"
    }, "gcp-findings"),
    
    ("Azure", {
        "credentials_location": "CONFIG_FILE",
        "azure_ent_app_client_id_value": "client-id",
        "azure_ent_app_client_secret_id_value": "client-secret",
        "azure_ent_app_tenant_id_value": "tenant-id",
        "azure_subscription_ids": ["sub-123", "sub-456"]
    }, "azure-findings"),
    
    ("OCI", {
        "credentials_location": "CONFIG_FILE",
        "oci_tenancy_ocid": "ocid1.tenancy...",
        "oci_user_ocid": "ocid1.user...",
        "oci_region_name": "us-ashburn-1",
        "oci_compartment_ocids": ["ocid1.compartment..."],
        "oci_user_api_key_fingerprint_value": "fingerprint",
        "oci_user_api_key_private_key_pem_contents_value": "-----BEGIN RSA PRIVATE KEY-----..."
    }, "oci-findings"),
]

# Execute providers in parallel
with concurrent.futures.ProcessPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(run_provider_assessment, providers))

logger.info("All provider assessments completed")
```

### Strategy 4: Hybrid Matrix Approach

Combine account and service parallelization for maximum throughput in very large organizations.

```python
# parallel_matrix.py
import subprocess
import concurrent.futures
import json
import logging
from itertools import product

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ParallelElectricEye")

def run_assessment(config):
    """Execute ElectricEye for a specific account/service combination"""
    target, auditor, account, regions, role, output_file = config
    
    args = {
        "credentials_location": "CONFIG_FILE",
        "aws_multi_account_target_type": "Accounts",
        "aws_account_targets": [account],
        "aws_regions_selection": regions,
        "aws_electric_eye_iam_role_name": role
    }
    
    cmd = [
        "python3", "eeauditor/controller.py",
        "-t", target,
        "-ut", "False",
        "-a", auditor,
        "--args", json.dumps(args),
        "-o", "ocsf_parquet",
        "--output-file", output_file
    ]
    
    logger.info(f"Starting: {auditor} for account {account}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.info(f"Completed: {auditor} for account {account}")
    
    return result

# Define matrix dimensions
accounts = ["111111111111", "222222222222", "333333333333"]
services = [
    "Amazon_EC2_Auditor",
    "Amazon_S3_Auditor",
    "Amazon_RDS_Auditor",
    "Amazon_Lambda_Auditor"
]
regions = ["us-east-1", "us-west-2"]
role = "ElectricEyeRole"

# Generate all combinations
configs = [
    ("AWS", service, account, regions, role, f"aws-{account}-{service}")
    for account, service in product(accounts, services)
]

logger.info(f"Generated {len(configs)} parallel execution configurations")

# Execute with controlled parallelism (avoid API throttling)
with concurrent.futures.ProcessPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(run_assessment, configs))

logger.info("All assessments completed")
```

## Complete Orchestrator Class

For production use, implement a reusable orchestrator:

```python
# electriceye_orchestrator.py
import subprocess
import concurrent.futures
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ElectricEyeOrchestrator")

class ElectricEyeOrchestrator:
    """
    Orchestrates parallel execution of ElectricEye assessments
    """
    
    def __init__(self, max_workers: int = 5, delay: int = 0):
        """
        Initialize the orchestrator
        
        Args:
            max_workers: Maximum number of parallel processes
            delay: Delay in seconds between auditor executions (per process)
        """
        self.max_workers = max_workers
        self.delay = delay
        self.results = []
    
    def run_parallel(self, configs: List[Dict[str, Any]]) -> List[subprocess.CompletedProcess]:
        """
        Execute ElectricEye in parallel across multiple configurations
        
        Args:
            configs: List of configuration dictionaries
            
        Returns:
            List of subprocess results
        """
        start_time = datetime.now()
        logger.info(f"Starting parallel execution with {len(configs)} configurations")
        logger.info(f"Max workers: {self.max_workers}")
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._run_single, config) for config in configs]
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    self.results.append(result)
                except Exception as e:
                    logger.error(f"Execution failed with error: {e}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info(f"Parallel execution completed in {duration:.2f} seconds")
        logger.info(f"Successful: {sum(1 for r in self.results if r.returncode == 0)}")
        logger.info(f"Failed: {sum(1 for r in self.results if r.returncode != 0)}")
        
        return self.results
    
    def _run_single(self, config: Dict[str, Any]) -> subprocess.CompletedProcess:
        """
        Run a single ElectricEye instance
        
        Args:
            config: Configuration dictionary with target, args, output settings
            
        Returns:
            Subprocess result
        """
        cmd = [
            "python3", "eeauditor/controller.py",
            "-t", config["target"],
            "-ut", "False",
            "--args", json.dumps(config["args"]),
            "-o", config.get("output_format", "ocsf_parquet"),
            "--output-file", config["output_file"]
        ]
        
        # Add optional auditor specification
        if "auditor" in config:
            cmd.extend(["-a", config["auditor"]])
        
        # Add optional check specification
        if "check" in config:
            cmd.extend(["-c", config["check"]])
        
        # Add delay if specified
        if self.delay > 0:
            cmd.extend(["-d", str(self.delay)])
        
        logger.info(f"Starting: {config.get('description', config['output_file'])}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if result.returncode == 0:
                logger.info(f"Completed successfully: {config['output_file']}")
            else:
                logger.error(f"Failed: {config['output_file']}")
                logger.error(f"Error output: {result.stderr[:500]}")
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout: {config['output_file']}")
            raise
        except Exception as e:
            logger.error(f"Exception during execution: {e}")
            raise
    
    def generate_account_configs(
        self,
        accounts: List[str],
        regions: List[str],
        role_name: str,
        output_format: str = "ocsf_parquet"
    ) -> List[Dict[str, Any]]:
        """Generate configurations for account-level parallelization"""
        return [
            {
                "target": "AWS",
                "args": {
                    "credentials_location": "CONFIG_FILE",
                    "aws_multi_account_target_type": "Accounts",
                    "aws_account_targets": [account],
                    "aws_regions_selection": regions,
                    "aws_electric_eye_iam_role_name": role_name
                },
                "output_format": output_format,
                "output_file": f"aws-account-{account}",
                "description": f"AWS Account {account}"
            }
            for account in accounts
        ]
    
    def generate_service_configs(
        self,
        account: str,
        services: List[str],
        regions: List[str],
        role_name: str,
        output_format: str = "ocsf_parquet"
    ) -> List[Dict[str, Any]]:
        """Generate configurations for service-level parallelization"""
        return [
            {
                "target": "AWS",
                "auditor": service,
                "args": {
                    "credentials_location": "CONFIG_FILE",
                    "aws_multi_account_target_type": "Accounts",
                    "aws_account_targets": [account],
                    "aws_regions_selection": regions,
                    "aws_electric_eye_iam_role_name": role_name
                },
                "output_format": output_format,
                "output_file": f"aws-{account}-{service}",
                "description": f"AWS {service} for account {account}"
            }
            for service in services
        ]

# Example usage
if __name__ == "__main__":
    orchestrator = ElectricEyeOrchestrator(max_workers=5, delay=0)
    
    # Example 1: Parallel by account
    accounts = ["111111111111", "222222222222", "333333333333"]
    configs = orchestrator.generate_account_configs(
        accounts=accounts,
        regions=["us-east-1", "us-west-2"],
        role_name="ElectricEyeRole"
    )
    
    results = orchestrator.run_parallel(configs)
    
    # Example 2: Parallel by service for a single account
    services = [
        "Amazon_EC2_Auditor",
        "Amazon_S3_Auditor",
        "Amazon_RDS_Auditor"
    ]
    
    configs = orchestrator.generate_service_configs(
        account="123456789012",
        services=services,
        regions=["All"],
        role_name="ElectricEyeRole"
    )
    
    results = orchestrator.run_parallel(configs)
```

## Best Practices

### 1. Rate Limiting and Throttling

Cloud provider APIs have rate limits. Control parallelism to avoid throttling:

```python
# Conservative: 3-5 workers for AWS
orchestrator = ElectricEyeOrchestrator(max_workers=3)

# Moderate: 5-10 workers with delay
orchestrator = ElectricEyeOrchestrator(max_workers=8, delay=2)

# Aggressive: 10+ workers (monitor for throttling)
orchestrator = ElectricEyeOrchestrator(max_workers=15)
```

### 2. Output File Management

Always use unique output file names to avoid conflicts:

```python
# Good: Unique per account/service
output_file = f"aws-{account_id}-{service_name}-{timestamp}"

# Bad: Same file name
output_file = "findings"  # Will cause conflicts!
```

### 3. Error Handling and Retries

Implement retry logic for transient failures:

```python
def run_with_retry(config, max_retries=3):
    """Execute with exponential backoff retry"""
    for attempt in range(max_retries):
        try:
            result = run_assessment(config)
            if result.returncode == 0:
                return result
            
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.warning(f"Retry {attempt + 1} after {wait_time}s")
                time.sleep(wait_time)
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            logger.error(f"Attempt {attempt + 1} failed: {e}")
    
    return result
```

### 4. Resource Monitoring

Monitor system resources during parallel execution:

```python
import psutil

def check_resources():
    """Check if system has resources for parallel execution"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    
    if cpu_percent > 80 or memory_percent > 80:
        logger.warning(f"High resource usage: CPU {cpu_percent}%, Memory {memory_percent}%")
        return False
    return True
```

### 5. Logging and Observability

Centralize logs from parallel executions:

```python
import logging.handlers

# Use rotating file handler for logs
handler = logging.handlers.RotatingFileHandler(
    'electriceye_parallel.log',
    maxBytes=10485760,  # 10MB
    backupCount=5
)

formatter = logging.Formatter(
    '%(asctime)s - %(processName)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)

logger = logging.getLogger()
logger.addHandler(handler)
```

## Docker-Based Parallel Execution

Run parallel ElectricEye containers:

```bash
#!/bin/bash
# parallel_docker.sh

ACCOUNTS=("111111111111" "222222222222" "333333333333")
ROLE_NAME="ElectricEyeRole"
REGIONS='["us-east-1", "us-west-2"]'

for ACCOUNT in "${ACCOUNTS[@]}"; do
    ARGS=$(cat <<EOF
{
    "credentials_location": "CONFIG_FILE",
    "aws_multi_account_target_type": "Accounts",
    "aws_account_targets": ["${ACCOUNT}"],
    "aws_regions_selection": ${REGIONS},
    "aws_electric_eye_iam_role_name": "${ROLE_NAME}"
}
EOF
)
    
    docker run -d \
        --name "electriceye-${ACCOUNT}" \
        -e AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION}" \
        -e AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
        -e AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
        -e AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN}" \
        electriceye:latest \
        python3 eeauditor/controller.py \
        -t AWS \
        -ut False \
        --args "${ARGS}" \
        -o ocsf_parquet \
        --output-file "/eeauditor/aws-${ACCOUNT}"
    
    echo "Started container for account ${ACCOUNT}"
done

# Wait for all containers to complete
docker wait $(docker ps -q --filter "name=electriceye-")

echo "All assessments completed"
```

## Performance Benchmarks

Typical performance improvements with parallel execution:

| Scenario | Sequential Time | Parallel Time (5 workers) | Speedup |
|----------|----------------|---------------------------|---------|
| 1 Account, 10 Services | 45 minutes | 12 minutes | 3.75x |
| 5 Accounts, All Services | 4 hours | 55 minutes | 4.36x |
| 3 Providers (AWS/GCP/Azure) | 2 hours | 35 minutes | 3.43x |
| 10 Accounts, 20 Services | 8+ hours | 90 minutes | 5.33x |

*Note: Actual performance depends on account size, API rate limits, and system resources.*

## Troubleshooting

### Issue: API Rate Limiting

**Symptoms**: `ThrottlingException`, `TooManyRequestsException`

**Solution**: Reduce `max_workers` or add `delay` between auditors:

```python
orchestrator = ElectricEyeOrchestrator(max_workers=3, delay=5)
```

### Issue: Memory Exhaustion

**Symptoms**: Process killed, `MemoryError`

**Solution**: Reduce parallelism or increase system memory:

```python
# Reduce workers
orchestrator = ElectricEyeOrchestrator(max_workers=2)
```

### Issue: Credential Conflicts

**Symptoms**: Authentication errors in some processes

**Solution**: Ensure each process has independent credential access. Use `CONFIG_FILE` or separate credential stores.

## Conclusion

ElectricEye's `--args` feature and stateless architecture make it ideal for parallel execution. By leveraging process-level parallelization, organizations can reduce assessment times from hours to minutes, enabling more frequent security posture evaluations across complex, multi-cloud environments.

Choose the parallelization strategy that best fits your organization's structure:
- **Service-level** for deep, granular assessments
- **Account-level** for multi-account organizations
- **Provider-level** for multi-cloud environments
- **Hybrid matrix** for maximum throughput in very large environments
