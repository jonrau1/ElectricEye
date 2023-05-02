## ElectricEye for Cloud Asset Management (CAM)

## Table of Contents

zonk

## CAM Concept of Operations (CONOPs)

The CONOPS for the CAM capabilities of ElectricEye largely lay within the evaluation logic provided by ElectricEye. All ElectricEye findings created by its checks are mapped to the [AWS Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) which supports up to 50 key-value pairs within its `ProductFields` object in the schema.

ElectricEye utilizes the `ProductFields` object to record information about the Assessment Target - the Cloud Service Provider (CSP) or Software-as-a-Service (SaaS) vendor - that is being evaluated in two distinct ways. Any key with `Provider` in its name corresponds to information about the Assessment Target itself and any key with `Asset` in its name corresponds to whatever discrete component or sub-service is being evaluated by an ElectricEye Check such as an AWS EC2 Instance or a ServiceNow Plugin.

The following CAM-related `ProductFields` keys are provided per Check within ElectricEye:

- **`Provider`**: This key contains the name of the Assessment Target that that Auditor corresponds to such as AWS, GCP, OCI, ServiceNow, M365, or otherwise.

- **`ProviderType`**: This key corresponds to the cloud offering of the Assessment Target, either `CSP` for public cloud service providers or `SaaS` for Software-as-a-Service vendors and providers. In the future, this may be further expanded as ElectricEye expands in its service coverage.

- **`ProviderAccountId`**: this key contains the unique identifier of the specific Assessment Target being evaluated such as a ServiceNow Instance Name, a M365 Tenant Identifier, an Oracle Cloud Infrastrucute Tenancy ID, an AWS Account ID, and so on. Only the value will be provided and it will always correspond to `Provider`.

- **`AssetRegion`**: This key contains information about the specific asset's (what the Check is evalauting against) geographic region, if known. In some cases this may correspond to a smaller geographical infrastructure repesentation such as a Google Cloud Platform `zone` and may be omitted completely if deducing the location is not known (such as from a Workday ERP or ServiceNow instance). Best effort is made to parse this information from information returned by a CSP or SaaS Provider API such as an AWS `region` or a GCP `zone`.

- **`AssetDetails`**: The key contains the JSON payload returned by the CSP or SaaS provider's API relative to the specific Asset being evaluated by an ElectricEye Check. The entire schema is captured in `AssetDetails` and will only appear in `json`, `json-normalized`, `stdout`, and `cam-json` ElectricEye Outputs.