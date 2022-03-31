# ElectricEye FAQ

## 0. Why is continuous compliance monitoring (CCM) important?

One of the main benefits to moving to the cloud is the agility it gives you to quickly iterate on prototypes, drive business value and globally scale. That is what is known as a double-edge sword, because you can also quickly iterate into an insecure state. CCM gives you near real-time security configuration information from which you can: assess risk to your applications and data, determine if you fell out of compliance with regulatory or industry framework requirements and/or determine if you fell out of your organizational privacy protection posture, among other things. Depending on how you deliver software or services, this will allow your developers to continue being agile in their delivery while remediating any security issues that pop up. If security is owned by a central function, CCM allows them to at least *keep up* with the business, make informed risk-based decisions and quickly take action and either remediate, mitigate or accept risks due to certain configurations.

ElectricEye won't take the place of a crack squad of principal security engineers or stand-in for a compliance, infosec, privacy or risk function but it will help you stay informed to the security posture of your AWS environment across a multitude of services. You should also implement secure software delivery, privacy engineering, secure-by-design configuration, and application security programs and rely on automation where you can to develop a mature cloud security program.

Or, you could just not do security at all and look like pic below:

![ThreatActorKittens](../screenshots/plz-no.jpg)

## 1. Why should I use this tool?

Primarily because it is free to *use* (you still need to pay for the infrastructure). This tool will also help cover services not currently covered by AWS Config rules or AWS Security Hub security standards. This tool is also natively integrated with Security Hub, no need to create additional services to perform translation into the AWS Security Finding Format and call the `BatchImportFindings` API to send findings to Security Hub.

There is logic that will auto-archive findings as they move in and out of compliance, there are also other add-ons such as multi-account response & remediation playbooks, Config Recorder integration, Shodan integration, Slack integration and others that even if you do not use ElectricEye you can get some usage from the other stuff. Or just, you know, steal the code?

Finally, you can look like the GIF below, where your security team is Jacob Trouba (New York Rangers #8 in white) laying sick open-ice hits on pesky security violations represented by Dal Colle (New York Islanders #28 in that ugly uniform).
![OpenIceHit](../screenshots/old-school-hockey-trouba.gif)

## 2. Will this tool help me become compliant with (insert framework of some sort here)?

No, it still won't. If you wanted to use this tool to satisfy an audit, I would recommend you work closely with your GRC and Legal functions to determine if the checks performed by ElectricEye will legally satisfy the requirements of any compliance framework or regulations you need to comply with. 

## 3. Can this be the primary tool I use for AWS security assessments?

Only you can make that determination. More is always better, there are far more mature projects that exist such as [Prowler](https://github.com/toniblyx/prowler), [PacBot](https://github.com/tmobile/pacbot), [Cloud Inquisitor](https://github.com/RiotGames/cloud-inquisitor) and [Scout2](https://github.com/nccgroup/ScoutSuite). You should perform a detailed analysis about which tools support what services, what checks, what your ultimate downstream tool will be for taking actions or analyzing findings (Splunk, Kibana, Security Hub, Demisto, Phantom, QuickSight, etc.) and how many false-positives or false-negatives are created by what tool. Some of those tools also do other things, and that is not to mention the endless list of logging, monitoring, tracing and AppSec related tools you will also need to use. There are additional tools listed in [FAQ #14](https://github.com/jonrau1/ElectricEye#14-what-are-those-other-tools-you-mentioned) below.

## 4. Why didn't you build Config rules do these?

I built ElectricEye with Security Hub in mind, using custom Config rules would require a lot of additional infrastructure and API calls to parse out a specific rule, map what little information Config gives to the ASFF and also perform more API calls to enrich the findings and send it, that is not something I would want to do. Additionally, you are looking at $0.001/rule evaluation/region and then have to pay for the Lambda invocations and (potentially) for any findings above the first 10,000 going to Security Hub a month.

## 5. What are the advantages over AWS Security Hub security standards? Why shouldn't I use those instead?

You should use them! The only notable "advantage" would be ElectricEye might support a resource before a Security Hub security standard does, or it may support a check that Security Hub security standards do not. At the very least, you should use the CIS AWS Foundations Benchmark standard, it contains common sense checks that audit IAM users and basic security group misconfigurations.

## 6. What are the advantages over Config Conformance Packs? Why shouldn't I use those instead?

Similar to above, ElectricEye may support another service or another type of check that Config rules do not, on top of the additional charges you pay for using Conformance packs ($0.0012 per evaluation per Region). That said, you should probably continue to use the IAM-related Config rules as many of them are powered by [Zelkova](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/), which uses automated reasoning to analyze policies and the future consequences of policies.

## 7. Can I scope these checks by tag or by a certain resource?

No. That is something in mind for the future, and a very good idea for a PR. The only way to do so now is to manually rewrite the checks and/or delete any auditors you don't need from use.

## 8. Why do I have to set this up per account? Why can't I just scan all of my resources across all accounts?

First, the IAM permissions needed to run all of the auditors' scans are numerous, and while not particularly destructive, give a lot of Read/List rights which can be an awesome recon tool (very fitting given the name of the tool) for a malicious insider or threat actor. Giving it cross-account just makes that totally-not-cool individual's job of mass destruction so much easier, this security information can give them all sorts of ideas for attacks to launch. Lastly, it could also make provisioning a little harder, given that you have to keep up to 1000s (depending on how many accounts you have) of roles up-to-date as ElectricEye adds new capabilities.

These are lazy answers above, I did not want to make this a master-member tool because security should be democratized. You are **NOT** doing your account owners, DevOps teams or anyone else in the business any favors if you are just running scans and slapping a report you did up in Quicksight in front of them. By allowing them to view their findings in their own Security Hub console and act on them, you are empowering and entrusting them with security goodness and fortune shall smile upon you. With that, I will not make this master-member nor accept any PRs that attempt to.

Plus, Security Hub supports master-member patterns, so you can get your nasty security-as-a-dashboard paws on the findings there.

## 9. Why don't you support (insert service name here)?

I will, eventually. If you really need a specific check supported RIGHT NOW please create an Issue, and if it is feasible, I will tackle it. PRs are welcome for any additions.

## 10. Where is that automated remediation you like so much?

Work has started in [ElectricEye-Response](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response)

## 11. Why do some of the severity scores / labels for the same failing check have different values?!

Some checks, such as the EC2 Systems Manager check for having the latest patches installed are dual-purpose and will have different severities. For instance, that check looks if you have any patch state information reported at all, if you do not you likely are not even managing that instance as part of the patch baseline. If a missing or failed patch is reported, then the severity is bumped up since you ARE managing patches, but something happened and now the patch is not being installed.

In a similar vein, some findings that have a severity score of 0 (severity label of `INFORMATIONAL`) and a Compliance status of `PASSED` may not be Archived if it is something you may want to pay attention to. An example of this are EBS Snapshots that are shared with other accounts, it is nowhere near as bad as being public but you should audit these accounts to make sure you are sharing with folks who should be shared with (I cannot tell who that is, your SecOps analyst should be able to).

## 12. What if I run into throttling issues, how can I get the findings?

For now, I put (lazy) sleep steps in the bash script that runs all the auditors. It should hopefully add enough cooldown to avoid getting near the 10TPS rate limit, let alone the 30TPS burst limit of the BIF API. You are throttled after bursting, but the auditors do not run in parallel for this reason, so you should not run into that unless for some reason you have 1000s of a single type of resource in a single region.

## 13. How much does this solution cost to run?

The costs are extremely negligible, as the primary costs are Fargate vCPU and Memory per GB per Hour and then Security Hub finding ingestion above 10,000 findings per Region per Month (the first 10,000 is perpetually free). We will use two scenarios as an example for the costs, you will likely need to perform your own analysis to forecast potential costs. ElectricEye's ECS Task Definition is ***2 vCPU and 4GB of Memory by default***. I made a [very rough cost calculator](https://github.com/jonrau1/ElectricEye/blob/master/cost-calculator/electriceye-cost-calculations.csv) in CSV you can refer to, I will try to reflect the latest that is on the ReadMe to the worksheet, but no promises.

### Fargate Costs

**NOTE:** This does not take Savings Plans into consideration, depending if you are an Enterprise Support customer and how well you tune these, you can possibly run ElectricEye for free on Fargate!

**30 Day Period: Running ElectricEye every 12 hours and it takes 5 minutes per Run**</br>
5 hours of total runtime per month: **$0.493700/region/account/month**

**30 Day Period: Running ElectricEye every 3 hours and it takes 10 minutes per Run**</br>
40 hours of total runtime per month: **$3.949600/region/account/month**

### Security Hub Costs

**Having 5 resources per check in scope for 108 checks running 60 times a month (every 12 hours)**</br>
32,400 findings with 22,400 in scope for charges: **$0.6720/region/account/month**

**Having 15 resources per check in scope for 108 checks running 240 times a month (every 3 hours)**</br>
388,800 findings with 378,800 in scope for charges: **$11.3640/region/account/month**

If you take the most expensive examples of having 15 resources in scope for 108 checks being run every 3 hours (for 40 total hours of Fargate runtime and 378K findings in Security Hub) that would be a combined monthly cost of **$15.3136** with a yearly cost of **$183.76** per region per account. If you were running across *4 regions* that would be **$735.05** and across *18 regions* would be **$3,307.74** per year per account.

If you ran in 2 regions across 50 accounts your approx. cost would be **$18,376.32** per year, bump that up to 4 regions and 500 accounts and you are looking at approx. **$367,526.40** a year (price is the same for 1 region, 2000 accounts). You could potentially save up to 70% on Fargate costs by modifying ElectricEye to run on [Fargate Spot](https://aws.amazon.com/blogs/aws/aws-fargate-spot-now-generally-available/).

The best way to estimate your Security Hub costs is to refer to the Usage tab within the Settings sub-menu, this will give you your total usage types, items in scope for it and estimated items per month with a forecasted cost.

## 14. What are those other tools you mentioned?

You should consider taking a look at all of these:
### Secrets Scanning

- [truffleHog](https://github.com/dxa4481/truffleHog)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [detect-secrets](https://github.com/Yelp/detect-secrets)

### SAST / SCA

- [Bandit](https://github.com/PyCQA/bandit) (for Python)
- [GoSec](https://github.com/securego/gosec) (for Golang)
- [NodeJsScan](https://github.com/ajinabraham/NodeJsScan) (for NodeJS)
- [tfsec](https://github.com/liamg/tfsec) (for Terraform SCA)
- [terrascan](https://github.com/cesar-rodriguez/terrascan) (another Terraform SCA)
- [Checkov](https://github.com/bridgecrewio/checkov) (Terraform & CFN SCA)
- [cfripper](https://github.com/Skyscanner/cfripper) (CloudFormation SCA)
- [codewarrior](https://github.com/CoolerVoid/codewarrior) (multi-language manual SAST tool)
- [brakeman](https://github.com/presidentbeef/brakeman) (Ruby on Rails SAST)
- [security-code-scan](https://github.com/security-code-scan/security-code-scan) (NET/netcore SAST tool)
- [dlint](https://github.com/dlint-py/dlint/) (another Python SAST / Linter tool for CI)
- [terraform_validate](https://github.com/elmundio87/terraform_validate) (Another Terraform SCA/Policy-as-Code tool, supports 0.11.x)
- [sKan](https://github.com/alcideio/skan) (K8s resource file / helm chart security scanner / linter by Alcide.io)
- [solgraph](https://github.com/raineorshine/solgraph) (Solidity smart contract SCA / control flow viz)

### Linters

- [hadolint](https://github.com/hadolint/hadolint) (for Docker)
- [cfn-python-lint](https://github.com/aws-cloudformation/cfn-python-lint) (for CloudFormation)
- [cfn-nag](https://github.com/stelligent/cfn_nag) (for CloudFormation)
- [terraform-kitchen](https://github.com/newcontext-oss/kitchen-terraform) (InSpec tests against Terraform - part linter/part SCA)

### DAST

- [Zed Attack Proxy (ZAP)](https://owasp.org/www-project-zap/)
- [Nikto](https://github.com/sullo/nikto) (web server scanner)

### AV

- [ClamAV](https://www.clamav.net/documents/clamav-development)
- [aws-s3-virusscan](https://github.com/widdix/aws-s3-virusscan) (for S3 buckets, obviously)
- [BinaryAlert](http://www.binaryalert.io/) (serverless, YARA backed for S3 buckets)

### IDS/IPS

- [Suricata](https://suricata-ids.org/)
- [Snort](https://www.snort.org/)
- [Zeek](https://www.zeek.org/)

### DFIR

- [Fenrir](https://github.com/Neo23x0/Fenrir) (bash-based IOC scanner)
- [Loki](https://github.com/Neo23x0/Loki) (Python-based IOC scanner w/ Yara)
- [GRR Rapid Response](https://github.com/google/grr) (Python agent-based IR)
- this one is deprecated but... [MIG](http://mozilla.github.io/mig/)

### TVM

- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)
- [OpenVAS](https://www.openvas.org/)
- [Trivy](https://github.com/aquasecurity/trivy) (container vuln scanning from Aqua Security)
- [Scuba](https://www.imperva.com/lg/lgw_trial.asp?pid=213) (database vuln scanning from Imperva)

### Threat Hunting

- [ThreatHunter-Playbook](https://github.com/hunters-forge/ThreatHunter-Playbook)
- [Mordor](https://github.com/hunters-forge/mordor)

### Red Team Toolbox

- [Pacu](https://github.com/RhinoSecurityLabs/pacu) (AWS exploitation framework)
- [LeakLooker](https://github.com/woj-ciech/LeakLooker) (Python-based finder of open databases / buckets)
- [aws_consoler](https://github.com/NetSPI/aws_consoler) (not a purpose built exploitation tool, but if your recon got you keys use this to turn it into console access)

### ~~Kubernetes / Container~~ Microservices(?) Security Tools

- [Istio](https://istio.io/docs/setup/getting-started/) (microservices service mesh, mTLS, etc.)
- [Calico](https://www.projectcalico.org/#getstarted) (K8s network policy)
- [Envoy](https://www.envoyproxy.io/) (microservices proxy services, underpins AWS AppMesh)
- [Falco](https://sysdig.com/opensource/falco/) (a metric shitload of awesome k8s/container security features from Sysdig)
- [Goldilocks](https://github.com/FairwindsOps/goldilocks) (K8s cluster right-sizing from Fairwinds)
- [Polaris](https://github.com/FairwindsOps/polaris) (K8s best practices, YAML SCA/linting from Fairwinds)
- [kube-bench](https://github.com/aquasecurity/kube-bench) (K8s CIS Benchmark assessment from Aqua Security)
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) (K8s attacker-eye-view of K8s clusters from Aqua Security)
- [rbac-tool](https://github.com/alcideio/rbac-tool) (K8s RBAC visualization tool from Alcide.io)

### CCM Tools

- [Prowler](https://github.com/toniblyx/prowler)
  - [Prowler SecHub Integration](https://aws.amazon.com/blogs/security/use-aws-fargate-prowler-send-security-configuration-findings-about-aws-services-security-hub/)
- [PacBot](https://github.com/tmobile/pacbot)
- [Cloud Inquisitor](https://github.com/RiotGames/cloud-inquisitor)
- [Scout2](https://github.com/nccgroup/ScoutSuite)
- [Cloud Custodian](https://cloudcustodian.io/docs/index.html)

### Threat Intel Tools

- [MISP](https://github.com/MISP/MISP) (Threat intel sharing platform, formerly Malware Information Sharing Platform)
  - [PyMISP](https://github.com/MISP/PyMISP) (Python implementation of MISP APIs)
- [STAXX](https://www.anomali.com/community/staxx) (Community edition threat intel platform from Anomali)
- [TCOpen](https://threatconnect.com/free/) (Community edition of ThreatConnect's platform)

### Misc / Specialized

- [ContrastCE](https://www.contrastsecurity.com/contrast-community-edition) (open edition for Contrast Security IAST/SCA/RASP for Java and .NET)
- [LambdaGuard](https://github.com/Skyscanner/LambdaGuard)
- [SecHub SOC Inna Box](https://github.com/aws-samples/aws-security-services-with-terraform/tree/master/aws-security-hub-boostrap-and-operationalization)
- [OPA](https://github.com/open-policy-agent/opa) (open policy enforcement tool - works with K8s, TF, Docker, SSH, etc.)
- [SecHub InSpec Integration](https://aws.amazon.com/blogs/security/continuous-compliance-monitoring-with-chef-inspec-and-aws-security-hub/)
- [OpenDLP](https://code.google.com/archive/p/opendlp/) (open-source data loss protection tool)

## 15. Why did you swap the Dockerfile to being Alpine Linux-based?

The original (V1.0) Dockerfile used the `ubuntu:latest` image as its base image and was chunky (~450MB) where the Alpine image is a tiny bit under a 10th of that (41.95MB). It is also much faster to create and push the image since `apk` adds only what is needed and isn't bloated by the Ubuntu dependencies from `apt` or that come prepackaged. Lastly, the build logs are a lot less chatty with the (hacky) ENV value set for Python and Pip related logs. I have added a Trivy GitHub Action that will pipe to Security Findings any high / critical findings, DependaBot and Snyk will also catch things

## 16. I thought you said that ElectricEye will not help me pass an audit!?

**I have no idea if ElectricEye can be used to pass an audit. I will make no warranty or suggestion of that**. All I did was pick frameworks that are aligned to best practices such as NIST CSF and NIST SP 800-53. The other two (TSC & ISO 27001:2013) are backed by governing organizations and you *will* need a qualified 3rd Party Assessment Organization (3PAO) (yes I know that's a FedRAMP term) to audit you. This was requested by quite a lot of you who reached out to me so, all I did was do some light mapping from ElectricEye Auditors into NIST CSF and used the provided mappings in the CSF document to map to the other frameworks. 

I would **strongly suggest** having your Legal, Audit, Enterprise Risk Management (ER) and InfoSec teams review these mappings if you have the crazy plan to use it for audit preparedness or as evidence during a real audit / assessment. If you manage to convince those departments to use this you should probably run away because: *"And if the band you're in starts playing different tunes, I'll see you on the dark side of the moon"* (Brain Damage by Pink Floyd if you didn't get the reference).

## 17. At a high-level, how did you map the ElectricEye Auditors into these compliance frameworks?

I am most familiar with NIST CSF so I mapped all checks that I felt satisfied the spirit of a NIST CSF Subcategory, some are very easy like `NIST CSF PR.DS-1: Data-at-rest is protected`, others are a bit more nuanced. Within the NIST CSF Excel workbook there are mappings that NIST did themselves into ISO/IEC 27001 and NIST SP 800-53 so I just used those as-is without touching either the SP or the ISO standard. The American Institute of Certified Public Accountants (AICPA) who is the governing body for SOC Reports and the Trust Services Criteria (TSC) also provide a mapping from TSC/COSO "points of focus" to NIST CSF which I mapped in reverse. 

The `Compliance.RelatedRequiremens` JSON list only accepts up to 32 strings so with that in mind I was not very aggressive in my mappings to NIST CSF to avoid running over that hard limit. I blame ISO 27001:2013, that compliance framework has a ton of mapped controls from the CSF. To that effect you will only be receiving a coarse-grained mapping, at best, hence why I stress that you should do your own analysis on this. I also did not do any mapping into the Respond or Recover functions of NIST CSF, the subcategories are very vague in those areas and I cannot assume that you actually analyze and respond to threats, map that on your own if need be.

~~The mappings list is [located here](https://github.com/jonrau1/ElectricEye/blob/master/compliance-mapping/electriceye-auditor-compliance-mapping.xlsx)~~ Shit, I don't know where I put that...